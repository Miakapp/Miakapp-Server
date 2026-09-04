package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

// Role is the authenticated role carried by HELLO.
type Role int64

const (
	RoleUser        Role = 1
	RoleCoordinator Role = 2
	RoleCLI         Role = 3
)

// Request contains only the binding information defined by RFC 0001. The token
// verifier is responsible for deriving trusted identity fields from the token.
type Request struct {
	Role            Role
	Token           string
	HomeID          string
	CoordinatorName string
}

// Identity is the relay's authenticated, immutable connection principal.
type Identity struct {
	Role            Role
	HomeID          string
	ID              string
	ClientID        string
	CoordinatorName string
	VerifiedEmail   string
	ExpiresAt       time.Time
	Scopes          map[string]struct{}
}

// Principal returns the non-spoofable tuple forwarded by the relay.
func (identity Identity) Principal(sessionID int64) []any {
	var coordinator any
	if identity.CoordinatorName != "" {
		coordinator = identity.CoordinatorName
	}
	var email any
	if identity.VerifiedEmail != "" {
		email = identity.VerifiedEmail
	}
	return []any{int64(identity.Role), identity.ID, sessionID, coordinator, email}
}

// Verifier validates initial and replacement access material. Implementations
// must perform all signature, issuer, audience, expiry and profile checks
// required by the platform control-plane contract.
type Verifier interface {
	Verify(context.Context, Request) (Identity, error)
}

// ErrorKind classifies failures without exposing token material.
type ErrorKind string

const (
	ErrRejected  ErrorKind = "rejected"
	ErrExpired   ErrorKind = "expired"
	ErrAudience  ErrorKind = "audience"
	ErrTemporary ErrorKind = "temporary"
)

// Error is safe to translate into the stable relay error catalogue.
type Error struct {
	Kind ErrorKind
}

func (err *Error) Error() string {
	return fmt.Sprintf("authentication %s", err.Kind)
}

// Failure creates a redacted verifier error.
func Failure(kind ErrorKind, _ error) error {
	return &Error{Kind: kind}
}

// Kind returns a stable error kind and defaults unknown verifier errors to a
// temporary failure rather than accidentally disclosing their text.
func Kind(err error) ErrorKind {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Kind
	}
	return ErrTemporary
}

// ValidateBinding enforces that authenticated material cannot change the role,
// home or coordinator selected by the connection.
func ValidateBinding(request Request, identity Identity, now time.Time) error {
	if identity.Role != request.Role {
		return Failure(ErrRejected, errors.New("role mismatch"))
	}
	if !validIdentityValue(identity.HomeID, 128) || !validIdentityValue(identity.ID, 128) {
		return Failure(ErrRejected, errors.New("missing identity binding"))
	}
	expectedScope := ""
	switch identity.Role {
	case RoleUser:
		expectedScope = "relay:user"
	case RoleCoordinator:
		expectedScope = "relay:coordinator"
	case RoleCLI:
		expectedScope = "relay:cli"
	default:
		return Failure(ErrRejected, errors.New("unsupported identity role"))
	}
	if _, ok := identity.Scopes[expectedScope]; !ok || len(identity.Scopes) != 1 {
		return Failure(ErrRejected, errors.New("identity scope does not match its role"))
	}
	if identity.Role == RoleUser {
		if identity.ClientID != "" {
			return Failure(ErrRejected, errors.New("unexpected Home Key client binding"))
		}
		if request.HomeID == "" || identity.HomeID != request.HomeID {
			return Failure(ErrRejected, errors.New("user home mismatch"))
		}
	} else if !validIdentityValue(identity.ClientID, 128) {
		return Failure(ErrRejected, errors.New("missing Home Key client binding"))
	} else {
		if request.HomeID != "" && identity.HomeID != request.HomeID {
			return Failure(ErrRejected, errors.New("home mismatch"))
		}
		if identity.VerifiedEmail != "" {
			return Failure(ErrRejected, errors.New("unexpected verified email"))
		}
	}
	if request.Role == RoleCoordinator {
		if identity.CoordinatorName != request.CoordinatorName {
			return Failure(ErrRejected, errors.New("coordinator mismatch"))
		}
	} else if identity.CoordinatorName != "" {
		return Failure(ErrRejected, errors.New("unexpected coordinator identity"))
	}
	if !identity.ExpiresAt.After(now) {
		return Failure(ErrExpired, errors.New("access material expired"))
	}
	expiresAtMilliseconds := identity.ExpiresAt.UnixMilli()
	if expiresAtMilliseconds <= 0 || expiresAtMilliseconds > 9_007_199_254_740_991 {
		return Failure(ErrRejected, errors.New("access material expiry is not representable"))
	}
	if identity.VerifiedEmail != "" && !validIdentityValue(identity.VerifiedEmail, 320) {
		return Failure(ErrRejected, errors.New("invalid verified email"))
	}
	return nil
}

func validIdentityValue(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// RejectingVerifier is retained for explicit embedded tests and fails closed.
type RejectingVerifier struct{}

func (RejectingVerifier) Verify(context.Context, Request) (Identity, error) {
	return Identity{}, Failure(ErrTemporary, errors.New("platform verifier is not configured"))
}
