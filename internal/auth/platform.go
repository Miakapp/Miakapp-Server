package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlplane "github.com/miakapp/miakapp-v3/control-plane-contract/go"
)

type platformDependencies struct {
	client *http.Client
	now    func() time.Time
}

// PlatformVerifier validates Miakapp access tokens without holding a platform
// secret or making an authenticated request.
type PlatformVerifier struct {
	config      PlatformConfig
	now         func() time.Time
	controlKeys *keyCache
}

// NewPlatformVerifier constructs the production verifier with pinned HTTPS
// authorities and redirect-free public-key clients.
func NewPlatformVerifier(config PlatformConfig) (*PlatformVerifier, error) {
	client := &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return newPlatformVerifier(config, platformDependencies{
		client: client,
		now:    time.Now,
	})
}

func newPlatformVerifier(config PlatformConfig, dependencies platformDependencies) (*PlatformVerifier, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if dependencies.client == nil || dependencies.now == nil {
		return nil, errors.New("platform verifier dependencies are incomplete")
	}
	return &PlatformVerifier{
		config: config,
		now:    dependencies.now,
		controlKeys: newKeyCache(keySource{
			url: config.JWKSURL, client: dependencies.client,
		}, dependencies.now),
	}, nil
}

// Verify derives the immutable relay principal exclusively from verified token
// claims. HELLO fields are checked separately as connection bindings.
func (verifier *PlatformVerifier) Verify(ctx context.Context, request Request) (Identity, error) {
	switch request.Role {
	case RoleCoordinator:
		return verifier.verifyAccess(ctx, request, "coordinator", "relay:coordinator")
	case RoleCLI:
		return verifier.verifyAccess(ctx, request, "cli", "relay:cli")
	case RoleUser:
		return verifier.verifyAccess(ctx, request, "user", "relay:user")
	default:
		return Identity{}, Failure(ErrRejected, errors.New("unsupported authentication role"))
	}
}

func (verifier *PlatformVerifier) verifyAccess(
	ctx context.Context,
	request Request,
	profile string,
	scope string,
) (Identity, error) {
	keys, err := verifier.controlKeys.current(ctx)
	if err != nil {
		return Identity{}, Failure(ErrTemporary, err)
	}
	verified, verifyErr := verifier.verifyMiakappToken(request.Token, profile, keys)
	if controlplane.VerificationCode(verifyErr) == controlplane.UnknownKID {
		keys, err = verifier.controlKeys.refreshUnknownKID(ctx)
		if err != nil {
			return Identity{}, Failure(ErrTemporary, err)
		}
		verified, verifyErr = verifier.verifyMiakappToken(request.Token, profile, keys)
	}
	if verifyErr != nil {
		return Identity{}, verificationFailureForContract(verifyErr)
	}
	return mapAccessIdentity(verified, profile, scope)
}

func mapAccessIdentity(
	verified controlplane.AccessIdentity,
	profile string,
	scope string,
) (Identity, error) {
	scopes := map[string]struct{}{scope: {}}
	switch identity := verified.(type) {
	case *controlplane.HomeKeyAccessIdentity:
		if profile == "user" || identity.Scope != scope || identity.Role == nil || *identity.Role != profile {
			return Identity{}, Failure(ErrRejected, errors.New("unexpected Home Key access-token profile"))
		}
		coordinatorName := ""
		if identity.CoordinatorName != nil {
			coordinatorName = *identity.CoordinatorName
		}
		if (profile == "coordinator") != (coordinatorName != "") {
			return Identity{}, Failure(ErrRejected, errors.New("unexpected coordinator access-token binding"))
		}
		role := RoleCLI
		if profile == "coordinator" {
			role = RoleCoordinator
		}
		return Identity{
			Role:            role,
			HomeID:          identity.HomeID,
			ID:              identity.PrincipalID,
			ClientID:        identity.ClientID,
			CoordinatorName: coordinatorName,
			ExpiresAt:       time.Unix(identity.ExpiresAt, 0),
			Scopes:          scopes,
		}, nil
	case *controlplane.UserAccessIdentity:
		if profile != "user" || identity.Scope != scope || identity.Role != "user" {
			return Identity{}, Failure(ErrRejected, errors.New("unexpected user access-token profile"))
		}
		verifiedEmail := ""
		if identity.VerifiedEmail != nil {
			verifiedEmail = *identity.VerifiedEmail
		}
		return Identity{
			Role:          RoleUser,
			HomeID:        identity.HomeID,
			ID:            identity.PrincipalID,
			VerifiedEmail: verifiedEmail,
			ExpiresAt:     time.Unix(identity.ExpiresAt, 0),
			Scopes:        scopes,
		}, nil
	default:
		return Identity{}, Failure(ErrRejected, errors.New("unsupported access-token identity"))
	}
}

func (verifier *PlatformVerifier) verifyMiakappToken(
	token string,
	profile string,
	keys []controlplane.PublicJWK,
) (controlplane.AccessIdentity, error) {
	fixture := &controlplane.Fixture{
		Now: verifier.now().Unix(),
		Deployment: controlplane.Deployment{
			Issuer:        verifier.config.Issuer,
			RelayAudience: verifier.config.RelayAudience,
		},
	}
	return controlplane.VerifyMiakappAccessToken(token, fixture, profile, keys)
}

func verificationFailureForContract(err error) error {
	switch controlplane.VerificationCode(err) {
	case controlplane.Expired:
		return Failure(ErrExpired, err)
	case controlplane.InvalidAudience:
		return Failure(ErrAudience, err)
	default:
		return Failure(ErrRejected, err)
	}
}
