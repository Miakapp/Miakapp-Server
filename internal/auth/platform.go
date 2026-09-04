package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlplane "github.com/miakapp/miakapp-v3/control-plane-contract/go"
)

type platformDependencies struct {
	client                  *http.Client
	now                     func() time.Time
	firebaseCertificatesURL string
}

// PlatformVerifier validates Miakapp access tokens and Firebase ID tokens
// without holding a platform secret or making an authenticated request.
type PlatformVerifier struct {
	config       PlatformConfig
	now          func() time.Time
	controlKeys  *keyCache
	firebaseKeys *keyCache
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
		client:                  client,
		now:                     time.Now,
		firebaseCertificatesURL: firebaseCertificateURL,
	})
}

func newPlatformVerifier(config PlatformConfig, dependencies platformDependencies) (*PlatformVerifier, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if dependencies.client == nil || dependencies.now == nil {
		return nil, errors.New("platform verifier dependencies are incomplete")
	}
	if _, err := canonicalURL(dependencies.firebaseCertificatesURL, "https", true); err != nil {
		return nil, errors.New("Firebase certificate endpoint is invalid")
	}
	return &PlatformVerifier{
		config: config,
		now:    dependencies.now,
		controlKeys: newKeyCache(keySource{
			url: config.JWKSURL, kind: controlPlaneJWKS, client: dependencies.client,
		}, dependencies.now),
		firebaseKeys: newKeyCache(keySource{
			url: dependencies.firebaseCertificatesURL, kind: firebaseCertificates, client: dependencies.client,
		}, dependencies.now),
	}, nil
}

// Verify derives the immutable relay principal exclusively from verified token
// claims and the HELLO home context used by Firebase users.
func (verifier *PlatformVerifier) Verify(ctx context.Context, request Request) (Identity, error) {
	switch request.Role {
	case RoleCoordinator:
		return verifier.verifyAccess(ctx, request, "coordinator", "relay:coordinator")
	case RoleCLI:
		return verifier.verifyAccess(ctx, request, "cli", "relay:cli")
	case RoleUser:
		return verifier.verifyFirebase(ctx, request)
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
	identity, verifyErr := verifier.verifyMiakappToken(request.Token, profile, keys)
	if controlplane.VerificationCode(verifyErr) == controlplane.UnknownKID {
		var refreshed bool
		keys, refreshed, err = verifier.controlKeys.refreshUnknownKID(ctx)
		if err != nil {
			return Identity{}, Failure(ErrTemporary, err)
		}
		if refreshed {
			identity, verifyErr = verifier.verifyMiakappToken(request.Token, profile, keys)
		}
	}
	if verifyErr != nil {
		return Identity{}, verificationFailureForContract(verifyErr)
	}
	coordinatorName := ""
	if identity.CoordinatorName != nil {
		coordinatorName = *identity.CoordinatorName
	}
	return Identity{
		Role:            request.Role,
		HomeID:          identity.HomeID,
		ID:              identity.PrincipalID,
		ClientID:        identity.ClientID,
		CoordinatorName: coordinatorName,
		ExpiresAt:       time.Unix(identity.ExpiresAt, 0),
		Scopes:          map[string]struct{}{scope: {}},
	}, nil
}

func (verifier *PlatformVerifier) verifyMiakappToken(
	token string,
	profile string,
	keys []controlplane.PublicJWK,
) (*controlplane.AccessIdentity, error) {
	fixture := &controlplane.Fixture{
		Now: verifier.now().Unix(),
		Deployment: controlplane.Deployment{
			Issuer:        verifier.config.Issuer,
			RelayAudience: verifier.config.RelayAudience,
		},
	}
	return controlplane.VerifyMiakappAccessToken(token, fixture, profile, keys)
}

func (verifier *PlatformVerifier) verifyFirebase(ctx context.Context, request Request) (Identity, error) {
	keys, err := verifier.firebaseKeys.current(ctx)
	if err != nil {
		return Identity{}, Failure(ErrTemporary, err)
	}
	identity, verifyErr := verifier.verifyFirebaseToken(request.Token, keys)
	if controlplane.VerificationCode(verifyErr) == controlplane.UnknownKID {
		var refreshed bool
		keys, refreshed, err = verifier.firebaseKeys.refreshUnknownKID(ctx)
		if err != nil {
			return Identity{}, Failure(ErrTemporary, err)
		}
		if refreshed {
			identity, verifyErr = verifier.verifyFirebaseToken(request.Token, keys)
		}
	}
	if verifyErr != nil {
		return Identity{}, verificationFailureForContract(verifyErr)
	}
	verifiedEmail := ""
	if identity.VerifiedEmail != nil {
		verifiedEmail = *identity.VerifiedEmail
	}
	return Identity{
		Role:          RoleUser,
		HomeID:        request.HomeID,
		ID:            identity.UserID,
		VerifiedEmail: verifiedEmail,
		ExpiresAt:     time.Unix(identity.ExpiresAt, 0),
	}, nil
}

func (verifier *PlatformVerifier) verifyFirebaseToken(
	token string,
	keys []controlplane.PublicJWK,
) (*controlplane.FirebaseIdentity, error) {
	fixture := &controlplane.Fixture{
		Now: verifier.now().Unix(),
		Firebase: controlplane.FirebaseProfile{
			ProjectID: verifier.config.FirebaseProjectID,
			Issuer:    "https://securetoken.google.com/" + verifier.config.FirebaseProjectID,
		},
	}
	return controlplane.VerifyFirebaseIDToken(token, fixture, keys)
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
