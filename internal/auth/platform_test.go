package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlplane "github.com/miakapp/miakapp-v3/control-plane-contract/go"
)

const (
	testControlKID = "test-control-key"
	testClientID   = "AAAAAAAAAAAAAAAAAAAAAA"
	testTokenID    = "AQEBAQEBAQEBAQEBAQEBAQ"
)

type lockedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *lockedClock) read() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *lockedClock) advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type verifierFixture struct {
	verifier       *PlatformVerifier
	server         *httptest.Server
	clock          *lockedClock
	controlPrivate ed25519.PrivateKey
	controlFetches atomic.Int64
	failControl    atomic.Bool
}

func newVerifierFixture(t *testing.T) *verifierFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("miakapp-relay-platform-verifier-test-key"))
	controlPrivate := ed25519.NewKeyFromSeed(seed[:])
	fixture := &verifierFixture{
		clock:          &lockedClock{now: time.Unix(1_788_211_200, 0)},
		controlPrivate: controlPrivate,
	}
	controlPublic := controlPrivate.Public().(ed25519.PublicKey)
	controlBody, err := json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "OKP", "kid": testControlKID, "use": "sig", "alg": "EdDSA",
			"crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(controlPublic),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/jwks.json":
			fixture.controlFetches.Add(1)
			response.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
			response.Header().Set("ETag", `"control-v1"`)
			if fixture.failControl.Load() {
				http.Error(response, "unavailable", http.StatusServiceUnavailable)
				return
			}
			if request.Header.Get("If-None-Match") == `"control-v1"` {
				response.WriteHeader(http.StatusNotModified)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write(controlBody)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(fixture.server.Close)
	config := PlatformConfig{
		Issuer:        fixture.server.URL,
		JWKSURL:       fixture.server.URL + "/.well-known/jwks.json",
		RelayAudience: "wss://relay.example.test/ws",
	}
	verifier, err := newPlatformVerifier(config, platformDependencies{
		client: fixture.server.Client(),
		now:    fixture.clock.read,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.verifier = verifier
	return fixture
}

func compactToken(t *testing.T, header, claims any, sign func([]byte) []byte) string {
	t.Helper()
	encode := func(value any) string {
		bytes, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(bytes)
	}
	input := encode(header) + "." + encode(claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(sign([]byte(input)))
}

func (fixture *verifierFixture) accessToken(t *testing.T, kid, audience string, expiresOffset int64) string {
	t.Helper()
	now := fixture.clock.read().Unix()
	return compactToken(t,
		map[string]any{"alg": "EdDSA", "kid": kid, "typ": "at+jwt"},
		map[string]any{
			"iss": fixture.server.URL, "sub": "synthetic-home", "aud": audience,
			"exp": now + expiresOffset, "iat": now, "jti": testTokenID,
			"client_id": testClientID, "scope": "relay:coordinator",
			"miakapp_role": "coordinator", "miakapp_coordinator": "automation",
		},
		func(input []byte) []byte { return ed25519.Sign(fixture.controlPrivate, input) },
	)
}

func (fixture *verifierFixture) userAccessToken(
	t *testing.T,
	kid string,
	audience string,
	homeID string,
	userID string,
	verifiedEmail *string,
	expiresOffset int64,
) string {
	t.Helper()
	now := fixture.clock.read().Unix()
	claims := map[string]any{
		"iss": fixture.server.URL, "sub": userID, "aud": audience,
		"exp": now + expiresOffset, "iat": now, "jti": testTokenID,
		"scope": "relay:user", "miakapp_home": homeID, "miakapp_role": "user",
	}
	if verifiedEmail != nil {
		claims["miakapp_verified_email"] = *verifiedEmail
	}
	return compactToken(t,
		map[string]any{"alg": "EdDSA", "kid": kid, "typ": "at+jwt"},
		claims,
		func(input []byte) []byte { return ed25519.Sign(fixture.controlPrivate, input) },
	)
}

func TestPlatformVerifierMapsCoordinatorAndUserAccessPrincipals(t *testing.T) {
	fixture := newVerifierFixture(t)
	coordinator, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleCoordinator, Token: fixture.accessToken(t, testControlKID, "wss://relay.example.test/ws", 300),
		CoordinatorName: "automation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.HomeID != "synthetic-home" || coordinator.ID != "synthetic-home" ||
		coordinator.ClientID != testClientID || coordinator.CoordinatorName != "automation" ||
		coordinator.Role != RoleCoordinator {
		t.Fatalf("unexpected coordinator identity: %#v", coordinator)
	}
	if _, ok := coordinator.Scopes["relay:coordinator"]; !ok || len(coordinator.Scopes) != 1 {
		t.Fatalf("unexpected coordinator scope: %#v", coordinator.Scopes)
	}

	verifiedEmail := "user@example.test"
	user, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleUser,
		Token: fixture.userAccessToken(
			t, testControlKID, "wss://relay.example.test/ws", "synthetic-home",
			"synthetic-user", &verifiedEmail, 300,
		),
		HomeID: "caller-selected-home-is-not-trusted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.HomeID != "synthetic-home" || user.ID != "synthetic-user" ||
		user.VerifiedEmail != verifiedEmail || user.Role != RoleUser || user.ClientID != "" ||
		user.CoordinatorName != "" {
		t.Fatalf("unexpected user access identity: %#v", user)
	}
	if _, ok := user.Scopes["relay:user"]; !ok || len(user.Scopes) != 1 {
		t.Fatalf("unexpected user scope: %#v", user.Scopes)
	}
	if err = ValidateBinding(Request{Role: RoleUser, HomeID: "synthetic-home"}, user, fixture.clock.read()); err != nil {
		t.Fatal(err)
	}
	if err = ValidateBinding(Request{Role: RoleUser, HomeID: "other-home"}, user, fixture.clock.read()); Kind(err) != ErrRejected {
		t.Fatalf("HELLO unexpectedly changed the token-bound Home: %v", err)
	}
	if fixture.controlFetches.Load() != 1 {
		t.Fatalf("user verification unexpectedly used another key source: %d", fixture.controlFetches.Load())
	}
	withoutEmail, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleUser,
		Token: fixture.userAccessToken(
			t, testControlKID, "wss://relay.example.test/ws", "synthetic-home",
			"synthetic-user", nil, 300,
		),
		HomeID: "synthetic-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	if withoutEmail.VerifiedEmail != "" {
		t.Fatalf("absent verified email was invented: %#v", withoutEmail)
	}
}

func TestPlatformVerifierRejectsCrossProfileAndFirebaseSourceTokens(t *testing.T) {
	fixture := newVerifierFixture(t)
	verifiedEmail := "user@example.test"
	userToken := fixture.userAccessToken(
		t, testControlKID, "wss://relay.example.test/ws", "synthetic-home",
		"synthetic-user", &verifiedEmail, 300,
	)
	if _, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleCoordinator, Token: userToken, CoordinatorName: "automation",
	}); Kind(err) != ErrRejected {
		t.Fatalf("user access token crossed into the coordinator profile: %v", err)
	}
	coordinatorToken := fixture.accessToken(t, testControlKID, "wss://relay.example.test/ws", 300)
	if _, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleUser, Token: coordinatorToken, HomeID: "synthetic-home",
	}); Kind(err) != ErrRejected {
		t.Fatalf("coordinator access token crossed into the user profile: %v", err)
	}
	firebaseSourceToken := compactToken(t,
		map[string]any{"alg": "RS256", "kid": testControlKID, "typ": "JWT"},
		map[string]any{
			"iss": "https://securetoken.google.com/demo-miakapp-v4",
			"sub": "synthetic-user", "aud": "demo-miakapp-v4",
			"exp": fixture.clock.read().Unix() + 3_600, "iat": fixture.clock.read().Unix(),
		},
		func(input []byte) []byte { return ed25519.Sign(fixture.controlPrivate, input) },
	)
	if _, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleUser, Token: firebaseSourceToken, HomeID: "synthetic-home",
	}); Kind(err) != ErrRejected {
		t.Fatalf("Firebase source token was accepted at the relay: %v", err)
	}
	if fixture.controlFetches.Load() != 1 {
		t.Fatalf("cross-profile verification used an unexpected key source: %d", fixture.controlFetches.Load())
	}
}

func TestPlatformVerifierClassifiesTokenFailuresWithoutRefetchingKnownKeys(t *testing.T) {
	fixture := newVerifierFixture(t)
	valid := fixture.accessToken(t, testControlKID, "wss://relay.example.test/ws", 300)
	if _, err := fixture.verifier.Verify(context.Background(), Request{Role: RoleCoordinator, Token: valid, CoordinatorName: "automation"}); err != nil {
		t.Fatal(err)
	}
	wrongAudience := fixture.accessToken(t, testControlKID, "wss://other.example.test/ws", 300)
	if _, err := fixture.verifier.Verify(context.Background(), Request{Role: RoleCoordinator, Token: wrongAudience, CoordinatorName: "automation"}); Kind(err) != ErrAudience {
		t.Fatalf("expected audience failure, received %v", err)
	}
	expired := fixture.accessToken(t, testControlKID, "wss://relay.example.test/ws", 0)
	if _, err := fixture.verifier.Verify(context.Background(), Request{Role: RoleCoordinator, Token: expired, CoordinatorName: "automation"}); Kind(err) != ErrExpired {
		t.Fatalf("expected expiry failure, received %v", err)
	}
	if fixture.controlFetches.Load() != 1 {
		t.Fatalf("known-key token failures unexpectedly fetched JWKS %d times", fixture.controlFetches.Load())
	}
}

func TestUnknownKIDRefreshIsRateLimited(t *testing.T) {
	fixture := newVerifierFixture(t)
	unknown := fixture.accessToken(t, "unknown-key", "wss://relay.example.test/ws", 300)
	request := Request{Role: RoleCoordinator, Token: unknown, CoordinatorName: "automation"}
	if _, err := fixture.verifier.Verify(context.Background(), request); Kind(err) != ErrRejected {
		t.Fatalf("expected unknown key rejection, received %v", err)
	}
	if _, err := fixture.verifier.Verify(context.Background(), request); Kind(err) != ErrRejected {
		t.Fatalf("expected repeated unknown key rejection, received %v", err)
	}
	if fixture.controlFetches.Load() != 2 {
		t.Fatalf("unknown key refresh was not bounded: %d fetches", fixture.controlFetches.Load())
	}
	fixture.clock.advance(unknownKIDRefreshDelay)
	if _, err := fixture.verifier.Verify(context.Background(), request); Kind(err) != ErrRejected {
		t.Fatalf("expected unknown key rejection after refresh window, received %v", err)
	}
	if fixture.controlFetches.Load() != 3 {
		t.Fatalf("unknown key did not permit one later refresh: %d fetches", fixture.controlFetches.Load())
	}
}

func TestPlatformVerifierReverifiesKeysReturnedByACompletedUnknownKIDRefresh(t *testing.T) {
	fixture := newVerifierFixture(t)
	now := fixture.clock.read()
	futureSeed := sha256.Sum256([]byte("miakapp-relay-future-verifier-test-key"))
	futurePrivate := ed25519.NewKeyFromSeed(futureSeed[:])
	futurePublic := futurePrivate.Public().(ed25519.PublicKey)
	futureKey := controlplane.PublicJWK{
		KTY: "OKP", KID: "future-control-key", Use: "sig", Alg: "EdDSA", CRV: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(futurePublic),
	}
	token := compactToken(t,
		map[string]any{"alg": "EdDSA", "kid": futureKey.KID, "typ": "at+jwt"},
		map[string]any{
			"iss": fixture.server.URL, "sub": "synthetic-home", "aud": "wss://relay.example.test/ws",
			"exp": now.Unix() + 300, "iat": now.Unix(), "jti": testTokenID,
			"client_id": testClientID, "scope": "relay:coordinator",
			"miakapp_role": "coordinator", "miakapp_coordinator": "automation",
		},
		func(input []byte) []byte { return ed25519.Sign(futurePrivate, input) },
	)
	oldPublic := fixture.controlPrivate.Public().(ed25519.PublicKey)
	fixture.verifier.controlKeys.mu.Lock()
	fixture.verifier.controlKeys.keys = []controlplane.PublicJWK{{
		KTY: "OKP", KID: testControlKID, Use: "sig", Alg: "EdDSA", CRV: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(oldPublic),
	}}
	fixture.verifier.controlKeys.expiresAt = now.Add(time.Minute)
	fixture.verifier.controlKeys.mu.Unlock()

	var clockCalls atomic.Int64
	racingClock := func() time.Time {
		// The third clock read happens under the cache lock after initial token
		// verification. Model another caller having just completed the refresh.
		if clockCalls.Add(1) == 3 {
			fixture.verifier.controlKeys.keys = []controlplane.PublicJWK{futureKey}
			fixture.verifier.controlKeys.expiresAt = now.Add(time.Minute)
			fixture.verifier.controlKeys.nextUnknownRefresh = now.Add(unknownKIDRefreshDelay)
		}
		return now
	}
	fixture.verifier.now = racingClock
	fixture.verifier.controlKeys.now = racingClock

	identity, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleCoordinator, Token: token, CoordinatorName: "automation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity.HomeID != "synthetic-home" || identity.ClientID != testClientID {
		t.Fatalf("unexpected identity after completed refresh: %#v", identity)
	}
	if fixture.controlFetches.Load() != 0 {
		t.Fatalf("completed refresh unexpectedly fetched JWKS %d times", fixture.controlFetches.Load())
	}
}

func TestExpiredKeyCacheFailureIsTemporaryAndRetryBounded(t *testing.T) {
	fixture := newVerifierFixture(t)
	request := Request{
		Role:            RoleCoordinator,
		Token:           fixture.accessToken(t, testControlKID, "wss://relay.example.test/ws", 300),
		CoordinatorName: "automation",
	}
	if _, err := fixture.verifier.Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	fixture.clock.advance(61 * time.Second)
	fixture.failControl.Store(true)
	if _, err := fixture.verifier.Verify(context.Background(), request); Kind(err) != ErrTemporary {
		t.Fatalf("expected stale-cache fetch failure to be temporary, received %v", err)
	}
	if _, err := fixture.verifier.Verify(context.Background(), request); Kind(err) != ErrTemporary {
		t.Fatalf("expected bounded repeated fetch failure, received %v", err)
	}
	if fixture.controlFetches.Load() != 2 {
		t.Fatalf("stale-cache failure retried too quickly: %d fetches", fixture.controlFetches.Load())
	}
}

func TestCanonicalControlPlaneTokenVectors(t *testing.T) {
	fixturePath := os.Getenv("MIAKAPP_CONTROL_PLANE_FIXTURE")
	if fixturePath == "" {
		t.Skip("set MIAKAPP_CONTROL_PLANE_FIXTURE to run the pinned external contract")
	}
	fixture, err := controlplane.LoadFixture(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		if vector.Kind != "miakapp" {
			continue
		}
		if vector.Profile != "coordinator" && vector.Profile != "cli" && vector.Profile != "user" {
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			verifier := canonicalVectorVerifier(t, fixture, vector)
			request := Request{Role: RoleUser, Token: vector.Token, HomeID: "synthetic-home"}
			switch vector.Profile {
			case "coordinator":
				request.Role = RoleCoordinator
				request.HomeID = ""
				request.CoordinatorName = "automation"
			case "cli":
				request.Role = RoleCLI
				request.HomeID = ""
			}
			identity, verifyErr := verifier.Verify(context.Background(), request)
			if !vector.Valid {
				if verifyErr == nil {
					t.Fatal("invalid canonical vector was accepted")
				}
				expectedKind := ErrRejected
				if vector.Error == controlplane.Expired {
					expectedKind = ErrExpired
				} else if vector.Error == controlplane.InvalidAudience {
					expectedKind = ErrAudience
				}
				if Kind(verifyErr) != expectedKind {
					t.Fatalf("expected %s, received %v", expectedKind, verifyErr)
				}
				return
			}
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if err = ValidateBinding(request, identity, time.Unix(vector.VerificationTime, 0)); err != nil {
				t.Fatal(err)
			}
			if vector.Profile == "user" {
				var expected controlplane.UserAccessIdentity
				if err = json.Unmarshal(vector.Expected, &expected); err != nil {
					t.Fatal(err)
				}
				email := ""
				if expected.VerifiedEmail != nil {
					email = *expected.VerifiedEmail
				}
				if identity.HomeID != expected.HomeID || identity.ID != expected.PrincipalID ||
					identity.ClientID != "" || identity.VerifiedEmail != email ||
					identity.ExpiresAt.Unix() != expected.ExpiresAt {
					t.Fatalf("canonical user access identity mismatch: %#v", identity)
				}
			} else {
				var expected controlplane.HomeKeyAccessIdentity
				if err = json.Unmarshal(vector.Expected, &expected); err != nil {
					t.Fatal(err)
				}
				if identity.HomeID != expected.HomeID || identity.ID != expected.PrincipalID ||
					identity.ClientID != expected.ClientID ||
					identity.ExpiresAt.Unix() != expected.ExpiresAt {
					t.Fatalf("canonical Home Key access identity mismatch: %#v", identity)
				}
			}
		})
	}
}

func canonicalVectorVerifier(
	t *testing.T,
	fixture *controlplane.Fixture,
	vector controlplane.TokenVector,
) *PlatformVerifier {
	t.Helper()
	keySet, ok := fixture.KeySets[vector.KeySet]
	if !ok {
		t.Fatalf("canonical vector references missing key set %q", vector.KeySet)
	}
	clock := &lockedClock{now: time.Unix(vector.VerificationTime, 0)}
	body, err := json.Marshal(keySet)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
		response.Header().Set("ETag", `"canonical-vector"`)
		_, _ = response.Write(body)
	}))
	t.Cleanup(server.Close)
	config := PlatformConfig{
		Issuer:        fixture.Deployment.Issuer,
		JWKSURL:       fixture.Deployment.JWKSURI,
		RelayAudience: fixture.Deployment.RelayAudience,
	}
	verifier, err := newPlatformVerifier(config, platformDependencies{
		client: server.Client(),
		now:    clock.read,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier.controlKeys = newKeyCache(keySource{
		url: server.URL, client: server.Client(),
	}, clock.read)
	return verifier
}
