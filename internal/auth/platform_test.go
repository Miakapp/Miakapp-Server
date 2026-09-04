package auth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
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
	testControlKID  = "test-control-key"
	testFirebaseKID = "test-firebase-key"
	testClientID    = "AAAAAAAAAAAAAAAAAAAAAA"
	testTokenID     = "AQEBAQEBAQEBAQEBAQEBAQ"
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
	verifier        *PlatformVerifier
	server          *httptest.Server
	clock           *lockedClock
	controlPrivate  ed25519.PrivateKey
	firebasePrivate *rsa.PrivateKey
	controlFetches  atomic.Int64
	firebaseFetches atomic.Int64
	failControl     atomic.Bool
}

func newVerifierFixture(t *testing.T) *verifierFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("miakapp-relay-platform-verifier-test-key"))
	controlPrivate := ed25519.NewKeyFromSeed(seed[:])
	firebasePrivate, err := rsa.GenerateKey(rand.Reader, 2_048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, firebasePrivate)
	fixture := &verifierFixture{
		clock:           &lockedClock{now: time.Unix(1_788_211_200, 0)},
		controlPrivate:  controlPrivate,
		firebasePrivate: firebasePrivate,
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
	firebaseBody, err := json.Marshal(map[string]string{testFirebaseKID: certificate})
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
		case "/firebase-certificates":
			fixture.firebaseFetches.Add(1)
			response.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
			response.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = response.Write(firebaseBody)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(fixture.server.Close)
	config := PlatformConfig{
		Issuer:            fixture.server.URL,
		JWKSURL:           fixture.server.URL + "/.well-known/jwks.json",
		RelayAudience:     "wss://relay.example.test/ws",
		FirebaseProjectID: "demo-miakapp-v4",
	}
	verifier, err := newPlatformVerifier(config, platformDependencies{
		client:                  fixture.server.Client(),
		now:                     fixture.clock.read,
		firebaseCertificatesURL: fixture.server.URL + "/firebase-certificates",
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.verifier = verifier
	return fixture
}

func testCertificate(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "synthetic Firebase signer"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
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

func (fixture *verifierFixture) firebaseToken(t *testing.T, verified bool) string {
	t.Helper()
	now := fixture.clock.read().Unix()
	claims := map[string]any{
		"iss": "https://securetoken.google.com/demo-miakapp-v4",
		"sub": "synthetic-user", "aud": "demo-miakapp-v4",
		"exp": now + 3_600, "iat": now, "auth_time": now - 10,
		"email": "user@example.test", "email_verified": verified,
	}
	return compactToken(t,
		map[string]any{"alg": "RS256", "kid": testFirebaseKID, "typ": "JWT"},
		claims,
		func(input []byte) []byte {
			digest := sha256.Sum256(input)
			signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.firebasePrivate, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			return signature
		},
	)
}

func TestPlatformVerifierMapsCoordinatorAndFirebasePrincipals(t *testing.T) {
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

	user, err := fixture.verifier.Verify(context.Background(), Request{
		Role: RoleUser, Token: fixture.firebaseToken(t, true), HomeID: "synthetic-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.HomeID != "synthetic-home" || user.ID != "synthetic-user" ||
		user.VerifiedEmail != "user@example.test" || user.Role != RoleUser {
		t.Fatalf("unexpected Firebase identity: %#v", user)
	}
	if fixture.controlFetches.Load() != 1 || fixture.firebaseFetches.Load() != 1 {
		t.Fatalf("unexpected public-key fetch count: control=%d Firebase=%d", fixture.controlFetches.Load(), fixture.firebaseFetches.Load())
	}
	if _, err = fixture.verifier.Verify(context.Background(), Request{
		Role: RoleUser, Token: fixture.firebaseToken(t, false), HomeID: "synthetic-home",
	}); err != nil {
		t.Fatal(err)
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
		if vector.Kind != "miakapp" && vector.Kind != "firebase" {
			continue
		}
		if vector.Kind == "miakapp" && vector.Profile != "coordinator" && vector.Profile != "cli" {
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			verifier := canonicalVectorVerifier(t, fixture, vector)
			request := Request{Role: RoleUser, Token: vector.Token, HomeID: "synthetic-home"}
			if vector.Kind == "miakapp" {
				if vector.Profile == "coordinator" {
					request.Role = RoleCoordinator
					request.CoordinatorName = "automation"
				} else {
					request.Role = RoleCLI
				}
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
			if vector.Kind == "miakapp" {
				var expected controlplane.AccessIdentity
				if err = json.Unmarshal(vector.Expected, &expected); err != nil {
					t.Fatal(err)
				}
				if identity.HomeID != expected.HomeID || identity.ID != expected.PrincipalID ||
					identity.ClientID != expected.ClientID || identity.ExpiresAt.Unix() != expected.ExpiresAt {
					t.Fatalf("canonical access identity mismatch: %#v", identity)
				}
			} else {
				var expected controlplane.FirebaseIdentity
				if err = json.Unmarshal(vector.Expected, &expected); err != nil {
					t.Fatal(err)
				}
				email := ""
				if expected.VerifiedEmail != nil {
					email = *expected.VerifiedEmail
				}
				if identity.ID != expected.UserID || identity.VerifiedEmail != email ||
					identity.ExpiresAt.Unix() != expected.ExpiresAt {
					t.Fatalf("canonical Firebase identity mismatch: %#v", identity)
				}
			}
		})
	}
}

func TestLiveFirebaseCertificateEndpointShape(t *testing.T) {
	if os.Getenv("MIAKAPP_RUN_LIVE_FIREBASE_CERTIFICATE_TEST") != "1" {
		t.Skip("set MIAKAPP_RUN_LIVE_FIREBASE_CERTIFICATE_TEST=1 for the read-only live check")
	}
	verifier, err := NewPlatformVerifier(validPlatformConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(context.Background(), Request{
		Role: RoleUser, Token: "deliberately-malformed", HomeID: "synthetic-home",
	})
	if Kind(err) != ErrRejected {
		t.Fatalf("live Firebase certificate response could not be consumed: %v", err)
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
	var body []byte
	if vector.Kind == "firebase" {
		certificates := make(map[string]string, len(keySet.Keys))
		for _, publicKey := range keySet.Keys {
			privateKey := canonicalRSAPrivateKey(t, fixture, publicKey.KID)
			certificates[publicKey.KID] = testCertificate(t, privateKey)
		}
		var err error
		body, err = json.Marshal(certificates)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		var err error
		body, err = json.Marshal(keySet)
		if err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if vector.Kind == "firebase" {
			response.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
		} else {
			response.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
			response.Header().Set("ETag", `"canonical-vector"`)
		}
		_, _ = response.Write(body)
	}))
	t.Cleanup(server.Close)
	config := PlatformConfig{
		Issuer:            fixture.Deployment.Issuer,
		JWKSURL:           fixture.Deployment.JWKSURI,
		RelayAudience:     fixture.Deployment.RelayAudience,
		FirebaseProjectID: fixture.Firebase.ProjectID,
	}
	verifier, err := newPlatformVerifier(config, platformDependencies{
		client:                  server.Client(),
		now:                     clock.read,
		firebaseCertificatesURL: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if vector.Kind == "firebase" {
		verifier.firebaseKeys = newKeyCache(keySource{
			url: server.URL, kind: firebaseCertificates, client: server.Client(),
		}, clock.read)
	} else {
		verifier.controlKeys = newKeyCache(keySource{
			url: server.URL, kind: controlPlaneJWKS, client: server.Client(),
		}, clock.read)
	}
	return verifier
}

type canonicalPrivateJWK struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
}

func canonicalRSAPrivateKey(t *testing.T, fixture *controlplane.Fixture, kid string) *rsa.PrivateKey {
	t.Helper()
	for _, raw := range fixture.PrivateKeys {
		var jwk canonicalPrivateJWK
		if err := json.Unmarshal(raw, &jwk); err != nil || jwk.KTY != "RSA" || jwk.KID != kid {
			continue
		}
		decode := func(value string) []byte {
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil || len(decoded) == 0 || base64.RawURLEncoding.EncodeToString(decoded) != value {
				t.Fatalf("canonical private JWK %q is invalid", kid)
			}
			return decoded
		}
		exponent := 0
		for _, value := range decode(jwk.E) {
			exponent = exponent<<8 | int(value)
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(decode(jwk.N)), E: exponent},
			D:         new(big.Int).SetBytes(decode(jwk.D)),
			Primes: []*big.Int{
				new(big.Int).SetBytes(decode(jwk.P)),
				new(big.Int).SetBytes(decode(jwk.Q)),
			},
		}
		if err := key.Validate(); err != nil {
			t.Fatalf("canonical private JWK %q failed RSA validation: %v", kid, err)
		}
		key.Precompute()
		return key
	}
	t.Fatalf("canonical Firebase key %q has no test-only private fixture", kid)
	return nil
}
