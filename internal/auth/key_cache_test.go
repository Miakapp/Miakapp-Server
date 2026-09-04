package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlplane "github.com/miakapp/miakapp-v3/control-plane-contract/go"
)

func validJWKSBody() string {
	return fmt.Sprintf(
		`{"keys":[{"kty":"OKP","kid":"key-1","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"%s"}]}`,
		base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	)
}

func TestControlPlaneJWKSDecoderIsClosedAndBounded(t *testing.T) {
	keys, err := decodeControlPlaneJWKS([]byte(validJWKSBody()))
	if err != nil || len(keys) != 1 || keys[0].KID != "key-1" {
		t.Fatalf("unexpected valid JWKS result: %#v, %v", keys, err)
	}
	tests := []string{
		`{}`,
		`{"keys":[]}`,
		`{"keys":[],"keys":[]}`,
		`{"keys":[],"unknown":true}`,
		`{"keys":[{"kty":"OKP","kid":"key-1","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"bad"}]}`,
		`{"keys":[{"kty":"OKP","kid":"key-1","kid":"key-2","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		`{"keys":[{"kty":"OKP","kid":"key-1","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","n":"forbidden"}]}`,
		`{"keys":[{"kty":"OKP","kid":"\ud800","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		validJWKSBody() + ` {}`,
	}
	for index, value := range tests {
		if _, err = decodeControlPlaneJWKS([]byte(value)); err == nil {
			t.Fatalf("expected malformed JWKS case %d to be rejected", index)
		}
	}

	entries := make([]string, maximumPublicKeys+1)
	for index := range entries {
		entries[index] = fmt.Sprintf(
			`{"kty":"OKP","kid":"key-%d","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
			index,
		)
	}
	if _, err = decodeControlPlaneJWKS([]byte(`{"keys":[` + strings.Join(entries, ",") + `]}`)); err == nil {
		t.Fatal("expected an overlong key set to be rejected")
	}
}

func TestCachePolicyRequiresExactControlPlaneDirectives(t *testing.T) {
	valid := http.Header{"Cache-Control": []string{"public, max-age=60, must-revalidate"}}
	if ttl, err := responseCacheTTL(valid, controlPlaneJWKS); err != nil || ttl != time.Minute {
		t.Fatalf("unexpected valid cache policy: %v, %v", ttl, err)
	}
	invalid := []string{
		"max-age=60, must-revalidate",
		"public, max-age=61, must-revalidate",
		"public, max-age=60",
		"public, max-age=60, must-revalidate, immutable",
		"public, max-age=60, max-age=60, must-revalidate",
		"public, max-age=\"60, must-revalidate",
	}
	for _, value := range invalid {
		if _, err := responseCacheTTL(http.Header{"Cache-Control": []string{value}}, controlPlaneJWKS); err == nil {
			t.Fatalf("expected cache policy %q to be rejected", value)
		}
	}
	aged := http.Header{
		"Cache-Control": []string{"public, max-age=3600, must-revalidate"},
		"Age":           []string{"60"},
	}
	if ttl, err := responseCacheTTL(aged, firebaseCertificates); err != nil || ttl != 59*time.Minute {
		t.Fatalf("unexpected aged Firebase cache policy: %v, %v", ttl, err)
	}
	if _, err := canonicalETag(`"strong"`); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalETag(`W/"weak"`); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"unquoted", `"unterminated`, `"bad\"quote"`} {
		if _, err := canonicalETag(value); err == nil {
			t.Fatalf("expected invalid ETag %q to be rejected", value)
		}
	}
}

func TestKeyCacheCoalescesConcurrentFetchesAndRevalidatesWithETag(t *testing.T) {
	var fetches atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fetches.Add(1)
		startOnce.Do(func() { close(started) })
		<-release
		response.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
		response.Header().Set("ETag", `"v1"`)
		if request.Header.Get("If-None-Match") == `"v1"` {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(validJWKSBody()))
	}))
	t.Cleanup(server.Close)
	clock := &lockedClock{now: time.Unix(1_788_211_200, 0)}
	cache := newKeyCache(keySource{
		url: server.URL, kind: controlPlaneJWKS, client: server.Client(),
	}, clock.read)

	const callers = 32
	results := make(chan error, callers)
	for range callers {
		go func() {
			keys, err := cache.current(context.Background())
			if err == nil && (len(keys) != 1 || keys[0].KID != "key-1") {
				err = fmt.Errorf("unexpected keys: %#v", keys)
			}
			results <- err
		}()
	}
	<-started
	close(release)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("concurrent cache miss issued %d requests", fetches.Load())
	}

	clock.advance(61 * time.Second)
	keys, err := cache.current(context.Background())
	if err != nil || len(keys) != 1 || fetches.Load() != 2 {
		t.Fatalf("conditional revalidation failed: keys=%#v fetches=%d error=%v", keys, fetches.Load(), err)
	}
}

func TestConcurrentUnknownKIDRefreshesJoinAnActiveRefreshBeforeApplyingTheAbuseWindow(t *testing.T) {
	now := time.Unix(1_788_211_200, 0)
	refreshDone := make(chan struct{})
	allWaiting := make(chan struct{})
	var clockCalls atomic.Int64
	var waitingOnce sync.Once
	const callers = 32
	cache := &keyCache{
		now: func() time.Time {
			if clockCalls.Add(1) == callers*2 {
				waitingOnce.Do(func() { close(allWaiting) })
			}
			return now
		},
		keys:               []controlplane.PublicJWK{{KID: "old-key"}},
		expiresAt:          now.Add(time.Minute),
		refreshing:         true,
		refreshDone:        refreshDone,
		nextUnknownRefresh: now.Add(unknownKIDRefreshDelay),
	}
	type result struct {
		keys []controlplane.PublicJWK
		err  error
	}
	completed := make(chan result, callers)
	for range callers {
		go func() {
			keys, err := cache.refreshUnknownKID(context.Background())
			completed <- result{keys: keys, err: err}
		}()
	}
	select {
	case <-allWaiting:
	case <-time.After(time.Second):
		t.Fatal("concurrent unknown-key callers did not reach the active refresh")
	}
	// Acquiring the cache lock after the final clock observation proves every
	// caller evaluated the active-refresh branch before it is released.
	cache.mu.Lock()
	cache.keys = []controlplane.PublicJWK{{KID: "new-key"}}
	cache.refreshing = false
	close(refreshDone)
	cache.mu.Unlock()

	for range callers {
		select {
		case received := <-completed:
			if received.err != nil ||
				len(received.keys) != 1 || received.keys[0].KID != "new-key" {
				t.Fatalf("unknown-key caller did not join the active refresh: %#v", received)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent unknown-key refresh did not complete")
		}
	}
}

func TestUnknownKIDRefreshHonorsWaiterCancellation(t *testing.T) {
	now := time.Unix(1_788_211_200, 0)
	cache := &keyCache{
		now:         func() time.Time { return now },
		keys:        []controlplane.PublicJWK{{KID: "old-key"}},
		expiresAt:   now.Add(time.Minute),
		refreshing:  true,
		refreshDone: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	keys, err := cache.refreshUnknownKID(ctx)
	if !errors.Is(err, context.Canceled) || keys != nil {
		t.Fatalf("cancelled unknown-key waiter returned an unexpected result: keys=%#v error=%v", keys, err)
	}
}

func TestUnknownKIDRefreshSharesAnActiveRefreshFailure(t *testing.T) {
	now := time.Unix(1_788_211_200, 0)
	refreshDone := make(chan struct{})
	waiting := make(chan struct{})
	var clockCalls atomic.Int64
	var waitingOnce sync.Once
	cache := &keyCache{
		now: func() time.Time {
			if clockCalls.Add(1) == 2 {
				waitingOnce.Do(func() { close(waiting) })
			}
			return now
		},
		keys:        []controlplane.PublicJWK{{KID: "old-key"}},
		expiresAt:   now.Add(-time.Second),
		refreshing:  true,
		refreshDone: refreshDone,
	}
	wantErr := errors.New("shared refresh failed")
	type result struct {
		keys []controlplane.PublicJWK
		err  error
	}
	completed := make(chan result, 1)
	go func() {
		keys, err := cache.refreshUnknownKID(context.Background())
		completed <- result{keys: keys, err: err}
	}()

	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("unknown-key caller did not reach the active refresh")
	}
	cache.mu.Lock()
	cache.lastFailure = wantErr
	cache.nextFetch = now.Add(failedFetchRetryDelay)
	cache.refreshing = false
	close(refreshDone)
	cache.mu.Unlock()

	select {
	case received := <-completed:
		if !errors.Is(received.err, wantErr) || received.keys != nil {
			t.Fatalf("unknown-key caller did not share the refresh failure: %#v", received)
		}
	case <-time.After(time.Second):
		t.Fatal("unknown-key refresh failure did not complete")
	}
}

func TestPublicKeyFetchRejectsRedirects(t *testing.T) {
	var destinationRequests atomic.Int64
	destination := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		response.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
		response.Header().Set("ETag", `"v1"`)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(validJWKSBody()))
	}))
	t.Cleanup(destination.Close)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", destination.URL)
		response.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	client := redirect.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	source := keySource{url: redirect.URL, kind: controlPlaneJWKS, client: client}
	if _, err := source.fetch(context.Background(), ""); err == nil {
		t.Fatal("expected public-key redirect to be rejected")
	}
	if destinationRequests.Load() != 0 {
		t.Fatal("redirect destination was contacted")
	}
}
