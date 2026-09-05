package relay

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/coder/websocket"
)

func TestCanonicalRemoteIPUsesOnlyTheImmediateTCPPeer(t *testing.T) {
	tests := []struct {
		remote string
		want   string
	}{
		{remote: "192.0.2.10:443", want: "192.0.2.10"},
		{remote: "[2001:db8::10]:443", want: "2001:db8::10"},
		{remote: "[::ffff:192.0.2.11]:443", want: "192.0.2.11"},
	}
	for _, test := range tests {
		address, err := canonicalRemoteIP(test.remote)
		if err != nil || address.String() != test.want {
			t.Fatalf("unexpected canonical address for %q: %v, %v", test.remote, address, err)
		}
	}
	for _, remote := range []string{"", "192.0.2.10", "example.test:443", "[fe80::1%en0]:443"} {
		if _, err := canonicalRemoteIP(remote); !errors.Is(err, errInvalidSourceAddress) {
			t.Fatalf("expected invalid immediate peer %q to be rejected: %v", remote, err)
		}
	}
}

func TestConnectionAdmissionBoundsActivePeersAndAttemptRate(t *testing.T) {
	configuration := config.Default()
	configuration.MaxConnections = 2
	configuration.MaxConnectionsPerIP = 1
	configuration.ConnectionAttemptsPerMinute = 2
	configuration.MaxTrackedIPs = 2
	controller := newAdmissionController(configuration)
	now := time.Unix(1_800_000_000, 0)
	controller.clock = func() time.Time { return now }

	first, err := controller.acquireConnection("192.0.2.1:1000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.acquireConnection("192.0.2.1:1001"); !errors.Is(err, errConnectionCapacity) {
		t.Fatalf("expected active per-IP capacity rejection, received %v", err)
	}
	first.release()
	first.release()
	if _, err = controller.acquireConnection("192.0.2.1:1002"); !errors.Is(err, errConnectionRate) {
		t.Fatalf("expected the rejected active attempt to consume rate, received %v", err)
	}
	now = now.Add(connectionAttemptWindow)
	second, err := controller.acquireConnection("192.0.2.1:1003")
	if err != nil {
		t.Fatal(err)
	}
	second.release()
}

func TestConnectionAdmissionBoundsTrackedSourceMemory(t *testing.T) {
	configuration := config.Default()
	configuration.MaxConnections = 1
	configuration.MaxConnectionsPerIP = 1
	configuration.ConnectionAttemptsPerMinute = 2
	configuration.MaxTrackedIPs = 2
	controller := newAdmissionController(configuration)
	now := time.Unix(1_800_000_000, 0)
	controller.clock = func() time.Time { return now }

	first, err := controller.acquireConnection("192.0.2.1:1000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.acquireConnection("192.0.2.2:1000"); !errors.Is(err, errConnectionCapacity) {
		t.Fatalf("expected total capacity rejection, received %v", err)
	}
	if _, err = controller.acquireConnection("192.0.2.3:1000"); !errors.Is(err, errConnectionCapacity) {
		t.Fatalf("expected tracked-source capacity rejection, received %v", err)
	}
	first.release()
	now = now.Add(connectionAttemptWindow)
	third, err := controller.acquireConnection("192.0.2.3:1001")
	if err != nil {
		t.Fatalf("expired idle source entries were not pruned: %v", err)
	}
	third.release()
}

func TestConcurrentConnectionAdmissionNeverExceedsTheProcessCeiling(t *testing.T) {
	configuration := config.Default()
	configuration.MaxConnections = 8
	configuration.MaxConnectionsPerIP = 8
	configuration.ConnectionAttemptsPerMinute = 64
	controller := newAdmissionController(configuration)
	type result struct {
		admission *connectionAdmission
		err       error
	}
	results := make(chan result, 64)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 64; index++ {
		workers.Add(1)
		go func(port int) {
			defer workers.Done()
			<-start
			admission, err := controller.acquireConnection(
				"192.0.2.1:" + fmt.Sprint(10_000+port),
			)
			results <- result{admission: admission, err: err}
		}(index)
	}
	close(start)
	workers.Wait()
	close(results)

	admissions := make([]*connectionAdmission, 0, configuration.MaxConnections)
	capacityFailures := 0
	for result := range results {
		switch {
		case result.err == nil:
			admissions = append(admissions, result.admission)
		case errors.Is(result.err, errConnectionCapacity):
			capacityFailures++
		default:
			t.Fatalf("unexpected concurrent admission result: %v", result.err)
		}
	}
	if len(admissions) != configuration.MaxConnections || capacityFailures != 56 {
		t.Fatalf("unexpected concurrent admission totals: admitted=%d rejected=%d", len(admissions), capacityFailures)
	}
	for _, admission := range admissions {
		admission.release()
	}
	controller.mu.Lock()
	active := controller.activeConnections
	controller.mu.Unlock()
	if active != 0 {
		t.Fatalf("concurrent admissions retained %d active leases", active)
	}
}

func TestAggregateOutboundQueueBudgetIsSharedAcrossConnections(t *testing.T) {
	configuration := config.Default()
	configuration.MaxQueuedBytes = 100
	configuration.MaxAggregateQueuedBytes = 100
	server := &Server{config: configuration}
	server.admission = newAdmissionController(configuration)
	first := &connection{server: server, queueWake: make(chan struct{}, 1)}
	second := &connection{server: server, queueWake: make(chan struct{}, 1)}

	if err := first.enqueueBytes(outboundMessage{bytes: make([]byte, 60)}, false); err != nil {
		t.Fatal(err)
	}
	if err := second.enqueueBytes(outboundMessage{bytes: make([]byte, 41)}, false); err == nil {
		t.Fatal("expected the process-wide queue ceiling to reject another connection")
	}
	if _, ok := first.nextMessage(); !ok {
		t.Fatal("expected the first queued message")
	}
	if err := second.enqueueBytes(outboundMessage{bytes: make([]byte, 41)}, false); err != nil {
		t.Fatalf("released aggregate bytes were not reusable: %v", err)
	}
	if _, ok := second.nextMessage(); !ok {
		t.Fatal("expected the second queued message")
	}
	if server.admission.queuedBytes != 0 {
		t.Fatalf("aggregate queue accounting did not return to zero: %d", server.admission.queuedBytes)
	}
}

func TestWebSocketAttemptsAreAdmittedBeforeProtocolUpgrade(t *testing.T) {
	configuration := config.Default()
	configuration.MaxConnections = 1
	configuration.MaxConnectionsPerIP = 1
	configuration.ConnectionAttemptsPerMinute = 1
	configuration.MaxTrackedIPs = 1
	server, err := New(
		configuration,
		fixtureVerifier{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	request := httptest.NewRequest(http.MethodPost, "http://relay.example.test/ws", nil)
	request.RemoteAddr = "192.0.2.1:1000"
	first := httptest.NewRecorder()
	server.ServeHTTP(first, request)
	if first.Code != http.StatusMethodNotAllowed || first.Header().Get("Allow") != "GET" {
		t.Fatalf("expected the invalid method to fail after admission, received %d", first.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "http://relay.example.test/ws", nil)
	request.RemoteAddr = "192.0.2.1:1001"
	second := httptest.NewRecorder()
	server.ServeHTTP(second, request)
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "60" {
		t.Fatalf("expected a bounded rate response, received %d with headers %#v", second.Code, second.Header())
	}
	server.admission.mu.Lock()
	activeConnections := server.admission.activeConnections
	server.admission.mu.Unlock()
	if activeConnections != 0 {
		t.Fatalf("rejected upgrades retained %d active admission leases", activeConnections)
	}
}

func TestConnectionAdmissionLeaseSpansTheWebSocketLifetime(t *testing.T) {
	server, httpServer := newTestServer(t, func(configuration *config.Config) {
		configuration.MaxConnections = 2
		configuration.MaxConnectionsPerIP = 1
		configuration.ConnectionAttemptsPerMinute = 4
	})
	first := connectPeer(t, httpServer)

	second, response, err := dialPeer(t, httpServer, &websocket.DialOptions{
		Subprotocols: []string{websocketSubprotocol},
	})
	if second != nil {
		_ = second.CloseNow()
	}
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected the active peer to consume per-IP capacity: response=%v error=%v", response, err)
	}
	if err = first.connection.Close(websocket.StatusNormalClosure, "test_release"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.admission.mu.Lock()
		active := server.admission.activeConnections
		server.admission.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed WebSocket retained %d active admission leases", active)
		}
		time.Sleep(time.Millisecond)
	}
	third := connectPeer(t, httpServer)
	if third == nil {
		t.Fatal("released WebSocket capacity was not reusable")
	}
}

func TestHomeRegistryRejectsNewHomesAtCapacityAndRecoversAfterRelease(t *testing.T) {
	configuration := config.Default()
	configuration.MaxHomes = 1
	server := &Server{config: configuration}
	server.homes = newHomeRegistry(server)

	first, err := server.homes.acquire("home-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.homes.acquire("home-2"); !errors.Is(err, errHomeCapacity) {
		t.Fatalf("expected home capacity rejection, received %v", err)
	}
	server.homes.release(first)
	second, err := server.homes.acquire("home-2")
	if err != nil {
		t.Fatalf("released home capacity was not reusable: %v", err)
	}
	server.homes.release(second)
}
