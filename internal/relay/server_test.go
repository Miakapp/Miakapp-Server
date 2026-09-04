package relay

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/coder/websocket"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

type fixtureVerifier struct{}

func (fixtureVerifier) Verify(_ context.Context, request auth.Request) (auth.Identity, error) {
	expiry := time.Now().Add(time.Hour)
	switch request.Token {
	case "coordinator-token", "coordinator-token-new":
		return auth.Identity{
			Role:            auth.RoleCoordinator,
			HomeID:          "home-1",
			ID:              "home-1",
			CoordinatorName: "automation",
			ExpiresAt:       expiry,
		}, nil
	case "coordinator-b-token":
		return auth.Identity{
			Role:            auth.RoleCoordinator,
			HomeID:          "home-1",
			ID:              "home-1",
			CoordinatorName: "secondary",
			ExpiresAt:       expiry,
		}, nil
	case "user-token", "user-token-new":
		return auth.Identity{
			Role:          auth.RoleUser,
			HomeID:        "home-1",
			ID:            "user-1",
			VerifiedEmail: "user@example.test",
			ExpiresAt:     expiry,
		}, nil
	case "user-token-changed":
		return auth.Identity{
			Role:          auth.RoleUser,
			HomeID:        "home-1",
			ID:            "user-2",
			VerifiedEmail: "other@example.test",
			ExpiresAt:     expiry,
		}, nil
	default:
		return auth.Identity{}, auth.Failure(auth.ErrRejected, nil)
	}
}

type testPeer struct {
	connection *websocket.Conn
}

func newTestServer(t *testing.T, mutate func(*config.Config)) (*Server, *httptest.Server) {
	return newTestServerWithVerifier(t, fixtureVerifier{}, mutate)
}

func newTestServerWithVerifier(
	t *testing.T,
	verifier auth.Verifier,
	mutate func(*config.Config),
) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.Config{
		ListenAddress:   ":0",
		AllowedOrigins:  map[string]struct{}{},
		Handshake:       time.Second,
		WriteTimeout:    time.Second,
		PingInterval:    time.Minute,
		PongTimeout:     time.Second,
		DeclarationTTL:  time.Second,
		DisconnectGrace: 50 * time.Millisecond,
		ShutdownTimeout: time.Second,
		MaxQueuedBytes:  1_048_576,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	server, err := New(cfg, verifier, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	t.Cleanup(func() {
		httpServer.CloseClientConnections()
		server.Close()
		httpServer.Close()
	})
	return server, httpServer
}

func connectPeer(t *testing.T, server *httptest.Server) *testPeer {
	t.Helper()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	connection, response, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
		Subprotocols: []string{websocketSubprotocol},
	})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	connection.SetReadLimit(protocol.MaxFrameBytes)
	peer := &testPeer{connection: connection}
	t.Cleanup(func() {
		_ = connection.Close(websocket.StatusNormalClosure, "test_complete")
	})
	return peer
}

func dialPeer(
	t *testing.T,
	server *httptest.Server,
	options *websocket.DialOptions,
) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	return websocket.Dial(context.Background(), url, options)
}

func (peer *testPeer) send(t *testing.T, frame protocol.Frame) {
	t.Helper()
	bytes, err := protocol.EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = peer.connection.Write(ctx, websocket.MessageBinary, bytes); err != nil {
		t.Fatal(err)
	}
}

func (peer *testPeer) receive(t *testing.T, opcode byte) protocol.Frame {
	t.Helper()
	frame := peer.receiveAny(t)
	if frame.Opcode != opcode {
		t.Fatalf("expected opcode %#x, received %#x (%#v)", opcode, frame.Opcode, frame.Payload)
	}
	return frame
}

func (peer *testPeer) receiveAny(t *testing.T) protocol.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	messageType, bytes, err := peer.connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageBinary {
		t.Fatalf("expected binary message, received %v", messageType)
	}
	frame, err := protocol.DecodeFrame(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func hello(role auth.Role, token string, roleContext []any) protocol.Frame {
	return protocol.Frame{
		Opcode:  protocol.OpcodeHello,
		Payload: []any{int64(1), int64(0), int64(0), int64(role), token, roleContext},
	}
}

func synchronizeCoordinator(t *testing.T, coordinator *testPeer) (epoch []byte, pathID, topicID, functionID int64) {
	t.Helper()
	coordinator.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateSync,
		Payload: []any{
			int64(1),
			[]any{[]any{"home.temperature", int64(20)}},
		},
	})
	stateOK := coordinator.receive(t, protocol.OpcodeStateSyncOK)
	epoch = bytesValue(stateOK.Payload[1])
	pathID = integer(arrayValue(arrayValue(stateOK.Payload[3])[0])[0])

	coordinator.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateACLSync,
		Payload: []any{
			int64(2),
			[]any{[]any{"user-1", []any{"home.*"}}},
		},
	})
	coordinator.receive(t, protocol.OpcodeStateACLOK)

	coordinator.send(t, protocol.Frame{
		Opcode: protocol.OpcodeEventSync,
		Payload: []any{
			int64(3),
			[]any{[]any{"home.alert", int64(eventAcceptUsers | eventPublishUsers)}},
		},
	})
	eventOK := coordinator.receive(t, protocol.OpcodeEventSyncOK)
	topicID = integer(arrayValue(arrayValue(eventOK.Payload[1])[0])[0])

	coordinator.send(t, protocol.Frame{
		Opcode: protocol.OpcodeEventACLSync,
		Payload: []any{
			int64(4),
			[]any{[]any{"user-1", []any{"home.alert"}, []any{"home.alert"}}},
		},
	})
	coordinator.receive(t, protocol.OpcodeEventACLOK)

	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeFunctionSync,
		Payload: []any{int64(5), []any{"home.set"}},
	})
	functionOK := coordinator.receive(t, protocol.OpcodeFunctionSyncOK)
	functionID = integer(arrayValue(arrayValue(functionOK.Payload[1])[0])[0])
	return epoch, pathID, topicID, functionID
}

func TestRelayStateAndCallVerticalSlice(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(
		auth.RoleCoordinator,
		"coordinator-token",
		[]any{"automation"},
	))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	epoch, pathID, _, functionID := synchronizeCoordinator(t, coordinator)

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	welcome := user.receive(t, protocol.OpcodeWelcome)
	if enrolled, ok := welcome.Payload[4].(bool); !ok || !enrolled {
		t.Fatalf("expected enrolled user WELCOME, received %#v", welcome.Payload)
	}
	user.receive(t, protocol.OpcodeStateDict)
	snapshot := user.receive(t, protocol.OpcodeStateSnapshot)
	if entries := arrayValue(snapshot.Payload[2]); len(entries) != 1 {
		t.Fatalf("expected one visible state entry, received %#v", entries)
	}
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	coordinator.receive(t, protocol.OpcodePresenceChange)

	coordinator.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateSet,
		Payload: []any{
			int64(6),
			epoch,
			[]any{[]any{pathID, int64(0), int64(21)}},
		},
	})
	coordinator.receive(t, protocol.OpcodeStateSetOK)
	patch := user.receive(t, protocol.OpcodeStatePatch)
	if mutations := arrayValue(patch.Payload[3]); len(mutations) != 1 {
		t.Fatalf("expected one state mutation, received %#v", mutations)
	}

	user.send(t, protocol.Frame{
		Opcode: protocol.OpcodeCall,
		Payload: []any{
			int64(11), int64(0), nil, functionID, int64(5_000), nil, int64(1),
			map[string]any{"temperature": int64(22)},
		},
	})
	dispatch := coordinator.receive(t, protocol.OpcodeCallDispatch)
	user.receive(t, protocol.OpcodeCallAccepted)
	calleeID := integer(dispatch.Payload[0])
	principal := arrayValue(dispatch.Payload[1])
	if principal[1] != "user-1" || principal[4] != "user@example.test" {
		t.Fatalf("relay did not construct expected principal: %#v", principal)
	}
	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeCallResult,
		Payload: []any{calleeID, true, map[string]any{"accepted": true}},
	})
	result := user.receive(t, protocol.OpcodeCallResult)
	if integer(result.Payload[0]) != 11 {
		t.Fatalf("relay did not restore caller call ID: %#v", result.Payload)
	}

	user.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeReauth,
		Payload: []any{int64(12), "user-token-new"},
	})
	user.receive(t, protocol.OpcodeReauthOK)
	user.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeStateResync,
		Payload: []any{int64(13)},
	})
	user.receive(t, protocol.OpcodeStateDict)
	resynced := user.receive(t, protocol.OpcodeStateSnapshot)
	if entries := arrayValue(resynced.Payload[2]); len(entries) != 1 {
		t.Fatalf("expected resynchronized state, received %#v", entries)
	}
}

func TestDeclarationCollisionNeverPublishesAStagedPrefix(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	primary := connectPeer(t, httpServer)
	primary.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	primary.receive(t, protocol.OpcodeWelcome)
	primary.receive(t, protocol.OpcodePresenceSnapshot)
	synchronizeCoordinator(t, primary)

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	initial := user.receive(t, protocol.OpcodeStateSnapshot)
	assertSnapshotValue(t, initial, int64(20))
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	primary.receive(t, protocol.OpcodePresenceChange)

	secondary := connectPeer(t, httpServer)
	secondary.send(t, hello(auth.RoleCoordinator, "coordinator-b-token", []any{"secondary"}))
	secondary.receive(t, protocol.OpcodeWelcome)
	secondary.receive(t, protocol.OpcodePresenceSnapshot)
	user.receive(t, protocol.OpcodeHomeStatus)

	secondary.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateSync,
		Payload: []any{
			int64(21),
			[]any{[]any{"home.temperature", int64(99)}},
		},
	})
	secondary.receive(t, protocol.OpcodeStateSyncOK)

	user.send(t, protocol.Frame{Opcode: protocol.OpcodeStateResync, Payload: []any{int64(31)}})
	user.receive(t, protocol.OpcodeStateDict)
	duringStage := user.receive(t, protocol.OpcodeStateSnapshot)
	assertSnapshotValue(t, duringStage, int64(20))

	secondary.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateACLSync,
		Payload: []any{
			int64(22),
			[]any{[]any{"user-1", []any{"home.*"}}},
		},
	})
	secondary.receive(t, protocol.OpcodeStateACLOK)
	secondary.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeEventSync,
		Payload: []any{int64(23), []any{}},
	})
	secondary.receive(t, protocol.OpcodeEventSyncOK)
	secondary.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeEventACLSync,
		Payload: []any{int64(24), []any{}},
	})
	secondary.receive(t, protocol.OpcodeEventACLOK)
	secondary.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeFunctionSync,
		Payload: []any{int64(25), []any{"secondary.run"}},
	})
	failure := secondary.receive(t, protocol.OpcodeError)
	if integer(failure.Payload[0]) != 25 ||
		integer(failure.Payload[1]) != int64(protocol.OpcodeFunctionSync) ||
		integer(failure.Payload[2]) != codeOwnershipCollision {
		t.Fatalf("unexpected activation failure: %#v", failure.Payload)
	}

	user.send(t, protocol.Frame{Opcode: protocol.OpcodeStateResync, Payload: []any{int64(32)}})
	user.receive(t, protocol.OpcodeStateDict)
	afterFailure := user.receive(t, protocol.OpcodeStateSnapshot)
	assertSnapshotValue(t, afterFailure, int64(20))
}

func TestEventAuthorizationAndCallCancellation(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	_, _, topicID, functionID := synchronizeCoordinator(t, coordinator)

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	user.receive(t, protocol.OpcodeStateSnapshot)
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	coordinator.receive(t, protocol.OpcodePresenceChange)

	user.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeSubscribe,
		Payload: []any{int64(41), []any{topicID}},
	})
	user.receive(t, protocol.OpcodeSubscribeOK)
	coordinator.send(t, protocol.Frame{
		Opcode: protocol.OpcodeEvent,
		Payload: []any{
			int64(42), topicID, int64(0), nil, map[string]any{"active": true},
		},
	})
	incoming := user.receive(t, protocol.OpcodeEvent)
	source := arrayValue(incoming.Payload[4])
	if integer(source[0]) != int64(auth.RoleCoordinator) || source[3] != "automation" {
		t.Fatalf("unexpected coordinator event principal: %#v", source)
	}

	user.send(t, protocol.Frame{
		Opcode: protocol.OpcodeEvent,
		Payload: []any{
			int64(43), topicID, int64(0), nil, map[string]any{"acknowledge": true},
		},
	})
	fromUser := coordinator.receive(t, protocol.OpcodeEvent)
	userSource := arrayValue(fromUser.Payload[4])
	if userSource[1] != "user-1" || userSource[4] != "user@example.test" {
		t.Fatalf("unexpected user event principal: %#v", userSource)
	}

	user.send(t, protocol.Frame{
		Opcode: protocol.OpcodeCall,
		Payload: []any{
			int64(44), int64(0), nil, functionID, int64(5_000), "intent-44", int64(0), nil,
		},
	})
	dispatch := coordinator.receive(t, protocol.OpcodeCallDispatch)
	user.receive(t, protocol.OpcodeCallAccepted)
	calleeID := integer(dispatch.Payload[0])
	user.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeCallCancel,
		Payload: []any{int64(44), int64(codeCancelled)},
	})
	cancel := coordinator.receive(t, protocol.OpcodeCallCancel)
	if integer(cancel.Payload[0]) != calleeID {
		t.Fatalf("call cancellation was not rewritten: %#v", cancel.Payload)
	}
	terminal := user.receive(t, protocol.OpcodeCallError)
	if integer(terminal.Payload[1]) != codeOutcomeUnknown {
		t.Fatalf("accepted cancellation did not preserve uncertainty: %#v", terminal.Payload)
	}

	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeCallResult,
		Payload: []any{calleeID, true, "late"},
	})

	user.send(t, protocol.Frame{
		Opcode: protocol.OpcodeCall,
		Payload: []any{
			int64(45), int64(0), nil, functionID, int64(5_000), nil, int64(0), nil,
		},
	})
	coordinator.receive(t, protocol.OpcodeCallDispatch)
	user.receive(t, protocol.OpcodeCallAccepted)
}

func TestHandshakeRejectsOriginsAndMissingSubprotocolBeforeUpgrade(t *testing.T) {
	_, httpServer := newTestServer(t, func(cfg *config.Config) {
		cfg.AllowedOrigins = map[string]struct{}{"https://miakapp.com": {}}
	})

	_, response, err := dialPeer(t, httpServer, &websocket.DialOptions{
		HTTPHeader:   http.Header{"Origin": []string{"https://evil.example"}},
		Subprotocols: []string{websocketSubprotocol},
	})
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden origin rejection, received response=%v error=%v", response, err)
	}
	_ = response.Body.Close()

	_, response, err = dialPeer(t, httpServer, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin": []string{"https://miakapp.com", "https://evil.example"},
		},
		Subprotocols: []string{websocketSubprotocol},
	})
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected ambiguous origin rejection, received response=%v error=%v", response, err)
	}
	_ = response.Body.Close()

	_, response, err = dialPeer(t, httpServer, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"https://miakapp.com"}},
	})
	if err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected missing subprotocol rejection, received response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
}

func TestProtocolFatalIsDeliveredBeforeClose(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	peer := connectPeer(t, httpServer)
	peer.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeHello,
		Payload: []any{int64(2), int64(0), int64(0), int64(auth.RoleUser), "user-token", []any{"home-1"}},
	})
	fatal := peer.receive(t, protocol.OpcodeFatal)
	if integer(fatal.Payload[0]) != int64(protocol.OpcodeHello) ||
		integer(fatal.Payload[1]) != codeUnsupportedVersion {
		t.Fatalf("unexpected protocol fatal: %#v", fatal.Payload)
	}
}

func TestReauthenticationCannotChangePrincipal(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	peer := connectPeer(t, httpServer)
	peer.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	peer.receive(t, protocol.OpcodeWelcome)
	peer.receive(t, protocol.OpcodeStateDict)
	peer.receive(t, protocol.OpcodeStateSnapshot)
	peer.receive(t, protocol.OpcodeTopicDict)
	peer.receive(t, protocol.OpcodeFunctionDict)

	peer.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeReauth,
		Payload: []any{int64(51), "user-token-changed"},
	})
	fatal := peer.receive(t, protocol.OpcodeFatal)
	if integer(fatal.Payload[1]) != codeUnauthenticated {
		t.Fatalf("unexpected reauthentication fatal: %#v", fatal.Payload)
	}
}

func TestConcurrentCollidingActivationsHaveExactlyOneWinner(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	first := connectPeer(t, httpServer)
	first.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	first.receive(t, protocol.OpcodeWelcome)
	first.receive(t, protocol.OpcodePresenceSnapshot)
	second := connectPeer(t, httpServer)
	second.send(t, hello(auth.RoleCoordinator, "coordinator-b-token", []any{"secondary"}))
	second.receive(t, protocol.OpcodeWelcome)
	second.receive(t, protocol.OpcodePresenceSnapshot)

	stageCollidingCoordinator(t, first, 100, int64(1))
	stageCollidingCoordinator(t, second, 200, int64(2))

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	welcome := user.receive(t, protocol.OpcodeWelcome)
	if enrolled, ok := welcome.Payload[4].(bool); !ok || enrolled {
		t.Fatalf("expected user to remain unenrolled before activation: %#v", welcome.Payload)
	}
	user.receive(t, protocol.OpcodeStateDict)
	user.receive(t, protocol.OpcodeStateSnapshot)
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	first.receive(t, protocol.OpcodePresenceChange)
	second.receive(t, protocol.OpcodePresenceChange)

	start := make(chan struct{})
	results := make(chan protocol.Frame, 2)
	activate := func(peer *testPeer, requestID int64, function string) {
		<-start
		peer.send(t, protocol.Frame{
			Opcode:  protocol.OpcodeFunctionSync,
			Payload: []any{requestID, []any{function}},
		})
		results <- peer.receiveAny(t)
	}
	go activate(first, 104, "automation.run")
	go activate(second, 204, "secondary.run")
	close(start)
	left := <-results
	right := <-results
	successes := 0
	failures := 0
	for _, result := range []protocol.Frame{left, right} {
		switch result.Opcode {
		case protocol.OpcodeFunctionSyncOK:
			successes++
		case protocol.OpcodeError:
			if integer(result.Payload[2]) != codeOwnershipCollision {
				t.Fatalf("unexpected activation error: %#v", result.Payload)
			}
			failures++
		default:
			t.Fatalf("unexpected activation response opcode %#x", result.Opcode)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("expected one winner and one collision, got %d successes and %d failures", successes, failures)
	}

	user.receive(t, protocol.OpcodeStateDict)
	snapshot := user.receive(t, protocol.OpcodeStateSnapshot)
	entries := arrayValue(snapshot.Payload[2])
	if len(entries) != 1 {
		t.Fatalf("expected exactly one winning path, received %#v", entries)
	}
	value := arrayValue(entries[0])[1]
	if value != int64(1) && value != int64(2) {
		t.Fatalf("unexpected winning value: %#v", value)
	}
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	user.receive(t, protocol.OpcodeHomeStatus)
}

func stageCollidingCoordinator(t *testing.T, peer *testPeer, base int64, value int64) {
	t.Helper()
	peer.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateSync,
		Payload: []any{
			base,
			[]any{[]any{"shared.value", value}},
		},
	})
	peer.receive(t, protocol.OpcodeStateSyncOK)
	peer.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateACLSync,
		Payload: []any{
			base + 1,
			[]any{[]any{"user-1", []any{"shared.value"}}},
		},
	})
	peer.receive(t, protocol.OpcodeStateACLOK)
	peer.send(t, protocol.Frame{Opcode: protocol.OpcodeEventSync, Payload: []any{base + 2, []any{}}})
	peer.receive(t, protocol.OpcodeEventSyncOK)
	peer.send(t, protocol.Frame{Opcode: protocol.OpcodeEventACLSync, Payload: []any{base + 3, []any{}}})
	peer.receive(t, protocol.OpcodeEventACLOK)
}

func TestCoordinatorDisconnectGraceRetainsThenAtomicallyPurgesState(t *testing.T) {
	_, httpServer := newTestServer(t, func(cfg *config.Config) {
		cfg.DisconnectGrace = 30 * time.Millisecond
	})
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	synchronizeCoordinator(t, coordinator)

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	user.receive(t, protocol.OpcodeStateSnapshot)
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	coordinator.receive(t, protocol.OpcodePresenceChange)

	if err := coordinator.connection.Close(websocket.StatusNormalClosure, "synthetic_disconnect"); err != nil {
		t.Fatal(err)
	}
	status := user.receive(t, protocol.OpcodeHomeStatus)
	coordinators := arrayValue(status.Payload[1])
	if len(coordinators) != 1 || integer(arrayValue(coordinators[0])[2]) != 2 {
		t.Fatalf("expected coordinator grace status, received %#v", status.Payload)
	}
	user.send(t, protocol.Frame{Opcode: protocol.OpcodeStateResync, Payload: []any{int64(61)}})
	user.receive(t, protocol.OpcodeStateDict)
	duringGrace := user.receive(t, protocol.OpcodeStateSnapshot)
	assertSnapshotValue(t, duringGrace, int64(20))

	user.receive(t, protocol.OpcodeStateDict)
	afterGrace := user.receive(t, protocol.OpcodeStateSnapshot)
	if entries := arrayValue(afterGrace.Payload[2]); len(entries) != 0 {
		t.Fatalf("expected state purge after grace, received %#v", entries)
	}
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	finalStatus := user.receive(t, protocol.OpcodeHomeStatus)
	if entries := arrayValue(finalStatus.Payload[1]); len(entries) != 0 {
		t.Fatalf("expected coordinator removal after grace, received %#v", entries)
	}
}

func assertSnapshotValue(t *testing.T, frame protocol.Frame, expected any) {
	t.Helper()
	entries := arrayValue(frame.Payload[2])
	if len(entries) != 1 {
		t.Fatalf("expected one snapshot entry, received %#v", entries)
	}
	entry := arrayValue(entries[0])
	if entry[1] != expected {
		t.Fatalf("expected snapshot value %#v, received %#v", expected, entry[1])
	}
}
