package relay

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/coder/websocket"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

type shortLeaseVerifier struct {
	lifetime time.Duration
}

func (verifier shortLeaseVerifier) Verify(_ context.Context, request auth.Request) (auth.Identity, error) {
	if request.Token != "short-user-token" {
		return auth.Identity{}, auth.Failure(auth.ErrRejected, nil)
	}
	return auth.Identity{
		Role:          auth.RoleUser,
		HomeID:        "home-1",
		ID:            "user-1",
		VerifiedEmail: "user@example.test",
		ExpiresAt:     time.Now().Add(verifier.lifetime),
		Scopes:        map[string]struct{}{"relay:user": {}},
	}, nil
}

func TestAuthenticationLeaseExpiryIsActivelyEnforced(t *testing.T) {
	server, httpServer := newTestServerWithVerifier(t, shortLeaseVerifier{lifetime: 150 * time.Millisecond}, nil)
	peer := connectPeer(t, httpServer)
	peer.send(t, hello(auth.RoleUser, "short-user-token", []any{"home-1"}))
	peer.receive(t, protocol.OpcodeWelcome)
	peer.receive(t, protocol.OpcodeStateDict)
	peer.receive(t, protocol.OpcodeStateSnapshot)
	peer.receive(t, protocol.OpcodeTopicDict)
	peer.receive(t, protocol.OpcodeFunctionDict)
	fatal := peer.receive(t, protocol.OpcodeFatal)
	if integer(fatal.Payload[0]) != 0 || integer(fatal.Payload[1]) != codeTokenExpired {
		t.Fatalf("unexpected lease-expiry fatal: %#v", fatal.Payload)
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.homes.mu.Lock()
		remainingHomes := len(server.homes.homes)
		server.homes.mu.Unlock()
		if remainingHomes == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired identity remained routable in %d home(s)", remainingHomes)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReauthenticationKeepsTheRoutedPrincipalImmutable(t *testing.T) {
	server := &Server{
		config: config.Config{
			Handshake:      time.Second,
			MaxQueuedBytes: 1_048_576,
		},
		verifier: fixtureVerifier{},
		context:  context.Background(),
		logger:   slog.Default(),
	}
	peer := newConnection(server, nil, 1, "fixture")
	peer.identity = auth.Identity{
		Role:          auth.RoleUser,
		HomeID:        "home-1",
		ID:            "user-1",
		VerifiedEmail: "user@example.test",
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if !peer.activateInitialLease() {
		t.Fatal("unable to activate the initial identity lease")
	}
	t.Cleanup(func() {
		peer.stopLease()
		peer.cancel()
	})

	stopReads := make(chan struct{})
	principalFailure := make(chan []any, 1)
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-stopReads:
				return
			default:
				principal := peer.identity.Principal(peer.sessionID)
				if principal[1] != "user-1" || principal[4] != "user@example.test" {
					select {
					case principalFailure <- principal:
					default:
					}
					return
				}
			}
		}
	}()
	for requestID := int64(1); requestID <= 256; requestID++ {
		failure := peer.reauthenticate(protocol.Frame{
			Opcode:  protocol.OpcodeReauth,
			Payload: []any{requestID, "user-token-new"},
		})
		if failure != nil {
			close(stopReads)
			wait.Wait()
			t.Fatal(failure)
		}
	}
	close(stopReads)
	wait.Wait()
	select {
	case principal := <-principalFailure:
		t.Fatalf("reauthentication changed the routed principal: %#v", principal)
	default:
	}
}

func TestCoordinatorReplacementTerminatesInflightCallsAndFencesEffects(t *testing.T) {
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
		Opcode: protocol.OpcodeCall,
		Payload: []any{
			int64(70), int64(0), nil, functionID, int64(5_000), "replacement-70", int64(0), nil,
		},
	})
	coordinator.receive(t, protocol.OpcodeCallDispatch)
	user.receive(t, protocol.OpcodeCallAccepted)

	replacement := connectPeer(t, httpServer)
	replacement.send(t, hello(auth.RoleCoordinator, "coordinator-token-new", []any{"automation"}))
	replacement.receive(t, protocol.OpcodeWelcome)
	replacement.receive(t, protocol.OpcodePresenceSnapshot)

	terminal := user.receive(t, protocol.OpcodeCallError)
	if integer(terminal.Payload[0]) != 70 || integer(terminal.Payload[1]) != codeOutcomeUnknown {
		t.Fatalf("replacement did not conservatively terminate the call: %#v", terminal.Payload)
	}
	coordinator.receive(t, protocol.OpcodeFatal)

	replacement.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeEvent,
		Payload: []any{int64(71), topicID, int64(0), nil, "must-not-route"},
	})
	failure := replacement.receive(t, protocol.OpcodeError)
	if integer(failure.Payload[0]) != 71 || integer(failure.Payload[2]) != codeUnavailable {
		t.Fatalf("unready replacement was allowed to publish: %#v", failure.Payload)
	}
}

func TestGraceExpiryDeletesAnUnreferencedHome(t *testing.T) {
	server, httpServer := newTestServer(t, func(cfg *config.Config) {
		cfg.DisconnectGrace = 20 * time.Millisecond
	})
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	if err := coordinator.connection.Close(websocket.StatusNormalClosure, "fixture_complete"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		server.homes.mu.Lock()
		count := len(server.homes.homes)
		server.homes.mu.Unlock()
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unreferenced home remained registered after grace: %d", count)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServerCloseRemovesOfflineGraceHomesWithoutLeavingTimers(t *testing.T) {
	server, httpServer := newTestServer(t, func(cfg *config.Config) {
		cfg.DisconnectGrace = time.Minute
	})
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	if err := coordinator.connection.Close(websocket.StatusNormalClosure, "fixture_complete"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		server.homes.mu.Lock()
		current := server.homes.homes["home-1"]
		ready := false
		if current != nil {
			current.mu.Lock()
			slot := current.coordinators["automation"]
			ready = current.references == 0 && slot != nil && slot.connection == nil && slot.grace != nil
			current.mu.Unlock()
		}
		server.homes.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("coordinator did not enter disconnect grace")
		}
		time.Sleep(5 * time.Millisecond)
	}

	server.Close()
	server.homes.mu.Lock()
	remaining := len(server.homes.homes)
	server.homes.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("relay shutdown retained %d offline home(s)", remaining)
	}
}

func TestServerCloseDoesNotWaitForPeerCloseHandshakes(t *testing.T) {
	server, httpServer := newTestServer(t, nil)
	peer := connectPeer(t, httpServer)
	peer.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	peer.receive(t, protocol.OpcodeWelcome)
	peer.receive(t, protocol.OpcodeStateDict)
	peer.receive(t, protocol.OpcodeStateSnapshot)
	peer.receive(t, protocol.OpcodeTopicDict)
	peer.receive(t, protocol.OpcodeFunctionDict)

	done := make(chan struct{})
	go func() {
		server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("relay shutdown waited for a peer close handshake")
	}
}

func TestConcurrentBootstrapNeverPrecedesWelcomeOrLosesPresence(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		server := &Server{
			config:  config.Config{MaxQueuedBytes: 1_048_576},
			context: context.Background(),
			logger:  slog.Default(),
		}
		current, err := newHome(server, fmt.Sprintf("bootstrap-%d", iteration))
		if err != nil {
			t.Fatal(err)
		}
		expiresAt := time.Now().Add(time.Hour)
		coordinator := newConnection(server, nil, 1, "fixture")
		coordinator.phase.Store(uint32(phaseActive))
		coordinator.home = current
		coordinator.identity = auth.Identity{
			Role:            auth.RoleCoordinator,
			HomeID:          current.id,
			ID:              current.id,
			CoordinatorName: "automation",
			ExpiresAt:       expiresAt,
		}
		user := newConnection(server, nil, 2, "fixture")
		user.phase.Store(uint32(phaseActive))
		user.home = current
		user.identity = auth.Identity{
			Role:          auth.RoleUser,
			HomeID:        current.id,
			ID:            "user-1",
			VerifiedEmail: "user@example.test",
			ExpiresAt:     expiresAt,
		}

		start := make(chan struct{})
		failures := make(chan *relayError, 2)
		var wait sync.WaitGroup
		for _, peer := range []*connection{coordinator, user} {
			wait.Add(1)
			go func(peer *connection) {
				defer wait.Done()
				<-start
				failures <- current.attach(peer)
			}(peer)
		}
		close(start)
		wait.Wait()
		close(failures)
		for failure := range failures {
			if failure != nil {
				t.Fatalf("bootstrap failed: %v", failure)
			}
		}

		coordinatorFrames := queuedFrames(t, coordinator)
		userFrames := queuedFrames(t, user)
		if len(coordinatorFrames) < 2 || coordinatorFrames[0].Opcode != protocol.OpcodeWelcome {
			t.Fatalf("coordinator bootstrap did not start with WELCOME: %#v", coordinatorFrames)
		}
		coordinators := arrayValue(coordinatorFrames[0].Payload[5])
		if len(coordinators) != 1 || integer(arrayValue(coordinators[0])[2]) != 1 {
			t.Fatalf("coordinator WELCOME did not include its connected session: %#v", coordinators)
		}
		if len(userFrames) < 5 || userFrames[0].Opcode != protocol.OpcodeWelcome {
			t.Fatalf("user bootstrap did not start with WELCOME: %#v", userFrames)
		}

		observedUser := 0
		for _, frame := range coordinatorFrames[1:] {
			switch frame.Opcode {
			case protocol.OpcodePresenceSnapshot:
				for _, raw := range arrayValue(frame.Payload[0]) {
					entry := arrayValue(raw)
					if integer(entry[0]) == user.sessionID && stringValue(entry[1]) == user.identity.ID {
						observedUser++
					}
				}
			case protocol.OpcodePresenceChange:
				if integer(frame.Payload[0]) == user.sessionID &&
					stringValue(frame.Payload[1]) == user.identity.ID &&
					integer(frame.Payload[2]) == 1 {
					observedUser++
				}
			}
		}
		if observedUser != 1 {
			t.Fatalf("coordinator observed the concurrent user %d times: %#v", observedUser, coordinatorFrames)
		}

		coordinator.stopLease()
		user.stopLease()
		coordinator.cancel()
		user.cancel()
	}
}

func queuedFrames(t *testing.T, peer *connection) []protocol.Frame {
	t.Helper()
	peer.queueMu.Lock()
	messages := append([]outboundMessage(nil), peer.queue...)
	peer.queueMu.Unlock()
	frames := make([]protocol.Frame, 0, len(messages))
	for _, message := range messages {
		frame, err := protocol.DecodeFrame(message.bytes)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func TestProtectedQueueEntryEvictsOnlyDroppableStreamData(t *testing.T) {
	connection := &connection{
		server:    &Server{config: config.Config{MaxQueuedBytes: 100}},
		queueWake: make(chan struct{}, 1),
	}
	if err := connection.enqueueBytes(outboundMessage{
		bytes:           make([]byte, 60),
		droppableStream: true,
	}, false); err != nil {
		t.Fatal(err)
	}
	if err := connection.enqueueBytes(outboundMessage{bytes: make([]byte, 30)}, false); err != nil {
		t.Fatal(err)
	}
	terminal := outboundMessage{bytes: make([]byte, 40)}
	if err := connection.enqueueBytes(terminal, true); err != nil {
		t.Fatal(err)
	}
	if connection.queuedBytes != 70 || len(connection.queue) != 2 {
		t.Fatalf("unexpected compacted queue: bytes=%d entries=%d", connection.queuedBytes, len(connection.queue))
	}
	if len(connection.queue[0].bytes) != 30 || len(connection.queue[1].bytes) != 40 {
		t.Fatalf("protected enqueue reordered non-stream traffic: %#v", connection.queue)
	}
}

func TestFatalMakesAConnectionUnavailableAndRejectsPostCloseFrames(t *testing.T) {
	peer := &connection{
		server:    &Server{config: config.Config{MaxQueuedBytes: 1_024}},
		logger:    slog.Default(),
		queueWake: make(chan struct{}, 1),
	}
	peer.phase.Store(uint32(phaseActive))
	peer.bootstrapped.Store(true)
	peer.fail(protocol.OpcodeEvent, fatalError(codeSlowConsumer, true, "slow consumer", closeLimit))
	if peer.available() {
		t.Fatal("fatal connection remained available for routing")
	}
	if err := peer.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeHomeStatus,
		Payload: []any{false, []any{}},
	}, true); err == nil {
		t.Fatal("connection accepted a frame behind its terminal FATAL")
	}
	frames := queuedFrames(t, peer)
	if len(frames) != 1 || frames[0].Opcode != protocol.OpcodeFatal {
		t.Fatalf("unexpected terminal queue: %#v", frames)
	}
}

func TestRequestIdentifierRemainsInflightUntilTerminalWrite(t *testing.T) {
	connection := &connection{
		server:     &Server{config: config.Config{MaxQueuedBytes: 1_024}},
		queueWake:  make(chan struct{}, 1),
		requestIDs: make(map[int64]struct{}),
	}
	if failure := connection.beginRequest(91); failure != nil {
		t.Fatal(failure)
	}
	if err := connection.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeReauthOK,
		Payload: []any{int64(91), time.Now().Add(time.Minute).UnixMilli()},
	}, true); err != nil {
		t.Fatal(err)
	}
	if failure := connection.beginRequest(91); failure == nil || failure.code != codeDuplicateRequest {
		t.Fatalf("request ID was released before its terminal write: %#v", failure)
	}
	message, ok := connection.nextMessage()
	if !ok || message.afterWrite == nil {
		t.Fatal("terminal response did not carry a write completion")
	}
	message.afterWrite()
	if failure := connection.beginRequest(91); failure != nil {
		t.Fatalf("request ID was not reusable after terminal write: %v", failure)
	}
}

func TestActivationRejectsAnUnencodableAggregateSnapshotAtomically(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	primary := connectPeer(t, httpServer)
	primary.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	primary.receive(t, protocol.OpcodeWelcome)
	primary.receive(t, protocol.OpcodePresenceSnapshot)
	stageLargeConfiguration(t, primary, 100, "primary", 3, strings.Repeat("a", 60_000), true)

	secondary := connectPeer(t, httpServer)
	secondary.send(t, hello(auth.RoleCoordinator, "coordinator-b-token", []any{"secondary"}))
	secondary.receive(t, protocol.OpcodeWelcome)
	secondary.receive(t, protocol.OpcodePresenceSnapshot)
	stageLargeConfiguration(t, secondary, 200, "secondary", 3, strings.Repeat("b", 60_000), false)
	failure := secondary.receive(t, protocol.OpcodeError)
	if integer(failure.Payload[0]) != 204 || integer(failure.Payload[2]) != codeLimitExceeded {
		t.Fatalf("unexpected aggregate activation failure: %#v", failure.Payload)
	}

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	snapshot := user.receive(t, protocol.OpcodeStateSnapshot)
	if entries := arrayValue(snapshot.Payload[2]); len(entries) != 3 {
		t.Fatalf("failed activation published a partial aggregate: %d entries", len(entries))
	}
}

func TestStateMutationRejectsAnUnencodableAggregateSnapshotAtomically(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	primary := connectPeer(t, httpServer)
	primary.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	primary.receive(t, protocol.OpcodeWelcome)
	primary.receive(t, protocol.OpcodePresenceSnapshot)
	stageLargeConfiguration(t, primary, 300, "primary", 3, strings.Repeat("a", 60_000), true)

	secondary := connectPeer(t, httpServer)
	secondary.send(t, hello(auth.RoleCoordinator, "coordinator-b-token", []any{"secondary"}))
	secondary.receive(t, protocol.OpcodeWelcome)
	secondary.receive(t, protocol.OpcodePresenceSnapshot)
	epoch, pathIDs := stageLargeConfiguration(t, secondary, 400, "secondary", 2, "initial", true)
	mutations := make([]any, 0, len(pathIDs))
	for _, pathID := range pathIDs {
		mutations = append(mutations, []any{pathID, int64(0), strings.Repeat("b", 60_000)})
	}
	secondary.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeStateSet,
		Payload: []any{int64(405), epoch, mutations},
	})
	failure := secondary.receive(t, protocol.OpcodeError)
	if integer(failure.Payload[0]) != 405 || integer(failure.Payload[2]) != codeLimitExceeded {
		t.Fatalf("unexpected aggregate mutation failure: %#v", failure.Payload)
	}

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	snapshot := user.receive(t, protocol.OpcodeStateSnapshot)
	values := make(map[int64]any)
	for _, raw := range arrayValue(snapshot.Payload[2]) {
		entry := arrayValue(raw)
		values[integer(entry[0])] = entry[1]
	}
	for _, pathID := range pathIDs {
		if values[pathID] != "initial" {
			t.Fatalf("rejected mutation changed path %d to %#v", pathID, values[pathID])
		}
	}
}

func stageLargeConfiguration(
	t *testing.T,
	peer *testPeer,
	base int64,
	prefix string,
	count int,
	value string,
	activate bool,
) ([]byte, []int64) {
	t.Helper()
	entries := make([]any, 0, count)
	for index := 0; index < count; index++ {
		entries = append(entries, []any{fmt.Sprintf("%s.value%d", prefix, index), value})
	}
	peer.send(t, protocol.Frame{Opcode: protocol.OpcodeStateSync, Payload: []any{base, entries}})
	stateOK := peer.receive(t, protocol.OpcodeStateSyncOK)
	pathDictionary := arrayValue(stateOK.Payload[3])
	pathIDs := make([]int64, 0, len(pathDictionary))
	for _, raw := range pathDictionary {
		pathIDs = append(pathIDs, integer(arrayValue(raw)[0]))
	}
	peer.send(t, protocol.Frame{
		Opcode: protocol.OpcodeStateACLSync,
		Payload: []any{
			base + 1,
			[]any{[]any{"user-1", []any{prefix + ".*"}}},
		},
	})
	peer.receive(t, protocol.OpcodeStateACLOK)
	peer.send(t, protocol.Frame{Opcode: protocol.OpcodeEventSync, Payload: []any{base + 2, []any{}}})
	peer.receive(t, protocol.OpcodeEventSyncOK)
	peer.send(t, protocol.Frame{Opcode: protocol.OpcodeEventACLSync, Payload: []any{base + 3, []any{}}})
	peer.receive(t, protocol.OpcodeEventACLOK)
	peer.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeFunctionSync,
		Payload: []any{base + 4, []any{prefix + ".run"}},
	})
	if activate {
		peer.receive(t, protocol.OpcodeFunctionSyncOK)
	}
	return bytesValue(stateOK.Payload[1]), pathIDs
}

func TestStateDictionaryRetainsDeclaredPathAcrossDeleteAndResync(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	epoch, pathID, _, _ := synchronizeCoordinator(t, coordinator)

	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	user.receive(t, protocol.OpcodeStateSnapshot)
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	coordinator.receive(t, protocol.OpcodePresenceChange)

	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeStateSet,
		Payload: []any{int64(80), epoch, []any{[]any{pathID, int64(1)}}},
	})
	coordinator.receive(t, protocol.OpcodeStateSetOK)
	user.receive(t, protocol.OpcodeStatePatch)

	user.send(t, protocol.Frame{Opcode: protocol.OpcodeStateResync, Payload: []any{int64(81)}})
	dictionary := user.receive(t, protocol.OpcodeStateDict)
	if entries := arrayValue(dictionary.Payload[2]); len(entries) != 1 {
		t.Fatalf("declared deleted path disappeared from the dictionary: %#v", entries)
	}
	snapshot := user.receive(t, protocol.OpcodeStateSnapshot)
	if entries := arrayValue(snapshot.Payload[2]); len(entries) != 0 {
		t.Fatalf("deleted state remained in the snapshot: %#v", entries)
	}

	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeStateSet,
		Payload: []any{int64(82), epoch, []any{[]any{pathID, int64(0), int64(22)}}},
	})
	coordinator.receive(t, protocol.OpcodeStateSetOK)
	patch := user.receive(t, protocol.OpcodeStatePatch)
	if integer(arrayValue(arrayValue(patch.Payload[3])[0])[0]) != pathID {
		t.Fatalf("recreated state used an unexpected path ID: %#v", patch.Payload)
	}
}

func TestLateCallResultRemainsDiscardedBeyondThePreviousWindow(t *testing.T) {
	_, httpServer := newTestServer(t, nil)
	coordinator := connectPeer(t, httpServer)
	coordinator.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	coordinator.receive(t, protocol.OpcodeWelcome)
	coordinator.receive(t, protocol.OpcodePresenceSnapshot)
	_, _, _, functionID := synchronizeCoordinator(t, coordinator)
	user := connectPeer(t, httpServer)
	user.send(t, hello(auth.RoleUser, "user-token", []any{"home-1"}))
	user.receive(t, protocol.OpcodeWelcome)
	user.receive(t, protocol.OpcodeStateDict)
	user.receive(t, protocol.OpcodeStateSnapshot)
	user.receive(t, protocol.OpcodeTopicDict)
	user.receive(t, protocol.OpcodeFunctionDict)
	coordinator.receive(t, protocol.OpcodePresenceChange)

	var firstCalleeID int64
	for index := int64(1); index <= 260; index++ {
		user.send(t, protocol.Frame{
			Opcode: protocol.OpcodeCall,
			Payload: []any{
				index, int64(0), nil, functionID, int64(5_000), nil, int64(0), nil,
			},
		})
		dispatch := coordinator.receive(t, protocol.OpcodeCallDispatch)
		user.receive(t, protocol.OpcodeCallAccepted)
		calleeID := integer(dispatch.Payload[0])
		if index == 1 {
			firstCalleeID = calleeID
		}
		coordinator.send(t, protocol.Frame{
			Opcode:  protocol.OpcodeCallResult,
			Payload: []any{calleeID, true, index},
		})
		user.receive(t, protocol.OpcodeCallResult)
	}

	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeCallResult,
		Payload: []any{firstCalleeID, true, "very-late"},
	})
	user.send(t, protocol.Frame{
		Opcode: protocol.OpcodeCall,
		Payload: []any{
			int64(300), int64(0), nil, functionID, int64(5_000), nil, int64(0), nil,
		},
	})
	coordinator.receive(t, protocol.OpcodeCallDispatch)
	user.receive(t, protocol.OpcodeCallAccepted)
}
