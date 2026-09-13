package relay

import (
	"context"
	"testing"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

// RFC 0001 §6 gives the session layer a DRAINING state and §7.1 gives the relay
// GOAWAY to enter it, but nothing entered it before Drain existed: the phase was
// reachable only in the rule that refuses new requests. These tests pin the
// whole window, because a shutdown that silently dropped sockets would still
// have passed every other test in this package.

func TestDrainAnnouncesGoawayAndRefusesNewRequests(t *testing.T) {
	server, httpServer := newTestServer(t, nil)
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

	server.Drain(5_000, 1012, time.Minute)

	goaway := user.receive(t, protocol.OpcodeGoaway)
	if integer(goaway.Payload[0]) != 5_000 || integer(goaway.Payload[1]) != 1012 {
		t.Fatalf("unexpected goaway payload: %#v", goaway.Payload)
	}
	coordinator.receive(t, protocol.OpcodeGoaway)

	user.send(t, protocol.Frame{Opcode: protocol.OpcodeStateResync, Payload: []any{int64(90)}})
	refusal := user.receive(t, protocol.OpcodeError)
	if integer(refusal.Payload[0]) != 90 ||
		integer(refusal.Payload[1]) != int64(protocol.OpcodeStateResync) ||
		integer(refusal.Payload[2]) != codeUnexpectedFrame {
		t.Fatalf("a draining session accepted a new request: %#v", refusal.Payload)
	}
}

func TestDrainLetsAnInflightCallReachItsTerminalReply(t *testing.T) {
	server, httpServer := newTestServer(t, nil)
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

	user.send(t, protocol.Frame{
		Opcode: protocol.OpcodeCall,
		Payload: []any{
			int64(91), int64(0), nil, functionID, int64(5_000), nil, int64(0), nil,
		},
	})
	dispatch := coordinator.receive(t, protocol.OpcodeCallDispatch)
	user.receive(t, protocol.OpcodeCallAccepted)

	server.Drain(5_000, 1012, time.Minute)
	coordinator.receive(t, protocol.OpcodeGoaway)
	user.receive(t, protocol.OpcodeGoaway)

	// A terminal call frame is the one thing draining still accepts, so a call
	// already dispatched resolves instead of becoming an avoidable unknown.
	coordinator.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeCallResult,
		Payload: []any{integer(dispatch.Payload[0]), true, "done"},
	})
	result := user.receive(t, protocol.OpcodeCallResult)
	if integer(result.Payload[0]) != 91 {
		t.Fatalf("draining lost the terminal reply of an in-flight call: %#v", result.Payload)
	}
}

func TestDrainClosesEverySessionAtItsDeadline(t *testing.T) {
	server, httpServer := newTestServer(t, nil)
	peer := connectPeer(t, httpServer)
	peer.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	peer.receive(t, protocol.OpcodeWelcome)
	peer.receive(t, protocol.OpcodePresenceSnapshot)

	server.Drain(5_000, 1012, 20*time.Millisecond)
	peer.receive(t, protocol.OpcodeGoaway)

	closing, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := peer.connection.Read(closing); err == nil {
		t.Fatal("the relay left a drained session open past its deadline")
	}
}

func TestDrainReachesASessionThatAuthenticatesMidWindow(t *testing.T) {
	server, httpServer := newTestServer(t, nil)
	server.Drain(5_000, 1012, time.Minute)

	late := connectPeer(t, httpServer)
	late.send(t, hello(auth.RoleCoordinator, "coordinator-token", []any{"automation"}))
	late.receive(t, protocol.OpcodeWelcome)
	late.receive(t, protocol.OpcodePresenceSnapshot)
	late.receive(t, protocol.OpcodeGoaway)

	late.send(t, protocol.Frame{
		Opcode:  protocol.OpcodeFunctionSync,
		Payload: []any{int64(1), []any{"late.run"}},
	})
	refusal := late.receive(t, protocol.OpcodeError)
	if integer(refusal.Payload[2]) != codeUnexpectedFrame {
		t.Fatalf("a session that arrived mid-drain was served: %#v", refusal.Payload)
	}
}
