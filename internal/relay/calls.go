package relay

import (
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

type callRoute struct {
	caller   *connection
	callee   *connection
	callerID int64
	calleeID int64
	credit   int64
	accepted bool
	terminal bool
	deadline time.Time
	timer    *time.Timer
}

func (current *home) handleCall(peer *connection, frame protocol.Frame) *relayError {
	switch frame.Opcode {
	case protocol.OpcodeCall:
		return current.startCall(peer, frame)
	case protocol.OpcodeCallResult:
		return current.forwardCallResult(peer, frame)
	case protocol.OpcodeCallError:
		return current.forwardCallError(peer, frame)
	case protocol.OpcodeCallCancel:
		return current.cancelCall(peer, frame)
	case protocol.OpcodeCallCredit:
		return current.creditCall(peer, frame)
	default:
		return applicationError(codeUnexpectedFrame, false, "unexpected call frame", closeProtocol)
	}
}

func (current *home) startCall(peer *connection, frame protocol.Frame) *relayError {
	deadline := time.Now().Add(time.Duration(integer(frame.Payload[4])) * time.Millisecond)
	callerID := integer(frame.Payload[0])
	targetKind := integer(frame.Payload[1])
	target := frame.Payload[2]
	functionID := integer(frame.Payload[3])
	idempotencyKey := frame.Payload[5]
	credit := integer(frame.Payload[6])
	arguments := frame.Payload[7]

	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.identity.Role == auth.RoleCoordinator {
		if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
			return failure
		}
	}
	if _, duplicate := peer.calls[callerID]; duplicate {
		return applicationError(codeDuplicateRequest, false, "call identifier is already in flight", closeConflict)
	}
	if len(peer.calls) >= protocol.MaxInflightCalls {
		return applicationError(codeLimitExceeded, false, "call concurrency limit exceeded", closeLimit)
	}
	functionName := current.functionsByID[functionID]
	ownerName := current.functionOwners[functionName]
	if functionName == "" || ownerName == "" {
		return applicationError(codeNotDeclared, false, "function is not declared", closeAuthorization)
	}
	if peer.identity.Role == auth.RoleUser && !current.userEnrolledLocked(peer.identity.ID) && functionName != "miakapp.join" {
		return applicationError(codeNotEnrolled, false, "user is not enrolled", closeAuthorization)
	}
	callee, failure := current.resolveCallTargetLocked(peer, ownerName, targetKind, target)
	if failure != nil {
		return failure
	}
	if len(callee.calls) >= protocol.MaxInflightCalls {
		return applicationError(codeLimitExceeded, false, "callee call concurrency limit exceeded", closeLimit)
	}
	calleeID := current.allocateCalleeCallIDLocked(callee)
	route := &callRoute{
		caller:   peer,
		callee:   callee,
		callerID: callerID,
		calleeID: calleeID,
		credit:   credit,
		deadline: deadline,
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return applicationError(codeDeadlineExceeded, false, "call deadline expired before dispatch", closeTimeout)
	}
	remainingMilliseconds := remaining.Milliseconds()
	if remainingMilliseconds < 1 {
		remainingMilliseconds = 1
	}
	dispatch := protocol.Frame{
		Opcode: protocol.OpcodeCallDispatch,
		Payload: []any{
			calleeID,
			peer.identity.Principal(peer.sessionID),
			targetKind,
			target,
			functionID,
			remainingMilliseconds,
			idempotencyKey,
			credit,
			arguments,
		},
	}
	if failure := validateRoutableFrame(dispatch); failure != nil {
		return failure
	}
	peer.calls[callerID] = route
	callee.calls[calleeID] = route
	if err := callee.enqueue(dispatch, false); err != nil {
		current.removeRouteLocked(route)
		return applicationError(codeUnavailable, true, "call destination is unavailable", closeUnavailable)
	}
	route.accepted = true
	route.timer = time.AfterFunc(time.Until(deadline), func() {
		current.expireCall(route)
	})
	if err := peer.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeCallAccepted,
		Payload: []any{callerID},
	}, false); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	return nil
}

func (current *home) resolveCallTargetLocked(
	caller *connection,
	ownerName string,
	targetKind int64,
	target any,
) (*connection, *relayError) {
	switch targetKind {
	case 0:
		if target != nil {
			return nil, applicationError(codeInvalidValue, false, "default call target must be null", closeProtocol)
		}
		slot := current.coordinators[ownerName]
		if slot == nil || slot.connection == nil || !slot.connection.available() || !slot.ready {
			return nil, applicationError(codeNoCoordinator, true, "function owner is unavailable", closeUnavailable)
		}
		return slot.connection, nil
	case 1:
		if caller.identity.Role != auth.RoleCoordinator {
			return nil, applicationError(codeWrongDirection, false, "only coordinators may call a user session", closeAuthorization)
		}
		if caller.identity.CoordinatorName != ownerName {
			return nil, applicationError(codeForbidden, false, "coordinator does not own the targeted function", closeAuthorization)
		}
		user := current.users[integer(target)]
		if user == nil || !user.available() || !current.userEnrolledLocked(user.identity.ID) {
			return nil, applicationError(codeUnavailable, true, "target user session is unavailable", closeUnavailable)
		}
		return user, nil
	case 2:
		if caller.identity.Role != auth.RoleCoordinator {
			return nil, applicationError(codeWrongDirection, false, "only coordinators may call a named coordinator", closeAuthorization)
		}
		name := stringValue(target)
		if name != ownerName {
			return nil, applicationError(codeForbidden, false, "named coordinator does not own the targeted function", closeAuthorization)
		}
		slot := current.coordinators[name]
		if slot == nil || slot.connection == nil || !slot.connection.available() || !slot.ready {
			return nil, applicationError(codeNoCoordinator, true, "target coordinator is unavailable", closeUnavailable)
		}
		return slot.connection, nil
	default:
		return nil, applicationError(codeInvalidValue, false, "call target is invalid", closeProtocol)
	}
}

func (current *home) forwardCallResult(peer *connection, frame protocol.Frame) *relayError {
	callID := integer(frame.Payload[0])
	final, ok := frame.Payload[1].(bool)
	if !ok {
		return fatalError(codeInvalidValue, false, "call result final flag is invalid", closeProtocol)
	}
	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.identity.Role == auth.RoleCoordinator {
		if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
			return failure
		}
	}
	route := peer.calls[callID]
	if route == nil {
		if callID <= peer.nextCallID {
			return nil
		}
	}
	if route == nil || route.callee != peer || route.calleeID != callID || route.terminal {
		return applicationError(codeNotDeclared, false, "call route is not active", closeAuthorization)
	}
	if !final && route.credit == 0 {
		return applicationError(codeLimitExceeded, false, "call result exceeded stream credit", closeLimit)
	}
	forwarded := protocol.Frame{
		Opcode:  protocol.OpcodeCallResult,
		Payload: []any{route.callerID, final, frame.Payload[2]},
	}
	if failure := validateRoutableFrame(forwarded); failure != nil {
		return failure
	}
	if !final {
		route.credit--
	}
	if final {
		current.removeRouteLocked(route)
	}
	var err error
	if final {
		err = route.caller.enqueue(forwarded, true)
	} else {
		err = route.caller.enqueueStream(forwarded)
	}
	if err != nil {
		return applicationError(codeUnavailable, true, "call origin is unavailable", closeUnavailable)
	}
	return nil
}

func (current *home) forwardCallError(peer *connection, frame protocol.Frame) *relayError {
	callID := integer(frame.Payload[0])
	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.identity.Role == auth.RoleCoordinator {
		if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
			return failure
		}
	}
	route := peer.calls[callID]
	if route == nil {
		if callID <= peer.nextCallID {
			return nil
		}
	}
	if route == nil || route.callee != peer || route.calleeID != callID || route.terminal {
		return applicationError(codeNotDeclared, false, "call route is not active", closeAuthorization)
	}
	forwarded := protocol.Frame{
		Opcode: protocol.OpcodeCallError,
		Payload: []any{
			route.callerID,
			frame.Payload[1],
			frame.Payload[2],
			frame.Payload[3],
			frame.Payload[4],
		},
	}
	if failure := validateRoutableFrame(forwarded); failure != nil {
		return failure
	}
	current.removeRouteLocked(route)
	if err := route.caller.enqueue(forwarded, true); err != nil {
		return applicationError(codeUnavailable, true, "call origin is unavailable", closeUnavailable)
	}
	return nil
}

func (current *home) cancelCall(peer *connection, frame protocol.Frame) *relayError {
	callID := integer(frame.Payload[0])
	reason := frame.Payload[1]
	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.identity.Role == auth.RoleCoordinator {
		if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
			return failure
		}
	}
	route := peer.calls[callID]
	if route == nil || route.caller != peer || route.callerID != callID || route.terminal {
		return applicationError(codeNotDeclared, false, "call route is not active", closeAuthorization)
	}
	if !route.accepted {
		current.removeRouteLocked(route)
		if err := peer.enqueue(callFailureFrame(callID, codeCancelled, false, "call cancelled before dispatch", nil), true); err != nil {
			return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
		}
		return nil
	}
	_ = route.callee.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeCallCancel,
		Payload: []any{route.calleeID, reason},
	}, true)
	current.removeRouteLocked(route)
	if err := peer.enqueue(callFailureFrame(
		callID,
		codeOutcomeUnknown,
		false,
		"call cancellation outcome is unknown",
		nil,
	), true); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	return nil
}

func (current *home) creditCall(peer *connection, frame protocol.Frame) *relayError {
	callID := integer(frame.Payload[0])
	additional := integer(frame.Payload[1])
	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.identity.Role == auth.RoleCoordinator {
		if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
			return failure
		}
	}
	route := peer.calls[callID]
	if route == nil || route.caller != peer || route.callerID != callID || route.terminal {
		return applicationError(codeNotDeclared, false, "call route is not active", closeAuthorization)
	}
	if route.credit+additional > protocol.MaxStreamCredit {
		return applicationError(codeLimitExceeded, false, "call stream credit limit exceeded", closeLimit)
	}
	route.credit += additional
	if err := route.callee.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeCallCredit,
		Payload: []any{route.calleeID, additional},
	}, true); err != nil {
		return applicationError(codeUnavailable, true, "call destination is unavailable", closeUnavailable)
	}
	return nil
}

func (current *home) allocateCalleeCallIDLocked(callee *connection) int64 {
	for {
		callee.nextCallID++
		if callee.nextCallID <= 0 || callee.nextCallID > 9_007_199_254_740_991 {
			callee.nextCallID = 1
		}
		if _, used := callee.calls[callee.nextCallID]; used {
			continue
		}
		return callee.nextCallID
	}
}

func (current *home) expireCall(route *callRoute) {
	current.mu.Lock()
	if route.terminal {
		current.mu.Unlock()
		return
	}
	current.removeRouteLocked(route)
	caller := route.caller
	callee := route.callee
	callerID := route.callerID
	calleeID := route.calleeID
	accepted := route.accepted
	current.mu.Unlock()
	if accepted {
		_ = callee.enqueue(protocol.Frame{
			Opcode:  protocol.OpcodeCallCancel,
			Payload: []any{calleeID, codeDeadlineExceeded},
		}, true)
		_ = caller.enqueue(callFailureFrame(
			callerID,
			codeOutcomeUnknown,
			false,
			"call deadline expired after dispatch",
			nil,
		), true)
	} else {
		_ = caller.enqueue(callFailureFrame(
			callerID,
			codeDeadlineExceeded,
			false,
			"call deadline expired before dispatch",
			nil,
		), true)
	}
}

func (current *home) removeRouteLocked(route *callRoute) {
	if route.terminal {
		return
	}
	route.terminal = true
	if route.timer != nil {
		route.timer.Stop()
	}
	delete(route.caller.calls, route.callerID)
	delete(route.callee.calls, route.calleeID)
}

func (current *home) terminateCallsForConnectionLocked(peer *connection) []sendAction {
	actions := make([]sendAction, 0, len(peer.calls))
	seen := make(map[*callRoute]struct{}, len(peer.calls))
	for _, route := range peer.calls {
		if _, duplicate := seen[route]; duplicate || route.terminal {
			continue
		}
		seen[route] = struct{}{}
		current.removeRouteLocked(route)
		if route.caller == peer {
			actions = append(actions, sendAction{
				connection: route.callee,
				frame: protocol.Frame{
					Opcode:  protocol.OpcodeCallCancel,
					Payload: []any{route.calleeID, codeOutcomeUnknown},
				},
				priority: true,
			})
		} else {
			actions = append(actions, sendAction{
				connection: route.caller,
				frame: callFailureFrame(
					route.callerID,
					codeOutcomeUnknown,
					false,
					"call destination disconnected after dispatch",
					nil,
				),
				priority: true,
			})
		}
	}
	return actions
}
