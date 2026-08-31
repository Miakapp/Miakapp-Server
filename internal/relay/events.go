package relay

import (
	"sort"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

const (
	eventAcceptUsers         int64 = 0x01
	eventPublishUsers        int64 = 0x02
	eventAcceptCoordinators  int64 = 0x04
	eventPublishCoordinators int64 = 0x08
)

func (current *home) handleEvent(peer *connection, frame protocol.Frame) *relayError {
	switch frame.Opcode {
	case protocol.OpcodeSubscribe:
		return current.subscribe(peer, frame)
	case protocol.OpcodeUnsubscribe:
		return current.unsubscribe(peer, frame)
	case protocol.OpcodeEvent:
		return current.publishEvent(peer, frame)
	default:
		return applicationError(codeUnexpectedFrame, false, "unexpected event frame", closeProtocol)
	}
}

func (current *home) subscribe(peer *connection, frame protocol.Frame) *relayError {
	if peer.identity.Role != auth.RoleUser {
		return applicationError(codeWrongDirection, false, "only user sessions subscribe in protocol 1.0", closeAuthorization)
	}
	requestID := integer(frame.Payload[0])
	idsRaw := arrayValue(frame.Payload[1])

	current.mu.Lock()
	defer current.mu.Unlock()
	if !current.userEnrolledLocked(peer.identity.ID) {
		return applicationError(codeNotEnrolled, false, "user is not enrolled", closeAuthorization)
	}
	ids := make([]int64, 0, len(idsRaw))
	newSubscriptions := 0
	for _, raw := range idsRaw {
		id := integer(raw)
		topic := current.topicsByID[id]
		if topic == "" || !current.userCanSubscribeTopicLocked(peer.identity.ID, topic) {
			return applicationError(codeForbidden, false, "topic subscription is not authorized", closeAuthorization)
		}
		if _, subscribed := peer.subscriptions[id]; !subscribed {
			newSubscriptions++
		}
		ids = append(ids, id)
	}
	if len(peer.subscriptions)+newSubscriptions > protocol.MaxSubscriptions {
		return applicationError(codeLimitExceeded, false, "subscription limit exceeded", closeLimit)
	}
	for _, id := range ids {
		peer.subscriptions[id] = struct{}{}
	}
	if err := peer.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeSubscribeOK,
		Payload: []any{requestID, int64SliceValues(ids)},
	}, true); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	return nil
}

func (current *home) unsubscribe(peer *connection, frame protocol.Frame) *relayError {
	if peer.identity.Role != auth.RoleUser {
		return applicationError(codeWrongDirection, false, "only user sessions subscribe in protocol 1.0", closeAuthorization)
	}
	requestID := integer(frame.Payload[0])
	idsRaw := arrayValue(frame.Payload[1])

	current.mu.Lock()
	defer current.mu.Unlock()
	ids := make([]int64, 0, len(idsRaw))
	for _, raw := range idsRaw {
		id := integer(raw)
		if _, subscribed := peer.subscriptions[id]; !subscribed {
			return applicationError(codeNotDeclared, false, "topic is not subscribed", closeAuthorization)
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		delete(peer.subscriptions, id)
	}
	if err := peer.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeUnsubscribeOK,
		Payload: []any{requestID, int64SliceValues(ids)},
	}, true); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	return nil
}

func (current *home) publishEvent(peer *connection, frame protocol.Frame) *relayError {
	eventID := integer(frame.Payload[0])
	if failure := peer.claimEventID(eventID); failure != nil {
		return failure
	}
	topicID := integer(frame.Payload[1])
	targetKind := integer(frame.Payload[2])
	target := frame.Payload[3]
	payload := frame.Payload[4]

	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.identity.Role == auth.RoleCoordinator {
		if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
			return failure
		}
	}
	topic := current.topicsByID[topicID]
	owner := current.topicOwners[topic]
	if topic == "" || owner == "" {
		return applicationError(codeNotDeclared, false, "event topic is not declared", closeAuthorization)
	}
	ownerSlot := current.coordinators[owner]
	if ownerSlot == nil || ownerSlot.active == nil {
		return applicationError(codeNoCoordinator, true, "event owner is unavailable", closeUnavailable)
	}
	declaration := ownerSlot.active.events[topic]
	forwarded := protocol.Frame{
		Opcode: protocol.OpcodeEvent,
		Payload: []any{
			eventID,
			topicID,
			targetKind,
			target,
			peer.identity.Principal(peer.sessionID),
			payload,
		},
	}
	if failure := validateRoutableFrame(forwarded); failure != nil {
		return failure
	}

	switch peer.identity.Role {
	case auth.RoleUser:
		if targetKind != 0 || target != nil {
			return applicationError(codeWrongDirection, false, "users must use the default event target", closeAuthorization)
		}
		if !current.userEnrolledLocked(peer.identity.ID) {
			return applicationError(codeNotEnrolled, false, "user is not enrolled", closeAuthorization)
		}
		if declaration.flags&eventAcceptUsers == 0 ||
			!current.userCanPublishTopicLocked(peer.identity.ID, topic) {
			return applicationError(codeForbidden, false, "event publication is not authorized", closeAuthorization)
		}
		if ownerSlot.connection == nil || !ownerSlot.connection.available() || !ownerSlot.ready {
			return applicationError(codeNoCoordinator, true, "event owner is unavailable", closeUnavailable)
		}
		if err := ownerSlot.connection.enqueue(forwarded, false); err != nil {
			return applicationError(codeUnavailable, true, "event destination is unavailable", closeUnavailable)
		}
		return nil
	case auth.RoleCoordinator:
		if current.coordinators[peer.identity.CoordinatorName] != ownerSlot {
			return applicationError(codeForbidden, false, "coordinator does not own this event topic", closeAuthorization)
		}
		return current.routeCoordinatorEventLocked(peer, declaration, topic, topicID, targetKind, target, forwarded)
	default:
		return applicationError(codeWrongDirection, false, "role cannot publish events", closeAuthorization)
	}
}

func (current *home) routeCoordinatorEventLocked(
	peer *connection,
	declaration eventDeclaration,
	topic string,
	topicID int64,
	targetKind int64,
	target any,
	frame protocol.Frame,
) *relayError {
	switch targetKind {
	case 0:
		if target != nil {
			return applicationError(codeInvalidValue, false, "default event target must be null", closeProtocol)
		}
		if declaration.flags&eventPublishUsers == 0 {
			return applicationError(codeWrongDirection, false, "event is not declared for user delivery", closeAuthorization)
		}
		delivered := false
		for _, user := range current.users {
			if !user.available() {
				continue
			}
			if _, subscribed := user.subscriptions[topicID]; !subscribed {
				continue
			}
			if !current.userCanSubscribeTopicLocked(user.identity.ID, topic) {
				continue
			}
			if user.enqueue(frame, false) == nil {
				delivered = true
			}
		}
		if !delivered {
			return applicationError(codeUnavailable, true, "event has no available subscriber", closeUnavailable)
		}
		return nil
	case 1:
		if declaration.flags&eventPublishUsers == 0 {
			return applicationError(codeWrongDirection, false, "event is not declared for user delivery", closeAuthorization)
		}
		sessionID := integer(target)
		user := current.users[sessionID]
		if user == nil || !user.available() {
			return applicationError(codeUnavailable, true, "target user session is unavailable", closeUnavailable)
		}
		if _, subscribed := user.subscriptions[topicID]; !subscribed ||
			!current.userCanSubscribeTopicLocked(user.identity.ID, topic) {
			return applicationError(codeForbidden, false, "target user is not subscribed", closeAuthorization)
		}
		if err := user.enqueue(frame, false); err != nil {
			return applicationError(codeUnavailable, true, "target user session is unavailable", closeUnavailable)
		}
		return nil
	case 2:
		if declaration.flags&eventPublishCoordinators == 0 || declaration.flags&eventAcceptCoordinators == 0 {
			return applicationError(codeWrongDirection, false, "event is not declared for coordinator routing", closeAuthorization)
		}
		name := stringValue(target)
		slot := current.coordinators[name]
		if slot == nil || slot.connection == nil || !slot.connection.available() ||
			!slot.ready || slot.connection == peer {
			return applicationError(codeNoCoordinator, true, "target coordinator is unavailable", closeUnavailable)
		}
		if err := slot.connection.enqueue(frame, false); err != nil {
			return applicationError(codeUnavailable, true, "target coordinator is unavailable", closeUnavailable)
		}
		return nil
	default:
		return applicationError(codeInvalidValue, false, "event target is invalid", closeProtocol)
	}
}

func (current *home) pruneSubscriptionsLocked() {
	for _, user := range current.users {
		for topicID := range user.subscriptions {
			topic := current.topicsByID[topicID]
			if current.topicOwners[topic] == "" || !current.userCanSubscribeTopicLocked(user.identity.ID, topic) {
				delete(user.subscriptions, topicID)
			}
		}
	}
}

func int64SliceValues(values []int64) []any {
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	result := make([]any, len(sorted))
	for index, value := range sorted {
		result[index] = value
	}
	return result
}
