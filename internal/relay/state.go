package relay

import (
	"bytes"
	"reflect"
	"sort"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

type userStateView map[string]any

func (current *home) handleState(peer *connection, frame protocol.Frame) *relayError {
	switch frame.Opcode {
	case protocol.OpcodeStateResync:
		if peer.identity.Role != auth.RoleUser {
			return applicationError(codeForbidden, false, "state resynchronization is not available for this role", closeAuthorization)
		}
		requestID := integer(frame.Payload[0])
		current.mu.Lock()
		defer current.mu.Unlock()
		frames := []protocol.Frame{
			current.stateDictionaryFrameLocked(peer.identity.ID, true),
			current.stateSnapshotFrameLocked(peer.identity.ID),
		}
		peer.lastStateRevision = current.revision
		for index, response := range frames {
			var err error
			if index == len(frames)-1 {
				err = peer.enqueueRequestTerminal(response, requestID, false)
			} else {
				err = peer.enqueue(response, false)
			}
			if err != nil {
				return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
			}
		}
		return nil
	case protocol.OpcodeStateSet:
		return current.applyStateSet(peer, frame)
	default:
		return applicationError(codeUnexpectedFrame, false, "unexpected state frame", closeProtocol)
	}
}

func (current *home) applyStateSet(peer *connection, frame protocol.Frame) *relayError {
	if peer.identity.Role != auth.RoleCoordinator {
		return applicationError(codeWrongDirection, false, "only coordinators may mutate state", closeAuthorization)
	}
	requestID := integer(frame.Payload[0])
	current.mu.Lock()
	defer current.mu.Unlock()
	if !bytes.Equal(bytesValue(frame.Payload[1]), current.epoch[:]) {
		return applicationError(codeStaleEpoch, true, "state mutation uses a stale epoch", closeConflict)
	}
	if failure := current.activeCoordinatorLocked(peer, true); failure != nil {
		return failure
	}
	slot := current.coordinators[peer.identity.CoordinatorName]

	mutations := arrayValue(frame.Payload[2])
	paths := make([]string, len(mutations))
	for index, raw := range mutations {
		mutation := arrayValue(raw)
		pathID := integer(mutation[0])
		path := current.pathsByID[pathID]
		if path == "" || current.stateOwners[path] != slot.name {
			return applicationError(codeNotDeclared, false, "state mutation references an unowned path", closeAuthorization)
		}
		if _, owned := slot.active.ownedState[path]; !owned {
			return applicationError(codeNotDeclared, false, "state mutation references an inactive path", closeAuthorization)
		}
		paths[index] = path
	}
	nextState := cloneAnyMap(current.state)
	for index, raw := range mutations {
		mutation := arrayValue(raw)
		path := paths[index]
		if integer(mutation[1]) == 1 {
			delete(nextState, path)
		} else {
			nextState[path] = mutation[2]
		}
	}
	projection := current.projectionForStateLocked(nextState, current.revision+1)
	if failure := projection.validateRequiredFramesLocked(); failure != nil {
		return failure
	}

	baseRevision := current.revision
	actions := make([]sendAction, 0, len(current.users))
	for _, user := range current.users {
		if !user.available() {
			continue
		}
		visibleMutations := make([]any, 0, len(mutations))
		for index, raw := range mutations {
			if current.userCanSeeStateLocked(user.identity.ID, paths[index]) {
				visibleMutations = append(visibleMutations, raw)
			}
		}
		if len(visibleMutations) == 0 {
			continue
		}
		base := user.lastStateRevision
		if base == 0 {
			base = baseRevision
		}
		patch := protocol.Frame{
			Opcode: protocol.OpcodeStatePatch,
			Payload: []any{
				append([]byte(nil), current.epoch[:]...),
				base,
				projection.revision,
				visibleMutations,
			},
		}
		if failure := validateEncodable(patch); failure != nil {
			patch = projection.stateSnapshotFrameLocked(user.identity.ID)
		}
		actions = append(actions, sendAction{connection: user, frame: patch})
	}

	if err := peer.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeStateSetOK,
		Payload: []any{requestID, append([]byte(nil), current.epoch[:]...), current.revision + 1},
	}, true); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	for index, raw := range mutations {
		mutation := arrayValue(raw)
		path := paths[index]
		if integer(mutation[1]) == 1 {
			delete(current.state, path)
			delete(slot.active.state, path)
		} else {
			current.state[path] = mutation[2]
			slot.active.state[path] = mutation[2]
		}
	}
	current.revision++
	for _, action := range actions {
		action.connection.lastStateRevision = current.revision
	}
	current.dispatch(actions)
	return nil
}

func (current *home) captureUserViewsLocked() map[int64]userStateView {
	views := make(map[int64]userStateView, len(current.users))
	for sessionID, peer := range current.users {
		views[sessionID] = current.visibleStateLocked(peer.identity.ID)
	}
	return views
}

func (current *home) visibleStateLocked(userID string) userStateView {
	view := make(userStateView)
	for path, value := range current.state {
		if current.userCanSeeStateLocked(userID, path) {
			view[path] = value
		}
	}
	return view
}

func (current *home) userCanSeeStateLocked(userID, path string) bool {
	for _, slot := range current.coordinators {
		if slot.active == nil {
			continue
		}
		if matchesAny(slot.active.stateACL[userID], path) {
			return true
		}
	}
	return false
}

func (current *home) userCanPublishTopicLocked(userID, topic string) bool {
	for _, slot := range current.coordinators {
		if slot.active == nil {
			continue
		}
		if access, found := slot.active.eventACL[userID]; found && matchesAny(access.publish, topic) {
			return true
		}
	}
	return false
}

func (current *home) userCanSubscribeTopicLocked(userID, topic string) bool {
	for _, slot := range current.coordinators {
		if slot.active == nil {
			continue
		}
		if access, found := slot.active.eventACL[userID]; found && matchesAny(access.subscribe, topic) {
			return true
		}
	}
	return false
}

func (current *home) stateDictionaryFrameLocked(userID string, replace bool) protocol.Frame {
	names := make([]string, 0, len(current.stateOwners))
	for name := range current.stateOwners {
		if current.userCanSeeStateLocked(userID, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	dictionary := make([]any, 0, len(names))
	for _, name := range names {
		dictionary = append(dictionary, []any{current.pathsByName[name], name})
	}
	return protocol.Frame{
		Opcode:  protocol.OpcodeStateDict,
		Payload: []any{append([]byte(nil), current.epoch[:]...), replace, dictionary},
	}
}

func (current *home) stateSnapshotFrameLocked(userID string) protocol.Frame {
	view := current.visibleStateLocked(userID)
	ids := make([]int64, 0, len(view))
	values := make(map[int64]any, len(view))
	for path, value := range view {
		id := current.pathsByName[path]
		ids = append(ids, id)
		values[id] = value
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	entries := make([]any, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, []any{id, values[id]})
	}
	return protocol.Frame{
		Opcode:  protocol.OpcodeStateSnapshot,
		Payload: []any{append([]byte(nil), current.epoch[:]...), current.revision, entries},
	}
}

func (current *home) topicDictionaryFrameLocked(userID string, replace bool) protocol.Frame {
	ids := make([]int64, 0)
	for topic := range current.topicOwners {
		if current.userCanPublishTopicLocked(userID, topic) || current.userCanSubscribeTopicLocked(userID, topic) {
			ids = append(ids, current.topicsByName[topic])
		}
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	entries := make([]any, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, []any{id, current.topicsByID[id]})
	}
	return protocol.Frame{
		Opcode:  protocol.OpcodeTopicDict,
		Payload: []any{append([]byte(nil), current.epoch[:]...), replace, entries},
	}
}

func (current *home) functionDictionaryFrameLocked(replace bool) protocol.Frame {
	ids := make([]int64, 0, len(current.functionOwners))
	for name := range current.functionOwners {
		ids = append(ids, current.functionsByName[name])
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	entries := make([]any, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, []any{id, current.functionsByID[id]})
	}
	return protocol.Frame{
		Opcode:  protocol.OpcodeFunctionDict,
		Payload: []any{append([]byte(nil), current.epoch[:]...), replace, entries},
	}
}

func (current *home) userViewActionsLocked(
	previous map[int64]userStateView,
	includeCapabilities bool,
) []sendAction {
	actions := make([]sendAction, 0, len(current.users)*4)
	for sessionID, user := range current.users {
		if !user.available() {
			continue
		}
		view := current.visibleStateLocked(user.identity.ID)
		if !reflect.DeepEqual(previous[sessionID], view) || includeCapabilities {
			actions = append(actions,
				sendAction{connection: user, frame: current.stateDictionaryFrameLocked(user.identity.ID, true)},
				sendAction{connection: user, frame: current.stateSnapshotFrameLocked(user.identity.ID)},
			)
			user.lastStateRevision = current.revision
		}
		if includeCapabilities {
			actions = append(actions,
				sendAction{connection: user, frame: current.topicDictionaryFrameLocked(user.identity.ID, true)},
				sendAction{connection: user, frame: current.functionDictionaryFrameLocked(true)},
			)
		}
	}
	return actions
}
