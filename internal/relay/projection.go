package relay

import (
	"reflect"

	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

// A projection is an isolated, lock-free copy of the home fields used to build
// complete client views. It lets the relay prove that every required recovery
// frame remains encodable before committing a declaration or state mutation.
func (current *home) baseProjectionLocked(state map[string]any, revision int64) *home {
	projection := &home{
		epoch:           current.epoch,
		revision:        revision,
		users:           current.users,
		coordinators:    make(map[string]*coordinatorSlot, len(current.coordinators)),
		pathsByName:     cloneMap(current.pathsByName),
		pathsByID:       cloneMap(current.pathsByID),
		topicsByName:    cloneMap(current.topicsByName),
		topicsByID:      cloneMap(current.topicsByID),
		functionsByName: cloneMap(current.functionsByName),
		functionsByID:   cloneMap(current.functionsByID),
		stateOwners:     cloneMap(current.stateOwners),
		topicOwners:     cloneMap(current.topicOwners),
		functionOwners:  cloneMap(current.functionOwners),
		state:           state,
	}
	for name, slot := range current.coordinators {
		projection.coordinators[name] = &coordinatorSlot{name: name, active: slot.active}
	}
	return projection
}

func (current *home) projectionForStateLocked(state map[string]any, revision int64) *home {
	return current.baseProjectionLocked(state, revision)
}

func (current *home) projectionForActivationLocked(
	name string,
	next *coordinatorConfig,
	stage *declarationStage,
) *home {
	revision := current.revision
	previous := current.coordinators[name].active
	if previous == nil || !reflect.DeepEqual(previous.state, next.state) {
		revision++
	}
	projection := current.baseProjectionLocked(cloneAnyMap(current.state), revision)
	if previous != nil {
		for path := range previous.ownedState {
			delete(projection.stateOwners, path)
			delete(projection.state, path)
		}
		for topic := range previous.events {
			delete(projection.topicOwners, topic)
		}
		for function := range previous.functions {
			delete(projection.functionOwners, function)
		}
	}
	for path, id := range stage.pathIDs {
		projection.pathsByName[path] = id
		projection.pathsByID[id] = path
	}
	for topic, id := range stage.topicIDs {
		projection.topicsByName[topic] = id
		projection.topicsByID[id] = topic
	}
	for function, id := range stage.functionIDs {
		projection.functionsByName[function] = id
		projection.functionsByID[id] = function
	}
	for path, value := range next.state {
		projection.stateOwners[path] = name
		projection.state[path] = value
	}
	for topic := range next.events {
		projection.topicOwners[topic] = name
	}
	for function := range next.functions {
		projection.functionOwners[function] = name
	}
	projection.coordinators[name].active = next
	return projection
}

func (current *home) validateRequiredFramesLocked() *relayError {
	if failure := validateEncodable(current.functionDictionaryFrameLocked(true)); failure != nil {
		return failure
	}
	userIDs := make(map[string]struct{}, len(current.users))
	for _, user := range current.users {
		userIDs[user.identity.ID] = struct{}{}
	}
	for _, slot := range current.coordinators {
		if slot.active == nil {
			continue
		}
		for userID := range slot.active.stateACL {
			userIDs[userID] = struct{}{}
		}
		for userID := range slot.active.eventACL {
			userIDs[userID] = struct{}{}
		}
	}
	for userID := range userIDs {
		frames := []protocol.Frame{
			current.stateDictionaryFrameLocked(userID, true),
			current.stateSnapshotFrameLocked(userID),
			current.topicDictionaryFrameLocked(userID, true),
		}
		for _, frame := range frames {
			if failure := validateEncodable(frame); failure != nil {
				return failure
			}
		}
	}
	return nil
}

func validateEncodable(frame protocol.Frame) *relayError {
	return validateFrame(frame, "update would make a required complete frame unencodable")
}

func validateRoutableFrame(frame protocol.Frame) *relayError {
	return validateFrame(frame, "forwarded frame would exceed protocol limits")
}

func validateFrame(frame protocol.Frame, message string) *relayError {
	if _, err := protocol.EncodeFrame(frame); err != nil {
		return applicationError(
			codeLimitExceeded,
			false,
			message,
			closeLimit,
		)
	}
	return nil
}

func cloneAnyMap(values map[string]any) map[string]any {
	return cloneMap(values)
}

func cloneMap[mapKey comparable, mapValue any](values map[mapKey]mapValue) map[mapKey]mapValue {
	cloned := make(map[mapKey]mapValue, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
