package relay

import (
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

type eventDeclaration struct {
	flags int64
}

type eventAccess struct {
	publish   []string
	subscribe []string
}

type coordinatorConfig struct {
	ownedState map[string]struct{}
	state      map[string]any
	stateACL   map[string][]string
	events     map[string]eventDeclaration
	eventACL   map[string]eventAccess
	functions  map[string]struct{}
}

type declarationStage struct {
	expected    byte
	state       map[string]any
	stateACL    map[string][]string
	events      map[string]eventDeclaration
	eventACL    map[string]eventAccess
	functions   map[string]struct{}
	pathIDs     map[string]int64
	topicIDs    map[string]int64
	functionIDs map[string]int64
	timer       *time.Timer
}

func (current *home) handleDeclaration(peer *connection, frame protocol.Frame) *relayError {
	if peer.identity.Role != auth.RoleCoordinator {
		return applicationError(codeWrongDirection, false, "only coordinators may declare slices", closeAuthorization)
	}
	requestID := integer(frame.Payload[0])
	current.mu.Lock()
	defer current.mu.Unlock()
	if failure := current.activeCoordinatorLocked(peer, false); failure != nil {
		return failure
	}
	slot := current.coordinators[peer.identity.CoordinatorName]

	if frame.Opcode == protocol.OpcodeStateSync {
		if peer.stage != nil && peer.stage.timer != nil {
			peer.stage.timer.Stop()
		}
		stage := &declarationStage{
			expected: protocol.OpcodeStateACLSync,
			state:    parseStateSlice(frame.Payload[1]),
			pathIDs:  make(map[string]int64),
		}
		for path := range stage.state {
			stage.pathIDs[path] = current.reservePathIDLocked(path)
		}
		response := protocol.Frame{
			Opcode: protocol.OpcodeStateSyncOK,
			Payload: []any{
				requestID,
				append([]byte(nil), current.epoch[:]...),
				current.revision,
				dictionaryFromIDs(stage.pathIDs),
			},
		}
		if failure := validateEncodable(response); failure != nil {
			return failure
		}
		stage.timer = time.AfterFunc(current.server.config.DeclarationTTL, func() {
			current.expireStage(peer, stage)
		})
		peer.stage = stage
		if err := peer.enqueue(response, true); err != nil {
			peer.stage = nil
			stage.timer.Stop()
			return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
		}
		return nil
	}

	stage := peer.stage
	if stage == nil || stage.expected != frame.Opcode {
		if stage != nil && stage.timer != nil {
			stage.timer.Stop()
		}
		peer.stage = nil
		return applicationError(codeUnexpectedFrame, false, "declaration slices are out of order", closeProtocol)
	}

	switch frame.Opcode {
	case protocol.OpcodeStateACLSync:
		stage.stateACL = parseStateACL(frame.Payload[1])
		stage.expected = protocol.OpcodeEventSync
		return current.ackDeclarationLocked(peer, protocol.OpcodeStateACLOK, requestID, current.policy)
	case protocol.OpcodeEventSync:
		stage.events = parseEventSlice(frame.Payload[1])
		stage.topicIDs = make(map[string]int64)
		for topic := range stage.events {
			stage.topicIDs[topic] = current.reserveTopicIDLocked(topic)
		}
		stage.expected = protocol.OpcodeEventACLSync
		response := protocol.Frame{
			Opcode:  protocol.OpcodeEventSyncOK,
			Payload: []any{requestID, dictionaryFromIDs(stage.topicIDs)},
		}
		if failure := validateEncodable(response); failure != nil {
			stage.timer.Stop()
			peer.stage = nil
			return failure
		}
		if err := peer.enqueue(response, true); err != nil {
			return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
		}
		return nil
	case protocol.OpcodeEventACLSync:
		stage.eventACL = parseEventACL(frame.Payload[1])
		stage.expected = protocol.OpcodeFunctionSync
		return current.ackDeclarationLocked(peer, protocol.OpcodeEventACLOK, requestID, current.policy)
	case protocol.OpcodeFunctionSync:
		stage.functions = parseFunctionSlice(frame.Payload[1])
		stage.functionIDs = make(map[string]int64)
		for name := range stage.functions {
			stage.functionIDs[name] = current.reserveFunctionIDLocked(name)
		}
		return current.activateLocked(peer, slot, requestID, stage)
	default:
		return applicationError(codeUnexpectedFrame, false, "invalid declaration frame", closeProtocol)
	}
}

func (current *home) ackDeclarationLocked(
	peer *connection,
	opcode byte,
	requestID int64,
	policyRevision int64,
) *relayError {
	if err := peer.enqueue(protocol.Frame{
		Opcode:  opcode,
		Payload: []any{requestID, policyRevision},
	}, true); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	return nil
}

func (current *home) activateLocked(
	peer *connection,
	slot *coordinatorSlot,
	requestID int64,
	stage *declarationStage,
) *relayError {
	next := configFromStage(stage)
	if failure := current.validateActivationLocked(slot.name, requestID, stage, next); failure != nil {
		stage.timer.Stop()
		peer.stage = nil
		return failure
	}
	if err := peer.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeFunctionSyncOK,
		Payload: []any{requestID, dictionaryFromIDs(stage.functionIDs)},
	}, true); err != nil {
		stage.timer.Stop()
		peer.stage = nil
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}

	previousViews := current.captureUserViewsLocked()
	previous := slot.active
	if previous != nil {
		for path := range previous.ownedState {
			delete(current.stateOwners, path)
			delete(current.state, path)
		}
		for topic := range previous.events {
			delete(current.topicOwners, topic)
		}
		for name := range previous.functions {
			delete(current.functionOwners, name)
		}
	}

	for name, id := range stage.pathIDs {
		current.pathsByName[name] = id
		current.pathsByID[id] = name
	}
	for name, id := range stage.topicIDs {
		current.topicsByName[name] = id
		current.topicsByID[id] = name
	}
	for name, id := range stage.functionIDs {
		current.functionsByName[name] = id
		current.functionsByID[id] = name
	}
	for path, value := range stage.state {
		current.stateOwners[path] = slot.name
		current.state[path] = value
	}
	for topic := range stage.events {
		current.topicOwners[topic] = slot.name
	}
	for name := range stage.functions {
		current.functionOwners[name] = slot.name
	}

	stateChanged := previous == nil || !reflect.DeepEqual(previous.state, next.state)
	policyChanged := previous == nil ||
		!reflect.DeepEqual(previous.stateACL, next.stateACL) ||
		!reflect.DeepEqual(previous.events, next.events) ||
		!reflect.DeepEqual(previous.eventACL, next.eventACL) ||
		!reflect.DeepEqual(previous.functions, next.functions)
	if stateChanged {
		current.revision++
	}
	if policyChanged {
		current.policy++
	}
	slot.active = next
	slot.ready = true
	stage.timer.Stop()
	peer.stage = nil

	actions := current.userViewActionsLocked(previousViews, true)
	current.pruneSubscriptionsLocked()
	current.dispatch(actions)
	current.dispatch(current.homeStatusActionsLocked())
	return nil
}

func (current *home) validateActivationLocked(
	name string,
	requestID int64,
	stage *declarationStage,
	next *coordinatorConfig,
) *relayError {
	for path := range stage.state {
		if owner := current.stateOwners[path]; owner != "" && owner != name {
			return applicationError(codeOwnershipCollision, false, "state path ownership collision", closeConflict)
		}
	}
	for topic := range stage.events {
		if owner := current.topicOwners[topic]; owner != "" && owner != name {
			return applicationError(codeOwnershipCollision, false, "event topic ownership collision", closeConflict)
		}
	}
	for function := range stage.functions {
		if owner := current.functionOwners[function]; owner != "" && owner != name {
			return applicationError(codeOwnershipCollision, false, "function ownership collision", closeConflict)
		}
	}
	if current.aggregateStateCountLocked(name, stage) > protocol.MaxStatePathsPerHome {
		return applicationError(codeLimitExceeded, false, "home state path limit exceeded", closeLimit)
	}
	if aggregateDictionaryCount(current.pathsByName, stage.pathIDs) > maxDictionaryEntries ||
		aggregateDictionaryCount(current.topicsByName, stage.topicIDs) > maxDictionaryEntries ||
		aggregateDictionaryCount(current.functionsByName, stage.functionIDs) > maxDictionaryEntries {
		return applicationError(codeLimitExceeded, false, "home dictionary lifetime limit exceeded", closeLimit)
	}
	if current.aggregateTopicCountLocked(name, stage) > maxDictionaryEntries ||
		current.aggregateFunctionCountLocked(name, stage) > maxDictionaryEntries {
		return applicationError(codeLimitExceeded, false, "home dictionary limit exceeded", closeLimit)
	}
	if failure := validateEncodable(protocol.Frame{
		Opcode:  protocol.OpcodeFunctionSyncOK,
		Payload: []any{requestID, dictionaryFromIDs(stage.functionIDs)},
	}); failure != nil {
		return failure
	}
	projection := current.projectionForActivationLocked(name, next, stage)
	if failure := projection.validateRequiredFramesLocked(); failure != nil {
		return failure
	}
	return nil
}

func aggregateDictionaryCount(existing, staged map[string]int64) int {
	count := len(existing)
	for name := range staged {
		if existing[name] == 0 {
			count++
		}
	}
	return count
}

func configFromStage(stage *declarationStage) *coordinatorConfig {
	return &coordinatorConfig{
		ownedState: namesAsSet(stage.state),
		state:      stage.state,
		stateACL:   stage.stateACL,
		events:     stage.events,
		eventACL:   stage.eventACL,
		functions:  stage.functions,
	}
}

func (current *home) aggregateStateCountLocked(name string, stage *declarationStage) int {
	count := len(current.stateOwners)
	if slot := current.coordinators[name]; slot != nil && slot.active != nil {
		count -= len(slot.active.ownedState)
	}
	return count + len(stage.state)
}

func (current *home) aggregateTopicCountLocked(name string, stage *declarationStage) int {
	count := len(current.topicOwners)
	if slot := current.coordinators[name]; slot != nil && slot.active != nil {
		count -= len(slot.active.events)
	}
	return count + len(stage.events)
}

func (current *home) aggregateFunctionCountLocked(name string, stage *declarationStage) int {
	count := len(current.functionOwners)
	if slot := current.coordinators[name]; slot != nil && slot.active != nil {
		count -= len(slot.active.functions)
	}
	return count + len(stage.functions)
}

func (current *home) reservePathIDLocked(path string) int64 {
	if id := current.pathsByName[path]; id != 0 {
		return id
	}
	id := current.nextPathID
	current.nextPathID++
	return id
}

func (current *home) reserveTopicIDLocked(topic string) int64 {
	if id := current.topicsByName[topic]; id != 0 {
		return id
	}
	id := current.nextTopicID
	current.nextTopicID++
	return id
}

func (current *home) reserveFunctionIDLocked(name string) int64 {
	if id := current.functionsByName[name]; id != 0 {
		return id
	}
	id := current.nextFunctionID
	current.nextFunctionID++
	return id
}

func (current *home) expireStage(peer *connection, stage *declarationStage) {
	current.mu.Lock()
	defer current.mu.Unlock()
	if peer.stage != stage {
		return
	}
	peer.stage = nil
	_ = peer.enqueue(errorFrame(0, 0, applicationError(
		codeDeadlineExceeded,
		false,
		"declaration transaction expired",
		closeTimeout,
	)), true)
}

func parseStateSlice(raw any) map[string]any {
	result := make(map[string]any)
	for _, entryRaw := range arrayValue(raw) {
		entry := arrayValue(entryRaw)
		result[stringValue(entry[0])] = entry[1]
	}
	return result
}

func parseStateACL(raw any) map[string][]string {
	result := make(map[string][]string)
	for _, entryRaw := range arrayValue(raw) {
		entry := arrayValue(entryRaw)
		result[stringValue(entry[0])] = stringArray(entry[1])
	}
	return result
}

func parseEventSlice(raw any) map[string]eventDeclaration {
	result := make(map[string]eventDeclaration)
	for _, entryRaw := range arrayValue(raw) {
		entry := arrayValue(entryRaw)
		result[stringValue(entry[0])] = eventDeclaration{flags: integer(entry[1])}
	}
	return result
}

func parseEventACL(raw any) map[string]eventAccess {
	result := make(map[string]eventAccess)
	for _, entryRaw := range arrayValue(raw) {
		entry := arrayValue(entryRaw)
		result[stringValue(entry[0])] = eventAccess{
			publish:   stringArray(entry[1]),
			subscribe: stringArray(entry[2]),
		}
	}
	return result
}

func parseFunctionSlice(raw any) map[string]struct{} {
	result := make(map[string]struct{})
	for _, name := range arrayValue(raw) {
		result[stringValue(name)] = struct{}{}
	}
	return result
}

func stringArray(raw any) []string {
	values := arrayValue(raw)
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = stringValue(value)
	}
	return result
}

func namesAsSet(values map[string]any) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for name := range values {
		result[name] = struct{}{}
	}
	return result
}

func dictionaryFromIDs(ids map[string]int64) []any {
	names := make([]string, 0, len(ids))
	for name := range ids {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]any, 0, len(names))
	for _, name := range names {
		result = append(result, []any{ids[name], name})
	}
	return result
}

func patternMatches(pattern, name string) bool {
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}
	return pattern == name
}

func matchesAny(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if patternMatches(pattern, name) {
			return true
		}
	}
	return false
}
