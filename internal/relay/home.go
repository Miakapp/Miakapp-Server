package relay

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

const (
	maxCoordinatorsPerHome = 64
	maxPresenceEntries     = 4_096
	maxDictionaryEntries   = 16_384
)

type homeRegistry struct {
	server *Server
	mu     sync.Mutex
	homes  map[string]*home
	closed bool
}

func newHomeRegistry(server *Server) *homeRegistry {
	return &homeRegistry{server: server, homes: make(map[string]*home)}
}

func (registry *homeRegistry) acquire(homeID string) (*home, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return nil, errors.New("home registry is closed")
	}
	current := registry.homes[homeID]
	if current == nil {
		var err error
		current, err = newHome(registry.server, homeID)
		if err != nil {
			return nil, err
		}
		registry.homes[homeID] = current
	}
	current.references++
	return current, nil
}

func (registry *homeRegistry) release(current *home) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	current.references--
	registry.deleteIfUnusedLocked(current)
}

func (registry *homeRegistry) deleteIfUnused(current *home) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.deleteIfUnusedLocked(current)
}

func (registry *homeRegistry) deleteIfUnusedLocked(current *home) {
	if registry.homes[current.id] == current && current.references == 0 && current.empty() {
		delete(registry.homes, current.id)
	}
}

func (registry *homeRegistry) close() {
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return
	}
	registry.closed = true
	homes := make([]*home, 0, len(registry.homes))
	for _, current := range registry.homes {
		homes = append(homes, current)
	}
	registry.mu.Unlock()
	for _, current := range homes {
		current.close()
	}
}

type coordinatorSlot struct {
	name       string
	generation int64
	connection *connection
	ready      bool
	active     *coordinatorConfig
	grace      *time.Timer
}

type home struct {
	server *Server
	id     string
	epoch  [16]byte

	mu           sync.Mutex
	references   int
	closed       bool
	revision     int64
	policy       int64
	connections  map[int64]*connection
	users        map[int64]*connection
	coordinators map[string]*coordinatorSlot

	pathsByName     map[string]int64
	pathsByID       map[int64]string
	nextPathID      int64
	topicsByName    map[string]int64
	topicsByID      map[int64]string
	nextTopicID     int64
	functionsByName map[string]int64
	functionsByID   map[int64]string
	nextFunctionID  int64

	stateOwners    map[string]string
	topicOwners    map[string]string
	functionOwners map[string]string
	state          map[string]any
}

type sendAction struct {
	connection *connection
	frame      protocol.Frame
	priority   bool
}

func newHome(server *Server, id string) (*home, error) {
	current := &home{
		server:          server,
		id:              id,
		revision:        1,
		policy:          1,
		connections:     make(map[int64]*connection),
		users:           make(map[int64]*connection),
		coordinators:    make(map[string]*coordinatorSlot),
		pathsByName:     make(map[string]int64),
		pathsByID:       make(map[int64]string),
		nextPathID:      1,
		topicsByName:    make(map[string]int64),
		topicsByID:      make(map[int64]string),
		nextTopicID:     1,
		functionsByName: make(map[string]int64),
		functionsByID:   make(map[int64]string),
		nextFunctionID:  1,
		stateOwners:     make(map[string]string),
		topicOwners:     make(map[string]string),
		functionOwners:  make(map[string]string),
		state:           make(map[string]any),
	}
	if _, err := rand.Read(current.epoch[:]); err != nil {
		return nil, errors.New("unable to create a cryptographic home epoch")
	}
	return current, nil
}

func (current *home) epochBytesLocked() []byte {
	return append([]byte(nil), current.epoch[:]...)
}

func (current *home) empty() bool {
	current.mu.Lock()
	defer current.mu.Unlock()
	return len(current.connections) == 0 && len(current.coordinators) == 0
}

func (current *home) attach(peer *connection) *relayError {
	current.mu.Lock()
	if current.closed {
		current.mu.Unlock()
		return fatalError(codeUnavailable, true, "relay is shutting down", closeUnavailable)
	}
	current.connections[peer.sessionID] = peer
	enrolled := true
	var frames []protocol.Frame
	var replaced *connection
	var replacementActions []sendAction
	var bootstrapActions []sendAction

	switch peer.identity.Role {
	case auth.RoleUser:
		if len(current.users) >= maxPresenceEntries {
			delete(current.connections, peer.sessionID)
			current.mu.Unlock()
			return fatalError(codeLimitExceeded, true, "home presence limit exceeded", closeLimit)
		}
		current.users[peer.sessionID] = peer
		if failure := validateEncodable(current.presenceSnapshotIncludingLocked(peer)); failure != nil {
			delete(current.users, peer.sessionID)
			delete(current.connections, peer.sessionID)
			current.mu.Unlock()
			return fatalError(
				codeLimitExceeded,
				true,
				"home presence snapshot would exceed the frame limit",
				closeLimit,
			)
		}
		enrolled = current.userEnrolledLocked(peer.identity.ID)
		frames = current.userBootstrapLocked(peer)
	case auth.RoleCoordinator:
		name := peer.identity.CoordinatorName
		slot := current.coordinators[name]
		if slot == nil {
			if len(current.coordinators) >= maxCoordinatorsPerHome {
				delete(current.connections, peer.sessionID)
				current.mu.Unlock()
				return fatalError(codeLimitExceeded, true, "home coordinator limit exceeded", closeLimit)
			}
			slot = &coordinatorSlot{name: name}
			current.coordinators[name] = slot
		}
		if slot.grace != nil {
			slot.grace.Stop()
			slot.grace = nil
		}
		replaced = slot.connection
		if replaced != nil && replaced != peer {
			replacementActions = current.terminateCallsForConnectionLocked(replaced)
		}
		slot.generation++
		slot.connection = peer
		slot.ready = false
		peer.generation = slot.generation
		frames = []protocol.Frame{current.presenceSnapshotLocked()}
	case auth.RoleCLI:
	default:
		delete(current.connections, peer.sessionID)
		current.mu.Unlock()
		return fatalError(codeUnauthenticated, false, "unsupported authenticated role", closeAuth)
	}

	coordinators := current.coordinatorStatusIncludingLocked(peer)
	var bootstrapFailure *relayError
	if err := peer.enqueue(peer.welcomeFrame(enrolled, coordinators), true); err != nil {
		bootstrapFailure = fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	} else {
		for _, frame := range frames {
			if err := peer.enqueue(frame, false); err != nil {
				bootstrapFailure = fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
				break
			}
		}
	}
	if bootstrapFailure == nil {
		if !peer.activateInitialLease() {
			bootstrapFailure = fatalError(codeTokenExpired, true, "access token expired", closeAuth)
		} else if peer.available() {
			switch peer.identity.Role {
			case auth.RoleUser:
				bootstrapActions = current.presenceActionsLocked(peer.sessionID, peer.identity.ID, 1)
			case auth.RoleCoordinator:
				bootstrapActions = current.homeStatusActionsLocked()
			}
		}
	}
	current.dispatch(replacementActions)
	current.dispatch(bootstrapActions)
	current.mu.Unlock()

	if replaced != nil && replaced != peer {
		replaced.fail(0, fatalError(
			codeGenerationReplaced,
			true,
			"coordinator generation was replaced",
			closeConflict,
		))
	}
	if bootstrapFailure != nil {
		return bootstrapFailure
	}
	return nil
}

func (current *home) detach(peer *connection) {
	current.mu.Lock()
	if _, present := current.connections[peer.sessionID]; !present {
		current.mu.Unlock()
		return
	}
	delete(current.connections, peer.sessionID)
	if peer.stage != nil && peer.stage.timer != nil {
		peer.stage.timer.Stop()
	}
	peer.stage = nil
	actions := current.terminateCallsForConnectionLocked(peer)
	var lifecycleActions []sendAction
	visible := peer.bootstrapped.Load()

	switch peer.identity.Role {
	case auth.RoleUser:
		delete(current.users, peer.sessionID)
		if visible && !current.closed {
			lifecycleActions = current.presenceActionsLocked(peer.sessionID, peer.identity.ID, 2)
		}
	case auth.RoleCoordinator:
		slot := current.coordinators[peer.identity.CoordinatorName]
		if slot != nil && slot.connection == peer && slot.generation == peer.generation {
			slot.connection = nil
			slot.ready = false
			switch {
			case current.closed:
				if slot.grace != nil {
					slot.grace.Stop()
				}
				delete(current.coordinators, slot.name)
			case !visible && slot.active == nil:
				delete(current.coordinators, slot.name)
			default:
				generation := slot.generation
				slot.grace = time.AfterFunc(current.server.config.DisconnectGrace, func() {
					current.expireCoordinator(slot.name, generation)
				})
				lifecycleActions = current.homeStatusActionsLocked()
			}
		}
	}
	current.dispatch(actions)
	current.dispatch(lifecycleActions)
	current.mu.Unlock()
}

func (current *home) handle(peer *connection, frame protocol.Frame) *relayError {
	switch frame.Opcode {
	case protocol.OpcodeStateSync,
		protocol.OpcodeStateACLSync,
		protocol.OpcodeEventSync,
		protocol.OpcodeEventACLSync,
		protocol.OpcodeFunctionSync:
		return current.handleDeclaration(peer, frame)
	case protocol.OpcodeStateSet, protocol.OpcodeStateResync:
		return current.handleState(peer, frame)
	case protocol.OpcodeSubscribe,
		protocol.OpcodeUnsubscribe,
		protocol.OpcodeEvent:
		return current.handleEvent(peer, frame)
	case protocol.OpcodeCall,
		protocol.OpcodeCallResult,
		protocol.OpcodeCallError,
		protocol.OpcodeCallCancel,
		protocol.OpcodeCallCredit:
		return current.handleCall(peer, frame)
	default:
		return applicationError(codeUnexpectedFrame, false, "frame is not implemented by this relay", closeProtocol)
	}
}

func (current *home) expireCoordinator(name string, generation int64) {
	current.mu.Lock()
	slot := current.coordinators[name]
	if slot == nil || slot.generation != generation || slot.connection != nil {
		current.mu.Unlock()
		return
	}
	slot.grace = nil
	actions := current.removeCoordinatorLocked(slot)
	delete(current.coordinators, name)
	current.dispatch(actions)
	current.dispatch(current.homeStatusActionsLocked())
	current.mu.Unlock()
	current.server.homes.deleteIfUnused(current)
}

func (current *home) activeCoordinatorLocked(peer *connection, requireReady bool) *relayError {
	slot := current.coordinators[peer.identity.CoordinatorName]
	if slot == nil || slot.connection != peer || slot.generation != peer.generation {
		return fatalError(codeGenerationReplaced, true, "coordinator generation was replaced", closeConflict)
	}
	if requireReady && (!slot.ready || slot.active == nil) {
		return applicationError(codeUnavailable, true, "coordinator declarations are not active", closeUnavailable)
	}
	return nil
}

func (current *home) removeCoordinatorLocked(slot *coordinatorSlot) []sendAction {
	if slot.active == nil {
		return nil
	}
	previousViews := current.captureUserViewsLocked()
	for path := range slot.active.ownedState {
		delete(current.stateOwners, path)
		delete(current.state, path)
	}
	for topic := range slot.active.events {
		delete(current.topicOwners, topic)
	}
	for name := range slot.active.functions {
		delete(current.functionOwners, name)
	}
	slot.active = nil
	current.revision++
	current.policy++
	current.pruneSubscriptionsLocked()
	return current.userViewActionsLocked(previousViews, true)
}

func (current *home) coordinatorStatusLocked() []any {
	return current.coordinatorStatusIncludingLocked(nil)
}

func (current *home) coordinatorStatusIncludingLocked(extra *connection) []any {
	names := make([]string, 0, len(current.coordinators))
	for name := range current.coordinators {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]any, 0, len(names))
	for _, name := range names {
		slot := current.coordinators[name]
		status := int64(2)
		if slot.connection != nil && (slot.connection == extra || slot.connection.available()) {
			status = 1
		} else if slot.connection != nil && slot.active == nil {
			continue
		}
		entries = append(entries, []any{name, slot.generation, status})
	}
	return entries
}

func (current *home) userEnrolledLocked(userID string) bool {
	for _, slot := range current.coordinators {
		if slot.active == nil {
			continue
		}
		if _, found := slot.active.stateACL[userID]; found {
			return true
		}
		if _, found := slot.active.eventACL[userID]; found {
			return true
		}
	}
	return false
}

func (current *home) userBootstrapLocked(peer *connection) []protocol.Frame {
	peer.lastStateRevision = current.revision
	return []protocol.Frame{
		current.stateDictionaryFrameLocked(peer.identity.ID, true),
		current.stateSnapshotFrameLocked(peer.identity.ID),
		current.topicDictionaryFrameLocked(peer.identity.ID, true),
		current.functionDictionaryFrameLocked(true),
	}
}

func (current *home) presenceSnapshotLocked() protocol.Frame {
	return current.presenceSnapshotIncludingLocked(nil)
}

func (current *home) presenceSnapshotIncludingLocked(extra *connection) protocol.Frame {
	ids := make([]int64, 0, len(current.users))
	for sessionID, user := range current.users {
		// Keep a bootstrapped session visible until detach removes it under this
		// lock, so a racing coordinator sees either snapshot+disconnect or neither.
		if user != extra && !user.bootstrapped.Load() {
			continue
		}
		ids = append(ids, sessionID)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	entries := make([]any, 0, len(ids))
	for _, sessionID := range ids {
		entries = append(entries, []any{sessionID, current.users[sessionID].identity.ID})
	}
	return protocol.Frame{Opcode: protocol.OpcodePresenceSnapshot, Payload: []any{entries}}
}

func (current *home) presenceActionsLocked(sessionID int64, userID string, event int64) []sendAction {
	actions := make([]sendAction, 0, len(current.coordinators))
	for _, slot := range current.coordinators {
		if slot.connection != nil && slot.connection.available() {
			actions = append(actions, sendAction{
				connection: slot.connection,
				frame: protocol.Frame{
					Opcode:  protocol.OpcodePresenceChange,
					Payload: []any{sessionID, userID, event},
				},
			})
		}
	}
	return actions
}

func (current *home) homeStatusActionsLocked() []sendAction {
	coordinators := current.coordinatorStatusLocked()
	actions := make([]sendAction, 0, len(current.users))
	for _, user := range current.users {
		if !user.available() {
			continue
		}
		actions = append(actions, sendAction{
			connection: user,
			frame: protocol.Frame{
				Opcode:  protocol.OpcodeHomeStatus,
				Payload: []any{current.userEnrolledLocked(user.identity.ID), coordinators},
			},
			priority: true,
		})
	}
	return actions
}

func (current *home) dispatch(actions []sendAction) {
	for _, action := range actions {
		_ = action.connection.enqueue(action.frame, action.priority)
	}
}

func (current *home) close() {
	current.mu.Lock()
	if current.closed {
		current.mu.Unlock()
		return
	}
	current.closed = true
	connections := make([]*connection, 0, len(current.connections))
	for _, peer := range current.connections {
		connections = append(connections, peer)
	}
	for _, slot := range current.coordinators {
		if slot.grace != nil {
			slot.grace.Stop()
		}
		if slot.connection == nil {
			delete(current.coordinators, slot.name)
		}
	}
	current.mu.Unlock()
	for _, peer := range connections {
		peer.stop(websocketStatusServiceRestart, "service_restart")
	}
	current.server.homes.deleteIfUnused(current)
}

const websocketStatusServiceRestart = 1012
