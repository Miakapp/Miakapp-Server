package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/coder/websocket"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

type connectionPhase uint8

const (
	phaseAwaitHello connectionPhase = iota
	phaseActive
	phaseDraining
	phaseClosed
)

type outboundMessage struct {
	bytes           []byte
	droppableStream bool
	closeStatus     websocket.StatusCode
	closeReason     string
	afterWrite      func()
}

type connection struct {
	server    *Server
	socket    *websocket.Conn
	sessionID int64
	remote    string
	logger    *slog.Logger

	context      context.Context
	cancel       context.CancelFunc
	phase        atomic.Uint32
	bootstrapped atomic.Bool
	identity     auth.Identity
	home         *home
	generation   int64

	queueMu     sync.Mutex
	queue       []outboundMessage
	queuedBytes int
	queueWake   chan struct{}
	queueClosed bool
	closeQueued bool
	writerDone  chan struct{}
	closeOnce   sync.Once
	fatalOnce   sync.Once
	detachOnce  sync.Once

	leaseMu         sync.Mutex
	leaseTimer      *time.Timer
	leaseDeadline   time.Time
	leaseGeneration uint64
	leaseExpired    bool

	requestMu         sync.Mutex
	requestIDs        map[int64]struct{}
	eventIDs          map[int64]struct{}
	subscriptions     map[int64]struct{}
	stage             *declarationStage
	calls             map[int64]*callRoute
	nextCallID        int64
	lastStateRevision int64
}

func newConnection(server *Server, socket *websocket.Conn, sessionID int64, remote string) *connection {
	ctx, cancel := context.WithCancel(server.context)
	connection := &connection{
		server:        server,
		socket:        socket,
		sessionID:     sessionID,
		remote:        remote,
		logger:        server.logger.With("session_id", sessionID),
		context:       ctx,
		cancel:        cancel,
		queueWake:     make(chan struct{}, 1),
		writerDone:    make(chan struct{}),
		requestIDs:    make(map[int64]struct{}),
		eventIDs:      make(map[int64]struct{}),
		subscriptions: make(map[int64]struct{}),
		calls:         make(map[int64]*callRoute),
	}
	connection.phase.Store(uint32(phaseAwaitHello))
	return connection
}

func (connection *connection) run(_ context.Context) {
	go connection.writeLoop()
	go connection.pingLoop()

	defer func() {
		if recovered := recover(); recovered != nil {
			connection.logger.Error(
				"Connection handler recovered an internal invariant failure",
				"panic_type",
				fmt.Sprintf("%T", recovered),
			)
			connection.fail(0, fatalError(codeInternal, true, "internal relay failure", closeInternal))
		}
		connection.detach()
		connection.queueMu.Lock()
		closeQueued := connection.closeQueued
		connection.queueMu.Unlock()
		if !closeQueued {
			connection.stop(int(websocket.StatusNormalClosure), "closed")
		}
		select {
		case <-connection.writerDone:
		case <-time.After(connection.server.config.WriteTimeout):
			connection.stop(closeInternal, "write_timeout")
			<-connection.writerDone
		}
	}()

	handshakeContext, cancel := context.WithTimeout(connection.context, connection.server.config.Handshake)
	messageType, bytes, err := connection.socket.Read(handshakeContext)
	cancel()
	if err != nil {
		connection.stop(closeTimeout, "hello_timeout")
		return
	}
	if messageType != websocket.MessageBinary {
		connection.fail(0, fatalError(codeMalformedFrame, false, "binary HELLO required", closeProtocol))
		return
	}
	frame, err := protocol.DecodeFrame(bytes)
	if err != nil {
		connection.fail(0, protocolFailure(err))
		return
	}
	if frame.Opcode != protocol.OpcodeHello {
		connection.fail(frame.Opcode, fatalError(codeUnexpectedFrame, false, "HELLO must be the first frame", closeProtocol))
		return
	}
	if failure := connection.authenticate(frame); failure != nil {
		connection.fail(protocol.OpcodeHello, failure)
		return
	}

	for connection.context.Err() == nil {
		messageType, bytes, err = connection.socket.Read(connection.context)
		if err != nil {
			if !normalSocketClosure(err) && connection.context.Err() == nil {
				connection.logger.Debug("WebSocket read ended", "error", err)
			}
			return
		}
		if messageType != websocket.MessageBinary {
			connection.fail(0, fatalError(codeMalformedFrame, false, "text messages are forbidden", closeProtocol))
			return
		}
		frame, err = protocol.DecodeFrame(bytes)
		if err != nil {
			connection.fail(0, protocolFailure(err))
			return
		}
		if frame.Opcode >= 0x80 {
			continue
		}
		requestID, requestFrame := requestIdentifier(frame)
		requestClaimed := false
		if requestFrame {
			if failure := connection.beginRequest(requestID); failure != nil {
				if err = connection.enqueue(errorFrame(requestID, frame.Opcode, failure), true); err != nil {
					return
				}
				continue
			}
			requestClaimed = true
		}
		if failure := connection.handle(frame); failure != nil {
			correlation := frameCorrelation(frame)
			if failure.fatal {
				connection.fail(frame.Opcode, failure)
				return
			}
			response := errorFrame(correlation, frame.Opcode, failure)
			if requestClaimed {
				err = connection.enqueueRequestTerminal(response, requestID, true)
			} else {
				err = connection.enqueue(response, true)
			}
			if err != nil {
				return
			}
		}
	}
}

func (connection *connection) authenticate(frame protocol.Frame) *relayError {
	major := integer(frame.Payload[0])
	minimumMinor := integer(frame.Payload[1])
	maximumMinor := integer(frame.Payload[2])
	if major != 1 || minimumMinor > 0 || maximumMinor < 0 {
		return fatalError(codeUnsupportedVersion, false, "protocol version is not supported", closeProtocol)
	}
	role := auth.Role(integer(frame.Payload[3]))
	request := auth.Request{Role: role, Token: stringValue(frame.Payload[4])}
	contextFields := arrayValue(frame.Payload[5])
	switch role {
	case auth.RoleUser:
		request.HomeID = stringValue(contextFields[0])
	case auth.RoleCoordinator:
		request.CoordinatorName = stringValue(contextFields[0])
	case auth.RoleCLI:
	default:
		return fatalError(codeUnauthenticated, false, "authentication role is invalid", closeAuth)
	}

	verifyContext, cancel := context.WithTimeout(connection.context, connection.server.config.Handshake)
	identity, err := connection.server.verifier.Verify(verifyContext, request)
	cancel()
	if err != nil {
		return authenticationFailure(err)
	}
	if err = auth.ValidateBinding(request, identity, time.Now()); err != nil {
		return authenticationFailure(err)
	}
	if role == auth.RoleCoordinator && identity.ID != identity.HomeID {
		return fatalError(codeUnauthenticated, false, "coordinator identity is invalid", closeAuth)
	}

	connection.identity = identity
	connection.home, err = connection.server.homes.acquire(identity.HomeID)
	if err != nil {
		if errors.Is(err, errHomeCapacity) {
			return fatalError(codeLimitExceeded, true, "relay home capacity exceeded", closeLimit)
		}
		return fatalError(codeUnavailable, true, "relay is shutting down", closeUnavailable)
	}
	connection.phase.Store(uint32(phaseActive))
	return connection.home.attach(connection)
}

func (connection *connection) welcomeFrame(enrolled bool, coordinators []any) protocol.Frame {
	return protocol.Frame{
		Opcode: protocol.OpcodeWelcome,
		Payload: []any{
			int64(1),
			int64(0),
			connection.sessionID,
			connection.home.epochBytesLocked(),
			enrolled,
			coordinators,
			[]any{
				int64(protocol.MaxFrameBytes),
				int64(protocol.MaxInflightCalls),
				int64(protocol.MaxSubscriptions),
				int64(connection.server.config.MaxQueuedBytes),
			},
			connection.identity.ExpiresAt.UnixMilli(),
		},
	}
}

func (connection *connection) handle(frame protocol.Frame) *relayError {
	if connectionPhase(connection.phase.Load()) == phaseClosed {
		return fatalError(codeUnavailable, true, "connection is closing", closeUnavailable)
	}
	if connection.authLeaseExpired() {
		return fatalError(codeTokenExpired, true, "access token expired", closeAuth)
	}
	if connectionPhase(connection.phase.Load()) == phaseDraining {
		if frame.Opcode != protocol.OpcodeCallResult && frame.Opcode != protocol.OpcodeCallError {
			return applicationError(codeUnexpectedFrame, false, "new requests are forbidden while draining", closeProtocol)
		}
	}
	if frame.Opcode == protocol.OpcodeHello || frame.Opcode == protocol.OpcodeWelcome {
		return fatalError(codeUnexpectedFrame, false, "frame is not valid in the active session", closeProtocol)
	}
	if !incomingAllowed(connection.identity.Role, frame.Opcode) {
		return applicationError(codeWrongDirection, false, "frame is not valid for this role", closeAuthorization)
	}
	if frame.Opcode == protocol.OpcodeReauth {
		return connection.reauthenticate(frame)
	}
	return connection.home.handle(connection, frame)
}

func (connection *connection) reauthenticate(frame protocol.Frame) *relayError {
	requestID := integer(frame.Payload[0])
	request := auth.Request{
		Role:            connection.identity.Role,
		Token:           stringValue(frame.Payload[1]),
		HomeID:          connection.identity.HomeID,
		CoordinatorName: connection.identity.CoordinatorName,
	}
	previousDeadline, expired := connection.currentLeaseDeadline()
	if expired || !previousDeadline.After(time.Now()) {
		return fatalError(codeTokenExpired, true, "access token expired", closeAuth)
	}
	verificationDeadline := time.Now().Add(connection.server.config.Handshake)
	if previousDeadline.Before(verificationDeadline) {
		verificationDeadline = previousDeadline
	}
	verifyContext, cancel := context.WithDeadline(connection.context, verificationDeadline)
	identity, err := connection.server.verifier.Verify(verifyContext, request)
	cancel()
	if err != nil {
		currentDeadline, leaseExpired := connection.currentLeaseDeadline()
		if leaseExpired || !currentDeadline.After(time.Now()) {
			return fatalError(codeTokenExpired, true, "access token expired", closeAuth)
		}
		return authenticationFailure(err)
	}
	if err = auth.ValidateBinding(request, identity, time.Now()); err != nil {
		return authenticationFailure(err)
	}
	if identity.ID != connection.identity.ID ||
		identity.ClientID != connection.identity.ClientID ||
		identity.VerifiedEmail != connection.identity.VerifiedEmail {
		return fatalError(codeUnauthenticated, false, "reauthentication changed the connection principal", closeAuth)
	}
	if !connection.replaceLease(previousDeadline, identity.ExpiresAt) {
		return fatalError(codeTokenExpired, true, "access token expired", closeAuth)
	}
	if err = connection.enqueue(protocol.Frame{
		Opcode:  protocol.OpcodeReauthOK,
		Payload: []any{requestID, identity.ExpiresAt.UnixMilli()},
	}, true); err != nil {
		return fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit)
	}
	return nil
}

func authenticationFailure(err error) *relayError {
	switch auth.Kind(err) {
	case auth.ErrExpired:
		return fatalError(codeTokenExpired, true, "access token expired", closeAuth)
	case auth.ErrAudience:
		return fatalError(codeInvalidAudience, false, "access token audience is invalid", closeAuth)
	case auth.ErrTemporary:
		return fatalError(codeUnavailable, true, "authentication service unavailable", closeUnavailable)
	default:
		return fatalError(codeUnauthenticated, false, "authentication failed", closeAuth)
	}
}

func incomingAllowed(role auth.Role, opcode byte) bool {
	if opcode == protocol.OpcodeReauth {
		return true
	}
	switch role {
	case auth.RoleCoordinator:
		return opcode == protocol.OpcodeStateSync ||
			opcode == protocol.OpcodeStateSet ||
			opcode == protocol.OpcodeStateACLSync ||
			opcode == protocol.OpcodeEventSync ||
			opcode == protocol.OpcodeEventACLSync ||
			opcode == protocol.OpcodeEvent ||
			opcode == protocol.OpcodeFunctionSync ||
			isCallFlowOpcode(opcode)
	case auth.RoleUser:
		return opcode == protocol.OpcodeStateResync ||
			opcode == protocol.OpcodeSubscribe ||
			opcode == protocol.OpcodeUnsubscribe ||
			opcode == protocol.OpcodeEvent ||
			isCallFlowOpcode(opcode)
	case auth.RoleCLI:
		return opcode == protocol.OpcodeStateResync ||
			opcode == protocol.OpcodeSubscribe ||
			opcode == protocol.OpcodeUnsubscribe ||
			opcode == protocol.OpcodeEvent ||
			isCallFlowOpcode(opcode)
	default:
		return false
	}
}

func isCallFlowOpcode(opcode byte) bool {
	return opcode >= protocol.OpcodeCall && opcode <= protocol.OpcodeCallCredit &&
		opcode != protocol.OpcodeCallDispatch && opcode != protocol.OpcodeCallAccepted
}

func (connection *connection) beginRequest(requestID int64) *relayError {
	connection.requestMu.Lock()
	defer connection.requestMu.Unlock()
	if _, duplicate := connection.requestIDs[requestID]; duplicate {
		return applicationError(codeDuplicateRequest, false, "request identifier is already in flight", closeConflict)
	}
	connection.requestIDs[requestID] = struct{}{}
	return nil
}

func (connection *connection) endRequest(requestID int64) {
	connection.requestMu.Lock()
	defer connection.requestMu.Unlock()
	delete(connection.requestIDs, requestID)
}

func (connection *connection) claimEventID(eventID int64) *relayError {
	if _, duplicate := connection.eventIDs[eventID]; duplicate {
		return applicationError(codeDuplicateRequest, false, "event identifier was already used", closeConflict)
	}
	connection.eventIDs[eventID] = struct{}{}
	return nil
}

func (connection *connection) enqueue(frame protocol.Frame, priority bool) error {
	requestID, terminal := responseRequestIdentifier(frame)
	if terminal {
		return connection.enqueueRequestTerminal(frame, requestID, priority)
	}
	return connection.enqueueFrame(frame, outboundMessage{}, priority)
}

func (connection *connection) enqueueRequestTerminal(
	frame protocol.Frame,
	requestID int64,
	priority bool,
) error {
	message := outboundMessage{afterWrite: func() { connection.endRequest(requestID) }}
	return connection.enqueueFrame(frame, message, priority)
}

func (connection *connection) enqueueFrame(
	frame protocol.Frame,
	message outboundMessage,
	priority bool,
) error {
	bytes, err := protocol.EncodeFrame(frame)
	if err != nil {
		connection.logger.Error("Relay attempted to encode an invalid frame", "opcode", frame.Opcode, "error", err)
		connection.stop(closeInternal, "internal_failure")
		return err
	}
	message.bytes = bytes
	err = connection.enqueueBytes(message, priority)
	if err != nil {
		connection.fail(0, fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit))
	}
	return err
}

func (connection *connection) enqueueStream(frame protocol.Frame) error {
	bytes, err := protocol.EncodeFrame(frame)
	if err != nil {
		connection.logger.Error("Relay attempted to encode an invalid stream frame", "opcode", frame.Opcode, "error", err)
		connection.stop(closeInternal, "internal_failure")
		return err
	}
	err = connection.enqueueBytes(outboundMessage{bytes: bytes, droppableStream: true}, false)
	if err != nil {
		connection.fail(0, fatalError(codeSlowConsumer, true, "outbound queue limit exceeded", closeLimit))
	}
	return err
}

func (connection *connection) enqueueBytes(message outboundMessage, priority bool) error {
	connection.queueMu.Lock()
	defer connection.queueMu.Unlock()
	if connection.queueClosed || connection.closeQueued {
		return net.ErrClosed
	}
	if priority {
		connection.evictStreamsLocked(len(message.bytes))
	}
	if connection.queuedBytes+len(message.bytes) > connection.server.config.MaxQueuedBytes {
		return errors.New("outbound queue limit exceeded")
	}
	if !connection.server.admission.reserveQueuedBytes(len(message.bytes)) {
		return errors.New("aggregate outbound queue limit exceeded")
	}
	connection.queuedBytes += len(message.bytes)
	if message.closeStatus != 0 {
		connection.closeQueued = true
	}
	connection.queue = append(connection.queue, message)
	select {
	case connection.queueWake <- struct{}{}:
	default:
	}
	return nil
}

func (connection *connection) evictStreamsLocked(requiredBytes int) {
	if connection.queuedBytes+requiredBytes <= connection.server.config.MaxQueuedBytes {
		return
	}
	retained := connection.queue[:0]
	releasedBytes := 0
	for _, message := range connection.queue {
		if message.droppableStream && connection.queuedBytes+requiredBytes > connection.server.config.MaxQueuedBytes {
			connection.queuedBytes -= len(message.bytes)
			releasedBytes += len(message.bytes)
			continue
		}
		retained = append(retained, message)
	}
	for index := len(retained); index < len(connection.queue); index++ {
		connection.queue[index] = outboundMessage{}
	}
	connection.queue = retained
	connection.server.admission.releaseQueuedBytes(releasedBytes)
}

func (connection *connection) writeLoop() {
	defer close(connection.writerDone)
	for {
		message, ok := connection.nextMessage()
		if !ok {
			return
		}
		writeContext, cancel := context.WithTimeout(connection.context, connection.server.config.WriteTimeout)
		err := connection.socket.Write(writeContext, websocket.MessageBinary, message.bytes)
		cancel()
		if err != nil {
			connection.stop(int(websocket.StatusInternalError), "write_failed")
			return
		}
		if message.afterWrite != nil {
			message.afterWrite()
		}
		if message.closeStatus != 0 {
			connection.stop(int(message.closeStatus), message.closeReason)
			return
		}
	}
}

func requestIdentifier(frame protocol.Frame) (int64, bool) {
	switch frame.Opcode {
	case protocol.OpcodeReauth,
		protocol.OpcodeStateSync,
		protocol.OpcodeStateSet,
		protocol.OpcodeStateACLSync,
		protocol.OpcodeStateResync,
		protocol.OpcodeEventSync,
		protocol.OpcodeEventACLSync,
		protocol.OpcodeSubscribe,
		protocol.OpcodeUnsubscribe,
		protocol.OpcodeFunctionSync:
		return integer(frame.Payload[0]), true
	default:
		return 0, false
	}
}

func responseRequestIdentifier(frame protocol.Frame) (int64, bool) {
	switch frame.Opcode {
	case protocol.OpcodeReauthOK,
		protocol.OpcodeStateSyncOK,
		protocol.OpcodeStateSetOK,
		protocol.OpcodeStateACLOK,
		protocol.OpcodeEventSyncOK,
		protocol.OpcodeEventACLOK,
		protocol.OpcodeSubscribeOK,
		protocol.OpcodeUnsubscribeOK,
		protocol.OpcodeFunctionSyncOK:
		return integer(frame.Payload[0]), true
	default:
		return 0, false
	}
}

func (connection *connection) nextMessage() (outboundMessage, bool) {
	for {
		connection.queueMu.Lock()
		if len(connection.queue) > 0 {
			message := connection.queue[0]
			connection.queue[0] = outboundMessage{}
			connection.queue = connection.queue[1:]
			connection.queuedBytes -= len(message.bytes)
			connection.server.admission.releaseQueuedBytes(len(message.bytes))
			connection.queueMu.Unlock()
			return message, true
		}
		closed := connection.queueClosed
		connection.queueMu.Unlock()
		if closed {
			return outboundMessage{}, false
		}
		select {
		case <-connection.queueWake:
		case <-connection.context.Done():
			return outboundMessage{}, false
		}
	}
}

func (connection *connection) pingLoop() {
	ticker := time.NewTicker(connection.server.config.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pingContext, cancel := context.WithTimeout(connection.context, connection.server.config.PongTimeout)
			err := connection.socket.Ping(pingContext)
			cancel()
			if err != nil {
				connection.stop(closeTimeout, "liveness_timeout")
				return
			}
		case <-connection.context.Done():
			return
		}
	}
}

func (connection *connection) fail(sourceOpcode byte, failure *relayError) {
	connection.fatalOnce.Do(func() {
		connection.phase.Store(uint32(phaseClosed))
		// Detach in parallel because a peer can be failed while another home
		// transition holds the home lock. Routing stops immediately via phase.
		go connection.detach()
		frame := fatalFrame(sourceOpcode, failure)
		bytes, err := protocol.EncodeFrame(frame)
		if err != nil {
			connection.stop(closeInternal, "internal_failure")
			return
		}
		message := outboundMessage{
			bytes:       bytes,
			closeStatus: websocket.StatusCode(failure.closeCode),
			closeReason: closeReason(failure.closeCode),
		}
		if connection.enqueueBytes(message, true) == nil {
			return
		}
		queued := false
		connection.queueMu.Lock()
		if !connection.queueClosed {
			releasedBytes := connection.queuedBytes
			for index := range connection.queue {
				connection.queue[index] = outboundMessage{}
			}
			connection.queue = nil
			connection.queuedBytes = 0
			connection.server.admission.releaseQueuedBytes(releasedBytes)
			if connection.server.admission.reserveQueuedBytes(len(message.bytes)) {
				connection.queue = []outboundMessage{message}
				connection.queuedBytes = len(message.bytes)
				connection.closeQueued = true
				queued = true
			} else {
				connection.queueClosed = true
			}
		}
		connection.queueMu.Unlock()
		if !queued {
			connection.stop(closeInternal, "aggregate_queue_exhausted")
			return
		}
		select {
		case connection.queueWake <- struct{}{}:
		default:
		}
	})
}

func (connection *connection) stop(status int, reason string) {
	connection.closeOnce.Do(func() {
		connection.phase.Store(uint32(phaseClosed))
		connection.stopLease()
		connection.cancel()
		connection.queueMu.Lock()
		releasedBytes := connection.queuedBytes
		for index := range connection.queue {
			connection.queue[index] = outboundMessage{}
		}
		connection.queue = nil
		connection.queuedBytes = 0
		connection.queueClosed = true
		connection.server.admission.releaseQueuedBytes(releasedBytes)
		connection.queueMu.Unlock()
		select {
		case connection.queueWake <- struct{}{}:
		default:
		}
		go func() {
			_ = connection.socket.Close(websocket.StatusCode(status), reason)
		}()
	})
}

func (connection *connection) activateInitialLease() bool {
	connection.leaseMu.Lock()
	defer connection.leaseMu.Unlock()
	expiresAt := connection.identity.ExpiresAt
	if !expiresAt.After(time.Now()) {
		connection.leaseExpired = true
		return false
	}
	connection.installLeaseLocked(expiresAt)
	connection.bootstrapped.Store(true)
	return true
}

func (connection *connection) replaceLease(previousDeadline, expiresAt time.Time) bool {
	connection.leaseMu.Lock()
	defer connection.leaseMu.Unlock()
	now := time.Now()
	if connection.leaseExpired ||
		!connection.leaseDeadline.Equal(previousDeadline) ||
		!connection.leaseDeadline.After(now) ||
		!expiresAt.After(now) {
		return false
	}
	connection.installLeaseLocked(expiresAt)
	return true
}

func (connection *connection) installLeaseLocked(expiresAt time.Time) {
	connection.leaseGeneration++
	generation := connection.leaseGeneration
	connection.leaseExpired = false
	connection.leaseDeadline = expiresAt
	if connection.leaseTimer != nil {
		connection.leaseTimer.Stop()
	}
	delay := time.Until(expiresAt)
	connection.leaseTimer = time.AfterFunc(delay, func() {
		connection.expireLease(generation)
	})
}

func (connection *connection) expireLease(generation uint64) {
	connection.leaseMu.Lock()
	if generation != connection.leaseGeneration || connection.leaseExpired {
		connection.leaseMu.Unlock()
		return
	}
	connection.leaseExpired = true
	connection.leaseMu.Unlock()
	connection.fail(0, fatalError(codeTokenExpired, true, "access token expired", closeAuth))
}

func (connection *connection) currentLeaseDeadline() (time.Time, bool) {
	connection.leaseMu.Lock()
	defer connection.leaseMu.Unlock()
	return connection.leaseDeadline, connection.leaseExpired
}

func (connection *connection) authLeaseExpired() bool {
	connection.leaseMu.Lock()
	defer connection.leaseMu.Unlock()
	return connection.leaseExpired ||
		(!connection.leaseDeadline.IsZero() && !connection.leaseDeadline.After(time.Now()))
}

func (connection *connection) stopLease() {
	connection.leaseMu.Lock()
	connection.leaseGeneration++
	if connection.leaseTimer != nil {
		connection.leaseTimer.Stop()
		connection.leaseTimer = nil
	}
	connection.leaseMu.Unlock()
}

func (connection *connection) detach() {
	connection.detachOnce.Do(func() {
		if connection.home == nil {
			return
		}
		connection.home.detach(connection)
		connection.server.homes.release(connection.home)
	})
}

func (connection *connection) available() bool {
	return connection.bootstrapped.Load() &&
		connectionPhase(connection.phase.Load()) == phaseActive &&
		!connection.authLeaseExpired()
}

func frameCorrelation(frame protocol.Frame) int64 {
	if len(frame.Payload) == 0 {
		return 0
	}
	switch frame.Opcode {
	case protocol.OpcodeReauth,
		protocol.OpcodeStateSync,
		protocol.OpcodeStateSet,
		protocol.OpcodeStateACLSync,
		protocol.OpcodeStateResync,
		protocol.OpcodeEventSync,
		protocol.OpcodeEventACLSync,
		protocol.OpcodeSubscribe,
		protocol.OpcodeUnsubscribe,
		protocol.OpcodeEvent,
		protocol.OpcodeFunctionSync,
		protocol.OpcodeCall,
		protocol.OpcodeCallResult,
		protocol.OpcodeCallError,
		protocol.OpcodeCallCancel,
		protocol.OpcodeCallCredit:
		return integer(frame.Payload[0])
	default:
		return 0
	}
}

func closeReason(code int) string {
	switch code {
	case closeAuth:
		return "authentication_failed"
	case closeAuthorization:
		return "authorization_failed"
	case closeTimeout:
		return "timeout"
	case closeConflict:
		return "conflict"
	case closeLimit:
		return "limit_exceeded"
	case closeUnavailable:
		return "temporarily_unavailable"
	case closeInternal:
		return "internal_failure"
	default:
		return "protocol_error"
	}
}

func normalSocketClosure(err error) bool {
	status := websocket.CloseStatus(err)
	return status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway || errors.Is(err, io.EOF)
}
