package relay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/coder/websocket"
	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

const websocketSubprotocol = "miakapp"

// Server owns all in-memory relay state for one process epoch.
type Server struct {
	config      config.Config
	verifier    auth.Verifier
	logger      *slog.Logger
	homes       *homeRegistry
	admission   *admissionController
	context     context.Context
	cancel      context.CancelFunc
	lifecycleMu sync.Mutex
	closed      bool
	draining    bool
	live        map[*connection]struct{}

	drainRetryAfterMs int64
	drainReasonCode   int64
	connections       sync.WaitGroup
	nextSession       atomic.Int64
}

// New creates an isolated relay process state.
func New(cfg config.Config, verifier auth.Verifier, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid relay configuration: %w", err)
	}
	if verifier == nil {
		return nil, errors.New("authentication verifier is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cfg.AllowedOrigins = cloneMap(cfg.AllowedOrigins)
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		config:   cfg,
		verifier: verifier,
		logger:   logger,
		context:  ctx,
		cancel:   cancel,
	}
	server.admission = newAdmissionController(cfg)
	server.live = make(map[*connection]struct{})
	server.homes = newHomeRegistry(server)
	server.nextSession.Store(randomSessionSeed())
	return server, nil
}

// Drain starts a graceful shutdown window, per RFC 0001 §6 and §12.
//
// Every authenticated connection receives GOAWAY and moves to DRAINING, where
// the session layer already refuses new requests and accepts only the terminal
// call frames that let an in-flight call finish. A connection that is still
// open when the window closes is closed as a service restart, so a drain
// always terminates even if a peer ignores GOAWAY.
//
// Draining is one-way: a drained relay never returns to serving new requests.
// Connections that authenticate after the window opens are drained on arrival,
// so no peer can slip past the announcement.
func (server *Server) Drain(retryAfterMs int64, reasonCode int64, window time.Duration) {
	server.lifecycleMu.Lock()
	if server.closed || server.draining {
		server.lifecycleMu.Unlock()
		return
	}
	server.draining = true
	server.drainRetryAfterMs = retryAfterMs
	server.drainReasonCode = reasonCode
	pending := make([]*connection, 0, len(server.live))
	for connection := range server.live {
		pending = append(pending, connection)
	}
	server.lifecycleMu.Unlock()

	for _, connection := range pending {
		connection.startDraining(retryAfterMs, reasonCode)
	}

	go func() {
		select {
		case <-time.After(window):
		case <-server.context.Done():
			return
		}
		server.lifecycleMu.Lock()
		remaining := make([]*connection, 0, len(server.live))
		for connection := range server.live {
			remaining = append(remaining, connection)
		}
		server.lifecycleMu.Unlock()
		for _, connection := range remaining {
			connection.stop(int(websocket.StatusServiceRestart), "draining")
		}
	}()
}

// drainState reports whether a connection that has just authenticated must be
// told to drain immediately rather than being served.
func (server *Server) drainState() (bool, int64, int64) {
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	return server.draining, server.drainRetryAfterMs, server.drainReasonCode
}

func (server *Server) trackConnection(connection *connection) bool {
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	if server.closed {
		return false
	}
	server.live[connection] = struct{}{}
	server.connections.Add(1)
	return true
}

func (server *Server) forgetConnection(connection *connection) {
	server.lifecycleMu.Lock()
	delete(server.live, connection)
	server.lifecycleMu.Unlock()
	server.connections.Done()
}

// Close starts relay shutdown and waits for owned connection goroutines.
func (server *Server) Close() {
	server.lifecycleMu.Lock()
	if !server.closed {
		server.closed = true
		server.cancel()
		server.homes.close()
	}
	server.lifecycleMu.Unlock()
	server.connections.Wait()
}

// ServeHTTP exposes the health check and protocol endpoint only.
func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/ping":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			response.Header().Set("Allow", "GET, HEAD")
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.Header().Set("Cache-Control", "no-store")
		if request.Method == http.MethodGet {
			_, _ = response.Write([]byte("pong\n"))
		}
	case "/ws":
		server.serveWebSocket(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (server *Server) serveWebSocket(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	admission, err := server.admission.acquireConnection(request.RemoteAddr)
	if err != nil {
		switch {
		case errors.Is(err, errInvalidSourceAddress):
			http.Error(response, "invalid connection source", http.StatusBadRequest)
		case errors.Is(err, errConnectionRate):
			response.Header().Set("Retry-After", "60")
			http.Error(response, "connection rate exceeded", http.StatusTooManyRequests)
		default:
			response.Header().Set("Retry-After", "1")
			http.Error(response, "relay capacity unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	defer admission.release()
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", "GET")
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !server.originAllowed(request.Header.Values("Origin")) {
		http.Error(response, "origin not allowed", http.StatusForbidden)
		return
	}
	if !hasSubprotocol(request.Header.Values("Sec-WebSocket-Protocol"), websocketSubprotocol) {
		http.Error(response, "miakapp WebSocket subprotocol required", http.StatusBadRequest)
		return
	}

	// Origin validation is performed above against the exact configured set.
	// Disable the library's independent host-only policy so it cannot weaken or
	// contradict that single authorization decision.
	socket, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols:       []string{websocketSubprotocol},
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		server.logger.Debug("WebSocket upgrade rejected", "error", err)
		return
	}
	if socket.Subprotocol() != websocketSubprotocol {
		_ = socket.Close(websocket.StatusProtocolError, "subprotocol_required")
		return
	}
	socket.SetReadLimit(protocol.MaxFrameBytes)

	connection := newConnection(server, socket, server.allocateSessionID(), request.RemoteAddr)
	if !server.trackConnection(connection) {
		_ = socket.CloseNow()
		return
	}
	defer server.forgetConnection(connection)
	connection.run(request.Context())
}

func (server *Server) originAllowed(origins []string) bool {
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 || origins[0] == "" || strings.Contains(origins[0], ",") {
		return false
	}
	origin := origins[0]
	_, allowed := server.config.AllowedOrigins[origin]
	return allowed
}

func (server *Server) allocateSessionID() int64 {
	for {
		next := server.nextSession.Add(1)
		if next > 0 && next <= 9_007_199_254_740_991 {
			return next
		}
		server.nextSession.CompareAndSwap(next, 1)
	}
}

func randomSessionSeed() int64 {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 1
	}
	return int64(binary.BigEndian.Uint64(raw[:]) & uint64(math.MaxInt64>>11))
}

func hasSubprotocol(headers []string, expected string) bool {
	for _, header := range headers {
		for _, candidate := range strings.Split(header, ",") {
			if strings.TrimSpace(candidate) == expected {
				return true
			}
		}
	}
	return false
}
