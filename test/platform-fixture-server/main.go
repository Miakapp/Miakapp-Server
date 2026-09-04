//go:build integration

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/Miakapp/Miakapp-Server/internal/relay"
)

const maximumControlBodyBytes = 10 * 1024

type controlMetadata struct {
	Schema     string `json:"schema"`
	ControlURL string `json:"controlUrl"`
	JWKSURL    string `json:"jwksUrl"`
}

type relayMetadata struct {
	Schema   string `json:"schema"`
	RelayURL string `json:"relayUrl"`
}

type probeEvidence struct {
	Requests        int `json:"requests"`
	InFlight        int `json:"in_flight"`
	MaximumInFlight int `json:"maximum_in_flight"`
	Succeeded       int `json:"succeeded"`
	Rejected        int `json:"rejected"`
	Temporary       int `json:"temporary"`
}

type integrationEvidence struct {
	Schema                             string        `json:"schema"`
	SuccessfulCoordinatorVerifications int           `json:"successful_coordinator_verifications"`
	SuccessfulUserVerifications        int           `json:"successful_user_verifications"`
	CoordinatorPrincipalConsistent     bool          `json:"coordinator_principal_consistent"`
	UserPrincipalConsistent            bool          `json:"user_principal_consistent"`
	UnexpectedRoles                    int           `json:"unexpected_roles"`
	RelayWarmupSuccesses               int           `json:"relay_warmup_successes"`
	ProbeClockOffsetMilliseconds       int64         `json:"probe_clock_offset_milliseconds"`
	Probe                              probeEvidence `json:"probe"`
}

type principalBinding struct {
	homeID          string
	principalID     string
	clientID        string
	coordinatorName string
	verifiedEmail   string
	role            auth.Role
}

type integrationState struct {
	evidenceFile string

	mu                             sync.Mutex
	coordinatorSuccesses           int
	userSuccesses                  int
	coordinatorPrincipalConsistent bool
	userPrincipalConsistent        bool
	unexpectedRoles                int
	firstCoordinatorPrincipal      *principalBinding
	firstUserPrincipal             *principalBinding
	relayWarmups                   int
	probeBase                      time.Time
	probeFrozen                    bool
	probeOffset                    time.Duration
	probe                          probeEvidence
}

func newIntegrationState(evidenceFile string) *integrationState {
	return &integrationState{
		evidenceFile:                   evidenceFile,
		coordinatorPrincipalConsistent: true,
		userPrincipalConsistent:        true,
	}
}

func (state *integrationState) evidenceLocked() integrationEvidence {
	return integrationEvidence{
		Schema:                             "miakapp.relay-integration-evidence/3",
		SuccessfulCoordinatorVerifications: state.coordinatorSuccesses,
		SuccessfulUserVerifications:        state.userSuccesses,
		CoordinatorPrincipalConsistent:     state.coordinatorPrincipalConsistent,
		UserPrincipalConsistent:            state.userPrincipalConsistent,
		UnexpectedRoles:                    state.unexpectedRoles,
		RelayWarmupSuccesses:               state.relayWarmups,
		ProbeClockOffsetMilliseconds:       state.probeOffset.Milliseconds(),
		Probe:                              state.probe,
	}
}

func (state *integrationState) persistLocked() error {
	return writeJSON(state.evidenceFile, state.evidenceLocked())
}

func (state *integrationState) initialize() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.persistLocked()
}

func (state *integrationState) snapshot() integrationEvidence {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.evidenceLocked()
}

func (state *integrationState) recordRelay(identity auth.Identity) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	principal := principalBinding{
		homeID:          identity.HomeID,
		principalID:     identity.ID,
		clientID:        identity.ClientID,
		coordinatorName: identity.CoordinatorName,
		verifiedEmail:   identity.VerifiedEmail,
		role:            identity.Role,
	}
	switch identity.Role {
	case auth.RoleCoordinator:
		if state.firstCoordinatorPrincipal == nil {
			state.firstCoordinatorPrincipal = &principal
		} else if *state.firstCoordinatorPrincipal != principal {
			state.coordinatorPrincipalConsistent = false
		}
		state.coordinatorSuccesses++
	case auth.RoleUser:
		if state.firstUserPrincipal == nil {
			state.firstUserPrincipal = &principal
		} else if *state.firstUserPrincipal != principal {
			state.userPrincipalConsistent = false
		}
		state.userSuccesses++
	default:
		state.unexpectedRoles++
		if err := state.persistLocked(); err != nil {
			return err
		}
		return errors.New("relay verifier returned an unexpected integration role")
	}
	return state.persistLocked()
}

func (state *integrationState) recordRelayWarmup() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.relayWarmups++
	return state.persistLocked()
}

func (state *integrationState) startProbe() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.probe.Requests++
	state.probe.InFlight++
	if state.probe.InFlight > state.probe.MaximumInFlight {
		state.probe.MaximumInFlight = state.probe.InFlight
	}
	return state.persistLocked()
}

func (state *integrationState) finishProbe(kind auth.ErrorKind, succeeded bool) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.probe.InFlight--
	if succeeded {
		state.probe.Succeeded++
	} else if kind == auth.ErrTemporary {
		state.probe.Temporary++
	} else {
		state.probe.Rejected++
	}
	return state.persistLocked()
}

func (state *integrationState) setProbeOffset(milliseconds int64) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if milliseconds < 0 || milliseconds > 240_000 {
		return errors.New("probe clock offset is invalid")
	}
	offset := time.Duration(milliseconds) * time.Millisecond
	if offset < state.probeOffset {
		return errors.New("probe clock offset is invalid")
	}
	if !state.probeFrozen {
		state.probeBase = time.Now()
		state.probeFrozen = true
	}
	state.probeOffset = offset
	return state.persistLocked()
}

func (state *integrationState) probeNow() time.Time {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.probeFrozen {
		return time.Now()
	}
	return state.probeBase.Add(state.probeOffset)
}

type recordingVerifier struct {
	delegate auth.Verifier
	state    *integrationState
}

func (verifier *recordingVerifier) Verify(ctx context.Context, request auth.Request) (auth.Identity, error) {
	identity, err := verifier.delegate.Verify(ctx, request)
	if err != nil || (request.Role != auth.RoleCoordinator && request.Role != auth.RoleUser) {
		return identity, err
	}
	if err = verifier.state.recordRelay(identity); err != nil {
		return auth.Identity{}, auth.Failure(auth.ErrTemporary, err)
	}
	return identity, nil
}

type fixtureHandler struct {
	secret        []byte
	state         *integrationState
	relayVerifier auth.Verifier
	probeVerifier auth.Verifier
}

type verifyRequest struct {
	Target string `json:"target"`
	Token  string `json:"token"`
}

type fixtureControlRequest struct {
	Action             string `json:"action"`
	OffsetMilliseconds *int64 `json:"offset_ms,omitempty"`
}

func (fixture *fixtureHandler) authorize(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	prefix := "Bearer "
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	actual := []byte(strings.TrimPrefix(header, prefix))
	return len(actual) == len(fixture.secret) &&
		subtle.ConstantTimeCompare(actual, fixture.secret) == 1
}

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("control content type is invalid")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumControlBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("control body has trailing data")
	}
	return nil
}

func privateResponse(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func (fixture *fixtureHandler) control(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !fixture.authorize(request) {
		privateResponse(response, http.StatusUnauthorized, map[string]string{"error": "invalid_control"})
		return
	}
	var input fixtureControlRequest
	if err := decodeJSON(response, request, &input); err != nil {
		privateResponse(response, http.StatusBadRequest, map[string]string{"error": "invalid_control"})
		return
	}
	switch input.Action {
	case "status":
		if input.OffsetMilliseconds != nil {
			privateResponse(response, http.StatusBadRequest, map[string]string{"error": "invalid_control"})
			return
		}
	case "set_clock":
		if input.OffsetMilliseconds == nil ||
			fixture.state.setProbeOffset(*input.OffsetMilliseconds) != nil {
			privateResponse(response, http.StatusConflict, map[string]string{"error": "invalid_control"})
			return
		}
	default:
		privateResponse(response, http.StatusBadRequest, map[string]string{"error": "invalid_control"})
		return
	}
	privateResponse(response, http.StatusOK, fixture.state.snapshot())
}

func validToken(token string) bool {
	if len(token) == 0 || len(token) > 8_192 {
		return false
	}
	for index := range len(token) {
		if token[index] < 0x21 || token[index] > 0x7e {
			return false
		}
	}
	return true
}

func (fixture *fixtureHandler) verify(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !fixture.authorize(request) {
		privateResponse(response, http.StatusUnauthorized, map[string]string{"error": "invalid_control"})
		return
	}
	var input verifyRequest
	if err := decodeJSON(response, request, &input); err != nil ||
		(input.Target != "relay" && input.Target != "probe") ||
		!validToken(input.Token) {
		privateResponse(response, http.StatusBadRequest, map[string]string{"error": "invalid_control"})
		return
	}

	verifier := fixture.relayVerifier
	now := time.Now
	if input.Target == "probe" {
		verifier = fixture.probeVerifier
		now = fixture.state.probeNow
		if err := fixture.state.startProbe(); err != nil {
			privateResponse(response, http.StatusServiceUnavailable, map[string]string{"error": "evidence_failure"})
			return
		}
	}
	verificationRequest := auth.Request{
		Role:            auth.RoleCoordinator,
		Token:           input.Token,
		CoordinatorName: "integration",
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	identity, err := verifier.Verify(ctx, verificationRequest)
	cancel()
	if err == nil {
		err = auth.ValidateBinding(verificationRequest, identity, now())
	}
	kind := auth.Kind(err)
	if input.Target == "probe" {
		if evidenceErr := fixture.state.finishProbe(kind, err == nil); evidenceErr != nil {
			privateResponse(response, http.StatusServiceUnavailable, map[string]string{"error": "evidence_failure"})
			return
		}
	} else if err == nil {
		if evidenceErr := fixture.state.recordRelayWarmup(); evidenceErr != nil {
			privateResponse(response, http.StatusServiceUnavailable, map[string]string{"error": "evidence_failure"})
			return
		}
	}
	if err == nil {
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if kind == auth.ErrTemporary {
		privateResponse(response, http.StatusServiceUnavailable, map[string]string{"error": "temporary"})
		return
	}
	privateResponse(response, http.StatusUnauthorized, map[string]string{"error": "rejected"})
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(name + " is required")
	}
	return value
}

func readSecret(path string) []byte {
	bytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	value := strings.TrimSpace(string(bytes))
	if len(value) != 64 {
		panic("integration control secret is invalid")
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			panic("integration control secret is invalid")
		}
	}
	return []byte(value)
}

func writeJSON(path string, value any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".miakapp-integration-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(bytes)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	return err
}

func main() {
	controlMetadataFile := requiredEnvironment("MIAKAPP_CONTROL_METADATA_FILE")
	relayMetadataFile := requiredEnvironment("MIAKAPP_RELAY_METADATA_FILE")
	evidenceFile := requiredEnvironment("MIAKAPP_RELAY_EVIDENCE_FILE")
	certificateFile := requiredEnvironment("MIAKAPP_INTEGRATION_CERT_FILE")
	privateKeyFile := requiredEnvironment("MIAKAPP_INTEGRATION_KEY_FILE")
	controlSecret := readSecret(requiredEnvironment("MIAKAPP_RELAY_CONTROL_SECRET_FILE"))

	controlBytes, err := os.ReadFile(controlMetadataFile)
	if err != nil {
		panic(err)
	}
	var control controlMetadata
	if err = json.Unmarshal(controlBytes, &control); err != nil ||
		control.Schema != "miakapp.relay-integration-control/1" ||
		control.ControlURL == "" || control.JWKSURL == "" {
		panic("control-plane integration metadata is invalid")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	relayURL := "wss://" + listener.Addr().String() + "/ws"
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		panic(err)
	}
	platformConfig := auth.PlatformConfig{
		Issuer:        control.ControlURL,
		JWKSURL:       control.JWKSURL,
		RelayAudience: relayURL,
	}
	relayPlatformVerifier, err := auth.NewPlatformVerifierForIntegration(
		platformConfig,
		certificatePEM,
		time.Now,
	)
	if err != nil {
		panic(err)
	}
	state := newIntegrationState(evidenceFile)
	probePlatformVerifier, err := auth.NewPlatformVerifierForIntegration(
		platformConfig,
		certificatePEM,
		state.probeNow,
	)
	if err != nil {
		panic(err)
	}
	if err = state.initialize(); err != nil {
		panic(err)
	}
	verifier := &recordingVerifier{delegate: relayPlatformVerifier, state: state}

	cfg := config.Config{
		ListenAddress:   listener.Addr().String(),
		AllowedOrigins:  map[string]struct{}{control.ControlURL: {}},
		Handshake:       5 * time.Second,
		WriteTimeout:    5 * time.Second,
		PingInterval:    time.Minute,
		PongTimeout:     5 * time.Second,
		DeclarationTTL:  5 * time.Second,
		DisconnectGrace: 100 * time.Millisecond,
		ShutdownTimeout: 5 * time.Second,
		MaxQueuedBytes:  1_048_576,
	}
	engine, err := relay.New(cfg, verifier, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		panic(err)
	}
	fixture := &fixtureHandler{
		secret:        controlSecret,
		state:         state,
		relayVerifier: relayPlatformVerifier,
		probeVerifier: probePlatformVerifier,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/__integration/control", fixture.control)
	mux.HandleFunc("/__integration/verify", fixture.verify)
	mux.Handle("/ws", engine)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	serveFailure := make(chan error, 1)
	go func() {
		serveFailure <- server.ServeTLS(listener, certificateFile, privateKeyFile)
	}()
	if err = writeJSON(relayMetadataFile, relayMetadata{
		Schema:   "miakapp.relay-integration-relay/1",
		RelayURL: relayURL,
	}); err != nil {
		panic(err)
	}

	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-shutdown.Done():
	case err = <-serveFailure:
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownContext)
	engine.Close()
}
