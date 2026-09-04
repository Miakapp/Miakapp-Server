//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/Miakapp/Miakapp-Server/internal/relay"
)

type controlMetadata struct {
	Schema     string `json:"schema"`
	ControlURL string `json:"controlUrl"`
	JWKSURL    string `json:"jwksUrl"`
}

type recordingVerifier struct {
	delegate     auth.Verifier
	evidenceFile string
	mu           sync.Mutex
	successes    int
}

func (verifier *recordingVerifier) Verify(ctx context.Context, request auth.Request) (auth.Identity, error) {
	identity, err := verifier.delegate.Verify(ctx, request)
	if err != nil || request.Role != auth.RoleCoordinator {
		return identity, err
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.successes++
	if err = writeJSON(verifier.evidenceFile, map[string]any{
		"schema":                               "miakapp.relay-integration-evidence/1",
		"successful_coordinator_verifications": verifier.successes,
	}); err != nil {
		return auth.Identity{}, auth.Failure(auth.ErrTemporary, err)
	}
	return identity, nil
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(name + " is required")
	}
	return value
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
	platformVerifier, err := auth.NewPlatformVerifierForIntegration(auth.PlatformConfig{
		Issuer:            control.ControlURL,
		JWKSURL:           control.JWKSURL,
		RelayAudience:     relayURL,
		FirebaseProjectID: "demo-miakapp-v4",
	}, certificatePEM)
	if err != nil {
		panic(err)
	}
	verifier := &recordingVerifier{delegate: platformVerifier, evidenceFile: evidenceFile}
	if err = writeJSON(evidenceFile, map[string]any{
		"schema":                               "miakapp.relay-integration-evidence/1",
		"successful_coordinator_verifications": 0,
	}); err != nil {
		panic(err)
	}

	cfg := config.Config{
		ListenAddress:   listener.Addr().String(),
		AllowedOrigins:  map[string]struct{}{},
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
	server := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	serveFailure := make(chan error, 1)
	go func() {
		serveFailure <- server.ServeTLS(listener, certificateFile, privateKeyFile)
	}()
	if err = writeJSON(relayMetadataFile, map[string]any{
		"schema":   "miakapp.relay-integration-relay/1",
		"relayUrl": relayURL,
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
