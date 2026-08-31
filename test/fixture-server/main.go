package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/Miakapp/Miakapp-Server/internal/relay"
)

type verifier struct{}

func (verifier) Verify(_ context.Context, request auth.Request) (auth.Identity, error) {
	expiresAt := time.Now().Add(10 * time.Minute)
	switch request.Token {
	case "integration-coordinator-token":
		return auth.Identity{
			Role:            auth.RoleCoordinator,
			HomeID:          "integration-home",
			ID:              "integration-home",
			CoordinatorName: "integration",
			ExpiresAt:       expiresAt,
		}, nil
	case "integration-user-token", "integration-user-token-new":
		return auth.Identity{
			Role:          auth.RoleUser,
			HomeID:        "integration-home",
			ID:            "integration-user",
			VerifiedEmail: "integration@example.test",
			ExpiresAt:     expiresAt,
		}, nil
	default:
		return auth.Identity{}, auth.Failure(auth.ErrRejected, nil)
	}
}

func main() {
	cfg := config.Config{
		ListenAddress:   ":0",
		AllowedOrigins:  map[string]struct{}{},
		Handshake:       2 * time.Second,
		WriteTimeout:    2 * time.Second,
		PingInterval:    time.Minute,
		PongTimeout:     2 * time.Second,
		DeclarationTTL:  2 * time.Second,
		DisconnectGrace: 100 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
		MaxQueuedBytes:  1_048_576,
	}
	engine, err := relay.New(cfg, verifier{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		panic(err)
	}
	server := httptest.NewUnstartedServer(engine)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	defer engine.Close()

	certificate := server.Certificate()
	certificateFile, err := os.CreateTemp("", "miakapp-relay-ca-*.pem")
	if err != nil {
		panic(err)
	}
	certificatePath := certificateFile.Name()
	defer os.Remove(certificatePath)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if _, err = certificateFile.Write(encoded); err != nil {
		panic(err)
	}
	if err = certificateFile.Close(); err != nil {
		panic(err)
	}

	metadata := map[string]string{
		"relayUrl": strings.Replace(server.URL, "https://", "wss://", 1) + "/ws",
		"caFile":   certificatePath,
	}
	if err = json.NewEncoder(os.Stdout).Encode(metadata); err != nil {
		panic(err)
	}

	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-shutdown.Done()
}
