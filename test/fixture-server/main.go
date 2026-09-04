package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	switch request.Token {
	case "integration-coordinator-token":
		return auth.Identity{
			Role:            auth.RoleCoordinator,
			HomeID:          "integration-home",
			ID:              "integration-home",
			ClientID:        "integration-client",
			CoordinatorName: "integration",
			ExpiresAt:       time.Now().Add(10 * time.Minute),
			Scopes:          map[string]struct{}{"relay:coordinator": {}},
		}, nil
	case "integration.user.initial":
		return auth.Identity{
			Role:          auth.RoleUser,
			HomeID:        "integration-home",
			ID:            "integration-user",
			VerifiedEmail: "integration@example.test",
			ExpiresAt:     time.Now().Add(4 * time.Second),
			Scopes:        map[string]struct{}{"relay:user": {}},
		}, nil
	case "integration.user.renewed":
		return auth.Identity{
			Role:          auth.RoleUser,
			HomeID:        "integration-home",
			ID:            "integration-user",
			VerifiedEmail: "integration@example.test",
			ExpiresAt:     time.Now().Add(30 * time.Second),
			Scopes:        map[string]struct{}{"relay:user": {}},
		}, nil
	default:
		return auth.Identity{}, auth.Failure(auth.ErrRejected, nil)
	}
}

func main() {
	browserBundlePath := os.Getenv("MIAKAPP_BROWSER_BUNDLE")
	if browserBundlePath == "" {
		panic("MIAKAPP_BROWSER_BUNDLE is required")
	}
	browserBundle, err := os.ReadFile(browserBundlePath)
	if err != nil {
		panic(err)
	}
	if len(browserBundle) > 2*1024*1024 {
		panic("MIAKAPP_BROWSER_BUNDLE exceeds the fixture limit")
	}

	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	cfg := config.Config{
		ListenAddress:   ":0",
		AllowedOrigins:  map[string]struct{}{origin: {}},
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
	mux := http.NewServeMux()
	mux.Handle("/", engine)
	mux.HandleFunc("/integration", func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/integration" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", fmt.Sprintf(
			"default-src 'none'; script-src 'self'; connect-src wss://%s; base-uri 'none'; frame-ancestors 'none'",
			server.Listener.Addr().String(),
		))
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(response, "<!doctype html><meta charset=\"utf-8\"><script src=\"/browser.js\"></script>")
	})
	mux.HandleFunc("/browser.js", func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/browser.js" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = response.Write(browserBundle)
	})
	server.Config.Handler = mux
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
		"pageUrl":  server.URL + "/integration",
		"caFile":   certificatePath,
	}
	if err = json.NewEncoder(os.Stdout).Encode(metadata); err != nil {
		panic(err)
	}

	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-shutdown.Done()
}
