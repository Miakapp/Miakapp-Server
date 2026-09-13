// Command conformance-subject runs this relay as a subject of the RFC 0001
// relay conformance kit.
//
// The kit drives any implementation of the protocol's server side over a real
// WebSocket and compares observable behaviour, so the subject contract is
// deliberately tiny:
//
//   - start, then print exactly one line "LISTENING <ws url>" on stdout;
//   - serve RFC 0001 at that URL;
//   - accept the fixture credentials below and reject everything else;
//   - apply the configuration profile named by MIAKAPP_CONFORMANCE_PROFILE;
//   - exit cleanly on SIGINT or SIGTERM.
//
// The fixture verifier lives here rather than in the production binary. It is
// a separate main package, so no build of cmd/miakapp-server can contain it.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Miakapp/Miakapp-Server/internal/auth"
	"github.com/Miakapp/Miakapp-Server/internal/config"
	"github.com/Miakapp/Miakapp-Server/internal/relay"
)

// The home every fixture credential belongs to. Scenarios that need a second
// home use the tokens suffixed with -other.
const conformanceHome = "conformance-home"

// Long enough that no scenario expires mid-run, short enough to stay a test
// credential. Scenarios that exercise lease expiry use the -expiring tokens.
const fixtureLease = 10 * time.Minute

const expiringLease = 900 * time.Millisecond

type fixtureIdentity struct {
	role        auth.Role
	home        string
	id          string
	coordinator string
	email       string
	lease       time.Duration
}

// The closed fixture credential set. A conforming subject accepts exactly
// these tokens. Adding one is a change to the kit, not to an implementation.
var fixtures = map[string]fixtureIdentity{
	"conformance.user.a":          {role: auth.RoleUser, home: conformanceHome, id: "user-a", email: "user-a@example.test", lease: fixtureLease},
	"conformance.user.b":          {role: auth.RoleUser, home: conformanceHome, id: "user-b", lease: fixtureLease},
	"conformance.user.a.renewed":  {role: auth.RoleUser, home: conformanceHome, id: "user-a", email: "user-a@example.test", lease: fixtureLease},
	"conformance.user.a.expiring": {role: auth.RoleUser, home: conformanceHome, id: "user-a", email: "user-a@example.test", lease: expiringLease},
	"conformance.user.a.other":    {role: auth.RoleUser, home: "conformance-home-other", id: "user-a", lease: fixtureLease},
	"conformance.user.c":          {role: auth.RoleUser, home: conformanceHome, id: "user-c", lease: fixtureLease},

	"conformance.coordinator.primary":   {role: auth.RoleCoordinator, home: conformanceHome, id: conformanceHome, coordinator: "primary", lease: fixtureLease},
	"conformance.coordinator.secondary": {role: auth.RoleCoordinator, home: conformanceHome, id: conformanceHome, coordinator: "secondary", lease: fixtureLease},

	"conformance.cli": {role: auth.RoleCLI, home: conformanceHome, id: conformanceHome, lease: fixtureLease},
}

type fixtureVerifier struct{}

func (fixtureVerifier) Verify(_ context.Context, request auth.Request) (auth.Identity, error) {
	fixture, ok := fixtures[request.Token]
	if !ok {
		return auth.Identity{}, auth.Failure(auth.ErrRejected, nil)
	}
	var scope string
	switch fixture.role {
	case auth.RoleUser:
		scope = "relay:user"
	case auth.RoleCoordinator:
		scope = "relay:coordinator"
	case auth.RoleCLI:
		scope = "relay:cli"
	default:
		return auth.Identity{}, auth.Failure(auth.ErrRejected, nil)
	}
	// A Home Key client binding belongs to a coordinator or the CLI. A user
	// identity carrying one is rejected, and a coordinator identity carrying a
	// verified email is too, so the fixture set mirrors that split exactly.
	clientID := "conformance-client"
	if fixture.role == auth.RoleUser {
		clientID = ""
	}
	return auth.Identity{
		Role:            fixture.role,
		HomeID:          fixture.home,
		ID:              fixture.id,
		ClientID:        clientID,
		CoordinatorName: fixture.coordinator,
		VerifiedEmail:   fixture.email,
		ExpiresAt:       time.Now().Add(fixture.lease),
		Scopes:          map[string]struct{}{scope: {}},
	}, nil
}

// Configuration profiles a scenario may name. A scenario declares the profile
// it assumes so the corpus never depends on one implementation's config type.
func profile(name string) (config.Config, error) {
	cfg := config.Default()
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.AllowedOrigins = map[string]struct{}{}
	cfg.Handshake = 2 * time.Second
	cfg.WriteTimeout = 2 * time.Second
	cfg.PingInterval = time.Minute
	cfg.PongTimeout = 2 * time.Second
	cfg.DeclarationTTL = 2 * time.Second
	cfg.ShutdownTimeout = 2 * time.Second

	switch name {
	case "", "default":
		cfg.DisconnectGrace = 30 * time.Second
	case "fast-grace":
		// Scenarios that must observe grace expiry within a test run.
		cfg.DisconnectGrace = 250 * time.Millisecond
	default:
		return config.Config{}, fmt.Errorf("unknown conformance profile %q", name)
	}
	return cfg, nil
}

func main() {
	cfg, err := profile(os.Getenv("MIAKAPP_CONFORMANCE_PROFILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if address := os.Getenv("MIAKAPP_CONFORMANCE_LISTEN"); address != "" {
		cfg.ListenAddress = address
	}

	engine, err := relay.New(cfg, fixtureVerifier{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// The runner blocks on this line, so it must be printed before serving and
	// must be the only thing on stdout.
	// RFC 0001 serves the socket at /ws; the relay audience is defined as a WSS
	// URL ending in that path, so the kit addresses it the same way.
	fmt.Printf("LISTENING ws://%s/ws\n", listener.Addr().String())
	_ = os.Stdout.Sync()

	server := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
	}

	stopped := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		shutdown, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdown)
		close(stopped)
	}()

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	<-stopped
}
