package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

const (
	defaultListenAddress   = ":3000"
	defaultHandshake       = 5 * time.Second
	defaultWriteTimeout    = 5 * time.Second
	defaultPingInterval    = 30 * time.Second
	defaultPongTimeout     = 10 * time.Second
	defaultDeclarationTTL  = 30 * time.Second
	defaultDisconnectGrace = 30 * time.Second
	defaultShutdownTimeout = 10 * time.Second
	defaultMaxQueuedBytes  = 1_048_576
)

// Config contains process-level relay configuration. Authentication material is
// deliberately absent: the platform control-plane adapter owns that boundary.
type Config struct {
	ListenAddress   string
	AllowedOrigins  map[string]struct{}
	Handshake       time.Duration
	WriteTimeout    time.Duration
	PingInterval    time.Duration
	PongTimeout     time.Duration
	DeclarationTTL  time.Duration
	DisconnectGrace time.Duration
	ShutdownTimeout time.Duration
	MaxQueuedBytes  int
}

// Load reads and validates configuration from the environment.
func Load() (Config, error) {
	config := Config{
		ListenAddress:   environment("MIAKAPP_LISTEN_ADDRESS", defaultListenAddress),
		Handshake:       defaultHandshake,
		WriteTimeout:    defaultWriteTimeout,
		PingInterval:    defaultPingInterval,
		PongTimeout:     defaultPongTimeout,
		DeclarationTTL:  defaultDeclarationTTL,
		DisconnectGrace: defaultDisconnectGrace,
		ShutdownTimeout: defaultShutdownTimeout,
		MaxQueuedBytes:  defaultMaxQueuedBytes,
	}

	var err error
	config.AllowedOrigins, err = parseOrigins(os.Getenv("MIAKAPP_ALLOWED_ORIGINS"))
	if err != nil {
		return Config{}, err
	}
	if config.Handshake, err = duration("MIAKAPP_HANDSHAKE_TIMEOUT", config.Handshake); err != nil {
		return Config{}, err
	}
	if config.WriteTimeout, err = duration("MIAKAPP_WRITE_TIMEOUT", config.WriteTimeout); err != nil {
		return Config{}, err
	}
	if config.PingInterval, err = duration("MIAKAPP_PING_INTERVAL", config.PingInterval); err != nil {
		return Config{}, err
	}
	if config.PongTimeout, err = duration("MIAKAPP_PONG_TIMEOUT", config.PongTimeout); err != nil {
		return Config{}, err
	}
	if config.DeclarationTTL, err = duration("MIAKAPP_DECLARATION_TIMEOUT", config.DeclarationTTL); err != nil {
		return Config{}, err
	}
	if config.DisconnectGrace, err = duration("MIAKAPP_DISCONNECT_GRACE", config.DisconnectGrace); err != nil {
		return Config{}, err
	}
	if config.ShutdownTimeout, err = duration("MIAKAPP_SHUTDOWN_TIMEOUT", config.ShutdownTimeout); err != nil {
		return Config{}, err
	}
	if config.MaxQueuedBytes, err = integer(
		"MIAKAPP_MAX_QUEUED_BYTES",
		config.MaxQueuedBytes,
		protocol.MaxFrameBytes,
		defaultMaxQueuedBytes,
	); err != nil {
		return Config{}, err
	}

	if err = config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Validate checks Config values supplied directly by tests or an embedded
// relay, rather than through Load.
func (config Config) Validate() error {
	if strings.TrimSpace(config.ListenAddress) == "" {
		return errors.New("MIAKAPP_LISTEN_ADDRESS must not be empty")
	}
	durations := []struct {
		name  string
		value time.Duration
	}{
		{name: "handshake timeout", value: config.Handshake},
		{name: "write timeout", value: config.WriteTimeout},
		{name: "ping interval", value: config.PingInterval},
		{name: "pong timeout", value: config.PongTimeout},
		{name: "declaration timeout", value: config.DeclarationTTL},
		{name: "disconnect grace", value: config.DisconnectGrace},
		{name: "shutdown timeout", value: config.ShutdownTimeout},
	}
	for _, duration := range durations {
		if duration.value <= 0 {
			return fmt.Errorf("%s must be positive", duration.name)
		}
	}
	if config.MaxQueuedBytes < protocol.MaxFrameBytes || config.MaxQueuedBytes > defaultMaxQueuedBytes {
		return fmt.Errorf(
			"outbound queue limit must be between %d and %d bytes",
			protocol.MaxFrameBytes,
			defaultMaxQueuedBytes,
		)
	}
	for origin := range config.AllowedOrigins {
		parsed, err := parseOrigins(origin)
		if err != nil || len(parsed) != 1 {
			return fmt.Errorf("allowed origin %q is invalid", origin)
		}
	}
	return nil
}

func environment(name, fallback string) string {
	if value, found := os.LookupEnv(name); found {
		return value
	}
	return fallback
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	raw, found := os.LookupEnv(name)
	if !found {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return value, nil
}

func integer(name string, fallback, minimum, maximum int) (int, error) {
	raw, found := os.LookupEnv(name)
	if !found {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func parseOrigins(raw string) (map[string]struct{}, error) {
	origins := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, fmt.Errorf("MIAKAPP_ALLOWED_ORIGINS contains invalid origin %q", candidate)
		}
		if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("MIAKAPP_ALLOWED_ORIGINS contains non-origin URL %q", candidate)
		}
		if parsed.String() != candidate {
			return nil, fmt.Errorf("MIAKAPP_ALLOWED_ORIGINS must contain canonical exact origins: %q", candidate)
		}
		origins[candidate] = struct{}{}
	}
	return origins, nil
}
