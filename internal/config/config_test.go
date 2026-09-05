package config

import (
	"testing"
	"time"

	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

func TestParseOriginsRequiresCanonicalExactOrigins(t *testing.T) {
	origins, err := parseOrigins("https://miakapp.com, http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 2 {
		t.Fatalf("expected two exact origins, received %#v", origins)
	}
	invalid := []string{
		"*.miakapp.com",
		"https://miakapp.com/path",
		"https://miakapp.com?query=true",
		"wss://miakapp.com",
		"HTTPS://miakapp.com",
	}
	for _, value := range invalid {
		if _, err = parseOrigins(value); err == nil {
			t.Fatalf("expected invalid origin %q to be rejected", value)
		}
	}
}

func TestEnvironmentParsersAreBounded(t *testing.T) {
	t.Setenv("TEST_DURATION", "250ms")
	value, err := duration("TEST_DURATION", time.Second)
	if err != nil || value != 250*time.Millisecond {
		t.Fatalf("unexpected duration result: %v, %v", value, err)
	}
	t.Setenv("TEST_INTEGER", "42")
	integerValue, err := integer("TEST_INTEGER", 10, 1, 100)
	if err != nil || integerValue != 42 {
		t.Fatalf("unexpected integer result: %v, %v", integerValue, err)
	}
	t.Setenv("TEST_INTEGER", "101")
	if _, err = integer("TEST_INTEGER", 10, 1, 100); err == nil {
		t.Fatal("expected out-of-range integer to be rejected")
	}
}

func TestLoadRejectsQueueThatCannotHoldOneMaximumFrame(t *testing.T) {
	t.Setenv("MIAKAPP_ALLOWED_ORIGINS", "")
	t.Setenv("MIAKAPP_MAX_QUEUED_BYTES", "1")
	_, err := Load()
	if err == nil {
		t.Fatal("expected undersized outbound queue to be rejected")
	}

	t.Setenv("MIAKAPP_MAX_QUEUED_BYTES", "262144")
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MaxQueuedBytes != protocol.MaxFrameBytes {
		t.Fatalf("unexpected queue limit: %d", loaded.MaxQueuedBytes)
	}
}

func TestLoadReadsTheBoundedProcessAdmissionProfile(t *testing.T) {
	t.Setenv("MIAKAPP_ALLOWED_ORIGINS", "")
	t.Setenv("MIAKAPP_MAX_QUEUED_BYTES", "262144")
	t.Setenv("MIAKAPP_MAX_CONNECTIONS", "8")
	t.Setenv("MIAKAPP_MAX_CONNECTIONS_PER_IP", "8")
	t.Setenv("MIAKAPP_CONNECTION_ATTEMPTS_PER_MINUTE", "32")
	t.Setenv("MIAKAPP_MAX_TRACKED_IPS", "64")
	t.Setenv("MIAKAPP_MAX_HOMES", "16")
	t.Setenv("MIAKAPP_MAX_AGGREGATE_QUEUED_BYTES", "4194304")
	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MaxQueuedBytes != 262_144 ||
		configuration.MaxConnections != 8 ||
		configuration.MaxConnectionsPerIP != 8 ||
		configuration.ConnectionAttemptsPerMinute != 32 ||
		configuration.MaxTrackedIPs != 64 ||
		configuration.MaxHomes != 16 ||
		configuration.MaxAggregateQueuedBytes != 4_194_304 {
		t.Fatalf("unexpected process admission profile: %#v", configuration)
	}
}

func TestValidateRejectsUnsafeEmbeddedConfiguration(t *testing.T) {
	configuration := Default()
	configuration.Handshake = time.Second
	configuration.WriteTimeout = time.Second
	configuration.PingInterval = time.Second
	configuration.PongTimeout = time.Second
	configuration.DeclarationTTL = time.Second
	configuration.DisconnectGrace = time.Second
	configuration.ShutdownTimeout = time.Second
	configuration.MaxQueuedBytes = protocol.MaxFrameBytes
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	configuration.PingInterval = 0
	if err := configuration.Validate(); err == nil {
		t.Fatal("expected zero ping interval to be rejected")
	}
}

func TestValidateRejectsIncoherentProcessAdmissionLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "per-IP connections exceed total",
			mutate: func(configuration *Config) {
				configuration.MaxConnectionsPerIP = configuration.MaxConnections + 1
			},
		},
		{
			name: "attempt rate below active connections",
			mutate: func(configuration *Config) {
				configuration.ConnectionAttemptsPerMinute = configuration.MaxConnectionsPerIP - 1
			},
		},
		{
			name: "aggregate queue below one connection",
			mutate: func(configuration *Config) {
				configuration.MaxAggregateQueuedBytes = configuration.MaxQueuedBytes - 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := Default()
			test.mutate(&configuration)
			if err := configuration.Validate(); err == nil {
				t.Fatal("expected invalid admission configuration to be rejected")
			}
		})
	}
}
