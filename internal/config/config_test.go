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

func TestValidateRejectsUnsafeEmbeddedConfiguration(t *testing.T) {
	configuration := Config{
		ListenAddress:   ":3000",
		AllowedOrigins:  map[string]struct{}{},
		Handshake:       time.Second,
		WriteTimeout:    time.Second,
		PingInterval:    time.Second,
		PongTimeout:     time.Second,
		DeclarationTTL:  time.Second,
		DisconnectGrace: time.Second,
		ShutdownTimeout: time.Second,
		MaxQueuedBytes:  protocol.MaxFrameBytes,
	}
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	configuration.PingInterval = 0
	if err := configuration.Validate(); err == nil {
		t.Fatal("expected zero ping interval to be rejected")
	}
}
