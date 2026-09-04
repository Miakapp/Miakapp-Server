package auth

import "testing"

func validPlatformConfig() PlatformConfig {
	return PlatformConfig{
		Issuer:        "https://control.example.test",
		JWKSURL:       "https://control.example.test/.well-known/jwks.json",
		RelayAudience: "wss://relay.example.test/ws",
	}
}

func TestPlatformConfigPinsCanonicalAuthorities(t *testing.T) {
	if err := validPlatformConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	prefixedRelay := validPlatformConfig()
	prefixedRelay.RelayAudience = "wss://relay.example.test/miakapp/ws"
	if err := prefixedRelay.Validate(); err != nil {
		t.Fatalf("expected a canonical relay path ending in /ws to be accepted: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*PlatformConfig)
	}{
		{name: "issuer path", mutate: func(config *PlatformConfig) { config.Issuer += "/path" }},
		{name: "issuer trailing slash", mutate: func(config *PlatformConfig) { config.Issuer += "/" }},
		{name: "insecure issuer", mutate: func(config *PlatformConfig) { config.Issuer = "http://control.example.test" }},
		{name: "foreign JWKS", mutate: func(config *PlatformConfig) { config.JWKSURL = "https://keys.example.test/.well-known/jwks.json" }},
		{name: "JWKS query", mutate: func(config *PlatformConfig) { config.JWKSURL += "?key=value" }},
		{name: "relay query", mutate: func(config *PlatformConfig) { config.RelayAudience += "?key=value" }},
		{name: "relay path", mutate: func(config *PlatformConfig) { config.RelayAudience = "wss://relay.example.test/socket" }},
		{name: "insecure relay", mutate: func(config *PlatformConfig) { config.RelayAudience = "ws://relay.example.test/ws" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validPlatformConfig()
			test.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("expected invalid platform configuration to be rejected")
			}
		})
	}
}

func TestLoadPlatformConfigRequiresEveryPublicAuthority(t *testing.T) {
	config := validPlatformConfig()
	t.Setenv("MIAKAPP_CONTROL_PLANE_ISSUER", config.Issuer)
	t.Setenv("MIAKAPP_CONTROL_PLANE_JWKS_URL", config.JWKSURL)
	t.Setenv("MIAKAPP_RELAY_AUDIENCE", config.RelayAudience)
	t.Setenv("MIAKAPP_FIREBASE_PROJECT_ID", "ignored-obsolete-setting")
	loaded, err := LoadPlatformConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded != config {
		t.Fatalf("unexpected authentication configuration: %#v", loaded)
	}
	t.Setenv("MIAKAPP_RELAY_AUDIENCE", "")
	if _, err = LoadPlatformConfig(); err == nil {
		t.Fatal("expected an incomplete authentication configuration to be rejected")
	}
}
