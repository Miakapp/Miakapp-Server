package auth

import (
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const firebaseCertificateURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

var firebaseProjectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// PlatformConfig pins every authority used by the production verifier. None of
// these values is a credential; deployments may publish them verbatim.
type PlatformConfig struct {
	Issuer            string
	JWKSURL           string
	RelayAudience     string
	FirebaseProjectID string
}

// LoadPlatformConfig reads the closed production authentication configuration.
func LoadPlatformConfig() (PlatformConfig, error) {
	config := PlatformConfig{
		Issuer:            os.Getenv("MIAKAPP_CONTROL_PLANE_ISSUER"),
		JWKSURL:           os.Getenv("MIAKAPP_CONTROL_PLANE_JWKS_URL"),
		RelayAudience:     os.Getenv("MIAKAPP_RELAY_AUDIENCE"),
		FirebaseProjectID: os.Getenv("MIAKAPP_FIREBASE_PROJECT_ID"),
	}
	if err := config.Validate(); err != nil {
		return PlatformConfig{}, err
	}
	return config, nil
}

// Validate rejects ambiguous or cross-origin verifier configuration before the
// relay starts accepting connections.
func (config PlatformConfig) Validate() error {
	issuer, err := canonicalURL(config.Issuer, "https", true)
	if err != nil || issuer.Path != "" {
		return errors.New("MIAKAPP_CONTROL_PLANE_ISSUER must be a canonical HTTPS origin without a trailing slash")
	}
	jwks, err := canonicalURL(config.JWKSURL, "https", true)
	if err != nil || jwks.Path != "/.well-known/jwks.json" {
		return errors.New("MIAKAPP_CONTROL_PLANE_JWKS_URL must be the canonical HTTPS JWKS endpoint")
	}
	if issuer.Scheme != jwks.Scheme || issuer.Host != jwks.Host {
		return errors.New("MIAKAPP_CONTROL_PLANE_JWKS_URL must use the control-plane issuer origin")
	}
	relay, err := canonicalURL(config.RelayAudience, "wss", true)
	if err != nil || relay.Path != "/ws" {
		return errors.New("MIAKAPP_RELAY_AUDIENCE must be a canonical WSS URL ending exactly in /ws")
	}
	if !firebaseProjectIDPattern.MatchString(config.FirebaseProjectID) {
		return errors.New("MIAKAPP_FIREBASE_PROJECT_ID is invalid")
	}
	return nil
}

func canonicalURL(raw, scheme string, allowPort bool) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > 2_048 {
		return nil, errors.New("URL is empty, padded, or overlong")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errors.New("URL is invalid")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return nil, errors.New("URL contains forbidden components")
	}
	if !allowPort && parsed.Port() != "" {
		return nil, errors.New("URL contains a forbidden port")
	}
	if parsed.String() != raw {
		return nil, errors.New("URL is not canonical")
	}
	return parsed, nil
}
