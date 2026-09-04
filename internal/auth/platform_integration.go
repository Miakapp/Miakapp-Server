//go:build integration

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"
)

// NewPlatformVerifierForIntegration keeps the production verification and
// caching path intact while trusting one ephemeral local test certificate.
// This constructor is absent from normal relay builds.
func NewPlatformVerifierForIntegration(
	config PlatformConfig,
	certificatePEM []byte,
	now func() time.Time,
) (*PlatformVerifier, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		return nil, errors.New("integration certificate is invalid")
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return newPlatformVerifier(config, platformDependencies{
		client:                  client,
		now:                     now,
		firebaseCertificatesURL: config.Issuer + "/firebase-certificates",
	})
}
