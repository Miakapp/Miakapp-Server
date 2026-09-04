package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	controlplane "github.com/miakapp/miakapp-v3/control-plane-contract/go"
)

const (
	maximumKeyDocumentBytes = 65_536
	maximumPublicKeys       = 16
	unknownKIDRefreshDelay  = 10 * time.Second
	failedFetchRetryDelay   = time.Second
	maximumFirebaseCacheTTL = 24 * time.Hour
)

type keyDocumentKind uint8

const (
	controlPlaneJWKS keyDocumentKind = iota
	firebaseCertificates
)

type keyFetchResult struct {
	keys        []controlplane.PublicJWK
	etag        string
	ttl         time.Duration
	notModified bool
}

type keySource struct {
	url    string
	kind   keyDocumentKind
	client *http.Client
}

type keyCache struct {
	source keySource
	now    func() time.Time

	mu                 sync.Mutex
	keys               []controlplane.PublicJWK
	etag               string
	expiresAt          time.Time
	refreshing         bool
	refreshDone        chan struct{}
	nextFetch          time.Time
	nextUnknownRefresh time.Time
	lastFailure        error
}

func newKeyCache(source keySource, now func() time.Time) *keyCache {
	return &keyCache{source: source, now: now}
}

func (cache *keyCache) current(ctx context.Context) ([]controlplane.PublicJWK, error) {
	return cache.load(ctx, false)
}

func (cache *keyCache) refreshUnknownKID(ctx context.Context) ([]controlplane.PublicJWK, bool, error) {
	cache.mu.Lock()
	now := cache.now()
	if len(cache.keys) > 0 &&
		now.Before(cache.expiresAt) &&
		!cache.refreshing &&
		now.Before(cache.nextUnknownRefresh) {
		keys := cloneKeys(cache.keys)
		cache.mu.Unlock()
		return keys, false, nil
	}
	cache.mu.Unlock()

	keys, err := cache.load(ctx, true)
	return keys, err == nil, err
}

func (cache *keyCache) load(ctx context.Context, force bool) ([]controlplane.PublicJWK, error) {
	for {
		cache.mu.Lock()
		now := cache.now()
		fresh := len(cache.keys) > 0 && now.Before(cache.expiresAt)
		if !force && fresh {
			keys := cloneKeys(cache.keys)
			cache.mu.Unlock()
			return keys, nil
		}
		if force && cache.refreshing {
			finished := cache.refreshDone
			cache.mu.Unlock()
			select {
			case <-finished:
				force = false
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if force && fresh && now.Before(cache.nextUnknownRefresh) {
			keys := cloneKeys(cache.keys)
			cache.mu.Unlock()
			return keys, nil
		}
		if cache.refreshing {
			finished := cache.refreshDone
			cache.mu.Unlock()
			select {
			case <-finished:
				force = false
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if now.Before(cache.nextFetch) {
			failure := cache.lastFailure
			if fresh && force {
				keys := cloneKeys(cache.keys)
				cache.mu.Unlock()
				return keys, nil
			}
			cache.mu.Unlock()
			if failure == nil {
				failure = errors.New("public-key fetch is rate limited")
			}
			return nil, failure
		}

		cache.refreshing = true
		cache.refreshDone = make(chan struct{})
		cache.nextFetch = now.Add(failedFetchRetryDelay)
		if force {
			cache.nextUnknownRefresh = now.Add(unknownKIDRefreshDelay)
		}
		etag := cache.etag
		cache.mu.Unlock()

		result, err := cache.source.fetch(ctx, etag)

		cache.mu.Lock()
		if err == nil {
			if result.notModified {
				if len(cache.keys) == 0 {
					err = errors.New("public-key endpoint returned 304 without cached keys")
				}
			} else {
				cache.keys = cloneKeys(result.keys)
				cache.etag = result.etag
			}
		}
		if err == nil {
			cache.expiresAt = cache.now().Add(result.ttl)
			cache.lastFailure = nil
			cache.nextFetch = time.Time{}
		} else {
			cache.lastFailure = err
		}
		cache.refreshing = false
		close(cache.refreshDone)
		fresh = len(cache.keys) > 0 && cache.now().Before(cache.expiresAt)
		keys := cloneKeys(cache.keys)
		cache.mu.Unlock()

		if err == nil || (force && fresh) {
			return keys, nil
		}
		return nil, err
	}
}

func cloneKeys(keys []controlplane.PublicJWK) []controlplane.PublicJWK {
	return append([]controlplane.PublicJWK(nil), keys...)
}

func (source keySource) fetch(ctx context.Context, etag string) (keyFetchResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return keyFetchResult{}, err
	}
	request.Header.Set("Accept", "application/json")
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := source.client.Do(request)
	if err != nil {
		return keyFetchResult{}, err
	}
	defer response.Body.Close()

	ttl, err := responseCacheTTL(response.Header, source.kind)
	if err != nil {
		return keyFetchResult{}, err
	}
	if response.StatusCode == http.StatusNotModified {
		if etag == "" {
			return keyFetchResult{}, errors.New("public-key endpoint returned an unsolicited 304")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumKeyDocumentBytes+1))
		if readErr != nil || len(body) != 0 {
			return keyFetchResult{}, errors.New("public-key endpoint returned a non-empty 304 response")
		}
		return keyFetchResult{etag: etag, ttl: ttl, notModified: true}, nil
	}
	if response.StatusCode != http.StatusOK {
		return keyFetchResult{}, fmt.Errorf("public-key endpoint returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return keyFetchResult{}, errors.New("public-key endpoint returned a non-JSON content type")
	}
	body, err := readBoundedBody(response.Body)
	if err != nil {
		return keyFetchResult{}, err
	}
	var keys []controlplane.PublicJWK
	var responseETag string
	if source.kind == controlPlaneJWKS {
		responseETag, err = canonicalETag(response.Header.Get("ETag"))
		if err == nil {
			keys, err = decodeControlPlaneJWKS(body)
		}
	} else {
		keys, err = decodeFirebaseCertificates(body)
		if rawETag := response.Header.Get("ETag"); rawETag != "" {
			responseETag, err = canonicalETag(rawETag)
		}
	}
	if err != nil {
		return keyFetchResult{}, err
	}
	return keyFetchResult{keys: keys, etag: responseETag, ttl: ttl}, nil
}

func readBoundedBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maximumKeyDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > maximumKeyDocumentBytes || !utf8.Valid(body) {
		return nil, errors.New("public-key document is empty, overlong, or invalid UTF-8")
	}
	if err = rejectUnpairedSurrogateEscapes(body); err != nil {
		return nil, err
	}
	return body, nil
}

func responseCacheTTL(header http.Header, kind keyDocumentKind) (time.Duration, error) {
	directives := make(map[string]string)
	for _, raw := range header.Values("Cache-Control") {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, value, found := strings.Cut(part, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				return 0, errors.New("public-key cache control is invalid")
			}
			if _, duplicate := directives[name]; duplicate {
				return 0, errors.New("public-key cache control contains a duplicate directive")
			}
			if found {
				parsedValue, valueErr := cacheDirectiveValue(value)
				if valueErr != nil {
					return 0, valueErr
				}
				value = parsedValue
			}
			directives[name] = value
		}
	}
	maxAgeText, exists := directives["max-age"]
	maxAge, err := strconv.ParseInt(maxAgeText, 10, 64)
	if !exists || err != nil || maxAge < 1 {
		return 0, errors.New("public-key cache control has no positive max-age")
	}
	if kind == controlPlaneJWKS {
		_, hasPublic := directives["public"]
		_, hasMustRevalidate := directives["must-revalidate"]
		if maxAge != 60 || !hasPublic || !hasMustRevalidate || directives["public"] != "" || directives["must-revalidate"] != "" || len(directives) != 3 {
			return 0, errors.New("control-plane JWKS cache control does not match the required policy")
		}
	} else if maxAge > int64(maximumFirebaseCacheTTL/time.Second) {
		return 0, errors.New("Firebase certificate cache lifetime is overlong")
	}
	age := int64(0)
	if ageText := header.Get("Age"); ageText != "" {
		age, err = strconv.ParseInt(ageText, 10, 64)
		if err != nil || age < 0 {
			return 0, errors.New("public-key response Age is invalid")
		}
	}
	remaining := maxAge - age
	if remaining < 1 {
		return 0, errors.New("public-key response is already stale")
	}
	return time.Duration(remaining) * time.Second, nil
}

func cacheDirectiveValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("public-key cache control contains an empty value")
	}
	if value[0] == '"' || value[len(value)-1] == '"' {
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return "", errors.New("public-key cache control contains an invalid quoted value")
		}
		value = value[1 : len(value)-1]
	}
	if value == "" || strings.ContainsAny(value, `"\`) {
		return "", errors.New("public-key cache control contains an invalid value")
	}
	return value, nil
}

func canonicalETag(value string) (string, error) {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
		return "", errors.New("control-plane JWKS response has no bounded ETag")
	}
	entityTag := value
	if strings.HasPrefix(entityTag, "W/") {
		entityTag = entityTag[2:]
	}
	if len(entityTag) < 2 || entityTag[0] != '"' || entityTag[len(entityTag)-1] != '"' {
		return "", errors.New("control-plane JWKS ETag is invalid")
	}
	for _, character := range []byte(entityTag[1 : len(entityTag)-1]) {
		if character < 0x21 || character == '"' || character > 0x7e {
			return "", errors.New("control-plane JWKS ETag is invalid")
		}
	}
	return value, nil
}

func decodeControlPlaneJWKS(body []byte) ([]controlplane.PublicJWK, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("control-plane JWKS is not an object")
	}
	seenKeysMember := false
	var keys []controlplane.PublicJWK
	for decoder.More() {
		member, memberErr := decoder.Token()
		name, ok := member.(string)
		if memberErr != nil || !ok || name != "keys" || seenKeysMember {
			return nil, errors.New("control-plane JWKS object is not closed")
		}
		seenKeysMember = true
		keys, err = decodeControlPlaneKeys(decoder)
		if err != nil {
			return nil, err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seenKeysMember {
		return nil, errors.New("control-plane JWKS object is incomplete")
	}
	if err = requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return keys, nil
}

func decodeControlPlaneKeys(decoder *json.Decoder) ([]controlplane.PublicJWK, error) {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('[') {
		return nil, errors.New("control-plane JWKS keys is not an array")
	}
	keys := make([]controlplane.PublicJWK, 0)
	kids := make(map[string]struct{})
	for decoder.More() {
		if len(keys) >= maximumPublicKeys {
			return nil, errors.New("control-plane JWKS has too many keys")
		}
		key, keyErr := decodeControlPlaneKey(decoder)
		if keyErr != nil {
			return nil, keyErr
		}
		if _, duplicate := kids[key.KID]; duplicate {
			return nil, errors.New("control-plane JWKS has a duplicate key ID")
		}
		kids[key.KID] = struct{}{}
		keys = append(keys, key)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') || len(keys) == 0 {
		return nil, errors.New("control-plane JWKS keys is empty or incomplete")
	}
	return keys, nil
}

func decodeControlPlaneKey(decoder *json.Decoder) (controlplane.PublicJWK, error) {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return controlplane.PublicJWK{}, errors.New("control-plane JWK is not an object")
	}
	values := make(map[string]string)
	allowed := map[string]struct{}{"kty": {}, "kid": {}, "use": {}, "alg": {}, "crv": {}, "x": {}}
	for decoder.More() {
		member, memberErr := decoder.Token()
		name, ok := member.(string)
		if memberErr != nil || !ok {
			return controlplane.PublicJWK{}, errors.New("control-plane JWK member is invalid")
		}
		if _, accepted := allowed[name]; !accepted {
			return controlplane.PublicJWK{}, errors.New("control-plane JWK has an unknown member")
		}
		if _, duplicate := values[name]; duplicate {
			return controlplane.PublicJWK{}, errors.New("control-plane JWK has a duplicate member")
		}
		var value string
		if err = decoder.Decode(&value); err != nil {
			return controlplane.PublicJWK{}, errors.New("control-plane JWK member is not a string")
		}
		values[name] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(values) != len(allowed) {
		return controlplane.PublicJWK{}, errors.New("control-plane JWK is incomplete")
	}
	decodedX, err := base64.RawURLEncoding.DecodeString(values["x"])
	if err != nil || len(decodedX) != 32 || base64.RawURLEncoding.EncodeToString(decodedX) != values["x"] {
		return controlplane.PublicJWK{}, errors.New("control-plane JWK public key is invalid")
	}
	if values["kty"] != "OKP" || values["crv"] != "Ed25519" || values["use"] != "sig" || values["alg"] != "EdDSA" || !validKeyID(values["kid"]) {
		return controlplane.PublicJWK{}, errors.New("control-plane JWK profile is invalid")
	}
	return controlplane.PublicJWK{
		KTY: values["kty"], KID: values["kid"], Use: values["use"],
		Alg: values["alg"], CRV: values["crv"], X: values["x"],
	}, nil
}

func decodeFirebaseCertificates(body []byte) ([]controlplane.PublicJWK, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("Firebase certificate document is not an object")
	}
	keys := make([]controlplane.PublicJWK, 0)
	seen := make(map[string]struct{})
	for decoder.More() {
		if len(keys) >= maximumPublicKeys {
			return nil, errors.New("Firebase certificate document has too many keys")
		}
		member, memberErr := decoder.Token()
		kid, ok := member.(string)
		if memberErr != nil || !ok || !validKeyID(kid) {
			return nil, errors.New("Firebase certificate key ID is invalid")
		}
		if _, duplicate := seen[kid]; duplicate {
			return nil, errors.New("Firebase certificate document has a duplicate key ID")
		}
		seen[kid] = struct{}{}
		var certificatePEM string
		if err = decoder.Decode(&certificatePEM); err != nil {
			return nil, errors.New("Firebase certificate value is not a string")
		}
		key, keyErr := firebaseCertificateJWK(kid, certificatePEM)
		if keyErr != nil {
			return nil, keyErr
		}
		keys = append(keys, key)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(keys) == 0 {
		return nil, errors.New("Firebase certificate document is empty or incomplete")
	}
	if err = requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return keys, nil
}

func firebaseCertificateJWK(kid, value string) (controlplane.PublicJWK, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return controlplane.PublicJWK{}, errors.New("Firebase certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return controlplane.PublicJWK{}, errors.New("Firebase certificate DER is invalid")
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() < 2_048 || publicKey.N.BitLen() > 4_096 || publicKey.E < 3 || publicKey.E%2 == 0 {
		return controlplane.PublicJWK{}, errors.New("Firebase certificate RSA key is invalid")
	}
	modulus := publicKey.N.Bytes()
	exponent := make([]byte, 0, 4)
	for value := publicKey.E; value > 0; value >>= 8 {
		exponent = append([]byte{byte(value)}, exponent...)
	}
	return controlplane.PublicJWK{
		KTY: "RSA", KID: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(modulus),
		E: base64.RawURLEncoding.EncodeToString(exponent),
	}, nil
}

func validKeyID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("public-key document has trailing JSON")
	}
	return nil
}

func rejectUnpairedSurrogateEscapes(data []byte) error {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			backslashes := 0
			for cursor := index - 1; cursor >= 0 && data[cursor] == '\\'; cursor-- {
				backslashes++
			}
			if backslashes%2 == 0 {
				inString = !inString
			}
		case '\\':
			if !inString || index+5 >= len(data) || data[index+1] != 'u' {
				continue
			}
			backslashes := 0
			for cursor := index - 1; cursor >= 0 && data[cursor] == '\\'; cursor-- {
				backslashes++
			}
			if backslashes%2 == 1 {
				continue
			}
			codePoint, ok := decodeHexQuad(data[index+2 : index+6])
			if !ok {
				continue
			}
			if codePoint >= 0xdc00 && codePoint <= 0xdfff {
				return errors.New("public-key document contains an unpaired Unicode surrogate")
			}
			if codePoint >= 0xd800 && codePoint <= 0xdbff {
				if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
					return errors.New("public-key document contains an unpaired Unicode surrogate")
				}
				low, lowOK := decodeHexQuad(data[index+8 : index+12])
				if !lowOK || low < 0xdc00 || low > 0xdfff {
					return errors.New("public-key document contains an unpaired Unicode surrogate")
				}
				index += 6
			}
		}
	}
	return nil
}

func decodeHexQuad(data []byte) (uint16, bool) {
	if len(data) != 4 {
		return 0, false
	}
	var value uint16
	for _, character := range data {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
