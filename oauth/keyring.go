package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// OAuthKeyring resolves public keys by issuer and key ID.
type OAuthKeyring interface {
	Key(ctx context.Context, issuer, kid string) (crypto.PublicKey, error)
}

// IdentifiableKey pairs a private key with its metadata.
type IdentifiableKey struct {
	Key    crypto.PrivateKey
	Issuer string
	KID    string
}

// PrivateKeyring provides private keys for JWT signing.
type PrivateKeyring interface {
	Key(ctx context.Context, usage string) (IdentifiableKey, error)
}

// PEMPrivateKeyring implements PrivateKeyring using a PEM-encoded private key.
type PEMPrivateKeyring struct {
	key    crypto.PrivateKey
	issuer string
	kid    string
}

// NewPEMPrivateKeyring creates a PrivateKeyring from a PEM-encoded private key.
func NewPEMPrivateKeyring(pemData []byte, issuer, kid string) (*PEMPrivateKeyring, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 for RSA keys
		rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if rsaErr != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		key = rsaKey
	}

	return &PEMPrivateKeyring{key: key, issuer: issuer, kid: kid}, nil
}

// Key returns the private key for the given usage.
func (r *PEMPrivateKeyring) Key(_ context.Context, _ string) (IdentifiableKey, error) {
	return IdentifiableKey{Key: r.key, Issuer: r.issuer, KID: r.kid}, nil
}

// JWKSOAuthKeyringOption configures a JWKSOAuthKeyring.
type JWKSOAuthKeyringOption func(*jwksKeyringConfig)

type jwksKeyringConfig struct {
	keyTTL       time.Duration
	discoveryTTL time.Duration
	fetchTimeout time.Duration
	maxKeyCache  int
	httpClient   *http.Client
}

// WithKeyTTL sets the TTL for cached public keys. Default: 5 minutes.
func WithKeyTTL(d time.Duration) JWKSOAuthKeyringOption {
	return func(cfg *jwksKeyringConfig) { cfg.keyTTL = d }
}

// WithDiscoveryTTL sets the TTL for cached discovery (issuer → jwks_uri) mappings. Default: 1 hour.
func WithDiscoveryTTL(d time.Duration) JWKSOAuthKeyringOption {
	return func(cfg *jwksKeyringConfig) { cfg.discoveryTTL = d }
}

// WithFetchTimeout sets the timeout for both discovery and JWKS fetch requests. Default: 10 seconds.
func WithFetchTimeout(d time.Duration) JWKSOAuthKeyringOption {
	return func(cfg *jwksKeyringConfig) { cfg.fetchTimeout = d }
}

// WithKeyringHTTPClient sets the HTTP client used for JWKS fetches.
func WithKeyringHTTPClient(c *http.Client) JWKSOAuthKeyringOption {
	return func(cfg *jwksKeyringConfig) { cfg.httpClient = c }
}

// WithMaxKeyCacheSize bounds the number of cached public keys. When the cache grows
// past this size an entry is evicted on the next insert (eviction order is unspecified).
// A value <= 0 disables the bound. Default: 256.
func WithMaxKeyCacheSize(n int) JWKSOAuthKeyringOption {
	return func(cfg *jwksKeyringConfig) { cfg.maxKeyCache = n }
}

type cacheEntry[T any] struct {
	value     T
	expiresAt time.Time
}

// JWKSOAuthKeyring implements OAuthKeyring with two-level caching:
//  1. Discovery cache: issuer → jwks_uri (default TTL: 1 hour)
//  2. Key cache: issuer::kid → public key (default TTL: 5 minutes)
//
// Concurrent requests for the same key share one fetch, which runs detached from any
// single caller's cancellation so one caller cannot poison it for the others.
type JWKSOAuthKeyring struct {
	cfg jwksKeyringConfig

	mu             sync.Mutex
	discoveryCache map[string]cacheEntry[string]
	keyCache       map[string]cacheEntry[crypto.PublicKey]

	discoveryGroup singleflight.Group
	keyGroup       singleflight.Group
}

// NewJWKSOAuthKeyring creates a new JWKSOAuthKeyring with optional configuration.
func NewJWKSOAuthKeyring(opts ...JWKSOAuthKeyringOption) *JWKSOAuthKeyring {
	cfg := jwksKeyringConfig{
		keyTTL:       5 * time.Minute,
		discoveryTTL: 1 * time.Hour,
		fetchTimeout: 10 * time.Second,
		maxKeyCache:  256,
		httpClient:   http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &JWKSOAuthKeyring{
		cfg:            cfg,
		discoveryCache: make(map[string]cacheEntry[string]),
		keyCache:       make(map[string]cacheEntry[crypto.PublicKey]),
	}
}

// Key resolves a public key by issuer and key ID.
func (k *JWKSOAuthKeyring) Key(ctx context.Context, issuer, kid string) (crypto.PublicKey, error) {
	cacheKey := issuer + "::" + kid

	// Check key cache
	if key, ok := k.getCached(cacheKey, true); ok {
		return key.(crypto.PublicKey), nil
	}

	// Resolve JWKS URI
	jwksURI, err := k.resolveJWKSURI(ctx, issuer)
	if err != nil {
		return nil, err
	}

	// Resolve key
	return k.resolveKey(ctx, issuer, kid, jwksURI, cacheKey)
}

// Invalidate removes cached entries for the given issuer and key ID.
func (k *JWKSOAuthKeyring) Invalidate(issuer, kid string) {
	cacheKey := issuer + "::" + kid
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keyCache, cacheKey)
	delete(k.discoveryCache, issuer)
}

func (k *JWKSOAuthKeyring) resolveJWKSURI(ctx context.Context, issuer string) (string, error) {
	// Check discovery cache
	if uri, ok := k.getCached(issuer, false); ok {
		return uri.(string), nil
	}

	result, err := sharedFetch(ctx, &k.discoveryGroup, issuer, k.cfg.fetchTimeout, func(fetchCtx context.Context) (any, error) {
		metadata, err := FetchAuthorizationServerMetadata(fetchCtx, issuer,
			WithDiscoveryHTTPClient(k.cfg.httpClient))
		if err != nil {
			return nil, &JWKSDiscoveryError{Message: fmt.Sprintf("discovering JWKS URI for %q", issuer), Err: err}
		}

		if metadata.JWKSURI == "" {
			return nil, &JWKSDiscoveryError{Message: fmt.Sprintf("no JWKS URI available for %q", issuer)}
		}

		if err := assertSameOrigin(issuer, metadata.JWKSURI); err != nil {
			return nil, err
		}

		k.mu.Lock()
		k.discoveryCache[issuer] = cacheEntry[string]{
			value:     metadata.JWKSURI,
			expiresAt: time.Now().Add(k.cfg.discoveryTTL),
		}
		k.mu.Unlock()

		return metadata.JWKSURI, nil
	})
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return "", &JWKSDiscoveryError{Message: fmt.Sprintf("discovering JWKS URI for %q", issuer), Err: err}
		}
		return "", err
	}

	return result.(string), nil
}

func (k *JWKSOAuthKeyring) resolveKey(ctx context.Context, issuer, kid, jwksURI, cacheKey string) (crypto.PublicKey, error) {
	result, err := sharedFetch(ctx, &k.keyGroup, cacheKey, k.cfg.fetchTimeout, func(fetchCtx context.Context) (any, error) {
		req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, jwksURI, nil)
		if err != nil {
			return nil, fmt.Errorf("creating JWKS request: %w", err)
		}

		resp, err := k.cfg.httpClient.Do(req)
		if err != nil {
			return nil, &JWKSFetchError{Message: fmt.Sprintf("fetching JWKS from %q", jwksURI), Err: err}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, &JWKSFetchError{Message: fmt.Sprintf("JWKS endpoint %q returned HTTP %d", jwksURI, resp.StatusCode)}
		}

		var jwkSet jwkSetJSON
		if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			return nil, &JWKSFetchError{Message: fmt.Sprintf("decoding JWKS from %q", jwksURI), Err: err}
		}

		jwk, err := findKey(jwkSet.Keys, kid)
		if err != nil {
			return nil, &JWKSKeyNotFoundError{Message: fmt.Sprintf("key %q not found for issuer %q", kid, issuer)}
		}

		pubKey, err := importJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("importing JWK %q: %w", kid, err)
		}

		k.mu.Lock()
		k.keyCache[cacheKey] = cacheEntry[crypto.PublicKey]{
			value:     pubKey,
			expiresAt: time.Now().Add(k.cfg.keyTTL),
		}
		// Bound the key cache: once over the configured size, evict entries other than
		// the one just inserted. Eviction order is unspecified (the spec permits this).
		for k.cfg.maxKeyCache > 0 && len(k.keyCache) > k.cfg.maxKeyCache {
			evicted := false
			for old := range k.keyCache {
				if old != cacheKey {
					delete(k.keyCache, old)
					evicted = true
					break
				}
			}
			if !evicted {
				break
			}
		}
		k.mu.Unlock()

		return pubKey, nil
	})
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return nil, &JWKSFetchError{Message: fmt.Sprintf("fetching JWKS from %q", jwksURI), Err: err}
		}
		return nil, err
	}

	return result.(crypto.PublicKey), nil
}

// getCached looks up a value in the appropriate cache. isKey=true for key cache, false for discovery.
func (k *JWKSOAuthKeyring) getCached(key string, isKey bool) (any, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if isKey {
		entry, ok := k.keyCache[key]
		if !ok || time.Now().After(entry.expiresAt) {
			delete(k.keyCache, key)
			return nil, false
		}
		return entry.value, true
	}

	entry, ok := k.discoveryCache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(k.discoveryCache, key)
		return nil, false
	}
	return entry.value, true
}

// assertSameOrigin validates that the JWKS URI has the same origin as the issuer.
func assertSameOrigin(issuer, jwksURI string) error {
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("parsing issuer URL: %w", err)
	}
	jwksURL, err := url.Parse(jwksURI)
	if err != nil {
		return fmt.Errorf("parsing JWKS URI: %w", err)
	}

	issuerOrigin := issuerURL.Scheme + "://" + issuerURL.Host
	jwksOrigin := jwksURL.Scheme + "://" + jwksURL.Host

	if issuerOrigin != jwksOrigin {
		return &JWKSUriValidationError{Message: fmt.Sprintf("JWKS URI origin %q does not match issuer origin %q for %q", jwksOrigin, issuerOrigin, issuer)}
	}
	return nil
}

// JWKS JSON structures

type jwkSetJSON struct {
	Keys []jwkJSON `json:"keys"`
}

type jwkJSON struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	KID string `json:"kid,omitempty"`

	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func findKey(keys []jwkJSON, kid string) (*jwkJSON, error) {
	for i := range keys {
		if keys[i].KID == kid {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

func importJWK(jwk *jwkJSON) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		return importRSAJWK(jwk)
	case "EC":
		return importECJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
}

func importRSAJWK(jwk *jwkJSON) (crypto.PublicKey, error) {
	nBytes, err := Base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA modulus: %w", err)
	}
	eBytes, err := Base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

func importECJWK(jwk *jwkJSON) (crypto.PublicKey, error) {
	xBytes, err := Base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decoding EC x coordinate: %w", err)
	}
	yBytes, err := Base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding EC y coordinate: %w", err)
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", jwk.Crv)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
