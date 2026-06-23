package mcp

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/keycardai/credentials-go/oauth"
)

// ClientAuth holds client_id and client_secret for HTTP basic auth.
type ClientAuth struct {
	ClientID     string
	ClientSecret string
}

// PrepareOptions provides optional context for token exchange request preparation.
type PrepareOptions struct {
	TokenEndpoint string
	AuthInfo      map[string]string
}

// ApplicationCredential authenticates the MCP server during token exchange.
type ApplicationCredential interface {
	// Auth returns client credentials for HTTP basic auth for the given zone issuer, or
	// nil for assertion-based auth or an unknown zone. Single-zone credentials ignore
	// the issuer.
	Auth(issuer string) *ClientAuth

	// PrepareTokenExchangeRequest builds a token exchange request with any needed
	// client authentication (assertions, etc.).
	PrepareTokenExchangeRequest(ctx context.Context, subjectToken, resource string, opts *PrepareOptions) (*oauth.TokenExchangeRequest, error)
}

// MultiZoneCredential is implemented by credentials that carry per-zone client
// credentials keyed by zone issuer URL. A provider uses Zones to discover the zone set
// and switch into multi-zone routing. Single-zone credentials report no zones.
type MultiZoneCredential interface {
	// Zones returns the configured zone issuer URLs (empty for a single-zone credential).
	Zones() []string
}

// ClientSecretCredential implements ApplicationCredential using client_id/client_secret
// basic auth. It is single-zone by default; NewMultiZoneClientSecret makes it carry
// per-zone credentials keyed by zone issuer URL.
type ClientSecretCredential struct {
	clientID     string
	clientSecret string
	zones        map[string]ClientAuth // non-nil only for a multi-zone credential
}

// NewClientSecret creates a single-zone ClientSecretCredential.
func NewClientSecret(clientID, clientSecret string) *ClientSecretCredential {
	return &ClientSecretCredential{clientID: clientID, clientSecret: clientSecret}
}

// NewMultiZoneClientSecret creates a multi-zone ClientSecretCredential from a map of
// zone issuer URL to that zone's client credentials. The credential is self-describing:
// holding zone entries marks it multi-zone.
func NewMultiZoneClientSecret(zones map[string]ClientAuth) *ClientSecretCredential {
	return &ClientSecretCredential{zones: zones}
}

// Auth returns the basic-auth credentials for the given zone issuer. A single-zone
// credential returns its one credential for any issuer; a multi-zone credential returns
// the matching zone's credential, or nil if the zone is unknown (fail-closed).
func (c *ClientSecretCredential) Auth(issuer string) *ClientAuth {
	if c.zones != nil {
		if a, ok := c.zones[issuer]; ok {
			return &a
		}
		return nil
	}
	return &ClientAuth{ClientID: c.clientID, ClientSecret: c.clientSecret}
}

// Zones returns the configured zone issuer URLs (nil for a single-zone credential),
// implementing MultiZoneCredential.
func (c *ClientSecretCredential) Zones() []string {
	if c.zones == nil {
		return nil
	}
	zones := make([]string, 0, len(c.zones))
	for issuer := range c.zones {
		zones = append(zones, issuer)
	}
	return zones
}

// PrepareTokenExchangeRequest builds a basic token exchange request.
func (c *ClientSecretCredential) PrepareTokenExchangeRequest(_ context.Context, subjectToken, resource string, _ *PrepareOptions) (*oauth.TokenExchangeRequest, error) {
	return &oauth.TokenExchangeRequest{
		SubjectToken:     subjectToken,
		Resource:         resource,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}, nil
}

// WebIdentityCredential implements ApplicationCredential using RFC 7523 private_key_jwt.
type WebIdentityCredential struct {
	keyManager *PrivateKeyManager

	bootstrapOnce sync.Once
	bootstrapErr  error
}

// WebIdentityOption configures a WebIdentityCredential.
type WebIdentityOption func(*webIdentityConfig)

type webIdentityConfig struct {
	serverName string
	storage    PrivateKeyStorage
	storageDir string
	keyID      string
}

// WithServerName sets the server name (used to derive key ID if not set).
func WithServerName(name string) WebIdentityOption {
	return func(cfg *webIdentityConfig) { cfg.serverName = name }
}

// WithStorage sets the private key storage implementation.
func WithStorage(s PrivateKeyStorage) WebIdentityOption {
	return func(cfg *webIdentityConfig) { cfg.storage = s }
}

// WithStorageDir sets the directory for file-based private key storage.
func WithStorageDir(dir string) WebIdentityOption {
	return func(cfg *webIdentityConfig) { cfg.storageDir = dir }
}

// WithKeyID sets the key ID explicitly.
func WithKeyID(kid string) WebIdentityOption {
	return func(cfg *webIdentityConfig) { cfg.keyID = kid }
}

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9\-_]`)

// NewWebIdentity creates a new WebIdentityCredential with the given options.
func NewWebIdentity(opts ...WebIdentityOption) *WebIdentityCredential {
	cfg := webIdentityConfig{
		storageDir: "./mcp_keys",
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	storage := cfg.storage
	if storage == nil {
		storage = NewFilePrivateKeyStorage(cfg.storageDir)
	}

	keyID := cfg.keyID
	if keyID == "" && cfg.serverName != "" {
		keyID = nonAlphanumericRegex.ReplaceAllString(cfg.serverName, "_")
	}
	if keyID == "" {
		keyID = generateUUID()
	}

	return &WebIdentityCredential{
		keyManager: NewPrivateKeyManager(storage, keyID),
	}
}

// Bootstrap initializes the key pair (generates or loads from storage).
func (w *WebIdentityCredential) Bootstrap() error {
	w.bootstrapOnce.Do(func() {
		w.bootstrapErr = w.keyManager.BootstrapIdentity()
	})
	return w.bootstrapErr
}

// Auth returns nil (WebIdentity uses assertion-based auth, not basic auth).
func (w *WebIdentityCredential) Auth(_ string) *ClientAuth {
	return nil
}

// PrepareTokenExchangeRequest builds a token exchange request with a client assertion.
func (w *WebIdentityCredential) PrepareTokenExchangeRequest(ctx context.Context, subjectToken, resource string, opts *PrepareOptions) (*oauth.TokenExchangeRequest, error) {
	if err := w.Bootstrap(); err != nil {
		return nil, fmt.Errorf("bootstrapping identity: %w", err)
	}

	issuer := w.keyManager.ClientID()
	if opts != nil && opts.AuthInfo != nil {
		if resourceClientID, ok := opts.AuthInfo["resource_client_id"]; ok {
			issuer = resourceClientID
		}
	}

	audience := issuer
	if opts != nil && opts.TokenEndpoint != "" {
		audience = opts.TokenEndpoint
	}

	assertion, err := w.keyManager.CreateClientAssertion(ctx, issuer, audience)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	return &oauth.TokenExchangeRequest{
		SubjectToken:        subjectToken,
		Resource:            resource,
		SubjectTokenType:    "urn:ietf:params:oauth:token-type:access_token",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		ClientAssertion:     assertion,
	}, nil
}

// PublicJWKS returns the public key in JWKS format.
func (w *WebIdentityCredential) PublicJWKS() map[string]any {
	return w.keyManager.PublicJWKS()
}

// ClientJWKSURL returns the well-known JWKS URL for the given resource server URL.
func (w *WebIdentityCredential) ClientJWKSURL(resourceServerURL string) string {
	return w.keyManager.ClientJWKSURL(resourceServerURL)
}

// EKSWorkloadIdentityCredential implements ApplicationCredential using AWS EKS pod identity tokens.
type EKSWorkloadIdentityCredential struct {
	tokenFilePath string
}

var defaultEKSEnvVars = []string{
	"KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
}

// EKSWorkloadIdentityOption configures an EKSWorkloadIdentityCredential.
type EKSWorkloadIdentityOption func(*eksConfig)

type eksConfig struct {
	tokenFilePath string
	envVarName    string
}

// WithTokenFilePath sets the path to the EKS token file directly.
func WithTokenFilePath(path string) EKSWorkloadIdentityOption {
	return func(cfg *eksConfig) { cfg.tokenFilePath = path }
}

// WithEnvVarName adds a custom environment variable name to check for the token file path.
func WithEnvVarName(name string) EKSWorkloadIdentityOption {
	return func(cfg *eksConfig) { cfg.envVarName = name }
}

// NewEKSWorkloadIdentity creates a new EKSWorkloadIdentityCredential.
func NewEKSWorkloadIdentity(opts ...EKSWorkloadIdentityOption) (*EKSWorkloadIdentityCredential, error) {
	cfg := eksConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	var tokenFilePath string
	if cfg.tokenFilePath != "" {
		tokenFilePath = cfg.tokenFilePath
	} else {
		envVars := defaultEKSEnvVars
		if cfg.envVarName != "" {
			envVars = append([]string{cfg.envVarName}, envVars...)
		}

		for _, envVar := range envVars {
			if v := os.Getenv(envVar); v != "" {
				tokenFilePath = v
				break
			}
		}

		if tokenFilePath == "" {
			return nil, &EKSWorkloadIdentityConfigurationError{
				Message: fmt.Sprintf("could not find token file path in environment variables; checked: %s",
					strings.Join(envVars, ", ")),
			}
		}
	}

	// Validate that the token file exists and is non-empty
	data, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return nil, &EKSWorkloadIdentityConfigurationError{
			Message: fmt.Sprintf("error reading token file %q: %v", tokenFilePath, err),
		}
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, &EKSWorkloadIdentityConfigurationError{
			Message: fmt.Sprintf("token file is empty: %s", tokenFilePath),
		}
	}

	return &EKSWorkloadIdentityCredential{tokenFilePath: tokenFilePath}, nil
}

// Auth returns nil (EKS uses assertion-based auth, not basic auth).
func (e *EKSWorkloadIdentityCredential) Auth(_ string) *ClientAuth {
	return nil
}

// PrepareTokenExchangeRequest builds a token exchange request with the EKS pod identity token.
func (e *EKSWorkloadIdentityCredential) PrepareTokenExchangeRequest(_ context.Context, subjectToken, resource string, _ *PrepareOptions) (*oauth.TokenExchangeRequest, error) {
	data, err := os.ReadFile(e.tokenFilePath)
	if err != nil {
		return nil, fmt.Errorf("reading EKS token from %q: %w", e.tokenFilePath, err)
	}

	eksToken := strings.TrimSpace(string(data))
	if eksToken == "" {
		return nil, fmt.Errorf("EKS token file is empty: %s", e.tokenFilePath)
	}

	return &oauth.TokenExchangeRequest{
		SubjectToken:        subjectToken,
		Resource:            resource,
		SubjectTokenType:    "urn:ietf:params:oauth:token-type:access_token",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		ClientAssertion:     eksToken,
	}, nil
}
