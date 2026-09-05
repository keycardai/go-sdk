package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AuthorizationServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414).
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`

	// UserinfoEndpoint is where the signed-in user's identity claims are fetched
	// (OpenID Connect Discovery 1.0 section 3). Empty when the server does not
	// advertise it.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// EndSessionEndpoint is where the browser is sent to end the server-side session
	// (OpenID Connect RP-Initiated Logout 1.0 section 2.1). Empty when the server does
	// not advertise it.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`

	// Extra holds any fields beyond the standard set, preserved for forward compatibility.
	Extra map[string]any `json:"-"`
}

// knownASMetadataFields are the JSON names mapped to typed fields above; anything else
// in a discovery response is preserved in AuthorizationServerMetadata.Extra.
var knownASMetadataFields = []string{
	"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
	"registration_endpoint", "scopes_supported", "response_types_supported",
	"grant_types_supported", "token_endpoint_auth_methods_supported",
	"code_challenge_methods_supported", "userinfo_endpoint", "end_session_endpoint",
	"subject_types_supported", "id_token_signing_alg_values_supported", "claims_supported",
}

// DiscoveryOption configures a metadata discovery request.
type DiscoveryOption func(*discoveryConfig)

type discoveryConfig struct {
	httpClient *http.Client
}

// WithDiscoveryHTTPClient sets the HTTP client used for discovery requests.
func WithDiscoveryHTTPClient(c *http.Client) DiscoveryOption {
	return func(cfg *discoveryConfig) {
		cfg.httpClient = c
	}
}

// FetchAuthorizationServerMetadata fetches OAuth authorization server metadata
// from the well-known endpoint for the given issuer (RFC 8414).
func FetchAuthorizationServerMetadata(ctx context.Context, issuer string, opts ...DiscoveryOption) (*AuthorizationServerMetadata, error) {
	cfg := &discoveryConfig{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	issuer = strings.TrimRight(issuer, "/")
	url := issuer + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching authorization server metadata from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			Message: fmt.Sprintf("discovery endpoint returned HTTP %d for %s", resp.StatusCode, url),
			Status:  resp.StatusCode,
		}
	}

	// Read the body once so we can decode the typed fields and also capture any
	// unknown ones for forward compatibility.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading authorization server metadata: %w", err)
	}

	var metadata AuthorizationServerMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, &InvalidMetadataError{Message: fmt.Sprintf("decoding authorization server metadata from %s", url), Err: err}
	}

	// Validate the response issuer matches the requested issuer (RFC 8414 section 3.3),
	// ignoring a trailing slash.
	if strings.TrimRight(metadata.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, &IssuerMismatchError{
			Message: fmt.Sprintf("authorization server issuer %q does not match requested issuer %q", metadata.Issuer, issuer),
		}
	}

	// Preserve fields beyond the standard set.
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err == nil {
		for _, known := range knownASMetadataFields {
			delete(all, known)
		}
		if len(all) > 0 {
			metadata.Extra = make(map[string]any, len(all))
			for k, v := range all {
				var val any
				if err := json.Unmarshal(v, &val); err == nil {
					metadata.Extra[k] = val
				}
			}
		}
	}

	return &metadata, nil
}
