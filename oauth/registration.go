package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// RegistrationRequest is RFC 7591 §2 client metadata. Every field is optional; only the
// fields the caller sets are sent (the authorization server defaults the rest).
// AdditionalMetadata carries vendor or AS-specific keys and is merged into the request
// body, with the named fields below taking precedence on conflict.
type RegistrationRequest struct {
	ClientName              string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scope                   string
	TokenEndpointAuthMethod string
	JWKSURI                 string
	JWKS                    map[string]any
	ClientURI               string
	LogoURI                 string
	TosURI                  string
	PolicyURI               string
	SoftwareID              string
	SoftwareVersion         string
	AdditionalMetadata      map[string]any
}

// RegistrationResponse is RFC 7591 §3.2.1. Raw preserves the full response body so
// AS-specific fields not modeled here remain accessible.
type RegistrationResponse struct {
	ClientID                string
	ClientSecret            string
	ClientIDIssuedAt        int64
	ClientSecretExpiresAt   int64
	RegistrationAccessToken string
	RegistrationClientURI   string
	Raw                     map[string]any
}

// RegisterOption configures RegisterClient.
type RegisterOption func(*registrationConfig)

type registrationConfig struct {
	httpClient         *http.Client
	initialAccessToken string
}

// WithRegistrationHTTPClient sets the HTTP client used for discovery and registration.
func WithRegistrationHTTPClient(c *http.Client) RegisterOption {
	return func(cfg *registrationConfig) { cfg.httpClient = c }
}

// WithInitialAccessToken authenticates the registration request with a Bearer initial
// access token (RFC 7591 §3.1), for authorization servers that require one.
func WithInitialAccessToken(token string) RegisterOption {
	return func(cfg *registrationConfig) { cfg.initialAccessToken = token }
}

// RegisterClient registers a new OAuth client at the issuer's registration endpoint
// (resolved by discovery) and returns the issued credentials (RFC 7591).
func RegisterClient(ctx context.Context, issuer string, req RegistrationRequest, opts ...RegisterOption) (*RegistrationResponse, error) {
	cfg := registrationConfig{httpClient: http.DefaultClient}
	for _, opt := range opts {
		opt(&cfg)
	}

	metadata, err := FetchAuthorizationServerMetadata(ctx, issuer, WithDiscoveryHTTPClient(cfg.httpClient))
	if err != nil {
		return nil, fmt.Errorf("discovering registration endpoint: %w", err)
	}
	if metadata.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("authorization server %q does not advertise a registration_endpoint", issuer)
	}

	payload, err := json.Marshal(registrationBody(req))
	if err != nil {
		return nil, fmt.Errorf("encoding registration request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.RegistrationEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating registration request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if cfg.initialAccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.initialAccessToken)
	}

	resp, err := cfg.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	// RFC 7591 §3.2.1 returns 201 Created; some servers return 200.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&errBody); err == nil {
			if errCode, ok := errBody["error"].(string); ok {
				oauthErr := &OAuthError{ErrorCode: errCode, Message: errCode}
				if desc, ok := errBody["error_description"].(string); ok {
					oauthErr.Message = desc
				}
				if uri, ok := errBody["error_uri"].(string); ok {
					oauthErr.ErrorURI = uri
				}
				return nil, oauthErr
			}
		}
		return nil, &HTTPError{Message: "client registration failed", Status: resp.StatusCode}
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding registration response: %w", err)
	}

	clientID, _ := raw["client_id"].(string)
	if clientID == "" {
		return nil, fmt.Errorf("registration response missing client_id")
	}

	result := &RegistrationResponse{ClientID: clientID, Raw: raw}
	if v, ok := raw["client_secret"].(string); ok {
		result.ClientSecret = v
	}
	if v, ok := raw["client_id_issued_at"].(float64); ok {
		result.ClientIDIssuedAt = int64(v)
	}
	if v, ok := raw["client_secret_expires_at"].(float64); ok {
		result.ClientSecretExpiresAt = int64(v)
	}
	if v, ok := raw["registration_access_token"].(string); ok {
		result.RegistrationAccessToken = v
	}
	if v, ok := raw["registration_client_uri"].(string); ok {
		result.RegistrationClientURI = v
	}
	return result, nil
}

// registrationBody merges AdditionalMetadata with the named fields, with the named
// fields winning on conflict, and omits fields the caller left unset (RFC-minimal).
func registrationBody(req RegistrationRequest) map[string]any {
	body := map[string]any{}
	for k, v := range req.AdditionalMetadata {
		body[k] = v
	}
	if req.ClientName != "" {
		body["client_name"] = req.ClientName
	}
	if len(req.RedirectURIs) > 0 {
		body["redirect_uris"] = req.RedirectURIs
	}
	if len(req.GrantTypes) > 0 {
		body["grant_types"] = req.GrantTypes
	}
	if len(req.ResponseTypes) > 0 {
		body["response_types"] = req.ResponseTypes
	}
	if req.Scope != "" {
		body["scope"] = req.Scope
	}
	if req.TokenEndpointAuthMethod != "" {
		body["token_endpoint_auth_method"] = req.TokenEndpointAuthMethod
	}
	if req.JWKSURI != "" {
		body["jwks_uri"] = req.JWKSURI
	}
	if req.JWKS != nil {
		body["jwks"] = req.JWKS
	}
	if req.ClientURI != "" {
		body["client_uri"] = req.ClientURI
	}
	if req.LogoURI != "" {
		body["logo_uri"] = req.LogoURI
	}
	if req.TosURI != "" {
		body["tos_uri"] = req.TosURI
	}
	if req.PolicyURI != "" {
		body["policy_uri"] = req.PolicyURI
	}
	if req.SoftwareID != "" {
		body["software_id"] = req.SoftwareID
	}
	if req.SoftwareVersion != "" {
		body["software_version"] = req.SoftwareVersion
	}
	return body
}
