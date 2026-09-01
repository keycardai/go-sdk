package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// UserInfoResponse holds the signed-in user's identity claims as returned by the
// UserInfo endpoint (OpenID Connect Core 1.0 section 5.3). Claims carries the full
// document exactly as the server sent it, Subject included; nothing is filtered to a
// known set. Subject is the only claim OIDC requires and is validated present.
type UserInfoResponse struct {
	Subject string
	Claims  map[string]any
}

// UserInfoOption configures a UserInfo request.
type UserInfoOption func(*userInfoConfig)

type userInfoConfig struct {
	httpClient *http.Client
	metadata   *AuthorizationServerMetadata
}

// WithUserInfoHTTPClient sets the HTTP client used for discovery and the UserInfo request.
func WithUserInfoHTTPClient(c *http.Client) UserInfoOption {
	return func(cfg *userInfoConfig) { cfg.httpClient = c }
}

// WithUserInfoMetadata supplies pre-discovered authorization server metadata, so no
// discovery request is made. The caller owns caching and refreshing that metadata.
func WithUserInfoMetadata(m *AuthorizationServerMetadata) UserInfoOption {
	return func(cfg *userInfoConfig) { cfg.metadata = m }
}

// challengeErrorPattern extracts the RFC 6750 section 3 "error" code from a
// WWW-Authenticate challenge, in either the quoted or the bare-token form.
var challengeErrorPattern = regexp.MustCompile(`error\s*=\s*"?([^",\s]+)"?`)

// challengeError returns the error code named by a WWW-Authenticate challenge,
// defaulting to invalid_token when the header is absent or names no code.
func challengeError(wwwAuthenticate string) string {
	if wwwAuthenticate == "" {
		return "invalid_token"
	}
	if match := challengeErrorPattern.FindStringSubmatch(wwwAuthenticate); match != nil {
		return match[1]
	}
	return "invalid_token"
}

// ResolveUserInfoEndpoint returns the UserInfo endpoint advertised by the given
// authorization server metadata, or a *ConfigurationError when the server does not
// advertise one.
func ResolveUserInfoEndpoint(metadata *AuthorizationServerMetadata) (string, error) {
	if metadata == nil {
		return "", &ConfigurationError{Message: "authorization server metadata is required to resolve the userinfo_endpoint"}
	}
	if metadata.UserinfoEndpoint == "" {
		return "", &ConfigurationError{
			Message: fmt.Sprintf("authorization server %q does not advertise a userinfo_endpoint; UserInfo is unavailable for this issuer", metadata.Issuer),
		}
	}
	return metadata.UserinfoEndpoint, nil
}

// FetchUserInfo fetches the signed-in user's identity claims from the issuer's UserInfo
// endpoint (OpenID Connect Core 1.0 section 5.3).
//
// Keycard zone access tokens are authorization-only: identity claims such as email or
// groups are not in the token and live behind the issuer's userinfo_endpoint. The
// endpoint is resolved by discovery unless WithUserInfoMetadata supplies metadata.
//
// The access token is presented as a Bearer credential; the request carries no client
// authentication, because UserInfo authenticates the user, not the client. Signed
// (application/jwt) responses are not supported. Nothing is cached: caching claims per
// token is the caller's concern, since claims such as group membership change
// server-side.
func FetchUserInfo(ctx context.Context, issuer, accessToken string, opts ...UserInfoOption) (*UserInfoResponse, error) {
	cfg := userInfoConfig{httpClient: http.DefaultClient}
	for _, opt := range opts {
		opt(&cfg)
	}

	if accessToken == "" {
		return nil, &ConfigurationError{Message: "an access token is required to fetch UserInfo"}
	}

	metadata := cfg.metadata
	if metadata == nil {
		discovered, err := FetchAuthorizationServerMetadata(ctx, issuer, WithDiscoveryHTTPClient(cfg.httpClient))
		if err != nil {
			return nil, &UserInfoDiscoveryError{
				Message: fmt.Sprintf("discovering the userinfo_endpoint for issuer %q", issuer),
				Err:     err,
			}
		}
		metadata = discovered
	}

	endpoint, err := ResolveUserInfoEndpoint(metadata)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, &UserInfoFetchError{Message: "creating UserInfo request", Err: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, &UserInfoFetchError{
			Message: fmt.Sprintf("UserInfo request to %q failed", endpoint),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, userInfoChallengeError(resp.Header.Get("WWW-Authenticate"))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &HTTPError{
			Message: fmt.Sprintf("UserInfo request to %q failed", endpoint),
			Status:  resp.StatusCode,
		}
	}

	if contentType := resp.Header.Get("Content-Type"); strings.Contains(strings.ToLower(contentType), "application/jwt") {
		return nil, &OAuthError{
			ErrorCode: "invalid_response",
			Message:   fmt.Sprintf("unsupported UserInfo response content type %q: signed and encrypted UserInfo responses are not supported", contentType),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &UserInfoFetchError{Message: "reading UserInfo response", Err: err}
	}

	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, &OAuthError{
			ErrorCode: "invalid_response",
			Message:   "UserInfo response must be a JSON object of claims",
			Err:       err,
		}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		if code, ok := claims["error"].(string); ok {
			oauthErr := &OAuthError{ErrorCode: code, Message: code}
			if desc, ok := claims["error_description"].(string); ok {
				oauthErr.Message = desc
			}
			if uri, ok := claims["error_uri"].(string); ok {
				oauthErr.ErrorURI = uri
			}
			return nil, oauthErr
		}
		return nil, &OAuthError{
			ErrorCode: "invalid_response",
			Message:   "UserInfo response must include a non-empty 'sub' claim",
		}
	}

	return &UserInfoResponse{Subject: sub, Claims: claims}, nil
}

// userInfoChallengeError maps a 401 WWW-Authenticate challenge onto the typed error for
// the code it names (RFC 6750 section 3).
func userInfoChallengeError(wwwAuthenticate string) error {
	code := challengeError(wwwAuthenticate)
	message := fmt.Sprintf(
		"UserInfo request rejected with %q: the access token is expired, revoked, or not accepted at the UserInfo endpoint",
		code,
	)
	switch code {
	case "invalid_token":
		return &InvalidTokenError{Message: message}
	case "insufficient_scope":
		return &InsufficientScopeError{Message: message}
	default:
		return &OAuthError{ErrorCode: code, Message: message}
	}
}
