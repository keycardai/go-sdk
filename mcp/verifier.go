package mcp

import (
	"context"

	"github.com/keycardai/credentials-go/oauth"
)

// AuthInfo contains information about an authenticated request.
type AuthInfo struct {
	Token     string
	ClientID  string
	Scopes    []string
	Resource  string
	ExpiresAt int64
}

// TokenVerifier verifies access tokens and returns auth information.
type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, token string) (*AuthInfo, error)
}

// JWTOAuthTokenVerifier implements TokenVerifier using JWT verification with JWKS.
type JWTOAuthTokenVerifier struct {
	verifier *oauth.JWTVerifier
}

// NewJWTOAuthTokenVerifier creates a JWTOAuthTokenVerifier that trusts tokens issued
// by one of issuers, resolving verification keys through keyring. At least one trusted
// issuer is required. Additional verifier options (oauth.WithAudiences,
// oauth.WithAlgorithms, oauth.WithVerifierLeeway) are forwarded to the underlying JWT
// verifier. Returns a configuration error when no trusted issuer is supplied.
func NewJWTOAuthTokenVerifier(keyring oauth.OAuthKeyring, issuers []string, opts ...oauth.JWTVerifierOption) (*JWTOAuthTokenVerifier, error) {
	verifier, err := oauth.NewJWTVerifier(keyring, issuers, opts...)
	if err != nil {
		return nil, err
	}
	return &JWTOAuthTokenVerifier{verifier: verifier}, nil
}

// NewZoneTokenVerifier builds a verifier for a single Keycard zone. It trusts only
// tokens whose iss equals zoneURL and resolves verification keys from that zone's JWKS
// on demand. Pass oauth.WithAudiences to bind tokens to this resource server. This is
// the convenience path; use NewJWTOAuthTokenVerifier directly to supply your own keyring
// or trust more than one issuer.
func NewZoneTokenVerifier(zoneURL string, opts ...oauth.JWTVerifierOption) (*JWTOAuthTokenVerifier, error) {
	return NewJWTOAuthTokenVerifier(oauth.NewJWKSOAuthKeyring(), []string{zoneURL}, opts...)
}

// VerifyAccessToken verifies a JWT access token and returns auth information.
func (v *JWTOAuthTokenVerifier) VerifyAccessToken(ctx context.Context, token string) (*AuthInfo, error) {
	claims, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	info := &AuthInfo{
		Token:    token,
		ClientID: claims.ClientID,
		Scopes:   parseScopes(claims.Scope),
	}

	if claims.Expiry != 0 {
		info.ExpiresAt = claims.Expiry
	}

	if sub, ok := claims.Extra["resource"].(string); ok {
		info.Resource = sub
	}

	if info.ClientID == "" {
		info.ClientID = claims.Subject
	}

	return info, nil
}

func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	var scopes []string
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if i > start {
				scopes = append(scopes, scope[start:i])
			}
			start = i + 1
		}
	}
	return scopes
}
