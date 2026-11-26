package mcp

import (
	"context"
	"log/slog"

	"github.com/keycardai/go-sdk/internal/printed"
	"github.com/keycardai/go-sdk/oauth"
)

// JSONWebTokenSigner signs JWTs for MCP client authentication.
type JSONWebTokenSigner struct {
	signer *oauth.JWTSigner
}

func (s *JSONWebTokenSigner) printed() printed.Struct {
	return printed.Struct{Type: "mcp.JSONWebTokenSigner", Fields: []printed.Field{
		{Name: "Signer", Key: "signer", Value: s.signer},
	}}
}

// String implements [fmt.Stringer].
func (s *JSONWebTokenSigner) String() string { return s.printed().String() }

// GoString implements [fmt.GoStringer].
func (s *JSONWebTokenSigner) GoString() string { return s.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (s *JSONWebTokenSigner) LogValue() slog.Value {
	if s == nil {
		return slog.AnyValue(nil)
	}
	return s.printed().LogValue()
}

// NewJSONWebTokenSigner creates a new JSONWebTokenSigner with the given private keyring.
func NewJSONWebTokenSigner(keyring oauth.PrivateKeyring) *JSONWebTokenSigner {
	return &JSONWebTokenSigner{
		signer: oauth.NewJWTSigner(keyring),
	}
}

// SignToken produces a signed JWT from auth info.
func (s *JSONWebTokenSigner) SignToken(ctx context.Context, info *AuthInfo) (string, error) {
	claims := oauth.JWTClaims{
		Subject:  info.ClientID,
		Scope:    joinScopes(info.Scopes),
		ClientID: info.ClientID,
	}

	if info.ExpiresAt > 0 {
		claims.Expiry = info.ExpiresAt
	}

	if info.Resource != "" {
		claims.Extra = map[string]any{
			"resource": info.Resource,
		}
	}

	return s.signer.Sign(ctx, claims)
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	result := scopes[0]
	for _, s := range scopes[1:] {
		result += " " + s
	}
	return result
}
