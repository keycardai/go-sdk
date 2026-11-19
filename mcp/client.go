package mcp

import (
	"log/slog"

	"github.com/keycardai/go-sdk/internal/printed"
)

// OAuthTokens holds an OAuth token set for client-side storage.
//
// String, GoString, and LogValue leave out AccessToken and RefreshToken.
// encoding/json writes them.
type OAuthTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

func (t OAuthTokens) printed() printed.Struct {
	return printed.Struct{Type: "mcp.OAuthTokens", Fields: []printed.Field{
		{Name: "TokenType", Key: "token_type", Value: t.TokenType},
		{Name: "ExpiresIn", Key: "expires_in", Value: t.ExpiresIn},
	}}
}

// String implements [fmt.Stringer].
func (t OAuthTokens) String() string { return t.printed().String() }

// GoString implements [fmt.GoStringer].
func (t OAuthTokens) GoString() string { return t.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (t OAuthTokens) LogValue() slog.Value { return t.printed().LogValue() }

// OAuthTokenStore stores and retrieves OAuth tokens for MCP client providers.
type OAuthTokenStore interface {
	Get() (*OAuthTokens, error)
	Save(tokens *OAuthTokens) error
}

// InMemoryTokenStore implements OAuthTokenStore using in-memory storage.
//
// String, GoString, and LogValue print the stored OAuthTokens, which leave out the
// token values.
type InMemoryTokenStore struct {
	tokens *OAuthTokens
}

func (s *InMemoryTokenStore) printed() printed.Struct {
	return printed.Struct{Type: "mcp.InMemoryTokenStore", Fields: []printed.Field{
		{Name: "Tokens", Key: "tokens", Value: s.printedTokens()},
	}}
}

// String implements [fmt.Stringer].
func (s *InMemoryTokenStore) String() string { return s.printed().String() }

// GoString implements [fmt.GoStringer].
func (s *InMemoryTokenStore) GoString() string { return s.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (s *InMemoryTokenStore) LogValue() slog.Value {
	if s == nil {
		return slog.AnyValue(nil)
	}
	return s.printed().LogValue()
}

// printedTokens returns the stored tokens, or an untyped nil when there are none, so
// that slog does not call LogValue on a nil pointer.
func (s *InMemoryTokenStore) printedTokens() any {
	if s.tokens == nil {
		return nil
	}
	return s.tokens
}

// NewInMemoryTokenStore creates a new in-memory token store.
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{}
}

// Get returns the stored tokens, or nil if none are stored.
func (s *InMemoryTokenStore) Get() (*OAuthTokens, error) {
	return s.tokens, nil
}

// Save stores the tokens.
func (s *InMemoryTokenStore) Save(tokens *OAuthTokens) error {
	s.tokens = tokens
	return nil
}
