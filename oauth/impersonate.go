package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/keycardai/go-sdk/internal/printed"
)

// SubstituteUserTokenType is the vendor URN used as subject_token_type in
// Keycard impersonation token exchanges. It signals to the authorization
// server that the subject_token is an unsigned substitute-user assertion.
const SubstituteUserTokenType = "urn:keycard:params:oauth:token-type:substitute-user"

// ImpersonateRequest contains the inputs for an impersonation token exchange.
//
// String, GoString, and LogValue leave out ClientAssertion.
type ImpersonateRequest struct {
	// UserIdentifier is the target user. Becomes "sub" in the issued token. Required.
	UserIdentifier string
	// Resource is the target resource URI for the issued token. Required.
	Resource string
	// Scopes are the scopes requested for the issued token. Optional.
	Scopes []string
	// ClientAssertion, with ClientAssertionType, authenticates the exchange
	// via a JWT bearer assertion instead of the client's configured credential.
	ClientAssertion     string
	ClientAssertionType string
}

func (r ImpersonateRequest) printed() printed.Struct {
	return printed.Struct{Type: "oauth.ImpersonateRequest", Fields: []printed.Field{
		{Name: "UserIdentifier", Key: "user_identifier", Value: r.UserIdentifier},
		{Name: "Resource", Key: "resource", Value: r.Resource},
		{Name: "Scopes", Key: "scopes", Value: r.Scopes},
		{Name: "ClientAssertionType", Key: "client_assertion_type", Value: r.ClientAssertionType},
	}}
}

// String implements [fmt.Stringer].
func (r ImpersonateRequest) String() string { return r.printed().String() }

// GoString implements [fmt.GoStringer].
func (r ImpersonateRequest) GoString() string { return r.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (r ImpersonateRequest) LogValue() slog.Value { return r.printed().LogValue() }

// Impersonate exchanges the client's application credential for a token that
// acts on behalf of req.UserIdentifier.
//
// It performs an RFC 8693 token exchange where subject_token is an unsigned
// substitute-user JWT carrying the user id and subject_token_type is
// SubstituteUserTokenType. The authorization server derives the acting party
// from the authenticated client and records it in the issued token's "act"
// claim chain; no actor_token is sent.
//
// Impersonation is a privileged operation gated by server-side policy and is
// forbidden by default. The authorization server returns "unauthorized_client"
// when the calling client is not permitted to impersonate and "invalid_grant"
// when the user is unknown or not impersonatable.
func (c *TokenExchangeClient) Impersonate(ctx context.Context, req ImpersonateRequest) (*TokenResponse, error) {
	if req.UserIdentifier == "" {
		return nil, errors.New("oauth: ImpersonateRequest.UserIdentifier is required")
	}
	if req.Resource == "" {
		return nil, errors.New("oauth: ImpersonateRequest.Resource is required")
	}

	return c.ExchangeToken(ctx, TokenExchangeRequest{
		SubjectToken:        buildSubstituteUserToken(req.UserIdentifier),
		SubjectTokenType:    SubstituteUserTokenType,
		Resource:            req.Resource,
		Scope:               strings.Join(req.Scopes, " "),
		ClientAssertion:     req.ClientAssertion,
		ClientAssertionType: req.ClientAssertionType,
	})
}

// buildSubstituteUserToken constructs the unsigned JWT used as subject_token
// in Keycard impersonation exchanges. The format is:
//
//	base64url({"typ":"vnd.kc.su+jwt","alg":"none"}).base64url({"sub":id}).
//
// The trailing dot is intentional: it marks the absent signature segment.
// The token is intentionally unsigned. Authority comes from the client's
// authentication to the token endpoint plus server-side impersonation policy,
// not from a signature on this assertion.
func buildSubstituteUserToken(userIdentifier string) string {
	header := []byte(`{"typ":"vnd.kc.su+jwt","alg":"none"}`)
	payload, _ := json.Marshal(struct {
		Sub string `json:"sub"`
	}{Sub: userIdentifier})
	return Base64URLEncode(header) + "." + Base64URLEncode(payload) + "."
}
