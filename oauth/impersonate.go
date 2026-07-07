package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// SubstituteUserTokenType is the vendor URN used as subject_token_type in
// Keycard impersonation token exchanges. It signals to the authorization
// server that the subject_token is an unsigned substitute-user assertion.
const SubstituteUserTokenType = "urn:keycard:params:oauth:token-type:substitute-user"

// substituteUserActorTokenType is the IANA URN used as actor_token_type when
// the actor token is an OAuth 2.0 access token (RFC 8693 §3).
const substituteUserActorTokenType = "urn:ietf:params:oauth:token-type:access_token"

// ImpersonateRequest contains the inputs for an impersonation token exchange.
//
// The zero value of each optional field selects the plain substitute-user
// exchange: no actor token, authenticated by the credentials configured on
// the TokenExchangeClient. That is the shape current Keycard zones accept —
// zones without RFC 8693 actor-token support reject every actor_token_type
// with invalid_request ("Unsupported actor token type").
type ImpersonateRequest struct {
	// UserIdentifier is the target user. Becomes "sub" in the issued token. Required.
	UserIdentifier string
	// Resource is the target resource URI for the issued token. Required.
	Resource string
	// Scopes are the scopes requested for the issued token. Optional.
	Scopes []string
	// ActorResource, when set, attaches an RFC 8693 actor_token to the
	// exchange: an access token minted via a client_credentials grant
	// audienced to this resource (typically the calling service's own
	// resource — a resource-less mint is denied by zone policy). Leave zero
	// against zones without actor-token support.
	ActorResource string
	// ClientAssertion, with ClientAssertionType, authenticates the exchange
	// (and the actor mint, when ActorResource is set) via a JWT bearer
	// assertion — e.g. a workload-identity OIDC token — instead of the
	// client's configured basic-auth secret. Zero values use the secret.
	ClientAssertion     string
	ClientAssertionType string
}

// Impersonate exchanges the client's application credential for a token that
// acts on behalf of req.UserIdentifier.
//
// It performs an RFC 8693 token exchange where:
//   - subject_token is an unsigned substitute-user JWT carrying the user id
//   - subject_token_type is SubstituteUserTokenType
//   - actor_token is attached only when req.ActorResource is set, minted via
//     a client_credentials grant audienced to that resource
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

	exchange := TokenExchangeRequest{
		SubjectToken:        buildSubstituteUserToken(req.UserIdentifier),
		SubjectTokenType:    SubstituteUserTokenType,
		Resource:            req.Resource,
		Scope:               strings.Join(req.Scopes, " "),
		ClientAssertion:     req.ClientAssertion,
		ClientAssertionType: req.ClientAssertionType,
	}

	if req.ActorResource != "" {
		actor, err := c.clientCredentialsClient().RequestToken(ctx, ClientCredentialsRequest{
			Resource:            req.ActorResource,
			ClientAssertion:     req.ClientAssertion,
			ClientAssertionType: req.ClientAssertionType,
		})
		if err != nil {
			return nil, err
		}
		exchange.ActorToken = actor.AccessToken
		exchange.ActorTokenType = substituteUserActorTokenType
	}

	return c.ExchangeToken(ctx, exchange)
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
