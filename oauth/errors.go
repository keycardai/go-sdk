package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// KeycardError is the marker interface implemented by every error this package
// returns. It lets callers discriminate Keycard SDK errors from other errors with
// errors.As(err, &kc) where kc is a KeycardError, and pairs with the concrete error
// types for errors.As to a specific error.
type KeycardError interface {
	error
	keycardError()
}

// ConfigurationError indicates the SDK was constructed with invalid configuration,
// such as a verifier built without a trusted issuer or with an unsupported algorithm.
type ConfigurationError struct {
	Message string
}

func (e *ConfigurationError) Error() string {
	return e.Message
}

// HTTPError represents an HTTP-related error with a status code.
type HTTPError struct {
	Message string
	Status  int
}

func (e *HTTPError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
	return e.Message
}

// OAuthError represents an OAuth protocol error with an error code. Err carries the
// underlying cause, when there is one (e.g. a JSON decode failure behind an
// invalid_response), for errors.Is/errors.As.
type OAuthError struct {
	ErrorCode string
	Message   string
	ErrorURI  string
	Err       error
}

func (e *OAuthError) Error() string {
	msg := e.Message
	if e.Err != nil {
		msg = msg + ": " + e.Err.Error()
	}
	if e.ErrorCode != "" {
		return fmt.Sprintf("oauth error %s: %s", e.ErrorCode, msg)
	}
	return msg
}

func (e *OAuthError) Unwrap() error { return e.Err }

// InvalidTokenError indicates the token is invalid (expired, malformed, or bad signature).
type InvalidTokenError struct {
	Message  string
	ErrorURI string
	Err      error
}

func (e *InvalidTokenError) Unwrap() error { return e.Err }

func (e *InvalidTokenError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

// ErrorCode returns the OAuth error code for this error.
func (e *InvalidTokenError) ErrorCode() string {
	return "invalid_token"
}

// InsufficientScopeError indicates the token lacks required scopes.
type InsufficientScopeError struct {
	Message  string
	ErrorURI string
}

func (e *InsufficientScopeError) Error() string {
	return e.Message
}

// ErrorCode returns the OAuth error code for this error.
func (e *InsufficientScopeError) ErrorCode() string {
	return "insufficient_scope"
}

func (*ConfigurationError) keycardError()     {}
func (*HTTPError) keycardError()              {}
func (*OAuthError) keycardError()             {}
func (*InvalidTokenError) keycardError()      {}
func (*InsufficientScopeError) keycardError() {}

// IssuerMismatchError indicates an authorization server's discovery document reported
// an issuer that does not match the requested issuer (RFC 8414 section 3.3).
type IssuerMismatchError struct {
	Message string
}

func (e *IssuerMismatchError) Error() string { return e.Message }
func (*IssuerMismatchError) keycardError()   {}

// JWKSDiscoveryError indicates the JWKS URI could not be resolved from the issuer's
// authorization server metadata. Err carries the underlying cause (e.g. a discovery
// fetch failure or an *IssuerMismatchError) for errors.Is/errors.As.
type JWKSDiscoveryError struct {
	Message string
	Err     error
}

func (e *JWKSDiscoveryError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *JWKSDiscoveryError) Unwrap() error { return e.Err }
func (*JWKSDiscoveryError) keycardError()   {}

// JWKSUriValidationError indicates the discovered JWKS URI failed validation, such as
// not sharing an origin with the issuer.
type JWKSUriValidationError struct {
	Message string
}

func (e *JWKSUriValidationError) Error() string { return e.Message }
func (*JWKSUriValidationError) keycardError()   {}

// JWKSFetchError indicates the JWKS document could not be fetched or decoded. Err
// carries the underlying transport or decode cause (e.g. context.DeadlineExceeded) for
// errors.Is/errors.As.
type JWKSFetchError struct {
	Message string
	Err     error
}

func (e *JWKSFetchError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *JWKSFetchError) Unwrap() error { return e.Err }
func (*JWKSFetchError) keycardError()   {}

// JWKSKeyNotFoundError indicates no key matching the requested key ID was present in
// the issuer's JWKS.
type JWKSKeyNotFoundError struct {
	Message string
}

func (e *JWKSKeyNotFoundError) Error() string { return e.Message }
func (*JWKSKeyNotFoundError) keycardError()   {}

// UserInfoDiscoveryError indicates the UserInfo endpoint could not be resolved from the
// issuer's authorization server metadata. Err carries the underlying cause (e.g. a
// discovery fetch failure or an *IssuerMismatchError) for errors.Is/errors.As.
type UserInfoDiscoveryError struct {
	Message string
	Err     error
}

func (e *UserInfoDiscoveryError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *UserInfoDiscoveryError) Unwrap() error { return e.Err }
func (*UserInfoDiscoveryError) keycardError()   {}

// UserInfoFetchError indicates the UserInfo request failed in transport, or its body
// could not be read. Err carries the underlying cause (e.g. context.DeadlineExceeded)
// for errors.Is/errors.As.
type UserInfoFetchError struct {
	Message string
	Err     error
}

func (e *UserInfoFetchError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *UserInfoFetchError) Unwrap() error { return e.Err }
func (*UserInfoFetchError) keycardError()   {}

// parseOAuthErrorResponse parses an RFC 6749 section 5.2 error response from a token or
// registration endpoint. It returns an *OAuthError when the body is JSON carrying an
// "error" field, or nil otherwise so the caller can fall back to a generic HTTP error.
// It does not close resp.Body.
func parseOAuthErrorResponse(resp *http.Response) *OAuthError {
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	code, ok := body["error"].(string)
	if !ok {
		return nil
	}
	oauthErr := &OAuthError{ErrorCode: code, Message: code}
	if desc, ok := body["error_description"].(string); ok {
		oauthErr.Message = desc
	}
	if uri, ok := body["error_uri"].(string); ok {
		oauthErr.ErrorURI = uri
	}
	return oauthErr
}

// TokenEndpointDiscoveryError indicates the token endpoint could not be resolved from the
// issuer's authorization server metadata. Err carries the underlying cause (e.g. an
// *HTTPError, an *IssuerMismatchError, or the caller's context error) for
// errors.Is/errors.As; it is nil when the metadata simply omits token_endpoint.
type TokenEndpointDiscoveryError struct {
	Message string
	Err     error
}

func (e *TokenEndpointDiscoveryError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *TokenEndpointDiscoveryError) Unwrap() error { return e.Err }
func (*TokenEndpointDiscoveryError) keycardError()   {}
