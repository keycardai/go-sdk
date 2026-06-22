package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keycardai/credentials-go/oauth"
)

type contextKey string

const (
	authInfoKey      contextKey = "keycard_auth_info"
	accessContextKey contextKey = "keycard_access_context"
)

// AuthInfoFromRequest retrieves the AuthInfo from the request context.
// Returns nil if no AuthInfo is present (e.g., RequireBearerAuth middleware was not applied).
func AuthInfoFromRequest(r *http.Request) *AuthInfo {
	info, _ := r.Context().Value(authInfoKey).(*AuthInfo)
	return info
}

// AccessContextFromRequest retrieves the AccessContext from the request context.
// Returns nil if no AccessContext is present (e.g., Grant middleware was not applied).
func AccessContextFromRequest(r *http.Request) *AccessContext {
	ac, _ := r.Context().Value(accessContextKey).(*AccessContext)
	return ac
}

// BearerAuthOption configures RequireBearerAuth middleware.
type BearerAuthOption func(*bearerAuthConfig)

type bearerAuthConfig struct {
	requiredScopes []string
}

// WithRequiredScopes sets the scopes that must all be present in the token; a token
// missing any is rejected with an insufficient-scope failure.
func WithRequiredScopes(scopes ...string) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.requiredScopes = scopes }
}

// RequireBearerAuth returns middleware that verifies Bearer tokens with verifier.
// The verifier carries the trusted issuers and audience binding; build one with
// NewZoneTokenVerifier (single zone) or NewJWTOAuthTokenVerifier (custom keyring or
// multiple issuers). On success it stores AuthInfo in the request context (read with
// AuthInfoFromRequest); on failure it writes the appropriate WWW-Authenticate challenge
// and HTTP status. It panics if verifier is nil, since an auth boundary with no verifier
// is a programming error best caught at startup.
func RequireBearerAuth(verifier TokenVerifier, opts ...BearerAuthOption) func(http.Handler) http.Handler {
	if verifier == nil {
		panic("mcp: RequireBearerAuth requires a non-nil TokenVerifier")
	}

	cfg := bearerAuthConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resourceMetadataURL := protectedResourceMetadataURL(r)

			credentials := r.Header.Get("Authorization")
			if credentials == "" {
				challenge := fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceMetadataURL)
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(credentials, " ", 2)
			if len(parts) != 2 || parts[1] == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			scheme, token := parts[0], parts[1]
			if !strings.EqualFold(scheme, "bearer") {
				challenge := fmt.Sprintf(`Bearer error="invalid_token", error_description="Unsupported authentication scheme", resource_metadata="%s"`, resourceMetadataURL)
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			authInfo, err := verifier.VerifyAccessToken(r.Context(), token)
			if err != nil {
				var errCode, errMsg string

				switch e := err.(type) {
				case *oauth.InvalidTokenError:
					errCode = e.ErrorCode()
					errMsg = e.Message
				case *oauth.InsufficientScopeError:
					errCode = e.ErrorCode()
					errMsg = e.Message
					challenge := fmt.Sprintf(`Bearer error="%s", error_description="%s", resource_metadata="%s"`, errCode, errMsg, resourceMetadataURL)
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(http.StatusForbidden)
					return
				default:
					errCode = "invalid_token"
					errMsg = err.Error()
				}

				challenge := fmt.Sprintf(`Bearer error="%s", error_description="%s", resource_metadata="%s"`, errCode, errMsg, resourceMetadataURL)
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Check required scopes
			if len(cfg.requiredScopes) > 0 {
				scopeSet := make(map[string]bool, len(authInfo.Scopes))
				for _, s := range authInfo.Scopes {
					scopeSet[s] = true
				}
				for _, required := range cfg.requiredScopes {
					if !scopeSet[required] {
						challenge := fmt.Sprintf(`Bearer error="insufficient_scope", error_description="Insufficient scope", resource_metadata="%s"`, resourceMetadataURL)
						w.Header().Set("WWW-Authenticate", challenge)
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
			}

			// Check expiry
			if authInfo.ExpiresAt > 0 && authInfo.ExpiresAt < time.Now().Unix() {
				challenge := fmt.Sprintf(`Bearer error="invalid_token", error_description="Token has expired", resource_metadata="%s"`, resourceMetadataURL)
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), authInfoKey, authInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// protectedResourceMetadataURL constructs the well-known URL for the protected resource metadata.
func protectedResourceMetadataURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
			scheme = fwd
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", scheme, r.Host)
}
