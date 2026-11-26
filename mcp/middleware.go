package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

type contextKey string

const (
	authInfoKey      contextKey = "keycard_auth_info"
	accessContextKey contextKey = "keycard_access_context"
)

// AuthInfoFromContext retrieves the AuthInfo from ctx.
// Returns nil if no AuthInfo is present (e.g., RequireBearerAuth middleware was not applied).
// Use it in handlers that receive a context but not the *http.Request, such as MCP
// framework tool handlers whose context derives from the inbound HTTP request.
func AuthInfoFromContext(ctx context.Context) *AuthInfo {
	info, _ := ctx.Value(authInfoKey).(*AuthInfo)
	return info
}

// AuthInfoFromRequest retrieves the AuthInfo from the request context.
// Returns nil if no AuthInfo is present (e.g., RequireBearerAuth middleware was not applied).
func AuthInfoFromRequest(r *http.Request) *AuthInfo {
	return AuthInfoFromContext(r.Context())
}

// AccessContextFromContext retrieves the AccessContext from ctx.
// Returns nil if no AccessContext is present (e.g., Grant middleware was not applied).
// Use it in handlers that receive a context but not the *http.Request, such as MCP
// framework tool handlers whose context derives from the inbound HTTP request.
func AccessContextFromContext(ctx context.Context) *AccessContext {
	ac, _ := ctx.Value(accessContextKey).(*AccessContext)
	return ac
}

// AccessContextFromRequest retrieves the AccessContext from the request context.
// Returns nil if no AccessContext is present (e.g., Grant middleware was not applied).
func AccessContextFromRequest(r *http.Request) *AccessContext {
	return AccessContextFromContext(r.Context())
}

// BearerAuthOption configures RequireBearerAuth middleware.
type BearerAuthOption func(*bearerAuthConfig)

type bearerAuthConfig struct {
	requiredScopes []string
	keyring        oauth.OAuthKeyring
	resolveZone    func(host, target string) string
}

// WithRequiredScopes sets the scopes that must all be present in the token; a token
// missing any is rejected with an insufficient-scope failure.
func WithRequiredScopes(scopes ...string) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.requiredScopes = scopes }
}

// WithBearerKeyring supplies verification keys for ResourceBinding.BearerAuth.
// If omitted, the middleware fetches the issuers' JWKS on demand.
func WithBearerKeyring(keyring oauth.OAuthKeyring) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.keyring = keyring }
}

// WithInboundZoneResolver selects a configured zone by the request host and
// original path and query. It receives neither the token nor forwarded headers.
// It is required for per-zone resource verification and must be concurrency safe.
func WithInboundZoneResolver(resolve func(host, target string) string) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.resolveZone = resolve }
}

// BearerAuth builds HTTP middleware with the binding's issuer and audience policy.
// Per-zone mode requires WithInboundZoneResolver; shared discovery selects the
// issuer from the token using the complete configured zone set.
func (b *ResourceBinding) BearerAuth(opts ...BearerAuthOption) (func(http.Handler) http.Handler, error) {
	cfg := bearerOptions(opts)
	if b.issuer == "" {
		return nil, configurationError("bearer authentication requires a configured issuer")
	}
	if (b.zones != nil && !b.multi) != (cfg.resolveZone != nil) {
		return nil, configurationError("per-zone binding requires a token-independent inbound zone resolver")
	}
	if b.multi && len(b.audiences) == 0 {
		return nil, configurationError("multi_resource requires a nonempty audience list")
	}
	keyring := cfg.keyring
	if keyring == nil {
		keyring = oauth.NewJWKSOAuthKeyring()
	}
	if cfg.resolveZone != nil {
		verifiers := make(map[string]*JWTOAuthTokenVerifier, len(b.zones))
		for zone, id := range b.zones {
			verifier, err := newJWTOAuthTokenVerifier(keyring, []string{b.zoneIssuers[zone]}, oauth.WithAudiences(id.value))
			if err != nil {
				return nil, err
			}
			verifiers[zone] = verifier
		}
		return bearerAuth(cfg, func(r *http.Request) (TokenVerifier, string) {
			zone := cfg.resolveZone(r.Host, receivedTarget(r).RequestURI())
			verifier, ok := verifiers[zone]
			if !ok {
				return nil, ""
			}
			return verifier, b.zones[zone].challengeMetadataURL(r)
		}), nil
	}

	issuers := []string{b.issuer}
	if b.zones != nil {
		issuers = b.trustedZoneIssuers()
	}
	audienceOption := oauth.WithAllowAnyAudience()
	if len(b.audiences) != 0 {
		audienceOption = oauth.WithAudiences(b.audiences...)
	}
	verifier, err := newJWTOAuthTokenVerifier(keyring, issuers, audienceOption)
	if err != nil {
		return nil, err
	}
	return bearerAuth(cfg, func(r *http.Request) (TokenVerifier, string) {
		if b.legacy {
			return verifier, protectedResourceMetadataURL(r)
		}
		return verifier, b.single.challengeMetadataURL(r)
	}), nil
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
	if _, sdkVerifier := verifier.(*JWTOAuthTokenVerifier); !sdkVerifier {
		warnLegacyResourceBinding()
	}
	return bearerAuth(bearerOptions(opts), func(r *http.Request) (TokenVerifier, string) {
		return verifier, protectedResourceMetadataURL(r)
	})
}

func bearerOptions(opts []BearerAuthOption) bearerAuthConfig {
	cfg := bearerAuthConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

func bearerAuth(cfg bearerAuthConfig, selectBinding func(*http.Request) (TokenVerifier, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			verifier, resourceMetadataURL := selectBinding(r)

			credentials := r.Header.Get("Authorization")
			if credentials == "" {
				writeBearerChallenge(w, resourceMetadataURL, "")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if verifier == nil {
				writeBearerChallenge(w, "", `error="invalid_token"`)
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
				writeBearerChallenge(w, resourceMetadataURL, `error="invalid_token", error_description="Unsupported authentication scheme"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			authInfo, err := verifier.VerifyAccessToken(r.Context(), token)
			if err != nil {
				if keysUnavailable(err) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
					return
				}

				var errCode, errMsg string

				switch e := err.(type) {
				case *oauth.InvalidTokenError:
					errCode = e.ErrorCode()
					errMsg = e.Message
				case *oauth.InsufficientScopeError:
					errCode = e.ErrorCode()
					errMsg = e.Message
					writeBearerChallenge(w, resourceMetadataURL, fmt.Sprintf(`error="%s", error_description="%s"`, errCode, errMsg))
					w.WriteHeader(http.StatusForbidden)
					return
				default:
					errCode = "invalid_token"
					errMsg = err.Error()
				}

				writeBearerChallenge(w, resourceMetadataURL, fmt.Sprintf(`error="%s", error_description="%s"`, errCode, errMsg))
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
						writeBearerChallenge(w, resourceMetadataURL, `error="insufficient_scope", error_description="Insufficient scope"`)
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
			}

			// Check expiry
			if authInfo.ExpiresAt > 0 && authInfo.ExpiresAt < time.Now().Unix() {
				writeBearerChallenge(w, resourceMetadataURL, `error="invalid_token", error_description="Token has expired"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), authInfoKey, authInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeBearerChallenge(w http.ResponseWriter, metadataURL, params string) {
	if metadataURL != "" {
		if params != "" {
			params += ", "
		}
		params += fmt.Sprintf(`resource_metadata="%s"`, metadataURL)
	}
	challenge := "Bearer"
	if params != "" {
		challenge += " " + params
	}
	w.Header().Set("WWW-Authenticate", challenge)
}

// protectedResourceMetadataURL constructs the well-known URL for the protected resource
// metadata. Following RFC 9728 path insertion, the protected resource's path is appended
// after the well-known segment (e.g. a resource at /mcp advertises
// .../.well-known/oauth-protected-resource/mcp), so the metadata, and the resource audience
// it carries, match the full endpoint URL rather than the bare origin.
func protectedResourceMetadataURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
			scheme = fwd
		} else {
			scheme = "http"
		}
	}
	resourcePath := r.URL.Path
	if resourcePath == "/" {
		resourcePath = ""
	}
	return fmt.Sprintf("%s://%s%s%s", scheme, r.Host, protectedResourcePath, resourcePath)
}

// keysUnavailable reports whether verification could not complete because the
// zone's signing keys or authorization-server metadata could not be fetched.
// The verifier wraps these as the cause of its InvalidTokenError, so errors.As
// walks the chain. A kid absent from a JWKS that did load
// (JWKSKeyNotFoundError) is not in this set: that token is invalid.
func keysUnavailable(err error) bool {
	var fetchErr *oauth.JWKSFetchError
	var discoveryErr *oauth.JWKSDiscoveryError
	var metadataErr *oauth.InvalidMetadataError
	var httpErr *oauth.HTTPError
	return errors.As(err, &fetchErr) || errors.As(err, &discoveryErr) ||
		errors.As(err, &metadataErr) || errors.As(err, &httpErr)
}
