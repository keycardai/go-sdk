package mcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

// WithIntrospect enables an uncached token introspection check after local
// verification and scope checks. The default is false.
func WithIntrospect(enabled bool) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.introspect = enabled }
}

// WithIntrospectionCredential supplies the credential of the Application that
// owns the protected resource. A zone-keyed credential uses verified issuer URLs
// as keys. A credential without zone keys requires exactly one trusted issuer.
func WithIntrospectionCredential(credential oauth.ApplicationCredential) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.credential = credential }
}

// WithIntrospectionHTTPClient sets the HTTP client for introspection and its
// discovery requests. Both requests stop at redirects.
func WithIntrospectionHTTPClient(client *http.Client) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.introspectHTTP = client }
}

// WithIntrospectionRequestTimeout sets the timeout for each introspection or
// discovery request whose context has no deadline. The default is 10 seconds.
func WithIntrospectionRequestTimeout(timeout time.Duration) BearerAuthOption {
	return func(cfg *bearerAuthConfig) { cfg.introspectTime = timeout }
}

type bearerIntrospection struct {
	credential oauth.ApplicationCredential
	issuers    map[string]struct{}
	zones      map[string]struct{}
	options    []oauth.IntrospectionOption
	logged     sync.Map
}

func (cfg bearerAuthConfig) newIntrospection(trustedIssuers []string) (*bearerIntrospection, error) {
	if !cfg.introspect {
		return nil, nil
	}
	cred := cfg.credential
	if _, ok := cred.(oauth.ClientAuthenticator); !ok || nilPointer(cred) {
		return nil, configurationError("introspection requires a credential with client authentication")
	}
	if web, ok := cred.(*oauth.WebIdentityCredential); ok && web.ClientID() == "" {
		return nil, configurationError("introspection requires a web identity credential with a client id")
	}
	in := &bearerIntrospection{
		credential: cred,
		issuers:    make(map[string]struct{}, len(trustedIssuers)),
		zones:      make(map[string]struct{}),
	}
	for _, issuer := range trustedIssuers {
		if issuer != "" {
			in.issuers[issuer] = struct{}{}
		}
	}
	if keyed, ok := cred.(oauth.MultiZoneCredential); ok {
		for _, zone := range keyed.Zones() {
			if zone != "" {
				in.zones[zone] = struct{}{}
			}
		}
	}
	if len(in.zones) == 0 {
		if len(in.issuers) != 1 {
			return nil, configurationError("introspection requires a zone-keyed credential unless exactly one issuer is trusted")
		}
		if secret, ok := cred.(*oauth.ClientSecretCredential); ok {
			auth := secret.Auth("")
			if auth == nil || auth.ClientID == "" || auth.ClientSecret == "" {
				return nil, configurationError("introspection requires a client id and client secret")
			}
		}
	}
	client := cfg.introspectHTTP
	if client == nil {
		client = http.DefaultClient
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	in.options = append(in.options, oauth.WithIntrospectionHTTPClient(&noRedirect))
	if cfg.introspectTime > 0 {
		in.options = append(in.options, oauth.WithIntrospectionRequestTimeout(cfg.introspectTime))
	}
	return in, nil
}

func nilPointer(v any) bool {
	value := reflect.ValueOf(v)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func (in *bearerIntrospection) check(ctx context.Context, issuer, token string) (bool, error) {
	if _, trusted := in.issuers[issuer]; issuer == "" || (len(in.issuers) != 0 && !trusted) {
		return false, configurationError("introspection requires a verified trusted issuer")
	}
	if _, configured := in.zones[issuer]; len(in.zones) != 0 && !configured {
		return false, configurationError(fmt.Sprintf("no introspection credential for zone %q", issuer))
	}
	result, err := oauth.IntrospectToken(ctx, issuer, oauth.IntrospectTokenRequest{
		Token: token, Credential: in.credential,
	}, in.options...)
	if err != nil {
		return false, err
	}
	return result.Active, nil
}

func (in *bearerIntrospection) logFailure(err error) {
	cause := fmt.Sprintf("%T", err)
	key := sha256.Sum256([]byte(cause + ":" + err.Error()))
	if _, logged := in.logged.LoadOrStore(key, struct{}{}); logged {
		return
	}
	var oauthErr *oauth.OAuthError
	var httpErr *oauth.HTTPError
	switch {
	case errors.As(err, &oauthErr):
		status := oauthErr.Status
		switch oauthErr.ErrorCode {
		case "invalid_client", "invalid_request", "invalid_response", "server_error", "temporarily_unavailable":
			cause = fmt.Sprintf("OAuth %s (HTTP %d)", oauthErr.ErrorCode, status)
		default:
			cause = fmt.Sprintf("OAuth error (HTTP %d)", status)
		}
	case errors.As(err, &httpErr):
		cause = fmt.Sprintf("HTTP %d", httpErr.Status)
	case errors.Is(err, context.DeadlineExceeded):
		cause = "request deadline exceeded"
	case errors.Is(err, context.Canceled):
		cause = "request canceled"
	}
	slog.Warn("keycard: token introspection failed", "cause", cause)
}
