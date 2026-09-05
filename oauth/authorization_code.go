package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Loopback flow defaults (RFC 8252), aligned with the Python and TS SDKs.
const (
	defaultCallbackPort    = 8765
	defaultCallbackTimeout = 300 * time.Second
	defaultCallbackPath    = "/callback"
)

// AuthorizeURLParams are the inputs to BuildAuthorizeURL.
type AuthorizeURLParams struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string   // defaults to S256 when empty
	Scopes              []string // optional; space-joined on the wire
	State               string   // optional CSRF token
	Resource            string   // optional RFC 8707 resource indicator
}

// BuildAuthorizeURL builds an authorization-code request URL against the given
// authorization endpoint (RFC 6749 §4.1.1 with the RFC 7636 PKCE parameters).
func BuildAuthorizeURL(authorizationEndpoint string, params AuthorizeURLParams) (string, error) {
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("parsing authorization endpoint: %w", err)
	}

	method := params.CodeChallengeMethod
	if method == "" {
		method = PKCEMethodS256
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", params.ClientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", method)
	if len(params.Scopes) > 0 {
		q.Set("scope", strings.Join(params.Scopes, " "))
	}
	if params.State != "" {
		q.Set("state", params.State)
	}
	if params.Resource != "" {
		q.Set("resource", params.Resource)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// AuthorizationCodeExchangeRequest exchanges an authorization code for a token.
// A public client sets ClientID (sent in the body); a confidential client sets
// ClientSecret as well and is authenticated with HTTP Basic, with ClientID omitted
// from the body.
type AuthorizationCodeExchangeRequest struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	Resource     string // optional RFC 8707 resource indicator
}

// AuthCodeExchangeOption configures ExchangeAuthorizationCode.
type AuthCodeExchangeOption func(*authCodeExchangeConfig)

type authCodeExchangeConfig struct {
	httpClient *http.Client
}

// WithAuthCodeHTTPClient sets the HTTP client used for discovery and code exchange.
func WithAuthCodeHTTPClient(c *http.Client) AuthCodeExchangeOption {
	return func(cfg *authCodeExchangeConfig) { cfg.httpClient = c }
}

// ExchangeAuthorizationCode exchanges an authorization code at the issuer's token
// endpoint (resolved by discovery) for a token. The response has the same shape as
// Token Exchange.
func ExchangeAuthorizationCode(ctx context.Context, issuer string, req AuthorizationCodeExchangeRequest, opts ...AuthCodeExchangeOption) (*TokenResponse, error) {
	cfg := authCodeExchangeConfig{httpClient: http.DefaultClient}
	for _, opt := range opts {
		opt(&cfg)
	}

	tokenEndpoint, err := resolveTokenEndpoint(ctx, issuer, cfg.httpClient)
	if err != nil {
		return nil, err
	}
	return exchangeCodeAtEndpoint(ctx, tokenEndpoint, req, cfg.httpClient)
}

func exchangeCodeAtEndpoint(ctx context.Context, tokenEndpoint string, req AuthorizationCodeExchangeRequest, httpClient *http.Client) (*TokenResponse, error) {
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", req.Code)
	body.Set("code_verifier", req.CodeVerifier)
	body.Set("redirect_uri", req.RedirectURI)
	if req.Resource != "" {
		body.Set("resource", req.Resource)
	}

	confidential := req.ClientSecret != ""
	if !confidential && req.ClientID != "" {
		body.Set("client_id", req.ClientID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating code exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if confidential {
		httpReq.SetBasicAuth(req.ClientID, req.ClientSecret)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("code exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, oauthErrorFromResponse(resp)
	}
	return deserializeTokenResponse(resp)
}

// oauthErrorFromResponse converts a non-2xx token-endpoint response into an *OAuthError
// when the body carries an RFC 6749 §5.2 error, or a generic error otherwise.
func oauthErrorFromResponse(resp *http.Response) error {
	if oauthErr := parseOAuthErrorResponse(resp); oauthErr != nil {
		return oauthErr
	}
	return fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
}

// AuthenticateRequest configures the high-level loopback login flow. Zero-valued
// optional fields take their documented defaults.
type AuthenticateRequest struct {
	ClientID        string
	Scopes          []string
	RedirectURI     string        // default http://127.0.0.1:<CallbackPort><defaultCallbackPath>
	CallbackPort    int           // default 8765
	CallbackTimeout time.Duration // default 300s
	ClientSecret    string        // set for a confidential client
	Resource        string        // optional RFC 8707 resource indicator
}

// AuthenticateOption configures the transport and browser launcher of the high-level flow.
type AuthenticateOption func(*authenticateConfig)

type authenticateConfig struct {
	httpClient  *http.Client
	openBrowser func(rawURL string) error
}

// WithAuthenticateHTTPClient sets the HTTP client used for discovery and code exchange.
func WithAuthenticateHTTPClient(c *http.Client) AuthenticateOption {
	return func(cfg *authenticateConfig) { cfg.httpClient = c }
}

// WithBrowserOpener overrides how the authorize URL is opened. The default launches
// the system browser; tests and headless environments can supply their own.
func WithBrowserOpener(open func(rawURL string) error) AuthenticateOption {
	return func(cfg *authenticateConfig) { cfg.openBrowser = open }
}

// Authenticate runs the full authorization-code-with-PKCE flow: it generates a PKCE
// pair and CSRF state, opens the browser to the authorize URL, runs a loopback server
// to receive the redirect, validates the returned state, and exchanges the code for a
// token. The issuer's endpoints are resolved by discovery.
func Authenticate(ctx context.Context, issuer string, req AuthenticateRequest, opts ...AuthenticateOption) (*TokenResponse, error) {
	cfg := authenticateConfig{httpClient: http.DefaultClient, openBrowser: openBrowser}
	for _, opt := range opts {
		opt(&cfg)
	}

	port := req.CallbackPort
	if port == 0 {
		port = defaultCallbackPort
	}
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("http://127.0.0.1:%d%s", port, defaultCallbackPath)
	}
	timeout := req.CallbackTimeout
	if timeout == 0 {
		timeout = defaultCallbackTimeout
	}

	metadata, err := FetchAuthorizationServerMetadata(ctx, issuer, WithDiscoveryHTTPClient(cfg.httpClient))
	if err != nil {
		return nil, fmt.Errorf("discovering authorization server: %w", err)
	}
	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("authorization server %q is missing an authorization or token endpoint", issuer)
	}

	pkce, err := GeneratePKCEPair()
	if err != nil {
		return nil, err
	}
	state, err := generateState()
	if err != nil {
		return nil, err
	}

	authorizeURL, err := BuildAuthorizeURL(metadata.AuthorizationEndpoint, AuthorizeURLParams{
		ClientID:            req.ClientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       pkce.CodeChallenge,
		CodeChallengeMethod: pkce.CodeChallengeMethod,
		Scopes:              req.Scopes,
		State:               state,
		Resource:            req.Resource,
	})
	if err != nil {
		return nil, err
	}

	code, err := runLoopbackFlow(ctx, redirectURI, state, timeout, func() error {
		return cfg.openBrowser(authorizeURL)
	})
	if err != nil {
		return nil, err
	}

	return exchangeCodeAtEndpoint(ctx, metadata.TokenEndpoint, AuthorizationCodeExchangeRequest{
		Code:         code,
		CodeVerifier: pkce.CodeVerifier,
		RedirectURI:  redirectURI,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Resource:     req.Resource,
	}, cfg.httpClient)
}

// AuthenticateFromChallenge resolves the issuer from an RFC 9728 WWW-Authenticate
// challenge, then runs Authenticate against it.
func AuthenticateFromChallenge(ctx context.Context, wwwAuthenticateHeader string, req AuthenticateRequest, opts ...AuthenticateOption) (*TokenResponse, error) {
	cfg := authenticateConfig{httpClient: http.DefaultClient}
	for _, opt := range opts {
		opt(&cfg)
	}
	issuer, err := ResolveIssuerFromChallenge(ctx, wwwAuthenticateHeader, cfg.httpClient)
	if err != nil {
		return nil, err
	}
	return Authenticate(ctx, issuer, req, opts...)
}

// ResolveIssuerFromChallenge reads the resource_metadata URL from an RFC 6750
// WWW-Authenticate challenge, fetches the RFC 9728 protected-resource metadata, and
// returns its first advertised authorization server. A nil httpClient uses the default.
func ResolveIssuerFromChallenge(ctx context.Context, wwwAuthenticateHeader string, httpClient *http.Client) (string, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	metadataURL := resourceMetadataURLFromChallenge(wwwAuthenticateHeader)
	if metadataURL == "" {
		return "", fmt.Errorf("WWW-Authenticate challenge has no resource_metadata parameter")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating resource metadata request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("fetching resource metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", &HTTPError{Message: "fetching resource metadata", Status: resp.StatusCode}
	}

	var prm struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		return "", fmt.Errorf("decoding resource metadata: %w", err)
	}
	if len(prm.AuthorizationServers) == 0 {
		return "", fmt.Errorf("resource metadata advertises no authorization servers")
	}
	return prm.AuthorizationServers[0], nil
}

// resourceMetadataURLFromChallenge extracts the resource_metadata="<url>" parameter
// from a WWW-Authenticate header value.
func resourceMetadataURLFromChallenge(header string) string {
	const key = `resource_metadata="`
	i := strings.Index(header, key)
	if i < 0 {
		return ""
	}
	rest := header[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// runLoopbackFlow starts a loopback HTTP server at redirectURI, invokes open to launch
// the browser, and waits for the redirect carrying the authorization code. It validates
// that the returned state matches and that no error parameter was sent.
func runLoopbackFlow(ctx context.Context, redirectURI, wantState string, timeout time.Duration, open func() error) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parsing redirect URI: %w", err)
	}
	path := u.Path
	if path == "" {
		path = defaultCallbackPath
	}

	listener, err := net.Listen("tcp", u.Host)
	if err != nil {
		return "", fmt.Errorf("starting loopback listener on %s: %w", u.Host, err)
	}

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// The authorization server delivers the code via a browser GET redirect.
		// Ignore any other method (an OPTIONS probe, a scanner, a stray request) so
		// it cannot consume the one-shot result channel and abort the flow.
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if oauthErr := q.Get("error"); oauthErr != "" {
			http.Error(w, "Authentication failed. You can close this window.", http.StatusBadRequest)
			oe := &OAuthError{ErrorCode: oauthErr, Message: oauthErr}
			if desc := q.Get("error_description"); desc != "" {
				oe.Message = desc
			}
			resultCh <- result{err: oe}
			return
		}
		if q.Get("state") != wantState {
			http.Error(w, "Authentication failed. You can close this window.", http.StatusBadRequest)
			resultCh <- result{err: fmt.Errorf("authorization-code callback state mismatch")}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "Authentication failed. You can close this window.", http.StatusBadRequest)
			resultCh <- result{err: fmt.Errorf("authorization-code callback missing code")}
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Authentication complete. You can close this window."))
		resultCh <- result{code: code}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := open(); err != nil {
		return "", fmt.Errorf("opening browser: %w", err)
	}

	select {
	case res := <-resultCh:
		return res.code, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out after %s waiting for the authorization redirect", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating state: %w", err)
	}
	return Base64URLEncode(b), nil
}

// openBrowser launches the system browser without a shell (exec.Command does not
// invoke a shell, so the URL is not subject to shell interpretation).
func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "windows":
		// The empty argument is the window title that "start" expects first.
		return exec.Command("cmd", "/c", "start", "", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}
