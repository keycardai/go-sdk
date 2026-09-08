package oauth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// authServer is a test authorization server: it serves discovery metadata pointing at
// its own /authorize and /token, and records the last token-endpoint request.
type authServer struct {
	*httptest.Server
	lastForm     url.Values
	lastAuthUser string // HTTP Basic username, if any
	lastAuthOK   bool
	tokenStatus  int
	tokenBody    string
}

func newAuthServer() *authServer {
	as := &authServer{tokenStatus: http.StatusOK, tokenBody: `{"access_token":"at","token_type":"Bearer","expires_in":3600}`}
	mux := http.NewServeMux()
	as.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 as.URL,
			"authorization_endpoint": as.URL + "/authorize",
			"token_endpoint":         as.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		as.lastForm = r.PostForm
		as.lastAuthUser, _, as.lastAuthOK = r.BasicAuth()
		w.WriteHeader(as.tokenStatus)
		_, _ = w.Write([]byte(as.tokenBody))
	})
	return as
}

func TestBuildAuthorizeURL(t *testing.T) {
	raw, err := BuildAuthorizeURL("https://zone.example.com/authorize", AuthorizeURLParams{
		ClientID:            "client-1",
		RedirectURI:         "http://127.0.0.1:8765/callback",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: PKCEMethodS256,
		Scopes:              []string{"openid", "mcp:tools"},
		State:               "state-123",
		Resource:            "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizeURL: %v", err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "client-1",
		"redirect_uri":          "http://127.0.0.1:8765/callback",
		"code_challenge":        "challenge-value",
		"code_challenge_method": "S256",
		"scope":                 "openid mcp:tools",
		"state":                 "state-123",
		"resource":              "https://api.example.com",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %q: got %q, want %q", k, got, want)
		}
	}
}

func TestBuildAuthorizeURL_DefaultsMethodAndOmitsEmptyScope(t *testing.T) {
	raw, err := BuildAuthorizeURL("https://zone.example.com/authorize", AuthorizeURLParams{
		ClientID:      "client-1",
		RedirectURI:   "http://127.0.0.1:8765/callback",
		CodeChallenge: "challenge-value",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizeURL: %v", err)
	}
	q, _ := url.Parse(raw)
	if q.Query().Get("code_challenge_method") != PKCEMethodS256 {
		t.Errorf("method should default to S256, got %q", q.Query().Get("code_challenge_method"))
	}
	if _, ok := q.Query()["scope"]; ok {
		t.Error("scope should be omitted when no scopes are set")
	}
}

func TestExchangeAuthorizationCode_PublicClient(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	tok, err := ExchangeAuthorizationCode(context.Background(), as.URL, AuthorizationCodeExchangeRequest{
		Code:         "auth-code",
		CodeVerifier: "verifier",
		RedirectURI:  "http://127.0.0.1:8765/callback",
		ClientID:     "public-client",
	}, WithAuthCodeHTTPClient(as.Client()))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token: got %q, want at", tok.AccessToken)
	}

	if as.lastForm.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type: got %q", as.lastForm.Get("grant_type"))
	}
	if as.lastForm.Get("code") != "auth-code" {
		t.Errorf("code: got %q", as.lastForm.Get("code"))
	}
	if as.lastForm.Get("code_verifier") != "verifier" {
		t.Errorf("code_verifier: got %q", as.lastForm.Get("code_verifier"))
	}
	if as.lastForm.Get("redirect_uri") != "http://127.0.0.1:8765/callback" {
		t.Errorf("redirect_uri: got %q", as.lastForm.Get("redirect_uri"))
	}
	if as.lastForm.Get("client_id") != "public-client" {
		t.Errorf("public client should send client_id in the body, got %q", as.lastForm.Get("client_id"))
	}
	if as.lastAuthOK {
		t.Error("public client should not send HTTP Basic auth")
	}
}

func TestExchangeAuthorizationCode_ConfidentialClient(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	_, err := ExchangeAuthorizationCode(context.Background(), as.URL, AuthorizationCodeExchangeRequest{
		Code:         "auth-code",
		CodeVerifier: "verifier",
		RedirectURI:  "http://127.0.0.1:8765/callback",
		ClientID:     "confidential-client",
		ClientSecret: "secret",
	}, WithAuthCodeHTTPClient(as.Client()))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	if !as.lastAuthOK || as.lastAuthUser != "confidential-client" {
		t.Errorf("confidential client should authenticate with HTTP Basic, got user %q ok=%v", as.lastAuthUser, as.lastAuthOK)
	}
	if as.lastForm.Get("client_id") != "" {
		t.Errorf("confidential client should not duplicate client_id in the body, got %q", as.lastForm.Get("client_id"))
	}
}

func TestExchangeAuthorizationCode_OAuthError(t *testing.T) {
	as := newAuthServer()
	defer as.Close()
	as.tokenStatus = http.StatusBadRequest
	as.tokenBody = `{"error":"invalid_grant","error_description":"code expired"}`

	_, err := ExchangeAuthorizationCode(context.Background(), as.URL, AuthorizationCodeExchangeRequest{
		Code:         "expired-code",
		CodeVerifier: "verifier",
		RedirectURI:  "http://127.0.0.1:8765/callback",
		ClientID:     "public-client",
	}, WithAuthCodeHTTPClient(as.Client()))
	if err == nil {
		t.Fatal("expected an error for the OAuth error response")
	}
	oauthErr, ok := err.(*OAuthError)
	if !ok {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_grant" {
		t.Errorf("error code: got %q, want invalid_grant", oauthErr.ErrorCode)
	}
}

func TestAuthenticate_FullLoopbackFlow(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	// The fake browser opener plays the role of the authorization server redirecting
	// back to the loopback listener with a code and the matching state.
	opener := func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		state := u.Query().Get("state")
		cb, err := url.Parse(u.Query().Get("redirect_uri"))
		if err != nil {
			return err
		}
		cbq := cb.Query()
		cbq.Set("code", "loopback-code")
		cbq.Set("state", state)
		cb.RawQuery = cbq.Encode()
		go func() {
			resp, err := http.Get(cb.String())
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	tok, err := Authenticate(context.Background(), as.URL, AuthenticateRequest{
		ClientID:     "public-client",
		Scopes:       []string{"mcp:tools"},
		CallbackPort: EphemeralCallbackPort,
	}, WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(opener))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token: got %q, want at", tok.AccessToken)
	}
	if as.lastForm.Get("code") != "loopback-code" {
		t.Errorf("exchanged code: got %q, want loopback-code", as.lastForm.Get("code"))
	}
	assertEphemeralRedirectURI(t, as.lastForm.Get("redirect_uri"))
}

// assertEphemeralRedirectURI checks that a redirect_uri synthesized with
// EphemeralCallbackPort carries the OS-assigned loopback port, not the default.
func assertEphemeralRedirectURI(t *testing.T, redirectURI string) {
	t.Helper()
	u, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("redirect_uri %q: %v", redirectURI, err)
	}
	if u.Hostname() != "127.0.0.1" || u.Path != defaultCallbackPath {
		t.Errorf("redirect_uri %q should be http://127.0.0.1:<port>%s", redirectURI, defaultCallbackPath)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 {
		t.Fatalf("redirect_uri %q should carry the bound port", redirectURI)
	}
	if port == defaultCallbackPort {
		t.Errorf("redirect_uri %q carries the default port; an ephemeral port was requested", redirectURI)
	}
}

func TestAuthenticate_StateMismatchRejected(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	opener := func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		cb, _ := url.Parse(u.Query().Get("redirect_uri"))
		cbq := cb.Query()
		cbq.Set("code", "loopback-code")
		cbq.Set("state", "the-wrong-state")
		cb.RawQuery = cbq.Encode()
		go func() {
			resp, err := http.Get(cb.String())
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	_, err := Authenticate(context.Background(), as.URL, AuthenticateRequest{
		ClientID:     "public-client",
		CallbackPort: EphemeralCallbackPort,
	}, WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(opener))
	if err == nil {
		t.Fatal("expected an error when the callback state does not match")
	}
}

func TestAuthenticate_IgnoresNonGetCallback(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	// A stray non-GET probe (e.g. OPTIONS) to the callback must not consume the
	// result channel and abort the flow; the real GET redirect still completes it.
	opener := func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		state := u.Query().Get("state")
		cb, err := url.Parse(u.Query().Get("redirect_uri"))
		if err != nil {
			return err
		}
		go func() {
			req, _ := http.NewRequest(http.MethodOptions, cb.String(), nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
			q := cb.Query()
			q.Set("code", "loopback-code")
			q.Set("state", state)
			cb.RawQuery = q.Encode()
			if resp, err := http.Get(cb.String()); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	tok, err := Authenticate(context.Background(), as.URL, AuthenticateRequest{
		ClientID:     "public-client",
		CallbackPort: EphemeralCallbackPort,
	}, WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(opener))
	if err != nil {
		t.Fatalf("non-GET probe should be ignored and the flow should complete: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token: got %q, want at", tok.AccessToken)
	}
	assertEphemeralRedirectURI(t, as.lastForm.Get("redirect_uri"))
}

func TestAuthenticate_ExplicitRedirectURIListensOnItsHost(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	// Reserve a free port, release it, and hand it to Authenticate as an explicit
	// RedirectURI so the parse-then-listen path is exercised without a fixed port.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := probe.Addr().String()
	probe.Close()
	redirectURI := "http://" + host + "/cb"

	var seen string
	opener := func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		seen = u.Query().Get("redirect_uri")
		cb, _ := url.Parse(seen)
		cbq := cb.Query()
		cbq.Set("code", "loopback-code")
		cbq.Set("state", u.Query().Get("state"))
		cb.RawQuery = cbq.Encode()
		go func() {
			if resp, err := http.Get(cb.String()); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}

	_, err = Authenticate(context.Background(), as.URL, AuthenticateRequest{
		ClientID:    "public-client",
		RedirectURI: redirectURI,
	}, WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(opener))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if seen != redirectURI || as.lastForm.Get("redirect_uri") != redirectURI {
		t.Errorf("explicit redirect URI must be used verbatim: authorize=%q exchanged=%q", seen, as.lastForm.Get("redirect_uri"))
	}
}

func TestAuthenticate_DefaultCallbackPortIsUnchanged(t *testing.T) {
	if defaultCallbackPort != 8765 {
		t.Fatalf("default callback port: got %d, want 8765", defaultCallbackPort)
	}
	if EphemeralCallbackPort == 0 {
		t.Fatal("the ephemeral sentinel must not collide with the zero value that selects the default port")
	}
}

func TestResolveIssuerFromChallenge(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srv.URL,
			"authorization_servers": []string{"https://zone.keycard.cloud"},
		})
	})

	header := `Bearer error="invalid_token", resource_metadata="` + srv.URL + `/.well-known/oauth-protected-resource"`
	issuer, err := ResolveIssuerFromChallenge(context.Background(), header, srv.Client())
	if err != nil {
		t.Fatalf("ResolveIssuerFromChallenge: %v", err)
	}
	if issuer != "https://zone.keycard.cloud" {
		t.Errorf("issuer: got %q, want https://zone.keycard.cloud", issuer)
	}
}

func TestResolveIssuerFromChallenge_NoMetadata(t *testing.T) {
	if _, err := ResolveIssuerFromChallenge(context.Background(), `Bearer error="invalid_token"`, nil); err == nil {
		t.Error("expected an error when the challenge has no resource_metadata")
	}
}
