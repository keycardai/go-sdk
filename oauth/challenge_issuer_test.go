package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// Challenge-resolved issuer pinning: Authorization Code with PKCE unit rows 23 to 28
// (spec-version 7). Client authentication goes to an issuer resolved from a challenge
// only when WithAllowedIssuers lists it.

// resourceMetadataServer serves an RFC 9728 document naming issuer and counts fetches.
func resourceMetadataServer(t *testing.T, issuer string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"authorization_servers": []string{issuer}})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// countingServer counts every request and answers 500, standing in for an issuer the
// flow must not contact.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func challengeFor(prm *httptest.Server) string {
	return `Bearer resource_metadata="` + prm.URL + `/.well-known/oauth-protected-resource"`
}

// loopbackOpener plays the authorization server: it redirects back to the loopback
// listener with a code and the request's state.
func loopbackOpener(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	cb, err := url.Parse(u.Query().Get("redirect_uri"))
	if err != nil {
		return err
	}
	cb.RawQuery = url.Values{"code": {"loopback-code"}, "state": {u.Query().Get("state")}}.Encode()
	go func() {
		resp, err := http.Get(cb.String())
		if err == nil {
			resp.Body.Close()
		}
	}()
	return nil
}

func noBrowser(t *testing.T) AuthenticateOption {
	return WithBrowserOpener(func(string) error { t.Error("browser should not open"); return nil })
}

func challengeClientAuths(t *testing.T) map[string]AuthenticateRequest {
	t.Helper()
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(context.Context) (string, error) { return "platform-token", nil }),
		WithWorkloadClientID("acr_123"))
	if err != nil {
		t.Fatalf("NewWorkloadIdentity: %v", err)
	}
	return map[string]AuthenticateRequest{
		"client secret": {ClientID: "c", ClientSecret: "s", CallbackPort: EphemeralCallbackPort},
		"credential":    {ClientID: "acr_123", Credential: cred, CallbackPort: EphemeralCallbackPort},
	}
}

func TestAuthenticateFromChallenge_ClientAuthWithoutAllowedIssuers(t *testing.T) {
	for name, req := range challengeClientAuths(t) {
		for _, opts := range [][]AuthenticateOption{nil, {WithAllowedIssuers()}} {
			t.Run(name, func(t *testing.T) {
				issuer, issuerHits := countingServer(t)
				prm, prmHits := resourceMetadataServer(t, issuer.URL)

				_, err := AuthenticateFromChallenge(context.Background(), challengeFor(prm), req, append(opts, noBrowser(t))...)
				var cfgErr *ConfigurationError
				if !errors.As(err, &cfgErr) {
					t.Fatalf("error: got %v, want ConfigurationError", err)
				}
				if prmHits.Load() != 0 || issuerHits.Load() != 0 {
					t.Errorf("no request should be sent: resource metadata %d, issuer %d", prmHits.Load(), issuerHits.Load())
				}
			})
		}
	}
}

func TestAuthenticateFromChallenge_IssuerNotAllowed(t *testing.T) {
	reqs := challengeClientAuths(t)
	reqs["public client"] = AuthenticateRequest{ClientID: "public-client", CallbackPort: EphemeralCallbackPort}
	for name, req := range reqs {
		t.Run(name, func(t *testing.T) {
			issuer, issuerHits := countingServer(t)
			prm, prmHits := resourceMetadataServer(t, issuer.URL)

			_, err := AuthenticateFromChallenge(context.Background(), challengeFor(prm), req,
				WithAllowedIssuers("https://zone.keycard.cloud"), noBrowser(t))
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v, want ConfigurationError", err)
			}
			if !strings.Contains(err.Error(), issuer.URL) {
				t.Errorf("error %q should name the resolved issuer %s", err, issuer.URL)
			}
			if prmHits.Load() != 1 {
				t.Errorf("resource metadata fetches: got %d, want 1", prmHits.Load())
			}
			if issuerHits.Load() != 0 {
				t.Errorf("no request should reach the resolved issuer, got %d", issuerHits.Load())
			}
		})
	}
}

func TestAuthenticateFromChallenge_AllowedIssuerReceivesClientAuth(t *testing.T) {
	for name, req := range challengeClientAuths(t) {
		t.Run(name, func(t *testing.T) {
			as := newAuthServer()
			defer as.Close()
			prm, _ := resourceMetadataServer(t, as.URL+"/")

			_, err := AuthenticateFromChallenge(context.Background(), challengeFor(prm), req,
				WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(loopbackOpener),
				WithAllowedIssuers(as.URL))
			if err != nil {
				t.Fatalf("AuthenticateFromChallenge: %v", err)
			}
			if req.ClientSecret != "" && (!as.lastAuthOK || as.lastAuthUser != "c") {
				t.Errorf("token request should carry HTTP Basic for c, got user %q ok=%v", as.lastAuthUser, as.lastAuthOK)
			}
			if req.Credential != nil && as.lastForm.Get("client_assertion") != "platform-token" {
				t.Errorf("token request should carry the credential's assertion, got %q", as.lastForm.Get("client_assertion"))
			}
		})
	}
}

func TestAuthenticateFromChallenge_PublicClientNeedsNoAllowedIssuers(t *testing.T) {
	as := newAuthServer()
	defer as.Close()
	prm, _ := resourceMetadataServer(t, as.URL)

	tok, err := AuthenticateFromChallenge(context.Background(), challengeFor(prm),
		AuthenticateRequest{ClientID: "public-client", CallbackPort: EphemeralCallbackPort},
		WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(loopbackOpener))
	if err != nil {
		t.Fatalf("AuthenticateFromChallenge: %v", err)
	}
	if tok.AccessToken != "at" || as.lastForm.Get("client_id") != "public-client" {
		t.Errorf("public client flow: token %q, client_id %q", tok.AccessToken, as.lastForm.Get("client_id"))
	}
}

func TestAuthenticate_IssuerDirectClientAuthNeedsNoAllowedIssuers(t *testing.T) {
	as := newAuthServer()
	defer as.Close()

	_, err := Authenticate(context.Background(), as.URL,
		AuthenticateRequest{ClientID: "c", ClientSecret: "s", CallbackPort: EphemeralCallbackPort},
		WithAuthenticateHTTPClient(as.Client()), WithBrowserOpener(loopbackOpener))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !as.lastAuthOK || as.lastAuthUser != "c" {
		t.Errorf("token request should carry HTTP Basic for c, got user %q ok=%v", as.lastAuthUser, as.lastAuthOK)
	}
}
