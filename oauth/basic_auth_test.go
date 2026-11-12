package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// splitBasic decodes an HTTP Basic credential and splits it at the first colon, as a
// server does. It returns the two halves still encoded.
func splitBasic(t *testing.T, header string) (string, string) {
	t.Helper()
	raw, ok := strings.CutPrefix(header, "Basic ")
	if !ok {
		t.Fatalf("Authorization = %q, want a Basic credential", header)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decoding Basic credential: %v", err)
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		t.Fatalf("Basic credential %q has no colon", decoded)
	}
	return user, pass
}

func TestBasicCredentials(t *testing.T) {
	tests := []struct {
		name               string
		clientID, secret   string
		wantUser, wantPass string
	}{
		{"unreserved characters", "client-1_a.b~", "secret", "client-1_a.b~", "secret"},
		{"colon in the client ID", "ua:client", "secret", "ua%3Aclient", "secret"},
		{"base64 secret", "client", "ab+c/d==", "client", "ab%2Bc%2Fd%3D%3D"},
		{"space", "my client", "a b", "my%20client", "a%20b"},
		{"literal percent escape", "client", "%41", "client", "%2541"},
		{"non-Latin-1 text", "клиент", "密钥", "%D0%BA%D0%BB%D0%B8%D0%B5%D0%BD%D1%82", "%E5%AF%86%E9%92%A5"},
		{"RFC 6749 Appendix B input", "c", " %&+£€", "c", "%20%25%26%2B%C2%A3%E2%82%AC"},
		{"!*'() are encoded", "c", "a~!*'()b", "c", "a~%21%2A%27%28%29b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass := splitBasic(t, "Basic "+basicCredentials(tt.clientID, tt.secret))
			if user != tt.wantUser || pass != tt.wantPass {
				t.Fatalf("encoded = %q:%q, want %q:%q", user, pass, tt.wantUser, tt.wantPass)
			}
			// A Keycard zone percent-decodes each half. Other servers form-decode.
			// Both must give back the input.
			decoders := map[string]func(string) (string, error){
				"percent": url.PathUnescape,
				"form":    url.QueryUnescape,
			}
			for name, decode := range decoders {
				gotUser, err := decode(user)
				if err != nil {
					t.Fatalf("%s-decoding client ID: %v", name, err)
				}
				gotPass, err := decode(pass)
				if err != nil {
					t.Fatalf("%s-decoding secret: %v", name, err)
				}
				if gotUser != tt.clientID || gotPass != tt.secret {
					t.Errorf("%s-decoded = %q:%q, want %q:%q", name, gotUser, gotPass, tt.clientID, tt.secret)
				}
			}
		})
	}
}

// TestBasicAuth_Grants checks that every grant that authenticates with a client ID and
// secret sends them percent-encoded.
func TestBasicAuth_Grants(t *testing.T) {
	const clientID, secret = "ua:client", "a b+%41"
	const wantUser, wantPass = "ua%3Aclient", "a%20b%2B%2541"

	var gotAuth string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	})

	ctx := context.Background()
	grants := []struct {
		name string
		run  func() error
	}{
		{"authorization code", func() error {
			_, err := ExchangeAuthorizationCode(ctx, srv.URL, AuthorizationCodeExchangeRequest{
				Code: "code", CodeVerifier: "verifier", RedirectURI: "http://127.0.0.1/callback",
				ClientID: clientID, ClientSecret: secret,
			})
			return err
		}},
		{"client credentials", func() error {
			_, err := NewClientCredentialsClient(srv.URL, WithCCBasicAuth(clientID, secret)).
				RequestToken(ctx, ClientCredentialsRequest{Resource: "urn:r"})
			return err
		}},
		{"token exchange", func() error {
			_, err := NewTokenExchangeClient(srv.URL, WithClientCredentials(clientID, secret)).
				ExchangeToken(ctx, TokenExchangeRequest{SubjectToken: "st", Resource: "urn:r"})
			return err
		}},
	}
	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			gotAuth = ""
			if err := g.run(); err != nil {
				t.Fatalf("request: %v", err)
			}
			user, pass := splitBasic(t, gotAuth)
			if user != wantUser || pass != wantPass {
				t.Errorf("Basic credential = %q:%q, want %q:%q", user, pass, wantUser, wantPass)
			}
		})
	}
}
