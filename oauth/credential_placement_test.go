package oauth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Rows name the Unit Tests rows of specs/oauth-client/credential-placement.md
// in keycard-sdk-spec.

func apiKeyToken(key, method string) *TokenResponse {
	return &TokenResponse{AccessToken: key, TokenType: TokenTypeKeycardAPIKey, Method: []byte(method)}
}

func passwordToken(username, password, method string) *TokenResponse {
	return &TokenResponse{AccessToken: password, TokenType: TokenTypeKeycardPassword, Username: username, Method: []byte(method)}
}

func allowAll(string) bool { return true }

func TestPlaceCredential(t *testing.T) {
	header := func(name, value string) CredentialField {
		return CredentialField{In: CredentialInHeader, Name: name, Value: value}
	}
	cookieKey := "!#$%&'()*+-./09:<=>?@AZ[]^_`az{|}~"
	for _, tc := range []struct {
		row   int
		token *TokenResponse
		opts  []PlacementOption
		want  CredentialPlacement
	}{
		{row: 1, token: &TokenResponse{AccessToken: "t", TokenType: "Bearer"},
			want: CredentialPlacement{header("Authorization", "Bearer t")}},
		{row: 2, token: &TokenResponse{AccessToken: "t"},
			want: CredentialPlacement{header("Authorization", "Bearer t")}},
		{row: 3, token: &TokenResponse{AccessToken: "t", TokenType: "bearer", Method: []byte(`{"in":"header","name":"X-API-Key"}`)},
			want: CredentialPlacement{header("Authorization", "Bearer t")}},
		{row: 4, token: &TokenResponse{AccessToken: "pw", TokenType: "Basic", UserID: "svc"},
			want: CredentialPlacement{header("Authorization", "Basic c3ZjOnB3")}},
		{row: 5, token: apiKeyToken("k", `{"in":"header","name":"X-API-Key"}`),
			want: CredentialPlacement{header("X-API-Key", "k")}},
		{row: 6, token: apiKeyToken("k", `{"in":"header","name":"authorization"}`),
			want: CredentialPlacement{header("authorization", "k")}},
		{row: 7, token: apiKeyToken("k", `{"in":"query","name":"api_key"}`),
			want: CredentialPlacement{{In: CredentialInQuery, Name: "api_key", Value: "k"}}},
		{row: 8, token: apiKeyToken("k", `{"in":"cookie","name":"X-API-KEY"}`),
			want: CredentialPlacement{{In: CredentialInCookie, Name: "X-API-KEY", Value: "k"}}},
		{row: 9, token: apiKeyToken("k", `{"in":"scheme","name":"Sentry-Bearer"}`),
			want: CredentialPlacement{header("Authorization", "Sentry-Bearer k")}},
		{row: 10, token: apiKeyToken("u+abc123", `{"in":"scheme","name":"Token","scheme_parameter":"token"}`),
			want: CredentialPlacement{header("Authorization", "Token token=u+abc123")}},
		{row: 11, token: &TokenResponse{AccessToken: "k", TokenType: "keycard-api-key", Method: []byte(`{"in":"header","name":"X-API-Key"}`)},
			want: CredentialPlacement{header("X-API-Key", "k")}},
		{row: 12, token: passwordToken("plaid-client-id", "plaid-secret",
			`{"username":{"in":"header","name":"PLAID-CLIENT-ID"},"password":{"in":"header","name":"PLAID-SECRET"}}`),
			want: CredentialPlacement{header("PLAID-CLIENT-ID", "plaid-client-id"), header("PLAID-SECRET", "plaid-secret")}},
		{row: 13, token: passwordToken("u", "p",
			`{"username":{"in":"query","name":"client_id"},"password":{"in":"header","name":"Authorization"}}`),
			want: CredentialPlacement{{In: CredentialInQuery, Name: "client_id", Value: "u"}, header("Authorization", "p")}},
		{row: 14, token: apiKeyToken("k", `{"in":"header","name":"Mcp-Session-Id"}`),
			want: CredentialPlacement{header("Mcp-Session-Id", "k")}},
		{row: 15, token: apiKeyToken("k", `{"in":"header","name":"Host"}`), opts: []PlacementOption{WithPlacementAllowHeader(allowAll)},
			want: CredentialPlacement{header("Host", "k")}},
		{row: 16, token: apiKeyToken(cookieKey, `{"in":"cookie","name":"k"}`),
			want: CredentialPlacement{{In: CredentialInCookie, Name: "k", Value: cookieKey}}},
	} {
		t.Run(fmt.Sprintf("row %d", tc.row), func(t *testing.T) {
			got, err := PlaceCredential(tc.token, tc.opts...)
			if err != nil {
				t.Fatalf("PlaceCredential: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("placement: got %#v, want %#v", []CredentialField(got), []CredentialField(tc.want))
				for i := range got {
					t.Logf("got[%d] value %q", i, got[i].Value)
				}
			}
		})
	}
}

func TestPlaceCredential_Refusals(t *testing.T) {
	const secret = "s3cret-value"
	refuseInternal := WithPlacementAllowHeader(func(name string) bool {
		return DefaultAllowHeader(name) && !strings.HasPrefix(strings.ToLower(name), "x-internal-")
	})
	type refusal struct {
		token *TokenResponse
		opts  []PlacementOption
	}
	for _, tc := range []struct {
		row   int
		cases []refusal
		want  CredentialPlacementReason
	}{
		{row: 17, want: PlacementUnsupportedTokenType, cases: []refusal{{token: &TokenResponse{AccessToken: secret, TokenType: "MAC"}}}},
		{row: 18, want: PlacementUnsupportedTokenType, cases: []refusal{{token: &TokenResponse{AccessToken: secret, TokenType: "N_A"}}}},
		{row: 19, want: PlacementInvalidMethod, cases: []refusal{
			{token: &TokenResponse{AccessToken: secret, TokenType: TokenTypeKeycardAPIKey}},
			{token: apiKeyToken(secret, `null`)},
		}},
		{row: 20, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `"header"`)}, {token: apiKeyToken(secret, `[]`)}}},
		{row: 21, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"body","name":"k"}`)}}},
		{row: 22, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"Header","name":"X-API-Key"}`)}}},
		{row: 23, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"header","name":"X-API-Key","location":"x"}`)}}},
		{row: 24, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"name":"X-API-Key"}`)}}},
		{row: 25, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"header"}`)}, {token: apiKeyToken(secret, `{"in":"header","name":7}`)}}},
		{row: 26, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"header","name":"X-API-Key","scheme_parameter":"token"}`)}}},
		{row: 27, want: PlacementInvalidMethod, cases: []refusal{
			{token: apiKeyToken(secret, `{"in":"header","name":""}`)},
			{token: apiKeyToken(secret, `{"in":"header","name":"X API"}`)},
		}},
		{row: 28, want: PlacementInvalidMethod, cases: []refusal{
			{token: apiKeyToken(secret, `{"in":"header","name":"Host"}`)},
			{token: apiKeyToken(secret, `{"in":"header","name":"transfer-encoding"}`)},
			{token: apiKeyToken(secret, `{"in":"header","name":"X-Forwarded-For"}`)},
			{token: apiKeyToken(secret, `{"in":"header","name":"Sec-Fetch-Mode"}`)},
		}},
		{row: 29, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"header","name":"X-Internal-User"}`), opts: []PlacementOption{refuseInternal}}}},
		{row: 30, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"header","name":"X API"}`), opts: []PlacementOption{WithPlacementAllowHeader(allowAll)}}}},
		{row: 31, want: PlacementInvalidMethod, cases: []refusal{{token: passwordToken("u", secret,
			`{"username":{"in":"header","name":"Host"},"password":{"in":"header","name":"X-Secret"}}`)}}},
		{row: 32, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"query","name":""}`)}}},
		{row: 33, want: PlacementInvalidMethod, cases: []refusal{{token: apiKeyToken(secret, `{"in":"cookie","name":"a=b"}`)}}},
		{row: 34, want: PlacementInvalidMethod, cases: []refusal{
			{token: apiKeyToken(secret, `{"in":"scheme","name":"Token token"}`)},
			{token: apiKeyToken(secret, `{"in":"scheme","name":"Token","scheme_parameter":"a b"}`)},
		}},
		{row: 35, want: PlacementInvalidMethod, cases: []refusal{{token: passwordToken("u", secret, `{"username":{"in":"header","name":"X-User"}}`)}}},
		{row: 36, want: PlacementInvalidMethod, cases: []refusal{{token: passwordToken("u", secret,
			`{"username":{"in":"header","name":"X-User"},"password":{"in":"header","name":"X-Secret"},"realm":{"in":"header","name":"X-Realm"}}`)}}},
		{row: 37, want: PlacementInvalidMethod, cases: []refusal{{token: passwordToken("u", secret, `{"in":"header","name":"X-Secret"}`)}}},
		{row: 38, want: PlacementInvalidMethod, cases: []refusal{
			{token: passwordToken("u", secret, `{"username":{"in":"header","name":"X-User"},"password":{"in":"cookie","name":"secret"}}`)},
			{token: passwordToken("u", secret, `{"username":{"in":"header","name":"X-User"},"password":{"in":"scheme","name":"Token"}}`)},
		}},
		{row: 39, want: PlacementInvalidMethod, cases: []refusal{{token: passwordToken("u", secret,
			`{"username":{"in":"header","name":"X-User"},"password":{"in":"header","name":"X-Secret","scheme_parameter":"token"}}`)}}},
		{row: 40, want: PlacementInvalidMethod, cases: []refusal{{token: passwordToken("u", secret,
			`{"username":{"in":"header","name":"X-Key"},"password":{"in":"header","name":"x-key"}}`)}}},
		// A missing username and an empty one are the same Go value. One case
		// covers both.
		{row: 41, want: PlacementInvalidCredential, cases: []refusal{
			{token: passwordToken("", secret, `{"username":{"in":"header","name":"X-User"},"password":{"in":"header","name":"X-Secret"}}`)},
		}},
		{row: 42, want: PlacementInvalidCredential, cases: []refusal{
			{token: &TokenResponse{AccessToken: secret, TokenType: TokenTypeBasic}},
			{token: &TokenResponse{AccessToken: secret, TokenType: TokenTypeBasic, UserID: "a:b"}},
		}},
		{row: 43, want: PlacementInvalidCredential, cases: []refusal{{token: apiKeyToken("", `{"in":"header","name":"X-API-Key"}`)}}},
		{row: 44, want: PlacementInvalidCredential, cases: []refusal{
			{token: apiKeyToken(secret+"\r\n", `{"in":"header","name":"X-API-Key"}`)},
			{token: passwordToken(secret+"\x00", secret, `{"username":{"in":"header","name":"X-User"},"password":{"in":"header","name":"X-Secret"}}`)},
		}},
		{row: 45, want: PlacementInvalidCredential, cases: []refusal{
			{token: apiKeyToken(secret+";b", `{"in":"cookie","name":"k"}`)},
			{token: apiKeyToken(secret+" b", `{"in":"cookie","name":"k"}`)},
			{token: apiKeyToken(secret+",b", `{"in":"cookie","name":"k"}`)},
			{token: apiKeyToken(secret+`"b`, `{"in":"cookie","name":"k"}`)},
			{token: apiKeyToken(secret+`\b`, `{"in":"cookie","name":"k"}`)},
			{token: apiKeyToken(secret+"\tb", `{"in":"cookie","name":"k"}`)},
			{token: apiKeyToken(secret+"éb", `{"in":"cookie","name":"k"}`)},
		}},
	} {
		for i, c := range tc.cases {
			t.Run(fmt.Sprintf("row %d case %d", tc.row, i), func(t *testing.T) {
				placement, err := PlaceCredential(c.token, c.opts...)
				if err == nil {
					t.Fatalf("PlaceCredential: got %v, want a %s refusal", placement, tc.want)
				}
				var pe *CredentialPlacementError
				if !errors.As(err, &pe) {
					t.Fatalf("error %T is not a *CredentialPlacementError", err)
				}
				if pe.Reason != tc.want {
					t.Errorf("reason: got %s, want %s (%v)", pe.Reason, tc.want, err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error message includes the secret: %v", err)
				}
			})
		}
	}
}

func TestPlaceCredential_DefaultAllowHeader(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true, "X-API-Key": true, "Mcp-Session-Id": true,
		"Connection": false, "proxy-connection": false, "Keep-Alive": false, "TE": false,
		"Trailer": false, "Transfer-Encoding": false, "Upgrade": false, "Proxy-Authenticate": false,
		"Proxy-Authorization": false, "content-length": false, "HOST": false, "Forwarded": false,
		"x-forwarded-proto": false, "Sec-Fetch-Mode": false,
	} {
		if got := DefaultAllowHeader(name); got != want {
			t.Errorf("DefaultAllowHeader(%q): got %v, want %v", name, got, want)
		}
	}
}

func TestApplyCredential(t *testing.T) {
	for _, tc := range []struct {
		row        int
		url        string
		header     http.Header
		token      *TokenResponse
		wantErr    bool
		wantURL    string
		wantHeader http.Header
	}{
		{
			row:        46,
			url:        "https://rs.example/mcp",
			header:     http.Header{"Authorization": {"Bearer old"}},
			token:      apiKeyToken("k", `{"in":"scheme","name":"Token","scheme_parameter":"token"}`),
			wantURL:    "https://rs.example/mcp",
			wantHeader: http.Header{"Authorization": {"Token token=k"}},
		},
		{
			row:        47,
			url:        "https://rs.example/mcp",
			header:     http.Header{"x-api-key": {"old"}},
			token:      apiKeyToken("k", `{"in":"header","name":"X-API-Key"}`),
			wantURL:    "https://rs.example/mcp",
			wantHeader: http.Header{"X-Api-Key": {"k"}},
		},
		{
			row:        48,
			url:        "https://rs.example/mcp?x=1",
			token:      apiKeyToken("a b&c", `{"in":"query","name":"api_key"}`),
			wantURL:    "https://rs.example/mcp?x=1&api_key=a+b%26c",
			wantHeader: http.Header{},
		},
		{
			row:        49,
			url:        "https://rs.example/mcp?api_key=old&x=1&api_key=old2&y=%2F",
			token:      apiKeyToken("k", `{"in":"query","name":"api_key"}`),
			wantURL:    "https://rs.example/mcp?x=1&y=%2F&api_key=k",
			wantHeader: http.Header{},
		},
		{
			row:        50,
			url:        "https://rs.example/mcp?api%5Fkey=old&API_KEY=1",
			token:      apiKeyToken("k", `{"in":"query","name":"api_key"}`),
			wantURL:    "https://rs.example/mcp?API_KEY=1&api_key=k",
			wantHeader: http.Header{},
		},
		{
			row:        51,
			url:        "https://rs.example/mcp",
			header:     http.Header{"Cookie": {"a=1; X-API-KEY=old; b=2"}},
			token:      apiKeyToken("k", `{"in":"cookie","name":"X-API-KEY"}`),
			wantURL:    "https://rs.example/mcp",
			wantHeader: http.Header{"Cookie": {"a=1; b=2; X-API-KEY=k"}},
		},
		{
			row:        52,
			url:        "https://rs.example/mcp",
			header:     http.Header{"Cookie": {"x-api-key=1"}},
			token:      apiKeyToken("k", `{"in":"cookie","name":"X-API-KEY"}`),
			wantURL:    "https://rs.example/mcp",
			wantHeader: http.Header{"Cookie": {"x-api-key=1; X-API-KEY=k"}},
		},
		{
			// Two Cookie headers end as one.
			row:        51,
			url:        "https://rs.example/mcp",
			header:     http.Header{"Cookie": {"a=1", "X-API-KEY=old"}, "cookie": {"b=2"}},
			token:      apiKeyToken("k", `{"in":"cookie","name":"X-API-KEY"}`),
			wantURL:    "https://rs.example/mcp",
			wantHeader: http.Header{"Cookie": {"a=1; b=2; X-API-KEY=k"}},
		},
		{
			row:        53,
			url:        "https://rs.example/mcp?x=1",
			header:     http.Header{"Authorization": {"Bearer old"}, "Cookie": {"a=1"}},
			token:      apiKeyToken("k", `{"in":"header","name":"Host"}`),
			wantErr:    true,
			wantURL:    "https://rs.example/mcp?x=1",
			wantHeader: http.Header{"Authorization": {"Bearer old"}, "Cookie": {"a=1"}},
		},
	} {
		t.Run(fmt.Sprintf("row %d", tc.row), func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.header {
				req.Header[k] = v
			}
			if err := ApplyCredential(tc.token, req); (err != nil) != tc.wantErr {
				t.Fatalf("ApplyCredential: got error %v, want error %v", err, tc.wantErr)
			}
			if got := req.URL.String(); got != tc.wantURL {
				t.Errorf("URL: got %s, want %s", got, tc.wantURL)
			}
			if !reflect.DeepEqual(req.Header, tc.wantHeader) {
				t.Errorf("header: got %v, want %v", req.Header, tc.wantHeader)
			}
		})
	}
}

func TestCredentialTransport_Redirects(t *testing.T) {
	t.Run("row 54 cross-origin redirect", func(t *testing.T) {
		var otherHits atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			otherHits.Add(1)
		}))
		defer other.Close()
		rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
		}))
		defer rs.Close()

		transport, err := NewCredentialTransport(apiKeyToken("k", `{"in":"header","name":"X-API-Key"}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: transport}).Get(rs.URL + "/mcp")
		if err == nil {
			resp.Body.Close()
			t.Fatal("Get: got nil error, want cross_origin_redirect")
		}
		var pe *CredentialPlacementError
		if !errors.As(err, &pe) || pe.Reason != PlacementCrossOriginRedirect {
			t.Fatalf("error: got %v, want a cross_origin_redirect *CredentialPlacementError", err)
		}
		if n := otherHits.Load(); n != 0 {
			t.Errorf("other origin got %d requests, want 0", n)
		}
	})

	t.Run("row 55 same-origin redirect", func(t *testing.T) {
		var mu sync.Mutex
		var got []*url.URL
		rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = append(got, r.URL)
			mu.Unlock()
			if r.URL.Path == "/old" {
				http.Redirect(w, r, "/new?api_key=stale&x=1", http.StatusFound)
			}
		}))
		defer rs.Close()

		transport, err := NewCredentialTransport(apiKeyToken("k", `{"in":"query","name":"api_key"}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodGet, rs.URL+"/old", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 2 {
			t.Fatalf("requests: got %d, want 2", len(got))
		}
		if q := got[0].RawQuery; q != "api_key=k" {
			t.Errorf("first request query: got %q, want api_key=k", q)
		}
		if q := got[1].RawQuery; q != "x=1&api_key=k" {
			t.Errorf("redirected request query: got %q, want x=1&api_key=k", q)
		}
		if req.URL.RawQuery != "" {
			t.Errorf("caller's request changed: query %q", req.URL.RawQuery)
		}
	})
}

func TestCredentialPlacement_PrintedForm(t *testing.T) {
	// Row 56. fmt calls Format for every verb, so the test tries each one.
	token := passwordToken("the-username", "the-password",
		`{"username":{"in":"header","name":"PLAID-CLIENT-ID"},"password":{"in":"query","name":"secret"}}`)
	token.RefreshToken = "the-refresh-token"
	token.UserID = "the-user-id"
	placement, err := PlaceCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"the-username", "the-password", "the-refresh-token", "the-user-id"}
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		{name: "token response", value: token, want: []string{"PLAID-CLIENT-ID", "header", "secret", "query"}},
		{name: "token response value", value: *token, want: []string{"PLAID-CLIENT-ID"}},
		{name: "placement", value: placement, want: []string{"[header PLAID-CLIENT-ID, query secret]"}},
		{name: "field", value: placement[0], want: []string{"header PLAID-CLIENT-ID"}},
		{name: "map of token responses", value: map[string]*TokenResponse{"r": token}, want: []string{"PLAID-CLIENT-ID"}},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			t.Run(tc.name+" "+verb, func(t *testing.T) {
				out := fmt.Sprintf(verb, tc.value)
				for _, s := range secrets {
					if strings.Contains(out, s) {
						t.Errorf("%s prints %q: %s", verb, s, out)
					}
				}
				for _, w := range tc.want {
					if !strings.Contains(out, w) {
						t.Errorf("%s output %q does not include %q", verb, out, w)
					}
				}
			})
		}
	}
}

// Token Exchange rows 27 to 29 (specs/oauth-client/token-exchange.md). The
// exchange keeps token_type, user_id, username and method as received.
func TestDeserializeTokenResponse_PlacementMembers(t *testing.T) {
	method := `{"username": {"in": "header", "name": "PLAID-CLIENT-ID"}, "password": {"in": "header", "name": "PLAID-SECRET"}}`
	for _, tc := range []struct {
		row  int
		body string
		want TokenResponse
	}{
		{
			row:  27,
			body: `{"access_token":"p","token_type":"Keycard-Password","username":"u","method":` + method + `}`,
			want: TokenResponse{AccessToken: "p", TokenType: "Keycard-Password", Username: "u", Method: []byte(method)},
		},
		{
			row:  28,
			body: `{"access_token":"p","token_type":"Basic","user_id":"svc"}`,
			want: TokenResponse{AccessToken: "p", TokenType: "Basic", UserID: "svc"},
		},
		{
			row:  29,
			body: `{"access_token":"t","token_type":"MAC"}`,
			want: TokenResponse{AccessToken: "t", TokenType: "MAC"},
		},
		{
			// A null method is the same as no method.
			row:  27,
			body: `{"access_token":"t","token_type":"Keycard-API-Key","method":null}`,
			want: TokenResponse{AccessToken: "t", TokenType: "Keycard-API-Key"},
		},
	} {
		t.Run(fmt.Sprintf("row %d", tc.row), func(t *testing.T) {
			got, err := deserializeTokenResponse(&http.Response{Body: io.NopCloser(strings.NewReader(tc.body))})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("got %+v method %s, want %+v method %s", *got, got.Method, tc.want, tc.want.Method)
			}
		})
	}
}
