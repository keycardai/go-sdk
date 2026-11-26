package mcp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

const (
	bindingIssuer = "https://keycard.cloud"
	bindingHost   = "https://api.example.com"
	bindingMCP    = bindingHost + "/mcp"
)

func bindingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func bindingToken(t *testing.T, key *rsa.PrivateKey, issuer string, aud ...string) string {
	t.Helper()
	return mintToken(t, key, issuer, oauth.JWTClaims{
		Subject: "caller", ClientID: "client", IssuedAt: time.Now().Unix(), Expiry: time.Now().Add(time.Hour).Unix(), Audience: aud,
	})
}

func makeBinding(t *testing.T, issuer string, opts ...ResourceBindingOption) *ResourceBinding {
	t.Helper()
	b, err := NewResourceBinding(issuer, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bindingAuth(t *testing.T, b *ResourceBinding, opts ...BearerAuthOption) http.Handler {
	t.Helper()
	mw, err := b.BearerAuth(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if AuthInfoFromRequest(r) == nil {
			t.Error("missing verified caller")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func sendBindingRequest(h http.Handler, target, token string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func assertBindingResponse(t *testing.T, rec *httptest.ResponseRecorder, status int, code, metadata string) {
	t.Helper()
	challenge := rec.Header().Get("WWW-Authenticate")
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; challenge = %q, body = %q", rec.Code, status, challenge, rec.Body.String())
	}
	if status == 204 {
		if challenge != "" {
			t.Errorf("unexpected challenge %q", challenge)
		}
		return
	}
	if !strings.HasPrefix(challenge, "Bearer") || (code != "" && !strings.Contains(challenge, `error="`+code+`"`)) {
		t.Errorf("expected Bearer challenge with error %q, got %q", code, challenge)
	}
	if metadata == "" && strings.Contains(challenge, "resource_metadata") ||
		metadata != "" && !strings.Contains(challenge, `resource_metadata="`+metadata+`"`) {
		t.Errorf("expected metadata URL %q, got challenge %q", metadata, challenge)
	}
	if metadata == "" && code == "" && challenge != "Bearer" {
		t.Errorf("expected bare Bearer challenge, got %q", challenge)
	}
}

func bindingWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func expectBindingConfigError(t *testing.T, err error) {
	t.Helper()
	var configErr *oauth.ConfigurationError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigurationError, got %v", err)
	}
}

// Spec row 1, 8, 12-12d, 15 and integration 2 (bearer-token-verification-middleware): one configured identifier drives the audience and challenge.
// Spec row 2, 2a and 6 (route-level-auth-gating): scope gates reuse the binding's challenge.
func TestResourceBinding_SingleResourceChallenges(t *testing.T) {
	warnings := bindingWarnings(t)
	key := bindingKey(t)
	for _, tc := range []struct {
		name, id, target, aud, code, suffix string
		status                              int
		mounted, spoofed, scoped            bool
	}{
		{name: "bearer_1_route_2", id: bindingMCP + "?x=1", target: "/mcp?x=1", status: 401, suffix: "/mcp?x=1", scoped: true},
		{name: "bearer_8_integration_2", id: bindingMCP, target: "/mcp", aud: bindingHost + "/other", status: 401, code: "invalid_token", suffix: "/mcp"},
		{name: "bearer_12", id: bindingMCP, target: "/mcp", status: 401, suffix: "/mcp"},
		{name: "bearer_12a_path", id: bindingMCP, target: "/tools", status: 401, suffix: "-"},
		{name: "bearer_12a_query", id: bindingMCP, target: "/mcp?other=1", status: 401, suffix: "-"},
		{name: "bearer_12b_route_2a", id: bindingHost, target: "/", status: 401, scoped: true},
		{name: "bearer_12b_audience", id: bindingHost, target: "/", aud: bindingHost + "/", status: 401, code: "invalid_token"},
		{name: "bearer_12c", id: bindingMCP, target: "/mcp", status: 401, suffix: "/mcp", spoofed: true},
		{name: "bearer_12d", id: bindingHost + "/app/mcp", target: "/app/mcp", status: 401, suffix: "/app/mcp", mounted: true},
		{name: "bearer_15", id: bindingMCP, target: "/mcp", aud: bindingMCP, status: 204, suffix: "-"},
		{name: "route_6", id: bindingMCP, target: "/tools", aud: bindingMCP, status: 403, code: "insufficient_scope", suffix: "-", scoped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := makeBinding(t, bindingIssuer, WithResourceIdentifier(tc.id))
			opts := []BearerAuthOption{WithBearerKeyring(&pubKeyring{pub: &key.PublicKey})}
			if tc.scoped {
				opts = append(opts, WithRequiredScopes("tools"))
			}
			h := bindingAuth(t, b, opts...)
			if tc.mounted {
				h = http.StripPrefix("/app", h)
			}
			var token string
			if tc.aud != "" {
				token = bindingToken(t, key, bindingIssuer, tc.aud)
			}
			host := "internal"
			var headers map[string]string
			if tc.spoofed {
				host = "other.example"
				headers = map[string]string{"X-Forwarded-Host": "third.example", "X-Forwarded-Proto": "https"}
			}
			metadata := ""
			if tc.suffix != "-" {
				metadata = bindingHost + protectedResourcePath + tc.suffix
			}
			assertBindingResponse(t, sendBindingRequest(h, "http://"+host+tc.target, token, headers), tc.status, tc.code, metadata)
		})
	}
	if warnings.Len() != 0 {
		t.Errorf("unexpected warnings: %s", warnings)
	}
}

// Spec row 8a-8h (bearer-token-verification-middleware): verifier-only modes serve no discovery and omit resource_metadata.
// Spec row 7 (route-level-auth-gating): out-of-binding scope denial omits resource_metadata.
func TestResourceBinding_VerifierOnly(t *testing.T) {
	warnings := bindingWarnings(t)
	key, wrongKey := bindingKey(t), bindingKey(t)
	multi := []ResourceBindingOption{WithMultiResource(true), WithResourceAudiences("resource-a", "resource-b")}
	any := []ResourceBindingOption{WithAllowAnyAudience(true)}
	urn := []ResourceBindingOption{WithResourceIdentifier("urn:example:service")}
	for _, tc := range []struct {
		name   string
		opts   []ResourceBindingOption
		aud    []string
		status int
		badSig bool
		code   string
	}{
		{"bearer_8a_8f", multi, []string{"resource-b"}, 204, false, ""},
		{"bearer_8b_8f", multi, []string{"resource-c"}, 401, false, "invalid_token"},
		{"bearer_8c", multi, []string{"resource-c", "resource-b"}, 204, false, ""},
		{"bearer_8d", multi, []string{"resource-c", "resource-d"}, 401, false, "invalid_token"},
		{"bearer_8g_other_audience", any, []string{"resource-c"}, 204, false, ""},
		{"bearer_8g_bad_signature", any, []string{"resource-c"}, 401, true, "invalid_token"},
		{"bearer_8h_match", urn, []string{"urn:example:service"}, 204, false, ""},
		{"bearer_8h_mismatch", urn, []string{"urn:example:other"}, 401, false, "invalid_token"},
		{"route_7_verifier_only", any, nil, 401, false, ""},
		{"route_7_urn", urn, nil, 401, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := bindingAuth(t, makeBinding(t, bindingIssuer, tc.opts...), WithBearerKeyring(&pubKeyring{pub: &key.PublicKey}), WithRequiredScopes())
			signingKey := key
			if tc.badSig {
				signingKey = wrongKey
			}
			var token string
			if tc.aud != nil {
				token = bindingToken(t, signingKey, bindingIssuer, tc.aud...)
			}
			assertBindingResponse(t, sendBindingRequest(h, "/mcp", token, nil), tc.status, tc.code, "")
		})
	}
	_, err := NewResourceBinding(bindingIssuer, WithMultiResource(true), WithResourceAudiences()) // Bearer spec row 8e.
	expectBindingConfigError(t, err)
	if warnings.Len() != 0 {
		t.Errorf("unexpected warnings: %s", warnings)
	}
}

// Spec row 16, 16a, 16c and 17 (bearer-token-verification-middleware): the request or token selects the zone before verification.
func TestResourceBinding_ZoneVerification(t *testing.T) {
	warnings := bindingWarnings(t)
	a, b := bindingKey(t), bindingKey(t)
	issuerA, issuerB := "https://a.keycard.cloud", "https://b.keycard.cloud"
	keyring := &multiZoneKeyring{keys: map[string]crypto.PublicKey{issuerA: &a.PublicKey, issuerB: &b.PublicKey}}
	idA, idB := bindingHost+"/a/mcp", bindingHost+"/b/mcp"
	perZone := makeBinding(t, bindingIssuer, WithResourceIdentifiersByZone(map[string]string{"a": idA, "b": idB}))
	h := bindingAuth(t, perZone, WithBearerKeyring(keyring), WithInboundZoneResolver(func(_, target string) string {
		zone, _, _ := strings.Cut(strings.TrimPrefix(target, "/"), "/")
		return zone
	}))
	metaA := bindingHost + protectedResourcePath + "/a/mcp"
	assertBindingResponse(t, sendBindingRequest(h, "/a/mcp", "", nil), 401, "", metaA)
	assertBindingResponse(t, sendBindingRequest(h, "/a/mcp", bindingToken(t, a, issuerA, idA), nil), 204, "", "")
	assertBindingResponse(t, sendBindingRequest(h, "/a/mcp", bindingToken(t, a, issuerA, idB), nil), 401, "invalid_token", metaA)
	assertBindingResponse(t, sendBindingRequest(h, "/a/mcp", bindingToken(t, b, issuerB, idA), nil), 401, "invalid_token", metaA)
	assertBindingResponse(t, sendBindingRequest(h, "/", "", nil), 401, "", "")
	assertBindingResponse(t, sendBindingRequest(h, "/unknown/mcp", "", nil), 401, "", "")
	assertBindingResponse(t, sendBindingRequest(h, "/unknown/mcp", bindingToken(t, a, issuerA, idA), nil), 401, "invalid_token", "")

	shared := makeBinding(t, bindingIssuer, WithMultiResource(true), WithResourceAudiences(bindingMCP),
		WithResourceIdentifiersByZone(map[string]string{"a": bindingMCP, "b": bindingMCP}))
	h = bindingAuth(t, shared, WithBearerKeyring(keyring))
	assertBindingResponse(t, sendBindingRequest(h, "/mcp", "", nil), 401, "", bindingHost+protectedResourcePath+"/mcp")
	assertBindingResponse(t, sendBindingRequest(h, "/mcp", bindingToken(t, a, issuerA, bindingMCP), nil), 204, "", "")
	assertBindingResponse(t, sendBindingRequest(h, "/mcp", bindingToken(t, b, issuerB, bindingMCP), nil), 204, "", "")
	assertBindingResponse(t, sendBindingRequest(h, "/mcp", bindingToken(t, a, issuerB, bindingMCP), nil), 401, "invalid_token", bindingHost+protectedResourcePath+"/mcp")
	if warnings.Len() != 0 {
		t.Errorf("unexpected warnings: %s", warnings)
	}
}

// Spec row 13, 14b, 16b, 16d and 17a (bearer-token-verification-middleware): conflicting modes fail at construction.
// Spec row 8b, 9b and 9d (oauth-metadata-endpoints): conflicting discovery configuration fails at construction.
func TestResourceBinding_InvalidConfiguration(t *testing.T) {
	zones := WithResourceIdentifiersByZone(map[string]string{"a": bindingMCP, "b": bindingHost + "/other"})
	sharedZones := WithResourceIdentifiersByZone(map[string]string{"a": bindingMCP, "b": bindingMCP})
	single := WithResourceIdentifier(bindingMCP)
	multi, any := WithMultiResource(true), WithAllowAnyAudience(true)
	for _, tc := range []struct {
		name   string
		issuer string
		opts   []ResourceBindingOption
	}{
		{"bearer_13_metadata_8b_single_any", bindingIssuer, []ResourceBindingOption{single, any}},
		{"metadata_8b_single_multi", bindingIssuer, []ResourceBindingOption{single, multi}},
		{"metadata_8b_both_flags", bindingIssuer, []ResourceBindingOption{multi, any}},
		{"bearer_16b_metadata_8b_both_identifier_forms", bindingIssuer, []ResourceBindingOption{single, zones}},
		{"bearer_16b_metadata_8b_zones_any", bindingIssuer, []ResourceBindingOption{zones, any}},
		{"bearer_17a_metadata_9d_differing_shared_urls", bindingIssuer, []ResourceBindingOption{zones, multi}},
		{"bearer_17_wrong_shared_audience", bindingIssuer, []ResourceBindingOption{sharedZones, multi, WithResourceAudiences(bindingHost)}},
		{"bearer_17_multiple_shared_audiences", bindingIssuer, []ResourceBindingOption{sharedZones, multi, WithResourceAudiences(bindingMCP, bindingHost)}},
		{"metadata_9b_missing_base_issuer", "", []ResourceBindingOption{zones}},
		{"metadata_9a_ambiguous_discovery", bindingIssuer, []ResourceBindingOption{sharedZones}},
		{"empty_explicit_map", bindingIssuer, []ResourceBindingOption{WithResourceIdentifiersByZone(nil)}},
		{"invalid_identifier", bindingIssuer, []ResourceBindingOption{WithResourceIdentifier("/mcp")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewResourceBinding(tc.issuer, tc.opts...)
			expectBindingConfigError(t, err)
		})
	}

	// A token-keyed verifier cannot supply the host/target-only resolver (row 16d).
	_, err := makeBinding(t, bindingIssuer, zones).BearerAuth()
	expectBindingConfigError(t, err)
	// Go accepts no scalar or map audience option (row 14b); neither standalone
	// metadata configuration supplies the required bearer audience list.
	for _, opts := range [][]ResourceBindingOption{{multi}, {multi, sharedZones}} {
		_, err := makeBinding(t, bindingIssuer, opts...).BearerAuth()
		expectBindingConfigError(t, err)
	}
}

// Spec row 7 and 14 (bearer-token-verification-middleware): legacy configuration keeps its behavior and warns once.
// Spec row 8c (oauth-metadata-endpoints): legacy metadata warns once during deprecation.
func TestResourceBinding_LegacyWarnsOnce(t *testing.T) {
	warnings := bindingWarnings(t)
	key := bindingKey(t)
	for _, tc := range []struct {
		name, audience, code string
		opts                 []ResourceBindingOption
		status               int
	}{
		{"bearer_7", "other", "", nil, 204},
		{"bearer_14_accept_list", "resource-b", "", []ResourceBindingOption{WithResourceAudiences("resource-a", "resource-b")}, 204},
		{"bearer_14_reject_other", "other", "invalid_token", []ResourceBindingOption{WithResourceAudiences("resource-a", "resource-b")}, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings.Reset()
			b := makeBinding(t, bindingIssuer, tc.opts...)
			headers := map[string]string{"X-Forwarded-Proto": "https"}
			h := bindingAuth(t, b, WithBearerKeyring(&pubKeyring{pub: &key.PublicKey}))
			metadata := "https://internal" + protectedResourcePath + "/mcp"
			assertBindingResponse(t, sendBindingRequest(h, "http://internal/mcp", "", headers), 401, "", metadata)
			token := bindingToken(t, key, bindingIssuer, tc.audience)
			assertBindingResponse(t, sendBindingRequest(h, "http://internal/mcp", token, headers), tc.status, tc.code, metadata)
			assertProtectedDocument(t, sendBindingRequest(b.MetadataHandler(), "http://internal"+protectedResourcePath+"/mcp", "", headers),
				"https://internal/mcp", bindingIssuer)
			if got := warnings.String(); strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "resource_identifier") {
				t.Errorf("expected one resource_identifier warning, got %q", got)
			}
		})
	}
	warnings.Reset()
	legacyVerifier := zoneVerifier(t, &key.PublicKey, oauth.WithAudiences("resource-a", "resource-b"))
	legacyMiddleware := RequireBearerAuth(legacyVerifier)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	assertBindingResponse(t, sendBindingRequest(legacyMiddleware, "/mcp", bindingToken(t, key, testZone, "resource-b"), nil), 204, "", "")
	if got := warnings.String(); strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "resource_identifier") {
		t.Errorf("expected one legacy verifier warning, got %q", got)
	}

	warnings.Reset()
	standalone := AuthMetadataHandler()
	assertProtectedDocument(t, sendBindingRequest(standalone, protectedResourcePath, "", nil), "http://example.com")
	assertProtectedDocument(t, sendBindingRequest(standalone, protectedResourcePath, "", nil), "http://example.com")
	if got := warnings.String(); strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "resource_identifier") {
		t.Errorf("expected one standalone resource_identifier warning, got %q", got)
	}
}

func assertProtectedDocument(t *testing.T, rec *httptest.ResponseRecorder, identifier string, issuers ...string) {
	t.Helper()
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected protected-resource JSON, got %d: %s", rec.Code, rec.Body)
	}
	var doc ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != identifier || !slices.Equal(doc.AuthorizationServers, issuers) {
		t.Errorf("document = %+v; want resource %q, issuers %v", doc, identifier, issuers)
	}
}

type bindingTransport func(*http.Request) (*http.Response, error)

func (f bindingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Spec row 1 and 7 (oauth-metadata-endpoints): the document publishes the configured identifier, query included, verbatim.
func TestResourceBinding_ProtectedResourceDocuments(t *testing.T) {
	for _, tc := range []struct{ name, target, id string }{
		{"metadata_1", protectedResourcePath, bindingHost},
		{"metadata_7", protectedResourcePath + "/mcp", bindingMCP},
		{"encoded_path_and_query", protectedResourcePath + "/a%2Fb?z=2&a=1", bindingHost + "/a%2Fb?z=2&a=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := makeBinding(t, bindingIssuer, WithResourceIdentifier(tc.id)).MetadataHandler()
			assertProtectedDocument(t, sendBindingRequest(h, "http://internal"+tc.target, "", nil), tc.id, bindingIssuer)
			if got := sendBindingRequest(h, "/.well-known/oauth-protected-resource/unconfigured", "", nil).Code; got != 404 {
				t.Errorf("unconfigured endpoint status = %d, want 404", got)
			}
		})
	}
}

// Spec row 9 (oauth-metadata-endpoints): distinct endpoints have separate metadata and audience policies.
func TestResourceBinding_MultipleDiscoverableEndpoints(t *testing.T) {
	key := bindingKey(t)
	keyring := WithBearerKeyring(&pubKeyring{pub: &key.PublicKey})
	mux := http.NewServeMux()
	for _, path := range []string{"/mcp", "/tools"} {
		b := makeBinding(t, bindingIssuer, WithResourceIdentifier(bindingHost+path))
		mux.Handle(path, bindingAuth(t, b, keyring))
		mux.Handle(protectedResourcePath+path, b.MetadataHandler())
	}
	for _, path := range []string{"/mcp", "/tools"} {
		assertProtectedDocument(t, sendBindingRequest(mux, protectedResourcePath+path, "", nil), bindingHost+path, bindingIssuer)
	}
	token := bindingToken(t, key, bindingIssuer, bindingMCP)
	assertBindingResponse(t, sendBindingRequest(mux, "/mcp", token, nil), 204, "", "")
	assertBindingResponse(t, sendBindingRequest(mux, "/tools", token, nil), 401, "invalid_token", bindingHost+protectedResourcePath+"/tools")
}

// Spec row 8 and 8a (oauth-metadata-endpoints): verifier-only modes leave AS metadata available and serve no resource document.
func TestResourceBinding_MetadataVerifierOnly(t *testing.T) {
	warnings := bindingWarnings(t)
	for _, option := range []ResourceBindingOption{WithResourceIdentifier("urn:example:service"), WithMultiResource(true), WithAllowAnyAudience(true)} {
		b := makeBinding(t, bindingIssuer, option)
		fetches := 0
		client := &http.Client{Transport: bindingTransport(func(r *http.Request) (*http.Response, error) {
			fetches++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"issuer":"https://keycard.cloud"}`))}, nil
		})}
		h := b.MetadataHandler(WithMetadataHTTPClient(client), WithPublicJWKS(map[string]any{"keys": []any{}}))
		if got := sendBindingRequest(h, protectedResourcePath, "", nil).Code; got != 404 {
			t.Errorf("resource status = %d, want 404", got)
		}
		for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/jwks.json"} {
			if got := sendBindingRequest(h, path, "", nil).Code; got != 200 {
				t.Errorf("%s: status = %d, want 200", path, got)
			}
		}
		if fetches != 1 {
			t.Errorf("upstream fetches = %d, want 1", fetches)
		}
	}
	if warnings.Len() != 0 {
		t.Errorf("unexpected warnings: %s", warnings)
	}
}

// Spec row 4a, 4b, 9a, 9c and integration 2 (oauth-metadata-endpoints): zone documents list only configured zone issuers.
func TestResourceBinding_ZoneMetadata(t *testing.T) {
	warnings := bindingWarnings(t)
	base := bindingIssuer + ":8443"
	issuerA, issuerB := "https://a.keycard.cloud:8443", "https://b.keycard.cloud:8443"
	idA, idB := bindingHost+"/a/mcp", bindingHost+"/b/mcp"
	perZone := makeBinding(t, base, WithResourceIdentifiersByZone(map[string]string{"a": idA, "b": idB}))
	var fetched []string
	const asPath = "/.well-known/oauth-authorization-server"
	const upstreamEndpoint = "https://upstream.example/authorize?resource=stale&keep=1"
	client := &http.Client{Transport: bindingTransport(func(r *http.Request) (*http.Response, error) {
		fetched = append(fetched, r.URL.String())
		doc := fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q}`, r.URL.Scheme+"://"+r.URL.Host, upstreamEndpoint)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(doc))}, nil
	})}
	h := perZone.MetadataHandler(WithMetadataHTTPClient(client))
	assertProtectedDocument(t, sendBindingRequest(h, protectedResourcePath+"/a/mcp", "", nil), idA, issuerA)
	assertProtectedDocument(t, sendBindingRequest(h, protectedResourcePath+"/b/mcp", "", nil), idB, issuerB)
	for _, tc := range []struct{ zone, issuer string }{{"a", issuerA}, {"b", issuerB}} {
		rec := sendBindingRequest(h, asPath+"/"+tc.zone, "", nil)
		want := fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q}`, tc.issuer, upstreamEndpoint)
		if rec.Code != 200 || rec.Body.String() != want {
			t.Fatalf("unexpected AS metadata response for %s: %d, %s", tc.zone, rec.Code, rec.Body)
		}
	}
	for _, target := range []string{asPath, asPath + "/unknown"} {
		if got := sendBindingRequest(h, target, "", nil).Code; got != 404 {
			t.Errorf("%s: status = %d, want 404", target, got)
		}
	}
	if !slices.Equal(fetched, []string{issuerA + asPath, issuerB + asPath}) {
		t.Errorf("fetched %v", fetched)
	}
	shared := makeBinding(t, base, WithMultiResource(true), WithResourceIdentifiersByZone(map[string]string{"a": bindingMCP, "b": bindingMCP}))
	assertProtectedDocument(t, sendBindingRequest(shared.MetadataHandler(), protectedResourcePath+"/mcp", "", nil), bindingMCP, issuerA, issuerB)
	if warnings.Len() != 0 {
		t.Errorf("unexpected warnings: %s", warnings)
	}
}

// Spec row 4b (oauth-metadata-endpoints): zones sharing a metadata path select their
// document by host, with the scheme's default port optional on either side.
func TestResourceBinding_ZoneMetadataDefaultPort(t *testing.T) {
	idA, idB := "https://a.example.com:443/mcp", "https://b.example.com/mcp"
	b := makeBinding(t, bindingIssuer, WithResourceIdentifiersByZone(map[string]string{"a": idA, "b": idB}))
	h := b.MetadataHandler()
	assertProtectedDocument(t, sendBindingRequest(h, "https://a.example.com"+protectedResourcePath+"/mcp", "", nil), idA, "https://a.keycard.cloud")
	assertProtectedDocument(t, sendBindingRequest(h, "https://B.example.com:443"+protectedResourcePath+"/mcp", "", nil), idB, "https://b.keycard.cloud")
	if _, err := NewResourceBinding(bindingIssuer, WithResourceIdentifiersByZone(map[string]string{
		"a": "https://a.example.com:443/mcp", "b": "https://A.example.com/mcp",
	})); err == nil {
		t.Error("expected a configuration error for zones publishing the same metadata URL")
	}
}

// Spec row 10 (oauth-metadata-endpoints): the application mounts auth but registers discovery at the host root.
func TestResourceBinding_MountedDiscovery(t *testing.T) {
	const id = bindingHost + "/app/mcp"
	b := makeBinding(t, bindingIssuer, WithResourceIdentifier(id))
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", bindingAuth(t, b)))
	mux.Handle("/.well-known/", b.MetadataHandler())
	assertProtectedDocument(t, sendBindingRequest(mux, protectedResourcePath+"/app/mcp", "", nil), id, bindingIssuer)
	assertBindingResponse(t, sendBindingRequest(mux, "/app/mcp", "", nil), 401, "", bindingHost+protectedResourcePath+"/app/mcp")
}
