package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests named TestAgentIntegration_RowN implement the SDK-observable part of
// row N of the Integration Tests table in keycard-sdk-spec
// specs/delegated-access/local-agent-token-source.md, against a fake agent on a
// real Unix socket and a resource server verifying the fake zone's signature.
// Nothing here needs the keycard binary or a network.

// fakeAgent stands in for the keycard agent daemon: it approves every request
// except one for declinedScope, refuses an app id it does not know, signs each
// token as the zone, and answers a repeat of an approved key from its cache.
type fakeAgent struct {
	t             *testing.T
	signer        *JWTSigner
	declinedScope string
	knownAppIDs   map[string]bool
	requireTenant bool

	mu     sync.Mutex
	issued int
	minted int
	cache  map[string]string
}

// signingZone signs tokens as the zone's issuer, and verifies them as a resource
// server would.
type signingZone struct {
	signer *JWTSigner
	key    *rsa.PublicKey
}

func newSigningZone(t *testing.T) *signingZone {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return &signingZone{
		signer: NewJWTSigner(&testPrivateKeyring{key: key, issuer: testIssuer}),
		key:    &key.PublicKey,
	}
}

// verifier verifies a token as one the zone issued for resource.
func (z *signingZone) verifier(t *testing.T, resource string) *JWTVerifier {
	t.Helper()
	return newVerifier(t, &staticTestKeyring{publicKey: z.key}, []string{testIssuer}, WithAudiences(resource))
}

func (f *fakeAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != agentIssueTokenProcedure {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Resource string   `json:"resource"`
		Scopes   []string `json:"scopes"`
		Workload string   `json:"workload"`
		AppID    string   `json:"appId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		connectError(w, http.StatusBadRequest, AgentCodeInvalidArgument, err.Error())
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued++

	if f.requireTenant && (r.Header.Get("Keycard-Org") == "" || r.Header.Get("Keycard-Zone") == "") {
		connectError(w, http.StatusForbidden, AgentCodePermissionDenied, "no session for this org and zone")
		return
	}
	if req.AppID != "" && !f.knownAppIDs[req.AppID] {
		connectError(w, http.StatusNotFound, AgentCodeNotFound, "no application "+req.AppID+" in this zone")
		return
	}
	for _, s := range req.Scopes {
		if s == f.declinedScope {
			connectError(w, http.StatusForbidden, AgentCodePermissionDenied, "the request was declined")
			return
		}
	}

	key := req.Resource + "\x00" + strings.Join(req.Scopes, " ") + "\x00" + req.AppID
	token, ok := f.cache[key]
	if !ok {
		claims := validClaims()
		claims.Audience = []string{req.Resource}
		claims.Scope = strings.Join(req.Scopes, " ")
		if req.AppID != "" {
			claims.Extra = map[string]any{"keycard_declared_app_id": req.AppID}
		}
		var err error
		if token, err = f.signer.Sign(r.Context(), claims); err != nil {
			f.t.Errorf("signing: %v", err)
			connectError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		f.minted++
		if f.cache == nil {
			f.cache = map[string]string{}
		}
		f.cache[key] = token
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":     token,
		"expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	})
}

func (f *fakeAgent) counts() (issued, minted int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued, f.minted
}

func connectError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

// startFakeAgent serves a fake agent on a fresh socket and returns it with its
// zone and the socket path.
func startFakeAgent(t *testing.T) (*fakeAgent, *signingZone, string) {
	t.Helper()
	requireUnix(t)
	zone := newSigningZone(t)
	agent := &fakeAgent{t: t, signer: zone.signer, declinedScope: "admin", knownAppIDs: map[string]bool{"incident-digest": true}}
	path := filepath.Join(socketTempDir(t), "agent.sock")
	serveAgent(t, path, agent)
	return agent, zone, path
}

// startResourceServer answers 200 only to a bearer token the zone issued for
// the server's own URL.
func startResourceServer(t *testing.T, zone *signingZone) *httptest.Server {
	t.Helper()
	var verifier *JWTVerifier
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			http.Error(w, "no bearer", http.StatusUnauthorized)
			return
		}
		if _, err := verifier.Verify(r.Context(), bearer); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Start()
	t.Cleanup(srv.Close)
	verifier = zone.verifier(t, srv.URL)
	return srv
}

func TestAgentIntegration_Row1_MintWithNoApplicationCredential(t *testing.T) {
	agent, zone, socket := startFakeAgent(t)
	const resource = "https://api.example.com"

	tok, err := mustAgentTokenSource(t, WithAgentSocket(socket), WithAgentWorkload("integration")).
		ResourceToken(context.Background(), resource, "read")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if _, err := zone.verifier(t, resource).Verify(context.Background(), tok.AccessToken); err != nil {
		t.Errorf("Verify with audience %s: %v", resource, err)
	}
	if tok.ExpiresIn == nil || *tok.ExpiresIn <= 0 {
		t.Errorf("ExpiresIn: got %v", tok.ExpiresIn)
	}
	if issued, _ := agent.counts(); issued != 1 {
		t.Errorf("agent requests: got %d, want 1", issued)
	}
}

func TestAgentIntegration_Row2_ResourceTransportVerifies(t *testing.T) {
	_, zone, socket := startFakeAgent(t)
	srv := startResourceServer(t, zone)

	client, err := NewResourceClient(mustAgentTokenSource(t, WithAgentSocket(socket)), srv.URL, "read")
	if err != nil {
		t.Fatalf("NewResourceClient: %v", err)
	}
	resp, err := client.Get(srv.URL + "/report")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestAgentIntegration_Row3_RepeatsReachTheAgent(t *testing.T) {
	agent, zone, socket := startFakeAgent(t)
	srv := startResourceServer(t, zone)
	src := mustAgentTokenSource(t, WithAgentSocket(socket))

	first, err := src.ResourceToken(context.Background(), srv.URL, "read")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	second, err := src.ResourceToken(context.Background(), srv.URL, "read")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if first.AccessToken != second.AccessToken {
		t.Error("the agent's cache answered with a different token")
	}

	client, err := NewResourceClient(src, srv.URL, "read")
	if err != nil {
		t.Fatalf("NewResourceClient: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}

	if issued, minted := agent.counts(); issued != 3 || minted != 1 {
		t.Errorf("agent: got %d requests and %d mints, want 3 and 1", issued, minted)
	}
}

func TestAgentIntegration_Row4_Declined(t *testing.T) {
	agent, _, socket := startFakeAgent(t)
	_, err := mustAgentTokenSource(t, WithAgentSocket(socket)).ResourceToken(context.Background(), "https://api.example.com", "admin")
	if !IsDeclined(err) {
		t.Fatalf("IsDeclined: got false for %v", err)
	}
	if _, minted := agent.counts(); minted != 0 {
		t.Errorf("mints: got %d, want 0", minted)
	}
}

func TestAgentIntegration_Row5_UnknownAppID(t *testing.T) {
	_, _, socket := startFakeAgent(t)
	_, err := mustAgentTokenSource(t, WithAgentSocket(socket), WithAgentAppID("no-such-app")).
		ResourceToken(context.Background(), "https://api.example.com")
	if !IsApplicationNotFound(err) {
		t.Fatalf("IsApplicationNotFound: got false for %v", err)
	}
}

func TestAgentIntegration_Row6_DeclaredAppIDClaim(t *testing.T) {
	_, zone, socket := startFakeAgent(t)
	tok, err := mustAgentTokenSource(t, WithAgentSocket(socket), WithAgentAppID("incident-digest")).
		ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	claims, err := zone.verifier(t, "https://api.example.com").Verify(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := claims.Extra["keycard_declared_app_id"]; got != "incident-digest" {
		t.Errorf("keycard_declared_app_id: got %v", got)
	}
}

// defaultSocketEnv returns an environment whose default agent socket is under
// a fresh home directory, and that socket's path.
func defaultSocketEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	home := socketTempDir(t)
	return map[string]string{"HOME": home}, filepath.Join(home, ".local", "state", "keycard", "run", "agent.sock")
}

func TestAgentIntegration_Row7_DefaultSocketReachesDaemon(t *testing.T) {
	requireUnix(t)
	env, path := defaultSocketEnv(t)
	// The CLI creates these directories when the daemon starts.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	agent := &fakeAgent{t: t, signer: newSigningZone(t).signer, requireTenant: true}
	serveAgent(t, path, agent)

	_, err := mustAgentTokenSource(t, WithAgentEnv(env)).ResourceToken(context.Background(), "https://api.example.com")
	if !IsDeclined(err) {
		t.Errorf("without org and zone: got %v, want a declined agent error", err)
	}

	tok, err := mustAgentTokenSource(t, WithAgentEnv(env), WithAgentOrg("org-1"), WithAgentZone("zone-1")).
		ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("empty token")
	}
}

func TestAgentIntegration_Row8_DaemonStopped(t *testing.T) {
	requireUnix(t)
	env, path := defaultSocketEnv(t)
	_, err := mustAgentTokenSource(t, WithAgentEnv(env), WithAgentOrg("org-1"), WithAgentZone("zone-1")).
		ResourceToken(context.Background(), "https://api.example.com")
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("got %v, want an error wrapping *net.OpError", err)
	}
	assertNamesSocket(t, err, path)
	if !strings.Contains(err.Error(), "keycard agent start") {
		t.Errorf("error does not suggest keycard agent start: %v", err)
	}
}

// The socket is resolved on every call, so a changed process environment
// reaches a different agent, and no pooled connection carries a request to the
// socket an earlier call resolved.
func TestAgentIntegration_SocketChangeBetweenCalls(t *testing.T) {
	first, _, firstSocket := startFakeAgent(t)
	second, _, secondSocket := startFakeAgent(t)
	src := mustAgentTokenSource(t)

	t.Setenv(AgentSocketEnv, firstSocket)
	if _, err := src.ResourceToken(context.Background(), "https://api.example.com", "read"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	t.Setenv(AgentSocketEnv, secondSocket)
	if _, err := src.ResourceToken(context.Background(), "https://api.example.com", "read"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}

	firstIssued, _ := first.counts()
	secondIssued, _ := second.counts()
	if firstIssued != 1 || secondIssued != 1 {
		t.Errorf("agent requests: got %d and %d, want 1 and 1", firstIssued, secondIssued)
	}
}
