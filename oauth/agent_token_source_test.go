package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests named TestAgentTokenSource_RowN implement row N of the Unit Tests table
// in keycard-sdk-spec specs/delegated-access/local-agent-token-source.md. Rows
// 19-23 cover an SDK-side cache, which this package does not keep.

// stubAgent answers IssueToken with a fixed response and records each request.
type stubAgent struct {
	status int
	body   string

	mu       sync.Mutex
	requests []stubRequest
}

type stubRequest struct {
	method string
	path   string
	header http.Header
	raw    string
	body   map[string]any
}

func (s *stubAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	s.mu.Lock()
	s.requests = append(s.requests, stubRequest{
		method: r.Method,
		path:   r.URL.Path,
		header: r.Header.Clone(),
		raw:    string(raw),
		body:   body,
	})
	s.mu.Unlock()

	status := s.status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, s.body)
}

func (s *stubAgent) recorded() []stubRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubRequest(nil), s.requests...)
}

// handlerTransport serves each request from an in-process handler: the
// injected HTTP client the unit rows run through.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func newStubSource(t *testing.T, stub http.Handler, opts ...AgentTokenSourceOption) *AgentTokenSource {
	t.Helper()
	base := []AgentTokenSourceOption{
		WithAgentEnv(map[string]string{AgentSocketEnv: "/stub/agent.sock"}),
		WithAgentHTTPClient(&http.Client{Transport: handlerTransport{stub}}),
	}
	return mustAgentTokenSource(t, append(base, opts...)...)
}

func mustAgentTokenSource(t *testing.T, opts ...AgentTokenSourceOption) *AgentTokenSource {
	t.Helper()
	src, err := NewAgentTokenSource(opts...)
	if err != nil {
		t.Fatalf("NewAgentTokenSource: %v", err)
	}
	return src
}

const okBody = `{"token":"tok-123"}`

func TestAgentTokenSource_Row1_Request(t *testing.T) {
	stub := &stubAgent{body: okBody}
	src := newStubSource(t, stub, WithAgentWorkload("nightly-report"))

	if _, err := src.ResourceToken(context.Background(), "https://api.example.com", "read", "write"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}

	reqs := stub.recorded()
	if len(reqs) != 1 {
		t.Fatalf("requests: got %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost || r.path != "/keycard.agent.v1.AgentService/IssueToken" {
		t.Errorf("request line: got %s %s", r.method, r.path)
	}
	if got := r.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: got %q", got)
	}
	if got := r.header.Get("Connect-Protocol-Version"); got != "1" {
		t.Errorf("Connect-Protocol-Version: got %q", got)
	}
	if r.body["resource"] != "https://api.example.com" {
		t.Errorf("resource: got %v", r.body["resource"])
	}
	if fmt.Sprint(r.body["scopes"]) != "[read write]" {
		t.Errorf("scopes: got %v", r.body["scopes"])
	}
	if r.body["workload"] != "nightly-report" {
		t.Errorf("workload: got %v", r.body["workload"])
	}
}

func TestAgentTokenSource_Row1_EmptyScopesAndWorkloadAreSent(t *testing.T) {
	stub := &stubAgent{body: okBody}
	if _, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	raw := stub.recorded()[0].raw
	if !strings.Contains(raw, `"scopes":[]`) || !strings.Contains(raw, `"workload":""`) {
		t.Errorf("body: got %s, want scopes [] and workload \"\"", raw)
	}
}

func TestAgentTokenSource_Row2_OrgAndZoneHeaders(t *testing.T) {
	stub := &stubAgent{body: okBody}
	src := newStubSource(t, stub, WithAgentOrg("org-1"), WithAgentZone("zone-1"))
	if _, err := src.ResourceToken(context.Background(), "https://api.example.com"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if _, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}

	reqs := stub.recorded()
	if got := reqs[0].header.Get("Keycard-Org"); got != "org-1" {
		t.Errorf("Keycard-Org: got %q", got)
	}
	if got := reqs[0].header.Get("Keycard-Zone"); got != "zone-1" {
		t.Errorf("Keycard-Zone: got %q", got)
	}
	for _, h := range []string{"Keycard-Org", "Keycard-Zone"} {
		if _, ok := reqs[1].header[h]; ok {
			t.Errorf("%s sent when unset", h)
		}
	}
}

func TestAgentTokenSource_Row3_AppID(t *testing.T) {
	stub := &stubAgent{body: okBody}
	if _, err := newStubSource(t, stub, WithAgentAppID("incident-digest")).ResourceToken(context.Background(), "https://api.example.com"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if _, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}

	reqs := stub.recorded()
	if reqs[0].body["appId"] != "incident-digest" {
		t.Errorf("appId: got %v", reqs[0].body["appId"])
	}
	if _, ok := reqs[1].body["appId"]; ok {
		t.Errorf("appId sent when unset: %s", reqs[1].raw)
	}
}

func TestAgentTokenSource_Row4_ResourcePassThrough(t *testing.T) {
	const resource = "HTTPS://API.Example.COM:443/a/./b/../c?x=1&y=<2>"
	stub := &stubAgent{body: okBody}
	if _, err := newStubSource(t, stub).ResourceToken(context.Background(), resource, "Read:All"); err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	r := stub.recorded()[0]
	if r.body["resource"] != resource {
		t.Errorf("resource: got %v, want %q", r.body["resource"], resource)
	}
	if !strings.Contains(r.raw, `"resource":"`+resource+`"`) {
		t.Errorf("body does not carry the resource byte for byte: %s", r.raw)
	}
	if fmt.Sprint(r.body["scopes"]) != "[Read:All]" {
		t.Errorf("scopes: got %v", r.body["scopes"])
	}
}

func TestAgentTokenSource_Row5_EmptyResource(t *testing.T) {
	stub := &stubAgent{body: okBody}
	_, err := newStubSource(t, stub).ResourceToken(context.Background(), "")
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("got %v, want *ConfigurationError", err)
	}
	if n := len(stub.recorded()); n != 0 {
		t.Errorf("requests: got %d, want 0", n)
	}
}

func TestAgentTokenSource_InvalidUTF8IsRefused(t *testing.T) {
	stub := &stubAgent{body: okBody}
	src := newStubSource(t, stub)
	tests := []struct {
		name     string
		resource string
		scopes   []string
	}{
		{"resource", "https://api.example.com/\xff", nil},
		{"scope", "https://api.example.com", []string{"\xff"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := src.ResourceToken(context.Background(), tt.resource, tt.scopes...)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("got %v, want *ConfigurationError", err)
			}
		})
	}
	if n := len(stub.recorded()); n != 0 {
		t.Errorf("requests: got %d, want 0", n)
	}
}

func TestAgentTokenSource_Row42_ControlCharacterInOrgOrZone(t *testing.T) {
	stub := &stubAgent{body: okBody}
	client := WithAgentHTTPClient(&http.Client{Transport: handlerTransport{stub}})
	for name, opt := range map[string]AgentTokenSourceOption{
		"org":  WithAgentOrg("org\r\nX-Injected: 1"),
		"zone": WithAgentZone("zone\r\nX-Injected: 1"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewAgentTokenSource(client, opt)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("got %v, want *ConfigurationError", err)
			}
		})
	}
	if n := len(stub.recorded()); n != 0 {
		t.Errorf("requests: got %d, want 0", n)
	}
}

func TestNewAgentTokenSource_InvalidOptionsAreRefused(t *testing.T) {
	tests := []struct {
		name string
		opt  AgentTokenSourceOption
	}{
		{"workload", WithAgentWorkload("report\xff")},
		{"app id", WithAgentAppID("digest\xff")},
		{"org", WithAgentOrg("org\xff")},
		{"zone", WithAgentZone("zone\xff")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, err := NewAgentTokenSource(tt.opt)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("got %v, want *ConfigurationError", err)
			}
			if src != nil {
				t.Error("got a source alongside the error")
			}
		})
	}
}

func TestAgentTokenSource_Row43_ResponseOver1MiB(t *testing.T) {
	bodies := map[string]string{
		"oversized token": `{"token":"` + strings.Repeat("a", maxAgentResponseBytes) + `"}`,
		// A complete object whose padding runs past the cap must not decode
		// from the prefix that fits.
		"padded object": okBody + strings.Repeat(" ", maxAgentResponseBytes),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			_, err := newStubSource(t, &stubAgent{body: body}).ResourceToken(context.Background(), "https://api.example.com")
			var respErr *AgentResponseError
			if !errors.As(err, &respErr) {
				t.Fatalf("got %v, want *AgentResponseError", err)
			}
		})
	}

	t.Run("exactly 1 MiB", func(t *testing.T) {
		body := okBody + strings.Repeat(" ", maxAgentResponseBytes-len(okBody))
		if _, err := newStubSource(t, &stubAgent{body: body}).ResourceToken(context.Background(), "https://api.example.com"); err != nil {
			t.Fatalf("ResourceToken: %v", err)
		}
	})
}

func TestAgentTokenSource_OversizedErrorIsNotParsed(t *testing.T) {
	stub := &stubAgent{
		status: http.StatusForbidden,
		body:   `{"code":"permission_denied","message":"` + strings.Repeat("a", maxAgentErrorBytes) + `"}`,
	}
	_, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("got %v, want *HTTPError", err)
	}
}

// requireUnix skips socket-resolution rows on platforms without rule 3.
func requireUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the default agent socket is Unix-only")
	}
}

// dialledSocket mints through the default client and returns the error, whose
// message names the socket that was dialled. Every path it is given is absent,
// so the dial fails.
func dialledSocket(t *testing.T, opts ...AgentTokenSourceOption) error {
	t.Helper()
	_, err := mustAgentTokenSource(t, opts...).ResourceToken(context.Background(), "https://api.example.com")
	if err == nil {
		t.Fatal("ResourceToken succeeded against an absent socket")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("got %v, want an error wrapping *net.OpError", err)
	}
	return err
}

func assertNamesSocket(t *testing.T, err error, path string) {
	t.Helper()
	if !strings.Contains(err.Error(), "socket "+path+" ") {
		t.Errorf("error does not name %s: %v", path, err)
	}
}

func TestAgentTokenSource_Row6_SocketOptionWins(t *testing.T) {
	dir := t.TempDir()
	explicit := filepath.Join(dir, "explicit.sock")
	fromEnv := filepath.Join(dir, "env.sock")
	err := dialledSocket(t, WithAgentSocket(explicit), WithAgentEnv(map[string]string{AgentSocketEnv: fromEnv}))
	assertNamesSocket(t, err, explicit)
	if !strings.Contains(err.Error(), "WithAgentSocket") {
		t.Errorf("error does not name the rule: %v", err)
	}
}

func TestAgentTokenSource_Row7_SocketFromEnvMapping(t *testing.T) {
	dir := t.TempDir()
	fromEnv := filepath.Join(dir, "env.sock")
	t.Setenv(AgentSocketEnv, filepath.Join(dir, "process.sock"))
	err := dialledSocket(t, WithAgentEnv(map[string]string{AgentSocketEnv: fromEnv}))
	assertNamesSocket(t, err, fromEnv)
	if !strings.Contains(err.Error(), AgentSocketEnv) {
		t.Errorf("error does not name the rule: %v", err)
	}
}

func TestAgentTokenSource_Row7_SocketFromProcessEnvironment(t *testing.T) {
	fromEnv := filepath.Join(t.TempDir(), "process.sock")
	t.Setenv(AgentSocketEnv, fromEnv)
	assertNamesSocket(t, dialledSocket(t), fromEnv)
}

func TestAgentTokenSource_DefaultSocketResolution(t *testing.T) {
	requireUnix(t)
	tests := []struct {
		row  int
		env  map[string]string
		want string
	}{
		{8, map[string]string{AgentSocketEnv: "", "HOME": "/h"}, "/h/.local/state/keycard/run/agent.sock"},
		{9, map[string]string{"HOME": "/h"}, "/h/.local/state/keycard/run/agent.sock"},
		{10, map[string]string{"HOME": "/h", "KEYCARD_HOME": "/k"}, "/k/.local/state/keycard/run/agent.sock"},
		{11, map[string]string{"HOME": "/h", "XDG_STATE_HOME": "/s"}, "/s/keycard/run/agent.sock"},
		{12, map[string]string{"HOME": "/h", "XDG_STATE_HOME": "/s", "XDG_RUNTIME_DIR": "/r"}, "/r/keycard/agent.sock"},
		{13, map[string]string{"HOME": "/h", "XDG_STATE_HOME": "/s", "XDG_RUNTIME_DIR": "/r", "KEYCARD_AGENT_DIR": "/a"}, "/a/agent.sock"},
		{0, map[string]string{"HOME": "/h", "KEYCARD_HOME": "", "XDG_STATE_HOME": "", "XDG_RUNTIME_DIR": "", "KEYCARD_AGENT_DIR": ""}, "/h/.local/state/keycard/run/agent.sock"},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("Row%d", tt.row)
		if tt.row == 0 {
			name = "EmptyValuesAreUnset"
		}
		t.Run(name, func(t *testing.T) {
			got, err := resolveAgentSocket("linux", "", mapGetenv(tt.env))
			if err != nil {
				t.Fatalf("resolveAgentSocket: %v", err)
			}
			if got.path != tt.want || got.rule != agentSocketDefault {
				t.Errorf("got %s (rule %d), want %s", got.path, got.rule, tt.want)
			}

			err = dialledSocket(t, WithAgentEnv(tt.env))
			assertNamesSocket(t, err, tt.want)
			if !strings.Contains(err.Error(), "keycard agent start") {
				t.Errorf("error does not suggest keycard agent start: %v", err)
			}
		})
	}
}

func TestAgentTokenSource_Row14_KeycardTOMLIsNotRead(t *testing.T) {
	requireUnix(t)
	dir := t.TempDir()
	toml := "[home]\ndir = \"/toml-home\"\n\n[agent]\nDir = \"/toml-agent\"\n"
	if err := os.WriteFile(filepath.Join(dir, "keycard.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)

	err := dialledSocket(t, WithAgentEnv(map[string]string{"HOME": "/h"}))
	assertNamesSocket(t, err, "/h/.local/state/keycard/run/agent.sock")
}

func TestAgentTokenSource_Row15_NoHome(t *testing.T) {
	requireUnix(t)
	stub := &stubAgent{body: okBody}
	src := mustAgentTokenSource(t,
		WithAgentEnv(map[string]string{}),
		WithAgentHTTPClient(&http.Client{Transport: handlerTransport{stub}}),
	)
	_, err := src.ResourceToken(context.Background(), "https://api.example.com")
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("got %v, want *ConfigurationError", err)
	}
	for _, name := range []string{AgentSocketEnv, "HOME"} {
		if !strings.Contains(cfgErr.Message, name) {
			t.Errorf("message does not name %s: %q", name, cfgErr.Message)
		}
	}
	if n := len(stub.recorded()); n != 0 {
		t.Errorf("requests: got %d, want 0", n)
	}
}

func TestAgentTokenSource_Windows_DefaultSocketIsConfigurationError(t *testing.T) {
	_, err := resolveAgentSocket("windows", "", mapGetenv(map[string]string{"HOME": "/h"}))
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("got %v, want *ConfigurationError", err)
	}
	if !strings.Contains(cfgErr.Message, AgentSocketEnv) {
		t.Errorf("message does not name %s: %q", AgentSocketEnv, cfgErr.Message)
	}

	got, err := resolveAgentSocket("windows", "", mapGetenv(map[string]string{AgentSocketEnv: `C:\agent.sock`}))
	if err != nil || got.path != `C:\agent.sock` {
		t.Errorf("KEYCARD_SOCKET on Windows: got %q, %v", got.path, err)
	}
}

func TestAgentTokenSource_Windows_NamedPipeIsConfigurationError(t *testing.T) {
	const pipe = `\\.\pipe\keycard-0b5e`
	tests := []struct {
		name   string
		socket string
		env    map[string]string
	}{
		{"KEYCARD_SOCKET", "", map[string]string{AgentSocketEnv: pipe}},
		{"WithAgentSocket", pipe, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveAgentSocket("windows", tt.socket, mapGetenv(tt.env))
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("got %v, want *ConfigurationError", err)
			}
			if !strings.Contains(cfgErr.Message, "named pipe") {
				t.Errorf("message does not say named pipes are unsupported: %q", cfgErr.Message)
			}
		})
	}
}

func TestAgentTokenSource_RedirectIsNotFollowed(t *testing.T) {
	requireUnix(t)
	path := filepath.Join(socketTempDir(t), "agent.sock")
	var mu sync.Mutex
	var paths []string
	serveAgent(t, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))

	_, err := mustAgentTokenSource(t, WithAgentSocket(path)).ResourceToken(context.Background(), "https://api.example.com")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusTemporaryRedirect {
		t.Fatalf("got %v, want *HTTPError with status 307", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 {
		t.Errorf("agent saw %d requests, want 1: %v", len(paths), paths)
	}
}

func TestAgentTokenSource_Row16_ConnectFailureLeavesNoState(t *testing.T) {
	requireUnix(t)
	home := t.TempDir()
	err := dialledSocket(t, WithAgentEnv(map[string]string{"HOME": home}))
	assertNamesSocket(t, err, filepath.Join(home, ".local/state/keycard/run/agent.sock"))
	if !strings.Contains(err.Error(), "keycard agent start") {
		t.Errorf("error does not suggest keycard agent start: %v", err)
	}
	entries, rerr := os.ReadDir(home)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Errorf("home is not empty after the mint: %v", entries)
	}
}

func TestAgentTokenSource_Row17_RealUnixSocket(t *testing.T) {
	requireUnix(t)
	path := filepath.Join(socketTempDir(t), "agent.sock")
	stub := &stubAgent{body: `{"token":"tok-unix"}`}
	serveAgent(t, path, stub)

	tok, err := mustAgentTokenSource(t, WithAgentSocket(path)).ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.AccessToken != "tok-unix" || tok.TokenType != "Bearer" {
		t.Errorf("token: got %+v", tok)
	}
}

func TestAgentTokenSource_Row18_NoSDKCache(t *testing.T) {
	stub := &stubAgent{body: okBody}
	src := newStubSource(t, stub)
	for range 2 {
		if _, err := src.ResourceToken(context.Background(), "https://api.example.com", "read"); err != nil {
			t.Fatalf("ResourceToken: %v", err)
		}
	}
	if n := len(stub.recorded()); n != 2 {
		t.Errorf("requests: got %d, want 2", n)
	}
}

func TestAgentTokenSource_Row24_NoExpiresAt(t *testing.T) {
	tok, err := newStubSource(t, &stubAgent{body: okBody}).ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.ExpiresIn != nil {
		t.Errorf("ExpiresIn: got %d, want nil", *tok.ExpiresIn)
	}
}

func TestAgentTokenSource_Row25_ExpiresAtInThePast(t *testing.T) {
	stub := &stubAgent{body: `{"token":"tok","expiresAt":"2020-01-01T00:00:00Z"}`}
	tok, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.ExpiresIn == nil || *tok.ExpiresIn != 0 {
		t.Errorf("ExpiresIn: got %v, want 0", tok.ExpiresIn)
	}
}

func TestAgentTokenSource_Row26_NineFractionalDigitsAndClock(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	stub := &stubAgent{body: `{"token":"tok","expiresAt":"2030-01-01T00:01:40.123456789Z"}`}
	src := newStubSource(t, stub, WithAgentClock(func() time.Time { return now }))
	tok, err := src.ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.ExpiresIn == nil || *tok.ExpiresIn != 100 {
		t.Errorf("ExpiresIn: got %v, want 100", tok.ExpiresIn)
	}
}

func TestAgentTokenSource_FarExpiresAtIsCapped(t *testing.T) {
	stub := &stubAgent{body: `{"token":"tok","expiresAt":"9999-12-31T23:59:59Z"}`}
	tok, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.ExpiresIn == nil || *tok.ExpiresIn != math.MaxInt32 {
		t.Errorf("ExpiresIn: got %v, want math.MaxInt32", tok.ExpiresIn)
	}
}

func TestAgentTokenSource_NilClockIsIgnored(t *testing.T) {
	stub := &stubAgent{body: `{"token":"tok","expiresAt":"` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"}`}
	tok, err := newStubSource(t, stub, WithAgentClock(nil)).ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.ExpiresIn == nil || *tok.ExpiresIn <= 0 {
		t.Errorf("ExpiresIn: got %v, want a positive lifetime", tok.ExpiresIn)
	}
}

func TestAgentTokenSource_Row27_GrantedScopes(t *testing.T) {
	stub := &stubAgent{body: `{"token":"tok","scopes":["a","b"]}`}
	tok, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com", "a")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if fmt.Sprint(tok.Scope) != "[a b]" {
		t.Errorf("Scope: got %v, want [a b]", tok.Scope)
	}
}

func TestAgentTokenSource_Row28_NoGrantedScopes(t *testing.T) {
	for _, body := range []string{`{"token":"tok"}`, `{"token":"tok","scopes":[]}`} {
		tok, err := newStubSource(t, &stubAgent{body: body}).ResourceToken(context.Background(), "https://api.example.com", "a")
		if err != nil {
			t.Fatalf("ResourceToken: %v", err)
		}
		if tok.Scope != nil {
			t.Errorf("%s: Scope: got %v, want absent", body, tok.Scope)
		}
	}
}

var agentCodePredicates = []struct {
	code      string
	predicate string
	retryable bool
}{
	{AgentCodePermissionDenied, "IsDeclined", false},
	{AgentCodeResourceExhausted, "IsRateLimited", true},
	{AgentCodeFailedPrecondition, "IsPrompterUnavailable", false},
	{AgentCodeUnauthenticated, "IsAuthorizationRequired", false},
	{AgentCodeNotFound, "IsApplicationNotFound", false},
	{AgentCodeUnavailable, "IsUnavailable", true},
	{AgentCodeInvalidArgument, "", false},
	{AgentCodeInternal, "", false},
	{AgentCodeUnknown, "", false},
}

func matchingPredicates(err error) []string {
	all := []struct {
		name string
		fn   func(error) bool
	}{
		{"IsDeclined", IsDeclined},
		{"IsRateLimited", IsRateLimited},
		{"IsPrompterUnavailable", IsPrompterUnavailable},
		{"IsAuthorizationRequired", IsAuthorizationRequired},
		{"IsApplicationNotFound", IsApplicationNotFound},
		{"IsUnavailable", IsUnavailable},
	}
	var matched []string
	for _, p := range all {
		if p.fn(err) {
			matched = append(matched, p.name)
		}
	}
	return matched
}

func TestAgentTokenSource_Row29_ConnectErrorCodes(t *testing.T) {
	for _, tt := range agentCodePredicates {
		t.Run(tt.code, func(t *testing.T) {
			stub := &stubAgent{
				status: http.StatusForbidden,
				body:   `{"code":"` + tt.code + `","message":"run keycard login"}`,
			}
			_, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
			var agentErr *AgentError
			if !errors.As(err, &agentErr) {
				t.Fatalf("got %v, want *AgentError", err)
			}
			if agentErr.Code != tt.code || agentErr.Message != "run keycard login" {
				t.Errorf("got code %q message %q", agentErr.Code, agentErr.Message)
			}
			matched := matchingPredicates(err)
			want := []string{tt.predicate}
			if tt.predicate == "" {
				want = nil
			}
			if fmt.Sprint(matched) != fmt.Sprint(want) {
				t.Errorf("matching predicates: got %v, want %v", matched, want)
			}
		})
	}
}

func TestAgentTokenSource_Row30_WrappedAgentError(t *testing.T) {
	for _, tt := range agentCodePredicates {
		if tt.predicate == "" {
			continue
		}
		err := fmt.Errorf("fetching report: %w", &AgentError{Code: tt.code})
		if matched := matchingPredicates(err); fmt.Sprint(matched) != fmt.Sprint([]string{tt.predicate}) {
			t.Errorf("%s: matching predicates: got %v, want [%s]", tt.code, matched, tt.predicate)
		}
	}
}

func TestAgentTokenSource_Row31_NonConnectErrorResponse(t *testing.T) {
	bodies := []string{
		`<html>bad gateway</html>`,
		`{"message":"no code"}`,
		`{"code":""}`,
		`{"code":7,"message":"numeric code"}`,
	}
	for _, body := range bodies {
		stub := &stubAgent{status: http.StatusBadGateway, body: body}
		_, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusBadGateway {
			t.Errorf("%s: got %v, want *HTTPError with status 502", body, err)
		}
		var agentErr *AgentError
		if errors.As(err, &agentErr) {
			t.Errorf("%s: got an *AgentError", body)
		}
	}
}

func TestAgentTokenSource_Row32_UnusableToken(t *testing.T) {
	bodies := map[string]string{
		"empty token":      `{"token":""}`,
		"missing token":    `{"expiresAt":"2030-01-01T00:00:00Z"}`,
		"null token":       `{"token":null}`,
		"non-string token": `{"token":42}`,
		"non-JSON body":    `tok-123`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			_, err := newStubSource(t, &stubAgent{body: body}).ResourceToken(context.Background(), "https://api.example.com")
			var respErr *AgentResponseError
			if !errors.As(err, &respErr) {
				t.Fatalf("got %v, want *AgentResponseError", err)
			}
			if respErr.Retryable() {
				t.Error("Retryable: got true")
			}
		})
	}
}

func TestAgentTokenSource_Row33_ControlCharacterInToken(t *testing.T) {
	const secret = "secret-token-value"
	stub := &stubAgent{body: `{"token":"` + secret + `\r\nX-Injected: 1"}`}
	_, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
	var respErr *AgentResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("got %v, want *AgentResponseError", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks the token: %v", err)
	}
}

// Row 44 is the token byte case; the rest refuse the other ways the decoder
// would rewrite the response.
func TestAgentTokenSource_Row44_InvalidUTF8Response(t *testing.T) {
	const secret = "secret-token-value"
	bodies := map[string]string{
		"token byte":           `{"token":"` + secret + "\xff" + `"}`,
		"token lone surrogate": `{"token":"` + secret + `\udc80"}`,
		"scope byte":           `{"token":"` + secret + `","scopes":["a` + "\xff" + `"]}`,
		"unknown key byte":     `{"token":"` + secret + `","note":"` + "\xff" + `"}`,
		"token literal U+FFFD": `{"token":"` + secret + "\uFFFD" + `"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			_, err := newStubSource(t, &stubAgent{body: body}).ResourceToken(context.Background(), "https://api.example.com")
			var respErr *AgentResponseError
			if !errors.As(err, &respErr) {
				t.Fatalf("got %v, want *AgentResponseError", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the token: %v", err)
			}
		})
	}
}

func TestAgentTokenSource_UnparseableExpiresAt(t *testing.T) {
	for _, expiresAt := range []string{`"tomorrow"`, `""`, `1700000000`} {
		stub := &stubAgent{body: `{"token":"secret-token-value","expiresAt":` + expiresAt + `}`}
		_, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
		var respErr *AgentResponseError
		if !errors.As(err, &respErr) {
			t.Errorf("expiresAt %s: got %v, want *AgentResponseError", expiresAt, err)
			continue
		}
		if strings.Contains(err.Error(), "secret-token-value") {
			t.Errorf("expiresAt %s: error leaks the token: %v", expiresAt, err)
		}
	}
}

func TestAgentTokenSource_Row34_Retryable(t *testing.T) {
	for _, tt := range agentCodePredicates {
		if got := (&AgentError{Code: tt.code}).Retryable(); got != tt.retryable {
			t.Errorf("%s: Retryable: got %v, want %v", tt.code, got, tt.retryable)
		}
	}
}

func TestAgentTokenSource_Row39_ScopesNotAnArrayOfStrings(t *testing.T) {
	bodies := map[string]string{
		"string":       `{"token":"tok","scopes":"a b"}`,
		"non-string":   `{"token":"tok","scopes":["a",42]}`,
		"null element": `{"token":"tok","scopes":["a",null]}`,
		"object":       `{"token":"tok","scopes":{"a":true}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			tok, err := newStubSource(t, &stubAgent{body: body}).ResourceToken(context.Background(), "https://api.example.com", "a")
			var respErr *AgentResponseError
			if !errors.As(err, &respErr) {
				t.Fatalf("got token %v, error %v, want *AgentResponseError", tok, err)
			}
		})
	}
}

func TestAgentTokenSource_Row40_NullExpiresAt(t *testing.T) {
	stub := &stubAgent{body: `{"token":"tok","expiresAt":null}`}
	tok, err := newStubSource(t, stub).ResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("ResourceToken: %v", err)
	}
	if tok.ExpiresIn != nil {
		t.Errorf("ExpiresIn: got %d, want nil", *tok.ExpiresIn)
	}
}

func TestAgentTokenSource_Row41_EmptySocketFallsBackToEnv(t *testing.T) {
	fromEnv := filepath.Join(t.TempDir(), "env.sock")
	err := dialledSocket(t, WithAgentSocket(""), WithAgentEnv(map[string]string{AgentSocketEnv: fromEnv}))
	assertNamesSocket(t, err, fromEnv)
	if !strings.Contains(err.Error(), AgentSocketEnv) {
		t.Errorf("error does not name the rule: %v", err)
	}
}

func TestAgentTokenSource_CancelledContext(t *testing.T) {
	requireUnix(t)
	path := filepath.Join(socketTempDir(t), "agent.sock")
	release := make(chan struct{})
	serveAgent(t, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := mustAgentTokenSource(t, WithAgentSocket(path)).ResourceToken(ctx, "https://api.example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	if msg := err.Error(); strings.Contains(msg, "cannot reach") || !strings.Contains(msg, "ended") {
		t.Errorf("a cancelled request reads as an unreachable agent: %v", err)
	}
}

func mapGetenv(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

// socketTempDir returns a directory short enough to hold a Unix socket path:
// macOS caps sun_path at 104 bytes, and its per-user TMPDIR is long.
func socketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kc")
	if err == nil && len(dir) > 60 {
		_ = os.Remove(dir)
		dir, err = os.MkdirTemp("/tmp", "kc")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveAgent serves h on a Unix socket at path until the test ends.
func serveAgent(t *testing.T, path string, h http.Handler) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
}
