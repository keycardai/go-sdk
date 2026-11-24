package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

// AgentSocketEnv is the environment variable `keycard run` sets on its child
// process to the per-session agent's socket. Its path is generated per session,
// so the environment is the only channel that delivers it.
const AgentSocketEnv = "KEYCARD_SOCKET"

const (
	// agentIssueTokenProcedure is the agent's Connect unary procedure. Connect
	// addresses a procedure by URL path, and the agent offers no alias for an
	// older one, so this path is the wire contract.
	agentIssueTokenProcedure = "/keycard.agent.v1.AgentService/IssueToken"

	// agentRequestURL's host is a placeholder: the request goes to the socket,
	// and the agent does not interpret the host.
	agentRequestURL = "http://keycard-agent" + agentIssueTokenProcedure

	maxAgentResponseBytes = 1 << 20
	maxAgentErrorBytes    = 64 << 10
)

// ResourceTokenSource supplies an access token for a named resource. resource
// is an RFC 8707 resource indicator.
type ResourceTokenSource interface {
	ResourceToken(ctx context.Context, resource string, scopes ...string) (*TokenResponse, error)
}

// AgentTokenSource obtains resource tokens from the Keycard agent running on
// the same machine: the per-session server `keycard run` starts for its child,
// or the `keycard agent` daemon. The agent brokers each token with the
// developer's own zone session and asks a human to approve each new request, so
// the application holds no client credential.
//
// The source keeps no token cache; the agent caches. Every ResourceToken call
// sends one IssueToken request. An AgentTokenSource is safe for concurrent use.
type AgentTokenSource struct {
	socket     string
	env        map[string]string
	workload   string
	appID      string
	org        string
	zone       string
	now        func() time.Time
	httpClient *http.Client
}

// AgentTokenSourceOption configures an AgentTokenSource.
type AgentTokenSourceOption func(*AgentTokenSource)

// WithAgentSocket sets the path of the agent's Unix socket, overriding
// KEYCARD_SOCKET and the daemon's default socket. Pass it when the socket's
// directory may be shared with other users: the source does not check who
// serves a resolved socket.
func WithAgentSocket(path string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.socket = path }
}

// WithAgentEnv sets the environment the socket is resolved from, in place of
// the process environment, which is then never read. A nil or empty map is an
// empty environment. The map is copied.
func WithAgentEnv(env map[string]string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) {
		a.env = make(map[string]string, len(env))
		for k, v := range env {
			a.env[k] = v
		}
	}
}

// WithAgentWorkload sets the name shown to the human in the approval prompt.
// It is self-declared and unauthenticated.
func WithAgentWorkload(name string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.workload = name }
}

// WithAgentAppID declares the Keycard application the caller acts for, by the
// identifier set on the application (such as "incident-digest"), not its
// public id. It is matched exactly, and is self-declared and unauthenticated:
// the agent labels it self-asserted, and the authorization server records an
// accepted id on the token as keycard_declared_app_id. An id naming no
// application in the zone fails with an error [IsApplicationNotFound] matches.
func WithAgentAppID(id string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.appID = id }
}

// WithAgentOrg sets the organization id, sent as Keycard-Org. The multi-zone
// daemon needs it, with [WithAgentZone]; a per-session server ignores it.
func WithAgentOrg(org string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.org = org }
}

// WithAgentZone sets the zone id, sent as Keycard-Zone, alongside
// [WithAgentOrg].
func WithAgentZone(zone string) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.zone = zone }
}

// WithAgentClock sets the wall-clock source ExpiresIn is computed against.
// Default: time.Now. A nil now is ignored.
func WithAgentClock(now func() time.Time) AgentTokenSourceOption {
	return func(a *AgentTokenSource) {
		if now != nil {
			a.now = now
		}
	}
}

// WithAgentHTTPClient replaces the client used to reach the agent, mainly for
// tests. The default dials the resolved Unix socket; a replacement is
// responsible for reaching the agent itself, and should carry no timeout,
// since a request can wait on a human.
func WithAgentHTTPClient(c *http.Client) AgentTokenSourceOption {
	return func(a *AgentTokenSource) { a.httpClient = c }
}

// NewAgentTokenSource creates an AgentTokenSource. It returns a
// *ConfigurationError when a workload or app id is not valid UTF-8, or an org or
// zone holds a control character or invalid UTF-8. Construction opens no
// connection and does not resolve the socket: both happen, and their errors
// surface, on each ResourceToken call.
func NewAgentTokenSource(opts ...AgentTokenSourceOption) (*AgentTokenSource, error) {
	a := &AgentTokenSource{now: time.Now}
	for _, opt := range opts {
		opt(a)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	if a.httpClient == nil {
		a.httpClient = &http.Client{
			// A zero Transport, not a clone of http.DefaultTransport, so that
			// HTTP_PROXY never redirects a request meant for the socket.
			// Keep-alives are off because the socket is resolved per call: a
			// pooled connection would carry a request to the socket an earlier
			// call resolved.
			Transport: &http.Transport{
				DialContext:       dialAgentSocket,
				DisableKeepAlives: true,
			},
			// Connect never redirects, and the dialer ignores the host, so a
			// followed redirect would re-send the request to the same socket.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return a, nil
}

// ResourceToken asks the agent for a token for resource carrying scopes. The
// resource and scopes are sent exactly as given.
//
// A nil ExpiresIn on the returned token means the token does not expire: the
// agent sends no expiresAt only for such a token. That is narrower than nil on
// a TokenResponse from a token endpoint, which means only that the response
// did not state a lifetime.
//
// The source sets no timeout: the first request for an approval waits for as
// long as the human takes to answer the prompt, so bound it with ctx.
//
// Errors: a *ConfigurationError for an empty resource or an unresolvable
// socket; an *AgentError when the agent refuses (see the Is* predicates); an
// *HTTPError for a non-200 response that is not a Connect error; an
// *AgentResponseError for a 200 response that cannot be used. A transport
// failure is returned wrapped, so errors.Is and errors.As reach the
// underlying net error, with a message naming the socket and how it was chosen.
func (a *AgentTokenSource) ResourceToken(ctx context.Context, resource string, scopes ...string) (*TokenResponse, error) {
	if resource == "" {
		return nil, &ConfigurationError{Message: "keycard agent: resource is required"}
	}
	if err := validateAgentRequest(resource, scopes); err != nil {
		return nil, err
	}

	sock, err := resolveAgentSocket(runtime.GOOS, a.socket, a.getenv)
	if err != nil {
		return nil, err
	}

	if scopes == nil {
		scopes = []string{}
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(issueTokenRequest{
		Resource: resource,
		Scopes:   scopes,
		Workload: a.workload,
		AppID:    a.appID,
	}); err != nil {
		return nil, fmt.Errorf("keycard agent: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.WithValue(ctx, agentSocketKey{}, sock.path),
		http.MethodPost, agentRequestURL, &body)
	if err != nil {
		return nil, fmt.Errorf("keycard agent: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	if a.org != "" {
		req.Header.Set("Keycard-Org", a.org)
	}
	if a.zone != "" {
		req.Header.Set("Keycard-Zone", a.zone)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, sock.transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentErrorBytes))
		if err != nil {
			return nil, sock.transportError(ctx, err)
		}
		return nil, agentErrorFromBody(resp.StatusCode, raw)
	}

	// One byte past the cap tells a body of exactly the cap from a longer one,
	// which must not be parsed from its prefix: a complete object followed by
	// padding would otherwise decode.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponseBytes+1))
	if err != nil {
		return nil, sock.transportError(ctx, err)
	}
	if len(raw) > maxAgentResponseBytes {
		return nil, &AgentResponseError{Message: "IssueToken response is over 1 MiB"}
	}
	return tokenFromIssueTokenResponse(raw, a.now())
}

// validateAgentRequest and validate refuse values the request cannot carry
// unchanged, rather than let the JSON encoder or net/http rewrite or reject
// them: JSON replaces invalid UTF-8 with U+FFFD, which would ask for a
// different resource than the caller named.
func validateAgentRequest(resource string, scopes []string) error {
	if !utf8.ValidString(resource) {
		return &ConfigurationError{Message: "keycard agent: resource is not valid UTF-8"}
	}
	for _, s := range scopes {
		if !utf8.ValidString(s) {
			return &ConfigurationError{Message: "keycard agent: scope is not valid UTF-8"}
		}
	}
	return nil
}

func (a *AgentTokenSource) validate() error {
	if !utf8.ValidString(a.workload) {
		return &ConfigurationError{Message: "keycard agent: workload is not valid UTF-8"}
	}
	if !utf8.ValidString(a.appID) {
		return &ConfigurationError{Message: "keycard agent: app id is not valid UTF-8"}
	}
	if !validHeaderValue(a.org) {
		return &ConfigurationError{Message: "keycard agent: org contains a control character or invalid UTF-8"}
	}
	if !validHeaderValue(a.zone) {
		return &ConfigurationError{Message: "keycard agent: zone contains a control character or invalid UTF-8"}
	}
	return nil
}

// getenv reads the WithAgentEnv map whenever the option was applied, even with
// a nil map: the option always allocates, so a non-nil env is that signal.
func (a *AgentTokenSource) getenv(key string) string {
	if a.env != nil {
		return a.env[key]
	}
	return os.Getenv(key)
}

type issueTokenRequest struct {
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes"`
	Workload string   `json:"workload"`
	AppID    string   `json:"appId,omitempty"`
}

type issueTokenResponse struct {
	Token     string  `json:"token"`
	ExpiresAt *string `json:"expiresAt"`
	// Scopes holds pointers because encoding/json decodes a null element of a
	// []string as "", which would report a scope the agent never granted.
	Scopes []*string `json:"scopes"`
}

func tokenFromIssueTokenResponse(raw []byte, now time.Time) (*TokenResponse, error) {
	// encoding/json replaces invalid UTF-8 with U+FFFD rather than failing, so
	// a decoded token would differ from the one the agent sent.
	if !utf8.Valid(raw) {
		return nil, &AgentResponseError{Message: "IssueToken response is not valid UTF-8"}
	}
	var out issueTokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &AgentResponseError{Message: "decoding IssueToken response", Err: err}
	}
	if out.Token == "" {
		return nil, &AgentResponseError{Message: "IssueToken response has no token"}
	}
	if hasControlChar(out.Token) {
		return nil, &AgentResponseError{Message: "IssueToken response token contains a control character"}
	}
	// The decoder also turns an escaped lone surrogate ("\udc80") into U+FFFD,
	// which the check on raw cannot see. A bearer token is ASCII (RFC 6750), so
	// refusing U+FFFD outright loses no real token.
	if strings.ContainsRune(out.Token, utf8.RuneError) {
		return nil, &AgentResponseError{Message: "IssueToken response token is not valid UTF-8"}
	}

	tok := &TokenResponse{AccessToken: out.Token, TokenType: "Bearer"}
	if out.ExpiresAt != nil {
		// RFC3339Nano parses up to nine fractional digits, and fewer.
		exp, err := time.Parse(time.RFC3339Nano, *out.ExpiresAt)
		if err != nil {
			return nil, &AgentResponseError{Message: "IssueToken response expiresAt is not an RFC 3339 timestamp", Err: err}
		}
		expiresIn := 0
		if d := exp.Sub(now); d > 0 {
			expiresIn = int(d / time.Second)
		}
		tok.ExpiresIn = &expiresIn
	}
	// An empty list means the grant is unknown, not that nothing was granted.
	for _, s := range out.Scopes {
		if s == nil {
			return nil, &AgentResponseError{Message: "IssueToken response scopes holds a null element"}
		}
		tok.Scope = append(tok.Scope, *s)
	}
	return tok, nil
}

func agentErrorFromBody(status int, raw []byte) error {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err == nil {
		if code, ok := body["code"].(string); ok && code != "" {
			message, _ := body["message"].(string)
			return &AgentError{Code: code, Message: message}
		}
	}
	return &HTTPError{Message: "keycard agent: response is not a Connect error", Status: status}
}

func hasControlChar(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

func validHeaderValue(s string) bool {
	return utf8.ValidString(s) && !hasControlChar(s)
}

// agentSocketKey carries the socket a ResourceToken call resolved to the
// default client's dialer, since resolution runs per call and the transport is
// shared.
type agentSocketKey struct{}

func dialAgentSocket(ctx context.Context, _, _ string) (net.Conn, error) {
	path, ok := ctx.Value(agentSocketKey{}).(string)
	if !ok {
		return nil, errors.New("keycard agent: no socket resolved for this request")
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// agentSocketRule records which socket-resolution rule chose a path, for the
// error raised when the path cannot be reached.
type agentSocketRule int

const (
	agentSocketFromOption agentSocketRule = iota + 1
	agentSocketFromEnv
	agentSocketDefault
)

type agentSocket struct {
	path string
	rule agentSocketRule
}

// resolveAgentSocket picks the agent's socket by the first rule that applies:
// the explicit socket, then KEYCARD_SOCKET, then the daemon's default socket.
// It only computes a path, and never creates or checks a directory or file.
//
// The default transcribes the Keycard CLI's Config.AgentSocketPath, which is
// canonical: <agent_dir>/agent.sock, where agent_dir is KEYCARD_AGENT_DIR, else
// $XDG_RUNTIME_DIR/keycard, else <state>/run with <state> $XDG_STATE_HOME/keycard
// or <home>/.local/state/keycard, and <home> KEYCARD_HOME, else HOME. The CLI
// also reads keycard.toml; this does not.
func resolveAgentSocket(goos, socket string, getenv func(string) string) (agentSocket, error) {
	if socket != "" {
		return agentSocket{path: socket, rule: agentSocketFromOption}.supportedOn(goos)
	}
	if s := getenv(AgentSocketEnv); s != "" {
		return agentSocket{path: s, rule: agentSocketFromEnv}.supportedOn(goos)
	}
	if goos == "windows" {
		return agentSocket{}, &ConfigurationError{
			Message: "keycard agent: " + AgentSocketEnv + " is not set, and the keycard agent daemon's default socket is not available on Windows; set " + AgentSocketEnv + " or pass WithAgentSocket",
		}
	}

	dir := getenv("KEYCARD_AGENT_DIR")
	if dir == "" {
		if runtimeDir := getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			dir = filepath.Join(runtimeDir, "keycard")
		} else {
			stateDir := getenv("XDG_STATE_HOME")
			if stateDir != "" {
				stateDir = filepath.Join(stateDir, "keycard")
			} else {
				home := getenv("KEYCARD_HOME")
				if home == "" {
					home = getenv("HOME")
				}
				if home == "" {
					return agentSocket{}, &ConfigurationError{
						Message: "keycard agent: " + AgentSocketEnv + " is not set, and neither KEYCARD_HOME nor HOME is set to locate the keycard agent daemon's default socket; set " + AgentSocketEnv + " or pass WithAgentSocket",
					}
				}
				stateDir = filepath.Join(home, ".local", "state", "keycard")
			}
			dir = filepath.Join(stateDir, "run")
		}
	}
	return agentSocket{path: filepath.Join(dir, "agent.sock"), rule: agentSocketDefault}, nil
}

// supportedOn refuses a Windows named pipe, which `keycard run` listens on
// there and puts in KEYCARD_SOCKET: the source dials only Unix sockets.
func (s agentSocket) supportedOn(goos string) (agentSocket, error) {
	if goos == "windows" && strings.HasPrefix(s.path, `\\.\pipe\`) {
		return agentSocket{}, &ConfigurationError{
			Message: "keycard agent: socket " + s.path + " is a Windows named pipe, which this SDK cannot dial; only Unix sockets are supported",
		}
	}
	return s, nil
}

// transportError wraps a failure to reach the agent, or a connection lost
// mid-request, naming the socket and the rule that chose it.
func (s agentSocket) transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("keycard agent: request to socket %s ended: %w", s.path, err)
	}
	switch s.rule {
	case agentSocketFromOption:
		return fmt.Errorf("keycard agent: cannot reach socket %s (set by WithAgentSocket): %w", s.path, err)
	case agentSocketFromEnv:
		return fmt.Errorf("keycard agent: cannot reach socket %s (named by %s): %w", s.path, AgentSocketEnv, err)
	default:
		return fmt.Errorf("keycard agent: cannot reach socket %s (the keycard agent daemon's default socket; start the daemon with `keycard agent start`, or run this application under `keycard run`): %w", s.path, err)
	}
}
