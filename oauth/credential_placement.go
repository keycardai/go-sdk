package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// The token types PlaceCredential accepts. It compares token_type without
// regard to case (RFC 6749 section 5.1).
const (
	TokenTypeBearer          = "Bearer"
	TokenTypeBasic           = "Basic"
	TokenTypeKeycardAPIKey   = "Keycard-API-Key"
	TokenTypeKeycardPassword = "Keycard-Password"
)

// CredentialLocation says where a placed value goes on a request.
type CredentialLocation string

// The locations of a CredentialField. A Keycard-API-Key method with in
// "scheme" places an Authorization header.
const (
	CredentialInHeader CredentialLocation = "header"
	CredentialInQuery  CredentialLocation = "query"
	CredentialInCookie CredentialLocation = "cookie"
)

// CredentialField is one value to set on a request.
type CredentialField struct {
	In CredentialLocation
	// Name is the header, query parameter or cookie name, with the case the
	// token response gave.
	Name string
	// Value is a secret. The printed form of a CredentialField does not
	// include it.
	Value string
}

// Format prints the field's location and name, for every verb.
func (f CredentialField) Format(s fmt.State, _ rune) {
	io.WriteString(s, string(f.In)+" "+f.Name)
}

// CredentialPlacement is the list of fields PlaceCredential returns.
type CredentialPlacement []CredentialField

// Format prints each field's location and name, for every verb.
func (p CredentialPlacement) Format(s fmt.State, _ rune) {
	fields := make([]string, len(p))
	for i, f := range p {
		fields[i] = string(f.In) + " " + f.Name
	}
	io.WriteString(s, "["+strings.Join(fields, ", ")+"]")
}

// CredentialPlacementReason says which rule refused a credential.
type CredentialPlacementReason string

// Reasons a CredentialPlacementError gives.
const (
	// PlacementUnsupportedTokenType: token_type is not Bearer, Basic,
	// Keycard-API-Key or Keycard-Password.
	PlacementUnsupportedTokenType CredentialPlacementReason = "unsupported_token_type"
	// PlacementInvalidMethod: method is missing or breaks a rule.
	PlacementInvalidMethod CredentialPlacementReason = "invalid_method"
	// PlacementInvalidCredential: a secret is missing or cannot be sent where
	// method puts it.
	PlacementInvalidCredential CredentialPlacementReason = "invalid_credential"
	// PlacementCrossOriginRedirect: a request with a placed credential was
	// redirected to another origin.
	PlacementCrossOriginRedirect CredentialPlacementReason = "cross_origin_redirect"
)

// CredentialPlacementError is returned when a credential cannot be placed on a
// request. The message names the token type and the rule that failed, and
// never includes a secret. Retrying does not help. Only a change to the zone's
// configuration for the resource fixes it.
type CredentialPlacementError struct {
	Reason    CredentialPlacementReason
	TokenType string
	Message   string
}

func (e *CredentialPlacementError) Error() string {
	return fmt.Sprintf("credential placement %s for token_type %q: %s", e.Reason, e.TokenType, e.Message)
}

func (*CredentialPlacementError) keycardError() {}

// PlacementOption configures PlaceCredential, ApplyCredential and
// NewCredentialTransport.
type PlacementOption func(*placementConfig)

type placementConfig struct {
	allowHeader func(name string) bool
}

// WithPlacementAllowHeader sets the function that decides whether a method may
// put a value in the header name. PlaceCredential calls it only for names
// that are RFC 9110 tokens. Returning true does not lift that check. Default:
// DefaultAllowHeader. Call DefaultAllowHeader from allow to refuse more names
// and still refuse the default ones.
func WithPlacementAllowHeader(allow func(name string) bool) PlacementOption {
	return func(cfg *placementConfig) { cfg.allowHeader = allow }
}

// refusedHeaders are the header names, in lower case, DefaultAllowHeader
// refuses. These headers control the connection, message framing, routing or
// a proxy. A resource's method must not set them.
var refusedHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"content-length":      true,
	"host":                true,
	"forwarded":           true,
}

// DefaultAllowHeader returns false for Connection, Proxy-Connection,
// Keep-Alive, TE, Trailer, Transfer-Encoding, Upgrade, Proxy-Authenticate,
// Proxy-Authorization, Content-Length, Host and Forwarded, and for any name
// that starts with X-Forwarded- or Sec-, ignoring case. It returns true for
// every other name, Authorization included.
func DefaultAllowHeader(name string) bool {
	lower := strings.ToLower(name)
	if refusedHeaders[lower] {
		return false
	}
	return !strings.HasPrefix(lower, "x-forwarded-") && !strings.HasPrefix(lower, "sec-")
}

// PlaceCredential returns the fields that send token's credential to the
// resource, per its token_type and method. It does not make a request. It
// returns a *CredentialPlacementError when it refuses the token.
//
//   - Bearer, or no token_type: Authorization: Bearer <access_token>.
//   - Basic: Authorization: Basic base64(<user_id>:<access_token>).
//   - Keycard-API-Key: one field, where method says.
//   - Keycard-Password: Username where method.username says, and AccessToken
//     where method.password says.
func PlaceCredential(token *TokenResponse, opts ...PlacementOption) (CredentialPlacement, error) {
	cfg := placementConfig{allowHeader: DefaultAllowHeader}
	for _, opt := range opts {
		opt(&cfg)
	}
	if token == nil {
		return nil, &CredentialPlacementError{Reason: PlacementInvalidCredential, Message: "token response is nil"}
	}
	p := placer{token: token, cfg: cfg}
	switch {
	case token.TokenType == "" || strings.EqualFold(token.TokenType, TokenTypeBearer):
		p.tokenType = TokenTypeBearer
		return p.bearer()
	case strings.EqualFold(token.TokenType, TokenTypeBasic):
		p.tokenType = TokenTypeBasic
		return p.basic()
	case strings.EqualFold(token.TokenType, TokenTypeKeycardAPIKey):
		p.tokenType = TokenTypeKeycardAPIKey
		return p.apiKey()
	case strings.EqualFold(token.TokenType, TokenTypeKeycardPassword):
		p.tokenType = TokenTypeKeycardPassword
		return p.password()
	default:
		return nil, &CredentialPlacementError{
			Reason:    PlacementUnsupportedTokenType,
			TokenType: token.TokenType,
			Message:   "token_type is not Bearer, Basic, Keycard-API-Key or Keycard-Password",
		}
	}
}

// ApplyCredential places token's credential and sets it on req. It returns the
// same errors as PlaceCredential and leaves req unchanged when it refuses.
//
// A header field replaces every header of that name, ignoring case. Header
// names are stored in canonical form (net/textproto). A query field replaces
// every query parameter with that form-decoded name and goes at the end. A
// cookie field replaces the cookie of that name in the Cookie header.
//
// ApplyCredential does not control redirects. On a redirect to another host,
// http.Client drops Authorization and Cookie and copies every other header.
// To send the request through an http.Client that follows redirects, use
// NewCredentialTransport.
func ApplyCredential(token *TokenResponse, req *http.Request, opts ...PlacementOption) error {
	placement, err := PlaceCredential(token, opts...)
	if err != nil {
		return err
	}
	placement.apply(req)
	return nil
}

// CredentialTransport is an http.RoundTripper that sets a placed credential on
// each request. It refuses a redirect to another origin (scheme, host and
// port) with a *CredentialPlacementError, reason cross_origin_redirect, and
// does not send that request. http.Client returns it wrapped in a *url.Error.
type CredentialTransport struct {
	placement CredentialPlacement
	tokenType string
	base      http.RoundTripper
}

// NewCredentialTransport places token's credential and returns a transport
// that sets it on every request it sends through base. A nil base means
// http.DefaultTransport. It returns the same errors as PlaceCredential.
func NewCredentialTransport(token *TokenResponse, base http.RoundTripper, opts ...PlacementOption) (*CredentialTransport, error) {
	placement, err := PlaceCredential(token, opts...)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = http.DefaultTransport
	}
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = TokenTypeBearer
	}
	return &CredentialTransport{placement: placement, tokenType: tokenType, base: base}, nil
}

// RoundTrip sets the credential on a clone of req and sends it.
func (t *CredentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response != nil && req.Response.Request != nil {
		from, to := origin(req.Response.Request.URL), origin(req.URL)
		if from != to {
			if req.Body != nil {
				req.Body.Close()
			}
			return nil, &CredentialPlacementError{
				Reason:    PlacementCrossOriginRedirect,
				TokenType: t.tokenType,
				Message:   fmt.Sprintf("redirect from %s to %s", from, to),
			}
		}
	}
	out := req.Clone(req.Context())
	t.placement.apply(out)
	return t.base.RoundTrip(out)
}

// origin returns the scheme, host and port of u, with the default port filled
// in for http and https.
func origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func (p CredentialPlacement) apply(req *http.Request) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for _, f := range p {
		switch f.In {
		case CredentialInHeader:
			takeHeader(req.Header, f.Name)
			req.Header.Set(f.Name, f.Value)
		case CredentialInQuery:
			req.URL.RawQuery = replaceQueryParam(req.URL.RawQuery, f.Name, f.Value)
		case CredentialInCookie:
			setCookie(req.Header, f.Name, f.Value)
		}
	}
}

// takeHeader removes every header whose name equals name, ignoring case, and
// returns their values in order.
func takeHeader(h http.Header, name string) []string {
	var values []string
	for key, v := range h {
		if strings.EqualFold(key, name) {
			values = append(values, v...)
			delete(h, key)
		}
	}
	return values
}

// replaceQueryParam drops every parameter of rawQuery whose form-decoded name
// is name, then appends name=value, form-encoded. The other parameters keep
// their order and bytes.
func replaceQueryParam(rawQuery, name, value string) string {
	var kept []string
	if rawQuery != "" {
		for _, param := range strings.Split(rawQuery, "&") {
			key, _, _ := strings.Cut(param, "=")
			if decoded, err := url.QueryUnescape(key); err == nil && decoded == name {
				continue
			}
			kept = append(kept, param)
		}
	}
	kept = append(kept, url.QueryEscape(name)+"="+url.QueryEscape(value))
	return strings.Join(kept, "&")
}

// setCookie replaces the cookie name in h's Cookie headers with name=value at
// the end, and leaves one Cookie header. Cookie names are compared with case.
func setCookie(h http.Header, name, value string) {
	var kept []string
	for _, line := range takeHeader(h, "Cookie") {
		for _, cookie := range strings.Split(line, ";") {
			cookie = strings.TrimSpace(cookie)
			if cookie == "" {
				continue
			}
			key, _, _ := strings.Cut(cookie, "=")
			if strings.TrimSpace(key) == name {
				continue
			}
			kept = append(kept, cookie)
		}
	}
	kept = append(kept, name+"="+value)
	h.Set("Cookie", strings.Join(kept, "; "))
}

// placer checks one token response and builds its placement.
type placer struct {
	token     *TokenResponse
	cfg       placementConfig
	tokenType string
}

func (p *placer) refuse(reason CredentialPlacementReason, format string, args ...any) error {
	return &CredentialPlacementError{Reason: reason, TokenType: p.tokenType, Message: fmt.Sprintf(format, args...)}
}

func (p *placer) bearer() (CredentialPlacement, error) {
	if err := p.headerValue("access_token", p.token.AccessToken); err != nil {
		return nil, err
	}
	return CredentialPlacement{{In: CredentialInHeader, Name: "Authorization", Value: "Bearer " + p.token.AccessToken}}, nil
}

func (p *placer) basic() (CredentialPlacement, error) {
	if p.token.UserID == "" {
		return nil, p.refuse(PlacementInvalidCredential, "user_id is missing")
	}
	if strings.Contains(p.token.UserID, ":") {
		return nil, p.refuse(PlacementInvalidCredential, "user_id has a colon (RFC 7617 section 2)")
	}
	if p.token.AccessToken == "" {
		return nil, p.refuse(PlacementInvalidCredential, "access_token is empty")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(p.token.UserID + ":" + p.token.AccessToken))
	return CredentialPlacement{{In: CredentialInHeader, Name: "Authorization", Value: "Basic " + encoded}}, nil
}

func (p *placer) apiKey() (CredentialPlacement, error) {
	members, err := p.object(p.token.Method, "method", "in", "name", "scheme_parameter")
	if err != nil {
		return nil, err
	}
	in, name, err := p.inAndName(members, "method")
	if err != nil {
		return nil, err
	}
	schemeParameter, hasSchemeParameter, err := p.optionalString(members, "method", "scheme_parameter")
	if err != nil {
		return nil, err
	}
	if hasSchemeParameter && in != "scheme" {
		return nil, p.refuse(PlacementInvalidMethod, "method.scheme_parameter is set and method.in is %q, not scheme", in)
	}

	key := p.token.AccessToken
	switch in {
	case "header":
		if err := p.headerName("method", name); err != nil {
			return nil, err
		}
		if err := p.headerValue("access_token", key); err != nil {
			return nil, err
		}
		return CredentialPlacement{{In: CredentialInHeader, Name: name, Value: key}}, nil
	case "query":
		if name == "" {
			return nil, p.refuse(PlacementInvalidMethod, "method.name is empty")
		}
		if key == "" {
			return nil, p.refuse(PlacementInvalidCredential, "access_token is empty")
		}
		return CredentialPlacement{{In: CredentialInQuery, Name: name, Value: key}}, nil
	case "cookie":
		if !isToken(name) {
			return nil, p.refuse(PlacementInvalidMethod, "cookie name %q in method.name is not an RFC 9110 token", name)
		}
		if err := p.cookieValue("access_token", key); err != nil {
			return nil, err
		}
		return CredentialPlacement{{In: CredentialInCookie, Name: name, Value: key}}, nil
	case "scheme":
		if !isToken(name) {
			return nil, p.refuse(PlacementInvalidMethod, "scheme name %q in method.name is not an RFC 9110 token", name)
		}
		if hasSchemeParameter && !isToken(schemeParameter) {
			return nil, p.refuse(PlacementInvalidMethod, "method.scheme_parameter %q is not an RFC 9110 token", schemeParameter)
		}
		if err := p.headerValue("access_token", key); err != nil {
			return nil, err
		}
		value := name + " " + key
		if hasSchemeParameter {
			value = name + " " + schemeParameter + "=" + key
		}
		return CredentialPlacement{{In: CredentialInHeader, Name: "Authorization", Value: value}}, nil
	default:
		return nil, p.refuse(PlacementInvalidMethod, "method.in %q is not header, query, cookie or scheme", in)
	}
}

func (p *placer) password() (CredentialPlacement, error) {
	members, err := p.object(p.token.Method, "method", "username", "password")
	if err != nil {
		return nil, err
	}
	if _, ok := members["username"]; !ok {
		return nil, p.refuse(PlacementInvalidMethod, "method does not have both username and password")
	}
	if _, ok := members["password"]; !ok {
		return nil, p.refuse(PlacementInvalidMethod, "method does not have both username and password")
	}
	user, err := p.passwordEntry(members["username"], "method.username")
	if err != nil {
		return nil, err
	}
	pass, err := p.passwordEntry(members["password"], "method.password")
	if err != nil {
		return nil, err
	}
	if user.In == pass.In && strings.EqualFold(user.Name, pass.Name) {
		return nil, p.refuse(PlacementInvalidMethod, "method.username and method.password both name %s %q", user.In, user.Name)
	}

	if p.token.Username == "" {
		return nil, p.refuse(PlacementInvalidCredential, "username is missing")
	}
	user.Value = p.token.Username
	pass.Value = p.token.AccessToken
	if err := p.entryValue("username", user); err != nil {
		return nil, err
	}
	if err := p.entryValue("access_token", pass); err != nil {
		return nil, err
	}
	return CredentialPlacement{user, pass}, nil
}

// passwordEntry checks one entry of a Keycard-Password method and returns its
// field without a value.
func (p *placer) passwordEntry(raw json.RawMessage, path string) (CredentialField, error) {
	members, err := p.object(raw, path, "in", "name")
	if err != nil {
		return CredentialField{}, err
	}
	in, name, err := p.inAndName(members, path)
	if err != nil {
		return CredentialField{}, err
	}
	switch in {
	case "header":
		if err := p.headerName(path, name); err != nil {
			return CredentialField{}, err
		}
		return CredentialField{In: CredentialInHeader, Name: name}, nil
	case "query":
		if name == "" {
			return CredentialField{}, p.refuse(PlacementInvalidMethod, "%s.name is empty", path)
		}
		return CredentialField{In: CredentialInQuery, Name: name}, nil
	default:
		return CredentialField{}, p.refuse(PlacementInvalidMethod, "%s.in %q is not header or query", path, in)
	}
}

func (p *placer) entryValue(secret string, f CredentialField) error {
	if f.Value == "" {
		return p.refuse(PlacementInvalidCredential, "%s is empty", secret)
	}
	if f.In == CredentialInHeader {
		return p.headerValue(secret, f.Value)
	}
	return nil
}

// object decodes raw as a JSON object whose members are all in allowed.
func (p *placer) object(raw json.RawMessage, path string, allowed ...string) (map[string]json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, p.refuse(PlacementInvalidMethod, "%s is missing", path)
	}
	if !strings.HasPrefix(trimmed, "{") {
		return nil, p.refuse(PlacementInvalidMethod, "%s is not an object", path)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, p.refuse(PlacementInvalidMethod, "%s is not an object", path)
	}
	for key := range members {
		known := false
		for _, a := range allowed {
			if key == a {
				known = true
				break
			}
		}
		if !known {
			return nil, p.refuse(PlacementInvalidMethod, "%s has unknown member %q", path, key)
		}
	}
	return members, nil
}

func (p *placer) inAndName(members map[string]json.RawMessage, path string) (in, name string, err error) {
	in, ok, err := p.optionalString(members, path, "in")
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", p.refuse(PlacementInvalidMethod, "%s has no in", path)
	}
	name, ok, err = p.optionalString(members, path, "name")
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", p.refuse(PlacementInvalidMethod, "%s has no name", path)
	}
	return in, name, nil
}

func (p *placer) optionalString(members map[string]json.RawMessage, path, key string) (string, bool, error) {
	raw, ok := members[key]
	if !ok {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || strings.TrimSpace(string(raw)) == "null" {
		return "", false, p.refuse(PlacementInvalidMethod, "%s.%s is not a string", path, key)
	}
	return s, true, nil
}

func (p *placer) headerName(path, name string) error {
	if !isToken(name) {
		return p.refuse(PlacementInvalidMethod, "header name %q in %s.name is not an RFC 9110 token", name, path)
	}
	if !p.cfg.allowHeader(name) {
		return p.refuse(PlacementInvalidMethod, "header name %q in %s.name is not allowed", name, path)
	}
	return nil
}

// headerValue refuses an empty value, or one with a character other than
// visible ASCII, space or horizontal tab (RFC 9110 section 5.5).
func (p *placer) headerValue(secret, value string) error {
	if value == "" {
		return p.refuse(PlacementInvalidCredential, "%s is empty", secret)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return p.refuse(PlacementInvalidCredential, "%s has a character that cannot go in a header", secret)
		}
	}
	return nil
}

// cookieValue refuses an empty value, or one with a character that is not a
// cookie-octet (RFC 6265 section 4.1.1).
func (p *placer) cookieValue(secret, value string) error {
	if value == "" {
		return p.refuse(PlacementInvalidCredential, "%s is empty", secret)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\' {
			return p.refuse(PlacementInvalidCredential, "%s has a character that cannot go in a cookie", secret)
		}
	}
	return nil
}

// isToken reports whether s is an RFC 9110 token (section 5.6.2).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
