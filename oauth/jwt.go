package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultLeeway is the default time leeway used when validating
// token temporal claims (exp, nbf, iat).
const DefaultLeeway = 60 * time.Second

// JWTClaims represents standard JWT claims with optional extra fields.
type JWTClaims struct {
	Issuer   string   `json:"iss,omitempty"`
	Subject  string   `json:"sub,omitempty"`
	Audience []string `json:"aud,omitempty"`
	Expiry   int64    `json:"exp,omitempty"`
	NotBefore int64   `json:"nbf,omitempty"`
	IssuedAt int64    `json:"iat,omitempty"`
	JWTID    string   `json:"jti,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	ClientID string   `json:"client_id,omitempty"`

	// Extra holds additional claims not covered by the standard fields.
	Extra map[string]any `json:"-"`
}

// GetExpirationTime implements jwt.Claims.
func (c JWTClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Expiry == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Expiry, 0)), nil
}

// GetIssuedAt implements jwt.Claims.
func (c JWTClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims.
func (c JWTClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

// GetIssuer implements jwt.Claims.
func (c JWTClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims.
func (c JWTClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience implements jwt.Claims.
func (c JWTClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audience), nil
}

// jwtClaimsForSigning builds a jwt.MapClaims from JWTClaims for signing.
func jwtClaimsForSigning(c JWTClaims) jwt.MapClaims {
	m := jwt.MapClaims{}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if len(c.Audience) == 1 {
		m["aud"] = c.Audience[0]
	} else if len(c.Audience) > 1 {
		m["aud"] = c.Audience
	}
	if c.Expiry != 0 {
		m["exp"] = c.Expiry
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.JWTID != "" {
		m["jti"] = c.JWTID
	}
	if c.Scope != "" {
		m["scope"] = c.Scope
	}
	if c.ClientID != "" {
		m["client_id"] = c.ClientID
	}
	for k, v := range c.Extra {
		m[k] = v
	}
	return m
}

// jwtClaimsFromMap parses a jwt.MapClaims into JWTClaims.
func jwtClaimsFromMap(m jwt.MapClaims) *JWTClaims {
	c := &JWTClaims{Extra: make(map[string]any)}

	if v, ok := m["iss"].(string); ok {
		c.Issuer = v
	}
	if v, ok := m["sub"].(string); ok {
		c.Subject = v
	}
	if v, ok := m["aud"]; ok {
		switch aud := v.(type) {
		case string:
			c.Audience = []string{aud}
		case []any:
			for _, a := range aud {
				if s, ok := a.(string); ok {
					c.Audience = append(c.Audience, s)
				}
			}
		}
	}
	if v, ok := m["exp"].(float64); ok {
		c.Expiry = int64(v)
	}
	if v, ok := m["nbf"].(float64); ok {
		c.NotBefore = int64(v)
	}
	if v, ok := m["iat"].(float64); ok {
		c.IssuedAt = int64(v)
	}
	if v, ok := m["jti"].(string); ok {
		c.JWTID = v
	}
	if v, ok := m["scope"].(string); ok {
		c.Scope = v
	}
	if v, ok := m["client_id"].(string); ok {
		c.ClientID = v
	}

	// Collect extra claims
	standard := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true,
		"nbf": true, "iat": true, "jti": true, "scope": true, "client_id": true,
	}
	for k, v := range m {
		if !standard[k] {
			c.Extra[k] = v
		}
	}
	if len(c.Extra) == 0 {
		c.Extra = nil
	}

	return c
}

// signingMethodForKey returns the appropriate JWT signing method for a private key.
func signingMethodForKey(key crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		return jwt.SigningMethodES256, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// JWTSigner signs JWTs using a PrivateKeyring.
type JWTSigner struct {
	keyring PrivateKeyring
}

// NewJWTSigner creates a new JWTSigner with the given private keyring.
func NewJWTSigner(keyring PrivateKeyring) *JWTSigner {
	return &JWTSigner{keyring: keyring}
}

// Sign produces a signed JWT string from the given claims.
// If the claims do not include an issuer, the issuer from the keyring is used.
func (s *JWTSigner) Sign(ctx context.Context, claims JWTClaims) (string, error) {
	ik, err := s.keyring.Key(ctx, "sign")
	if err != nil {
		return "", fmt.Errorf("retrieving signing key: %w", err)
	}

	method, err := signingMethodForKey(ik.Key)
	if err != nil {
		return "", err
	}

	if ik.Issuer != "" && claims.Issuer == "" {
		claims.Issuer = ik.Issuer
	}

	mapClaims := jwtClaimsForSigning(claims)
	token := jwt.NewWithClaims(method, mapClaims)
	token.Header["kid"] = ik.KID

	signed, err := token.SignedString(ik.Key)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signed, nil
}

// supportedVerifyAlgorithms is the set of signing algorithms the verifier implements.
// Construction rejects any configured algorithm outside this set (and "none" always).
var supportedVerifyAlgorithms = map[string]bool{
	"RS256": true,
	"ES256": true,
}

// jwtVerifierConfig holds the optional verifier settings applied via JWTVerifierOption.
type jwtVerifierConfig struct {
	audiences  []string
	algorithms []string
	leeway     time.Duration
}

// JWTVerifierOption configures a JWTVerifier.
type JWTVerifierOption func(*jwtVerifierConfig)

// WithAudiences sets the accepted audience values. When set, a verified token's aud
// claim must be present and intersect this set; when unset, audience is not checked.
func WithAudiences(audiences ...string) JWTVerifierOption {
	return func(c *jwtVerifierConfig) { c.audiences = audiences }
}

// WithAlgorithms sets the allowed JWT signing algorithms. Defaults to ["RS256"].
// "none" is always rejected, and an algorithm the verifier does not implement is a
// configuration error at construction time.
func WithAlgorithms(algorithms ...string) JWTVerifierOption {
	return func(c *jwtVerifierConfig) { c.algorithms = algorithms }
}

// WithVerifierLeeway sets the time leeway for validating exp and nbf claims.
// Default is DefaultLeeway (60s).
func WithVerifierLeeway(d time.Duration) JWTVerifierOption {
	return func(c *jwtVerifierConfig) { c.leeway = d }
}

// JWTVerifier verifies JWT signatures and validates claims using an OAuthKeyring.
// The verify surface is fail-closed: the algorithm and issuer are checked against
// allowlists before any key resolution or network I/O, so a token carrying an
// attacker-controlled iss cannot drive key lookup to an untrusted endpoint.
type JWTVerifier struct {
	keyring    OAuthKeyring
	issuers    []string
	audiences  []string
	algorithms []string
	leeway     time.Duration
}

// NewJWTVerifier creates a JWTVerifier that trusts tokens issued by one of issuers.
// At least one trusted issuer is required; an empty issuers list, or an unsupported
// algorithm, is a ConfigurationError.
func NewJWTVerifier(keyring OAuthKeyring, issuers []string, opts ...JWTVerifierOption) (*JWTVerifier, error) {
	if len(issuers) == 0 {
		return nil, &ConfigurationError{Message: "JWT verifier requires at least one trusted issuer"}
	}

	cfg := jwtVerifierConfig{
		algorithms: []string{"RS256"},
		leeway:     DefaultLeeway,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	for _, alg := range cfg.algorithms {
		if alg == "none" || !supportedVerifyAlgorithms[alg] {
			return nil, &ConfigurationError{Message: fmt.Sprintf("unsupported JWT algorithm %q", alg)}
		}
	}

	return &JWTVerifier{
		keyring:    keyring,
		issuers:    issuers,
		audiences:  cfg.audiences,
		algorithms: cfg.algorithms,
		leeway:     cfg.leeway,
	}, nil
}

// Verify parses and verifies a JWT, returning the claims. Every rejection is an
// *InvalidTokenError. Policy checks (algorithm, issuer, required claims, audience,
// kid) run on the unverified payload before key resolution, so an untrusted issuer
// never triggers a key lookup or network I/O.
func (v *JWTVerifier) Verify(ctx context.Context, tokenString string) (*JWTClaims, error) {
	// 1. Structure: parse without verification to read the header and payload.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("malformed JWT: %v", err)}
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &InvalidTokenError{Message: "invalid JWT claims"}
	}

	// 2. Algorithm: present, not "none", and within the allowlist.
	alg, _ := token.Header["alg"].(string)
	if alg == "" || alg == "none" || !stringInSlice(v.algorithms, alg) {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("disallowed JWT algorithm %q", alg)}
	}

	// 3. Issuer: present and in the trusted set, before any key lookup.
	issuer, _ := mapClaims["iss"].(string)
	if issuer == "" || !stringInSlice(v.issuers, issuer) {
		return nil, &InvalidTokenError{Message: "JWT issuer (iss) is missing or not trusted"}
	}

	// 4. Required claims (RFC 9068 §2.2 access-token profile): iss (checked above),
	// sub, aud, exp, iat, and client_id must all be present. jti, also listed in
	// §2.2, is intentionally not enforced here — it scopes replay tracking, not
	// access validation.
	if sub, _ := mapClaims["sub"].(string); sub == "" {
		return nil, &InvalidTokenError{Message: "JWT missing subject (sub) claim"}
	}
	if _, ok := mapClaims["exp"].(float64); !ok {
		return nil, &InvalidTokenError{Message: "JWT missing expiration (exp) claim"}
	}
	if _, ok := mapClaims["iat"].(float64); !ok {
		return nil, &InvalidTokenError{Message: "JWT missing issued-at (iat) claim"}
	}
	if clientID, _ := mapClaims["client_id"].(string); clientID == "" {
		return nil, &InvalidTokenError{Message: "JWT missing client_id claim"}
	}
	aud := audienceFromClaims(mapClaims)
	if len(aud) == 0 {
		return nil, &InvalidTokenError{Message: "JWT missing audience (aud) claim"}
	}

	// 6. Audience binding: when audiences are configured, aud must intersect them.
	if len(v.audiences) > 0 && !sliceIntersects(aud, v.audiences) {
		return nil, &InvalidTokenError{Message: "JWT audience (aud) is not accepted"}
	}

	// 7. Key id: present.
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, &InvalidTokenError{Message: "JWT missing key id (kid) header"}
	}

	// 8. Key resolution for (iss, kid) through the verification keyring.
	publicKey, err := v.keyring.Key(ctx, issuer, kid)
	if err != nil {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("failed to resolve key: %v", err)}
	}

	// 5 + 9. Temporal (exp, nbf with leeway) and signature, with alg pinned to the allowlist.
	verifiedToken, err := jwt.Parse(tokenString, func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithValidMethods(v.algorithms), jwt.WithLeeway(v.leeway))
	if err != nil {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("JWT verification failed: %v", err)}
	}

	verifiedClaims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &InvalidTokenError{Message: "invalid JWT claims"}
	}

	return jwtClaimsFromMap(verifiedClaims), nil
}

// stringInSlice reports whether v is present in set.
func stringInSlice(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// sliceIntersects reports whether a and b share at least one element.
func sliceIntersects(a, b []string) bool {
	for _, x := range a {
		if stringInSlice(b, x) {
			return true
		}
	}
	return false
}

// audienceFromClaims extracts the aud claim as a list, accepting a string or an array.
func audienceFromClaims(m jwt.MapClaims) []string {
	switch aud := m["aud"].(type) {
	case string:
		if aud == "" {
			return nil
		}
		return []string{aud}
	case []any:
		var out []string
		for _, a := range aud {
			if s, ok := a.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
