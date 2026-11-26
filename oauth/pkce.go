package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/keycardai/go-sdk/internal/printed"
)

// PKCE code challenge methods (RFC 7636 §4.3).
const (
	// PKCEMethodS256 derives the challenge as BASE64URL(SHA-256(verifier)).
	PKCEMethodS256 = "S256"
	// PKCEMethodPlain uses the verifier as the challenge. RFC-permitted but not recommended.
	PKCEMethodPlain = "plain"
)

// defaultCodeVerifierBytes yields a 128-character base64url verifier, the maximum
// length RFC 7636 §4.1 allows (96 bytes -> 128 base64url characters).
const defaultCodeVerifierBytes = 96

// PKCEPair is a PKCE code verifier and its derived challenge (RFC 7636).
//
// String, GoString, and LogValue leave out CodeVerifier.
type PKCEPair struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

func (p PKCEPair) printed() printed.Struct {
	return printed.Struct{Type: "oauth.PKCEPair", Fields: []printed.Field{
		{Name: "CodeChallenge", Key: "code_challenge", Value: p.CodeChallenge},
		{Name: "CodeChallengeMethod", Key: "code_challenge_method", Value: p.CodeChallengeMethod},
	}}
}

// String implements [fmt.Stringer].
func (p PKCEPair) String() string { return p.printed().String() }

// GoString implements [fmt.GoStringer].
func (p PKCEPair) GoString() string { return p.printed().GoString() }

// LogValue implements [slog.LogValuer].
func (p PKCEPair) LogValue() slog.Value { return p.printed().LogValue() }

// GenerateCodeVerifier returns a cryptographically random PKCE code verifier of 128
// unreserved characters. The base64url alphabet is a subset of the RFC 7636 §4.1
// unreserved set, so the result is a valid verifier.
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, defaultCodeVerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating code verifier: %w", err)
	}
	return Base64URLEncode(b), nil
}

// GenerateCodeChallenge derives the PKCE challenge from a verifier. For PKCEMethodS256
// it returns BASE64URL(SHA-256(verifier)); for PKCEMethodPlain it returns the verifier
// unchanged. Any other method is an error.
func GenerateCodeChallenge(verifier, method string) (string, error) {
	switch method {
	case PKCEMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		return Base64URLEncode(sum[:]), nil
	case PKCEMethodPlain:
		return verifier, nil
	default:
		return "", fmt.Errorf("unsupported PKCE method %q", method)
	}
}

// GeneratePKCEPair generates a verifier and its S256 challenge.
func GeneratePKCEPair() (PKCEPair, error) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return PKCEPair{}, err
	}
	challenge, err := GenerateCodeChallenge(verifier, PKCEMethodS256)
	if err != nil {
		return PKCEPair{}, err
	}
	return PKCEPair{
		CodeVerifier:        verifier,
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCEMethodS256,
	}, nil
}
