package policy

import (
	"crypto/sha256"
	"fmt"

	"github.com/gowebpki/jcs"
)

// sha256Hex returns the "sha256:<hex>" digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}

// contentSHA JCS-canonicalizes JSON content (RFC 8785) then returns its
// "sha256:<hex>" digest. The canonical form ensures equal JSON content hashes
// identically regardless of key ordering or whitespace — matching the digest
// computation used by the Keycard management API.
func contentSHA(content []byte) (string, error) {
	canonical, err := jcs.Transform(content)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize content: %w", err)
	}
	return sha256Hex(canonical), nil
}
