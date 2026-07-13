package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Bundle is the in-memory form of a policy bundle.
type Bundle struct {
	Manifest Manifest
	// Schema holds the full Cedar schema DSL text for Manifest.Schema.Version.
	Schema []byte
	// Policies maps a policy's public ID to its Cedar policy bytes.
	Policies map[string][]byte
}

// Manifest is the manifest.json contents.
type Manifest struct {
	Schema     SchemaRef  `json:"schema"`
	TargetType TargetType `json:"target_type"`
	// TargetID is the principal the bundle is bound to (PolicySetBinding.scope_target_id).
	TargetID string      `json:"target_id"`
	Policies []PolicyRef `json:"policies"`
}

// Digest returns the bundle's attestable identity: the JCS-canonical (RFC 8785)
// SHA-256 of the manifest with advisory fields removed. Because the manifest
// commits to the schema and every policy by SHA, this digest transitively
// commits to all bundle content. It is the value to attest, to serve as the
// bundle ETag, and that a consumer reproduces — by stripping each policy's
// advisory `name` from manifest.json and running JCS over the result — to prove
// the bundle it holds is the one that was signed. Names are excluded because
// they are mutable server metadata unrelated to policy bytes: including them
// would flip every ETag on a rename and break If-Match for clients whose
// content is unchanged. The digest is independent of the archive encoding and
// of Go's JSON formatting; policies are sorted so it is independent of map
// iteration order.
func (m Manifest) Digest() (string, error) {
	c := m
	c.Policies = append([]PolicyRef(nil), m.Policies...)
	for i := range c.Policies {
		c.Policies[i].Name = ""
	}
	sort.Slice(c.Policies, func(i, j int) bool {
		if c.Policies[i].PublicID != c.Policies[j].PublicID {
			return c.Policies[i].PublicID < c.Policies[j].PublicID
		}
		return c.Policies[i].NewPolicy < c.Policies[j].NewPolicy
	})
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}
	return contentSHA(raw)
}

// SchemaRef identifies the bundle's schema version and the digest of its bytes.
type SchemaRef struct {
	Version string `json:"version"`
	SHA     string `json:"sha"`
}

// TargetType reflects the PolicySetBinding.scope_type value.
type TargetType string

const (
	TargetTypeZone TargetType = "zone"
	TargetTypeUser TargetType = "user"
)

// PolicyRef identifies a policy by the digest of its bytes and either an existing
// PublicID or, for a not-yet-minted policy a caller is adding, a NewPolicy name.
// Exactly one of PublicID/NewPolicy is set; the ingest layer mints a public ID for
// a NewPolicy entry.
//
// Name is advisory, server-owned metadata: the human-readable policy name, emitted
// for PublicID entries on read so bundles are browsable. The DB is authoritative for
// names, so an incoming Name is ignored on ingest (apply keys off PublicID/NewPolicy).
// It is excluded from the Digest — a rename never changes the ETag.
type PolicyRef struct {
	PublicID  string `json:"public_id,omitempty"`
	NewPolicy string `json:"new_policy,omitempty"`
	Name      string `json:"name,omitempty"`
	SHA       string `json:"sha"`
}

// BundleCodec serializes a Bundle to and from a byte stream identified by a
// media type. Encode and Decode operate on io.Writer/io.Reader so they compose
// directly with HTTP bodies, files, and buffers without intermediate copies.
type BundleCodec interface {
	MediaType() string
	Encode(w io.Writer, b *Bundle) error
	Decode(r io.Reader) (*Bundle, error)
}

var codecs = map[string]BundleCodec{}

// Register adds a codec to the media-type registry. It is intended to be called
// from package init functions.
func Register(c BundleCodec) {
	codecs[c.MediaType()] = c
}

// CodecFor returns the codec registered for the given media type.
func CodecFor(mediaType string) (BundleCodec, bool) {
	c, ok := codecs[mediaType]
	return c, ok
}
