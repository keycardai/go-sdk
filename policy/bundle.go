package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
)

// MediaType is the MIME media type identifier for a bundle encoding.
type MediaType string

// Codec returns the codec registered for m, or false if m is unknown.
func (m MediaType) Codec() (BundleCodec, bool) { return CodecFor(m) }

// Bundle is the in-memory form of a policy bundle.
type Bundle struct {
	Manifest Manifest
	// Schema holds the full Cedar schema DSL text for Manifest.Schema.Version.
	Schema []byte
	// Policies maps a policy's archive key to its Cedar policy bytes. For an
	// existing policy the key is its PublicID; for a new policy it is NewPolicy.
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
	MediaType() MediaType
	Encode(w io.Writer, b *Bundle) error
	Decode(r io.Reader) (*Bundle, error)
}

var codecs = map[MediaType]BundleCodec{}

// Register adds a codec to the media-type registry. It is intended to be called
// from package init functions.
func Register(c BundleCodec) { codecs[c.MediaType()] = c }

// CodecFor returns the codec registered for the given media type.
func CodecFor(mediaType MediaType) (BundleCodec, bool) {
	c, ok := codecs[mediaType]
	return c, ok
}

// DecodeBundle reads r using the codec for mediaType and returns the decoded bundle.
func DecodeBundle(r io.Reader, mediaType MediaType) (*Bundle, error) {
	c, ok := CodecFor(mediaType)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownMediaType, mediaType)
	}
	return c.Decode(r)
}

// Encode writes the bundle to w using the codec for mediaType. It returns the
// number of bytes written.
func (b *Bundle) Encode(w io.Writer, mediaType MediaType) (int, error) {
	c, ok := CodecFor(mediaType)
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnknownMediaType, mediaType)
	}
	cw := &countWriter{w: w}
	if err := c.Encode(cw, b); err != nil {
		return cw.n, err
	}
	return cw.n, nil
}

type countWriter struct {
	w io.Writer
	n int
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += n
	return n, err
}

// LoadBundle reads an expanded bundle from fsys. fsys must contain manifest.json
// and all policy files listed in it; schema.cedarschema is optional. A
// policies/*.cedar file with no manifest entry returns ErrOrphanPolicy.
func LoadBundle(fsys fs.FS) (*Bundle, error) {
	manifestData, err := fs.ReadFile(fsys, pathManifest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingManifest, err)
	}
	var m Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if m.Schema.Version == "" {
		return nil, ErrMissingVersion
	}

	// build identity map from manifest
	identity := make(map[string]PolicyRef, len(m.Policies))
	for _, ref := range m.Policies {
		key, err := manifestRefKey(ref)
		if err != nil {
			return nil, err
		}
		identity[key] = ref
	}

	// The policies/ directory must contain only .cedar files that the manifest
	// references — the same shape tarGZipCodec.Decode enforces for an archive. A
	// subdirectory, a non-.cedar file, or a .cedar file with no manifest entry is
	// rejected so LoadBundle and Decode accept exactly the same set of bundles.
	dirEntries, err := fs.ReadDir(fsys, "policies")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read policies dir: %w", err)
	}
	for _, e := range dirEntries {
		name := e.Name()
		if e.IsDir() {
			return nil, fmt.Errorf("%w: policies/%s is a directory", ErrUnexpectedEntry, name)
		}
		if !strings.HasSuffix(name, policiesSuffix) {
			return nil, fmt.Errorf("%w: policies/%s", ErrUnexpectedEntry, name)
		}
		key := strings.TrimSuffix(name, policiesSuffix)
		if _, ok := identity[key]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrOrphanPolicy, key)
		}
	}

	// read schema (optional)
	schemaData, err := fs.ReadFile(fsys, pathSchema)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read schema: %w", err)
	}

	// read policy files; a manifest-referenced file that is absent makes the
	// manifest invalid, matching Decode's ErrInvalidManifest for the same case.
	policies := make(map[string][]byte, len(identity))
	for key := range identity {
		content, err := fs.ReadFile(fsys, policiesPrefix+key+policiesSuffix)
		if err != nil {
			return nil, fmt.Errorf("%w: policy %q has no policies/%s%s file: %v", ErrInvalidManifest, key, key, policiesSuffix, err)
		}
		policies[key] = content
	}

	// rebuild manifest with recomputed SHAs
	manifest := Manifest{
		Schema:     SchemaRef{Version: m.Schema.Version, SHA: sha256Hex(schemaData)},
		TargetType: m.TargetType,
		TargetID:   m.TargetID,
		Policies:   make([]PolicyRef, 0, len(identity)),
	}
	for key, ref := range identity {
		ref.SHA = sha256Hex(policies[key])
		manifest.Policies = append(manifest.Policies, ref)
	}
	sort.Slice(manifest.Policies, func(i, j int) bool {
		if manifest.Policies[i].PublicID != manifest.Policies[j].PublicID {
			return manifest.Policies[i].PublicID < manifest.Policies[j].PublicID
		}
		return manifest.Policies[i].NewPolicy < manifest.Policies[j].NewPolicy
	})

	return &Bundle{Manifest: manifest, Schema: schemaData, Policies: policies}, nil
}

// Unload writes the bundle's expanded form to fsys: manifest.json,
// schema.cedarschema, and policies/<key>.cedar for each policy. SHAs in the
// written manifest are computed from the bundle's in-memory bytes.
func (b *Bundle) Unload(fsys WriteFS) error {
	if b == nil {
		return ErrMissingBundle
	}
	if b.Manifest.Schema.Version == "" {
		return ErrMissingVersion
	}

	manifest := Manifest{
		Schema: SchemaRef{
			Version: b.Manifest.Schema.Version,
			SHA:     sha256Hex(b.Schema),
		},
		TargetType: b.Manifest.TargetType,
		TargetID:   b.Manifest.TargetID,
		Policies:   make([]PolicyRef, 0, len(b.Policies)),
	}
	// preserve PolicyRef type (PublicID vs NewPolicy) and advisory Name
	refByKey := make(map[string]PolicyRef, len(b.Manifest.Policies))
	for _, ref := range b.Manifest.Policies {
		key, err := manifestRefKey(ref)
		if err != nil {
			return err
		}
		refByKey[key] = ref
	}
	for id, content := range b.Policies {
		ref, ok := refByKey[id]
		if !ok {
			return fmt.Errorf("%w: policy %q has no manifest entry", ErrInvalidManifest, id)
		}
		ref.SHA = sha256Hex(content)
		manifest.Policies = append(manifest.Policies, ref)
	}
	sort.Slice(manifest.Policies, func(i, j int) bool {
		if manifest.Policies[i].PublicID != manifest.Policies[j].PublicID {
			return manifest.Policies[i].PublicID < manifest.Policies[j].PublicID
		}
		return manifest.Policies[i].NewPolicy < manifest.Policies[j].NewPolicy
	})

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	if err := fsys.MkdirAll("policies", 0o755); err != nil {
		return fmt.Errorf("mkdir policies: %w", err)
	}
	if err := writeFile(fsys, pathManifest, manifestJSON); err != nil {
		return err
	}
	if err := writeFile(fsys, pathSchema, b.Schema); err != nil {
		return err
	}
	for _, ref := range manifest.Policies {
		key, _ := manifestRefKey(ref)
		if err := writeFile(fsys, policiesPrefix+key+policiesSuffix, b.Policies[key]); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(fsys WriteFS, path string, content []byte) error {
	w, err := fsys.Create(path)
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer w.Close() //nolint:errcheck
	if _, err := w.Write(content); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	return nil
}
