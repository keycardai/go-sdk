package policy

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// MediaTypeTarGzip is the media type of the tar+gzip policy-bundle encoding.
const MediaTypeTarGzip = "application/vnd.keycard.policy-bundle.v1+tar+gzip"

const (
	pathManifest   = "manifest.json"
	pathSchema     = "schema.cedarschema"
	policiesPrefix = "policies/"
	policiesSuffix = ".cedar"
	tarEntryMode   = 0o644
)

// maxDecompressedSize caps the total bytes Decode reads out of the gzip stream.
// A small compressed archive can inflate to gigabytes (a decompression bomb);
// the ingress middleware bounds the compressed request but cannot bound what it
// expands to, so the codec enforces its own decompressed ceiling.
const maxDecompressedSize = 64 << 20 // 64 MiB

// epoch is the fixed modification time stamped on every tar entry and the gzip
// header so encoding is byte-for-byte deterministic.
var epoch = time.Unix(0, 0).UTC()

// TarGZipCodec encodes a Bundle as a gzip-compressed tar archive.
type TarGZipCodec struct{}

func init() { Register(TarGZipCodec{}) }

func (TarGZipCodec) MediaType() string { return MediaTypeTarGzip }

// Encode writes manifest.json, schema.cedarschema, and policies/<public_id>.cedar
// into a deterministic gzip-compressed tar archive on w. Content digests in the
// manifest are computed from the supplied bytes. All content-level errors occur
// before the first write; only w itself can fail mid-stream.
func (TarGZipCodec) Encode(w io.Writer, b *Bundle) (err error) {
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
	names := make(map[string]string, len(b.Manifest.Policies))
	for _, p := range b.Manifest.Policies {
		if p.PublicID != "" {
			names[p.PublicID] = p.Name
		}
	}
	for id, content := range b.Policies {
		manifest.Policies = append(manifest.Policies, PolicyRef{PublicID: id, Name: names[id], SHA: sha256Hex(content)})
	}
	sort.Slice(manifest.Policies, func(i, j int) bool {
		return manifest.Policies[i].PublicID < manifest.Policies[j].PublicID
	})

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	gw := gzip.NewWriter(w)
	defer func() {
		if cerr := gw.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close gzip: %w", cerr)
		}
	}()
	tw := tar.NewWriter(gw)
	defer func() {
		if cerr := tw.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close tar: %w", cerr)
		}
	}()

	if err := writeTarEntry(tw, pathManifest, manifestJSON); err != nil {
		return err
	}
	if err := writeTarEntry(tw, pathSchema, b.Schema); err != nil {
		return err
	}
	for _, p := range manifest.Policies {
		if err := writeTarEntry(tw, policiesPrefix+p.PublicID+policiesSuffix, b.Policies[p.PublicID]); err != nil {
			return err
		}
	}

	return nil
}

func writeTarEntry(tw *tar.Writer, name string, content []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     tarEntryMode,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
		ModTime:  epoch,
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write tar header %q: %w", name, err)
	}
	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("write tar content %q: %w", name, err)
	}
	return nil
}

// Decode reads a gzip-compressed tar archive from r into a Bundle. The schema
// version is taken from manifest.json; all content digests are re-computed from
// the archive bytes rather than trusted from the manifest. Validation is
// structural.
func (TarGZipCodec) Decode(r io.Reader) (*Bundle, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedArchive, err)
	}
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(&limitReader{r: gr, left: maxDecompressedSize + 1})

	var (
		manifestSeen bool
		schemaSeen   bool
		version      string
		schema       []byte
		targetType   TargetType
		targetID     string
		policies     = map[string][]byte{}
		identity     = map[string]PolicyRef{} // archive key -> manifest identity label
	)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, ErrBundleTooLarge) {
			return nil, ErrBundleTooLarge
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedArchive, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: %q", ErrUnexpectedEntry, hdr.Name)
		}

		content, err := io.ReadAll(tr)
		if errors.Is(err, ErrBundleTooLarge) {
			return nil, ErrBundleTooLarge
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read %q: %v", ErrMalformedArchive, hdr.Name, err)
		}

		switch {
		case hdr.Name == pathManifest:
			if manifestSeen {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateEntry, hdr.Name)
			}
			var m Manifest
			if err := json.Unmarshal(content, &m); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
			}
			if m.Schema.Version == "" {
				return nil, ErrMissingVersion
			}
			for _, ref := range m.Policies {
				key, err := manifestRefKey(ref)
				if err != nil {
					return nil, err
				}
				if _, dup := identity[key]; dup {
					return nil, fmt.Errorf("%w: policy %q", ErrDuplicateEntry, key)
				}
				identity[key] = ref
			}
			version = m.Schema.Version
			targetType = m.TargetType
			targetID = m.TargetID
			manifestSeen = true
		case hdr.Name == pathSchema:
			if schemaSeen {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateEntry, hdr.Name)
			}
			schema = content
			schemaSeen = true
		case strings.HasPrefix(hdr.Name, policiesPrefix):
			id := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, policiesPrefix), policiesSuffix)
			if id == "" || strings.Contains(id, "/") || !strings.HasSuffix(hdr.Name, policiesSuffix) {
				return nil, fmt.Errorf("%w: %q", ErrUnexpectedEntry, hdr.Name)
			}
			if _, dup := policies[id]; dup {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateEntry, hdr.Name)
			}
			policies[id] = content
		default:
			return nil, fmt.Errorf("%w: %q", ErrUnexpectedEntry, hdr.Name)
		}
	}

	// schema.cedarschema is a convenience snapshot, optional on ingest — the
	// authoritative schema version comes from the manifest. The manifest itself
	// is required: it is the only source of that version.
	if !manifestSeen {
		return nil, ErrMissingManifest
	}

	manifest := Manifest{
		Schema:     SchemaRef{Version: version, SHA: sha256Hex(schema)},
		TargetType: targetType,
		TargetID:   targetID,
		Policies:   make([]PolicyRef, 0, len(identity)),
	}
	// The manifest is authoritative for the bundle's membership and identity: a
	// policy is in the bundle iff the manifest references it. SHAs are always
	// recomputed from the archive bytes regardless of what the manifest claimed.
	// A policies/*.cedar member with no manifest entry is not part of the bundle
	// and is dropped — omitting the entry is how a caller removes a policy.
	kept := make(map[string][]byte, len(identity))
	for key, ref := range identity {
		content, ok := policies[key]
		if !ok {
			return nil, fmt.Errorf("%w: policy %q has no policies/%s%s entry", ErrInvalidManifest, key, key, policiesSuffix)
		}
		ref.SHA = sha256Hex(content)
		manifest.Policies = append(manifest.Policies, ref)
		kept[key] = content
	}
	sort.Slice(manifest.Policies, func(i, j int) bool {
		if manifest.Policies[i].PublicID != manifest.Policies[j].PublicID {
			return manifest.Policies[i].PublicID < manifest.Policies[j].PublicID
		}
		return manifest.Policies[i].NewPolicy < manifest.Policies[j].NewPolicy
	})

	return &Bundle{Manifest: manifest, Schema: schema, Policies: kept}, nil
}

// manifestRefKey returns the archive key (policies/<key>.cedar) a manifest entry
// maps to: its PublicID for an existing policy, or its NewPolicy name for one the
// caller is adding. Exactly one must be set.
func manifestRefKey(ref PolicyRef) (string, error) {
	switch {
	case ref.PublicID != "" && ref.NewPolicy != "":
		return "", fmt.Errorf("%w: policy entry sets both public_id and new_policy", ErrInvalidManifest)
	case ref.PublicID != "":
		return ref.PublicID, nil
	case ref.NewPolicy != "":
		return ref.NewPolicy, nil
	default:
		return "", fmt.Errorf("%w: policy entry sets neither public_id nor new_policy", ErrInvalidManifest)
	}
}

// limitReader returns ErrBundleTooLarge once the underlying reader yields more
// than left bytes, guarding Decode against decompression bombs. left is seeded
// to maxDecompressedSize+1 so an archive that decompresses to exactly the limit
// still reaches EOF rather than tripping on the boundary.
type limitReader struct {
	r    io.Reader
	left int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, ErrBundleTooLarge
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
