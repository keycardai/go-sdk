package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
)

const sampleSchema = `namespace Keycard {
  entity User { email: String };
  action any appliesTo { principal: [User], resource: User };
}
`

func sampleBundle() *Bundle {
	return &Bundle{
		Manifest: Manifest{
			Schema:     SchemaRef{Version: "2026-02-14"},
			TargetType: TargetTypeUser,
			TargetID:   "user_sample",
			Policies: []PolicyRef{
				{PublicID: "pol_a", Name: "allow-read"},
				{PublicID: "pol_b", Name: "deny-all"},
			},
		},
		Schema: []byte(sampleSchema),
		Policies: map[string][]byte{
			"pol_b": []byte(`permit(principal, action, resource);`),
			"pol_a": []byte(`forbid(principal, action, resource) when { true };`),
		},
	}
}

func encodeToBytes(t *testing.T, b *Bundle) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := tarGZipCodec{}.Encode(&buf, b)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return buf.Bytes()
}

func TestTarGZipCodec_RoundTrip(t *testing.T) {
	in := sampleBundle()

	codec := tarGZipCodec{}
	out, err := codec.Decode(bytes.NewReader(encodeToBytes(t, in)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got, want := out.Manifest.Schema.Version, "2026-02-14"; got != want {
		t.Errorf("schema version = %q, want %q", got, want)
	}
	if got, want := string(out.Schema), sampleSchema; got != want {
		t.Errorf("schema = %q, want %q", got, want)
	}
	if got, want := out.Manifest.Schema.SHA, sha256Hex([]byte(sampleSchema)); got != want {
		t.Errorf("schema SHA = %q, want %q", got, want)
	}

	if got := len(out.Policies); got != 2 {
		t.Fatalf("len(Policies) = %d, want 2", got)
	}
	if !bytes.Equal(out.Policies["pol_a"], in.Policies["pol_a"]) {
		t.Errorf("pol_a content mismatch")
	}
	if !bytes.Equal(out.Policies["pol_b"], in.Policies["pol_b"]) {
		t.Errorf("pol_b content mismatch")
	}

	if got := len(out.Manifest.Policies); got != 2 {
		t.Fatalf("len(Manifest.Policies) = %d, want 2", got)
	}
	if got, want := out.Manifest.Policies[0].PublicID, "pol_a"; got != want {
		t.Errorf("Policies[0].PublicID = %q, want %q", got, want)
	}
	if got, want := out.Manifest.Policies[1].PublicID, "pol_b"; got != want {
		t.Errorf("Policies[1].PublicID = %q, want %q", got, want)
	}
	if got, want := out.Manifest.Policies[0].SHA, sha256Hex(in.Policies["pol_a"]); got != want {
		t.Errorf("Policies[0].SHA = %q, want %q", got, want)
	}
	if got, want := out.Manifest.Policies[1].SHA, sha256Hex(in.Policies["pol_b"]); got != want {
		t.Errorf("Policies[1].SHA = %q, want %q", got, want)
	}
	if got, want := out.Manifest.Policies[0].Name, "allow-read"; got != want {
		t.Errorf("advisory name must survive the round trip: got %q, want %q", got, want)
	}
	if got, want := out.Manifest.Policies[1].Name, "deny-all"; got != want {
		t.Errorf("Policies[1].Name = %q, want %q", got, want)
	}
}

func TestTarGZipCodec_RoundTrip_NoPolicies(t *testing.T) {
	in := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}, TargetType: TargetTypeUser, TargetID: "user_sample"},
		Schema:   []byte(sampleSchema),
		Policies: map[string][]byte{},
	}

	codec := tarGZipCodec{}
	out, err := codec.Decode(bytes.NewReader(encodeToBytes(t, in)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got, want := string(out.Schema), sampleSchema; got != want {
		t.Errorf("schema = %q, want %q", got, want)
	}
	if len(out.Manifest.Policies) != 0 {
		t.Errorf("expected empty Manifest.Policies, got %v", out.Manifest.Policies)
	}
	if len(out.Policies) != 0 {
		t.Errorf("expected empty Policies, got %v", out.Policies)
	}
}

func TestTarGZipCodec_EncodeIsDeterministic(t *testing.T) {
	a := encodeToBytes(t, sampleBundle())
	b := encodeToBytes(t, sampleBundle())
	if !bytes.Equal(a, b) {
		t.Error("Encode must be byte-for-byte deterministic")
	}
}

func TestTarGZipCodec_RoundTripIsIdempotent(t *testing.T) {
	first := encodeToBytes(t, sampleBundle())
	codec := tarGZipCodec{}
	d1, err := codec.Decode(bytes.NewReader(first))
	if err != nil {
		t.Fatalf("first Decode: %v", err)
	}

	// Re-encoding a decoded bundle (Manifest now populated + sorted) must reach
	// a fixed point: identical bytes, and identical SHAs across the loop.
	second := encodeToBytes(t, d1)
	if !bytes.Equal(first, second) {
		t.Error("re-encoding a decoded bundle must be byte-identical")
	}

	d2, err := codec.Decode(bytes.NewReader(second))
	if err != nil {
		t.Fatalf("second Decode: %v", err)
	}
	if !reflect.DeepEqual(d1.Manifest, d2.Manifest) {
		t.Errorf("manifest incl. schema + policy SHAs must be stable across loops: got %v, want %v", d2.Manifest, d1.Manifest)
	}
	if !bytes.Equal(d1.Schema, d2.Schema) {
		t.Error("schema changed across re-encode loop")
	}
	if len(d1.Policies) != len(d2.Policies) {
		t.Errorf("policies length changed: %d vs %d", len(d2.Policies), len(d1.Policies))
	}
	for k, v := range d1.Policies {
		if !bytes.Equal(v, d2.Policies[k]) {
			t.Errorf("policy %q changed across re-encode loop", k)
		}
	}
}

func TestTarGZipCodec_DecodeIgnoresProducerSHAs(t *testing.T) {
	// A manifest claiming a bogus SHA must not survive: Decode recomputes from
	// the actual bytes, so the returned SHA reflects content, not the claim.
	encoded := encodeToBytes(t, &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14", SHA: "sha256:deadbeef"}, TargetType: TargetTypeUser},
		Schema:   []byte(sampleSchema),
	})

	codec2 := tarGZipCodec{}
	out, err := codec2.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := out.Manifest.Schema.SHA, sha256Hex([]byte(sampleSchema)); got != want {
		t.Errorf("schema SHA = %q, want %q", got, want)
	}
	if out.Manifest.Schema.SHA == "sha256:deadbeef" {
		t.Error("producer SHA must not survive Decode")
	}
}

func TestTarGZipCodec_Decode_MissingSchemaIsAccepted(t *testing.T) {
	// schema.cedarschema is optional on the way in (PUT): ingest authoritative
	// schema comes from manifest.schema.version. Encode still always emits it.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	manifest := []byte(`{"schema":{"version":"2026-02-14","sha":""},"policies":[{"public_id":"pol_x","sha":""}]}`)
	if err := tw.WriteHeader(&tar.Header{Name: pathManifest, Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	pol := []byte(`permit(principal, action, resource);`)
	if err := tw.WriteHeader(&tar.Header{Name: policiesPrefix + "pol_x" + policiesSuffix, Mode: 0o644, Size: int64(len(pol)), Typeflag: tar.TypeReg, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(pol); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	codec3 := tarGZipCodec{}
	out, err := codec3.Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := out.Manifest.Schema.Version, "2026-02-14"; got != want {
		t.Errorf("schema version = %q, want %q", got, want)
	}
	if out.Schema != nil {
		t.Errorf("expected nil Schema, got %q", out.Schema)
	}
	if got := len(out.Policies); got != 1 {
		t.Fatalf("len(Policies) = %d, want 1", got)
	}
	if !bytes.Equal(out.Policies["pol_x"], pol) {
		t.Errorf("pol_x content mismatch")
	}
	if got, want := out.Manifest.Policies[0].SHA, sha256Hex(pol); got != want {
		t.Errorf("policy SHA = %q, want %q", got, want)
	}
}

func TestTarGZipCodec_Encode_RejectsEmptyVersion(t *testing.T) {
	in := sampleBundle()
	in.Manifest.Schema.Version = ""

	codec4 := tarGZipCodec{}
	err := codec4.Encode(io.Discard, in)
	if !errors.Is(err, ErrMissingVersion) {
		t.Errorf("Encode with empty version: got %v, want %v", err, ErrMissingVersion)
	}
}

func TestTarGZipCodec_Decode_RejectsDecompressionBomb(t *testing.T) {
	// A tiny compressed archive whose single entry inflates past the codec's
	// decompressed ceiling must be rejected, not read into memory.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	size := int64(maxDecompressedSize) + 1
	if err := tw.WriteHeader(&tar.Header{Name: policiesPrefix + "pol_big" + policiesSuffix, Mode: 0o644, Size: size, Typeflag: tar.TypeReg, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(tw, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	if buf.Len() >= maxDecompressedSize {
		t.Errorf("compressed bomb should be far smaller than its inflated size: compressed=%d", buf.Len())
	}

	codec5 := tarGZipCodec{}
	_, err := codec5.Decode(bytes.NewReader(buf.Bytes()))
	if !errors.Is(err, ErrBundleTooLarge) {
		t.Errorf("Decode decompression bomb: got %v, want %v", err, ErrBundleTooLarge)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

// readArchiveEntry returns the raw bytes of a named entry in an encoded bundle.
func readArchiveEntry(t *testing.T, encoded []byte, name string) []byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == name {
			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return content
		}
	}
}

// A consumer that never runs our codec must reach the same digest by parsing
// manifest.json and canonicalizing it with JCS. This is the contract that makes
// the digest verifiable across the trust boundary.
func TestManifest_Digest_ReproducibleFromArchiveManifestJSON(t *testing.T) {
	encoded := encodeToBytes(t, sampleBundle())

	codec6 := tarGZipCodec{}
	decoded, err := codec6.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	digest, err := decoded.Manifest.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}

	// A consumer reproduces the digest by stripping each policy's advisory
	// `name` from manifest.json before canonicalizing.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(readArchiveEntry(t, encoded, pathManifest), &raw); err != nil {
		t.Fatal(err)
	}
	var policies []map[string]json.RawMessage
	if err := json.Unmarshal(raw["policies"], &policies); err != nil {
		t.Fatal(err)
	}
	for _, p := range policies {
		delete(p, "name")
	}
	stripped, err := json.Marshal(policies)
	if err != nil {
		t.Fatal(err)
	}
	raw["policies"] = stripped
	manifestJSON, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	consumerDigest, err := contentSHA(manifestJSON)
	if err != nil {
		t.Fatalf("contentSHA: %v", err)
	}

	if consumerDigest != digest {
		t.Errorf("Digest() = %q, want %q (Digest must equal contentSHA(manifest.json with names stripped))", digest, consumerDigest)
	}
}

// Digest commits to content, not to slice or map iteration order: the same
// members in any order yield the same identity.
func TestManifest_Digest_OrderIndependent(t *testing.T) {
	a := Manifest{
		Schema:   SchemaRef{Version: "v1", SHA: "sha256:aaa"},
		Policies: []PolicyRef{{PublicID: "pol_a", SHA: "sha256:1"}, {PublicID: "pol_b", SHA: "sha256:2"}},
	}
	b := Manifest{
		Schema:   SchemaRef{Version: "v1", SHA: "sha256:aaa"},
		Policies: []PolicyRef{{PublicID: "pol_b", SHA: "sha256:2"}, {PublicID: "pol_a", SHA: "sha256:1"}},
	}

	da, err := a.Digest()
	if err != nil {
		t.Fatalf("a.Digest: %v", err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatalf("b.Digest: %v", err)
	}
	if da != db {
		t.Errorf("Digest is not order-independent: %q vs %q", da, db)
	}
}

// Any change to committed content — here a single policy SHA — must change the
// digest. Otherwise it would not detect tampering.
func TestManifest_Digest_ChangesWithContent(t *testing.T) {
	base := sampleBundle().Manifest
	base.Policies = []PolicyRef{{PublicID: "pol_a", SHA: "sha256:1"}}
	d1, err := base.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}

	base.Policies[0].SHA = "sha256:2"
	d2, err := base.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d1 == d2 {
		t.Error("Digest must change when content changes")
	}
}

// Name is advisory metadata, not committed content: renames must not change the
// digest/ETag, and a manifest with names must digest identically to one without
// (ETag continuity with bundles served before names existed).
func TestManifest_Digest_IndependentOfName(t *testing.T) {
	named := Manifest{
		Schema:   SchemaRef{Version: "v1", SHA: "sha256:aaa"},
		Policies: []PolicyRef{{PublicID: "pol_a", Name: "old", SHA: "sha256:1"}},
	}
	d1, err := named.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}

	named.Policies[0].Name = "new"
	d2, err := named.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d1 != d2 {
		t.Errorf("rename must not change the digest: %q vs %q", d1, d2)
	}

	unnamed := Manifest{
		Schema:   SchemaRef{Version: "v1", SHA: "sha256:aaa"},
		Policies: []PolicyRef{{PublicID: "pol_a", SHA: "sha256:1"}},
	}
	d3, err := unnamed.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d1 != d3 {
		t.Errorf("digest must match a manifest that never had names: %q vs %q", d1, d3)
	}

	named.Policies[0].SHA = "sha256:2"
	d4, err := named.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d1 == d4 {
		t.Error("content changes must still change the digest")
	}
}

func TestRegistry(t *testing.T) {
	c, ok := CodecFor(MediaTypeTarGzip)
	if !ok {
		t.Fatal("tarGZipCodec must self-register via init")
	}
	if got, want := c.MediaType(), MediaTypeTarGzip; got != want {
		t.Errorf("MediaType() = %q, want %q", got, want)
	}

	_, ok = CodecFor("application/unknown")
	if ok {
		t.Error("unknown media type must not be found")
	}
}

func TestBundleEncode_RoundTrip(t *testing.T) {
	in := sampleBundle()

	var buf bytes.Buffer
	n, err := in.Encode(&buf, MediaTypeTarGzip)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if n != buf.Len() {
		t.Errorf("Encode returned %d bytes written but buffer holds %d", n, buf.Len())
	}

	out, err := DecodeBundle(&buf, MediaTypeTarGzip)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}

	if got, want := out.Manifest.Schema.Version, "2026-02-14"; got != want {
		t.Errorf("schema version = %q, want %q", got, want)
	}
	if got, want := string(out.Schema), sampleSchema; got != want {
		t.Errorf("schema content mismatch")
	}
	if len(out.Policies) != 2 {
		t.Fatalf("len(Policies) = %d, want 2", len(out.Policies))
	}
}

func TestBundleEncode_UnknownMediaType(t *testing.T) {
	_, err := sampleBundle().Encode(io.Discard, "application/unknown")
	if !errors.Is(err, ErrUnknownMediaType) {
		t.Errorf("got %v, want ErrUnknownMediaType", err)
	}
}

func TestDecodeBundle_UnknownMediaType(t *testing.T) {
	_, err := DecodeBundle(bytes.NewReader(nil), "application/unknown")
	if !errors.Is(err, ErrUnknownMediaType) {
		t.Errorf("got %v, want ErrUnknownMediaType", err)
	}
}

func TestBundleEncode_EncodeDecodeIsByteIdentical(t *testing.T) {
	// Bundle.Encode + DecodeBundle must produce the same result as the
	// direct codec calls.
	b := sampleBundle()
	var via bytes.Buffer
	if _, err := b.Encode(&via, MediaTypeTarGzip); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	direct := encodeToBytes(t, b)
	if !bytes.Equal(via.Bytes(), direct) {
		t.Error("Bundle.Encode must produce byte-identical output to the codec's Encode")
	}
}

func TestLoadBundle_RoundTrip(t *testing.T) {
	in := sampleBundle()

	vfs := &VFS{}
	if err := in.Unload(vfs); err != nil {
		t.Fatalf("Unload: %v", err)
	}

	out, err := LoadBundle(vfs)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	if got, want := out.Manifest.Schema.Version, "2026-02-14"; got != want {
		t.Errorf("schema version = %q, want %q", got, want)
	}
	if got, want := string(out.Schema), sampleSchema; got != want {
		t.Errorf("schema content mismatch")
	}
	if len(out.Policies) != 2 {
		t.Fatalf("len(Policies) = %d, want 2", len(out.Policies))
	}
	if !bytes.Equal(out.Policies["pol_a"], in.Policies["pol_a"]) {
		t.Errorf("pol_a content mismatch")
	}
	if !bytes.Equal(out.Policies["pol_b"], in.Policies["pol_b"]) {
		t.Errorf("pol_b content mismatch")
	}
	if got, want := out.Manifest.Policies[0].Name, "allow-read"; got != want {
		t.Errorf("advisory name must survive Unload/LoadBundle: got %q", got)
	}
}

// Decode-then-Encode and Load-then-Unload must both be byte-for-byte
// idempotent (cross-codec fixed-point).
func TestCrossFormatRoundTrip(t *testing.T) {
	in := sampleBundle()

	// Capture the canonical encoding first.
	encoded := encodeToBytes(t, in)

	// encoded → decoded → unloaded onto VFS → loaded → re-encoded
	decoded, err := DecodeBundle(bytes.NewReader(encoded), MediaTypeTarGzip)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}

	vfs := &VFS{}
	if err := decoded.Unload(vfs); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	loaded, err := LoadBundle(vfs)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	var buf2 bytes.Buffer
	if _, err := loaded.Encode(&buf2, MediaTypeTarGzip); err != nil {
		t.Fatalf("second Encode: %v", err)
	}

	if !bytes.Equal(encoded, buf2.Bytes()) {
		t.Error("decoded→unloaded→loaded→encoded bundle must be byte-identical to the original encoding")
	}
}
