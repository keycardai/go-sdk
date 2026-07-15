package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

// archiveWith builds a gzip+tar archive from a raw manifest plus policy files
// keyed by their archive path stem.
func archiveWith(t *testing.T, manifest string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	write := func(name, content string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write(pathManifest, manifest)
	for stem, content := range files {
		write(policiesPrefix+stem+policiesSuffix, content)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A manifest entry that omits public_id and carries new_policy marks a not-yet-
// minted policy. Decode preserves that label and recomputes the SHA from bytes.
func TestTarGZipCodec_Decode_NewPolicyEntry(t *testing.T) {
	body := `permit(principal, action, resource);`
	manifest := `{"schema":{"version":"2026-02-14","sha":""},"policies":[{"new_policy":"limit-prod","sha":"ignored"}]}`

	codec := tarGZipCodec{}
	out, err := codec.Decode(bytes.NewReader(archiveWith(t, manifest, map[string]string{"limit-prod": body})))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got := len(out.Manifest.Policies); got != 1 {
		t.Fatalf("len(Manifest.Policies) = %d, want 1", got)
	}
	ref := out.Manifest.Policies[0]
	if ref.PublicID != "" {
		t.Errorf("PublicID = %q, want empty", ref.PublicID)
	}
	if got, want := ref.NewPolicy, "limit-prod"; got != want {
		t.Errorf("NewPolicy = %q, want %q", got, want)
	}
	if got, want := ref.SHA, sha256Hex([]byte(body)); got != want {
		t.Errorf("SHA = %q, want %q", got, want)
	}
	if !bytes.Equal(out.Policies["limit-prod"], []byte(body)) {
		t.Errorf("policy content mismatch")
	}
}

// An existing policy (public_id present) and a new policy coexist in one bundle.
func TestTarGZipCodec_Decode_MixedExistingAndNew(t *testing.T) {
	manifest := `{"schema":{"version":"2026-02-14","sha":""},"policies":[` +
		`{"public_id":"AbC123","sha":"x"},` +
		`{"new_policy":"limit-prod","sha":"y"}]}`
	codec2 := tarGZipCodec{}
	out, err := codec2.Decode(bytes.NewReader(archiveWith(t, manifest, map[string]string{
		"AbC123":     `forbid(principal, action, resource);`,
		"limit-prod": `permit(principal, action, resource);`,
	})))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got := len(out.Manifest.Policies); got != 2 {
		t.Fatalf("len(Manifest.Policies) = %d, want 2", got)
	}
	byKey := map[string]PolicyRef{}
	for _, r := range out.Manifest.Policies {
		if r.PublicID != "" {
			byKey[r.PublicID] = r
		} else {
			byKey[r.NewPolicy] = r
		}
	}
	if got, want := byKey["AbC123"].PublicID, "AbC123"; got != want {
		t.Errorf("AbC123.PublicID = %q, want %q", got, want)
	}
	if byKey["AbC123"].NewPolicy != "" {
		t.Errorf("AbC123.NewPolicy = %q, want empty", byKey["AbC123"].NewPolicy)
	}
	if byKey["limit-prod"].PublicID != "" {
		t.Errorf("limit-prod.PublicID = %q, want empty", byKey["limit-prod"].PublicID)
	}
	if got, want := byKey["limit-prod"].NewPolicy, "limit-prod"; got != want {
		t.Errorf("limit-prod.NewPolicy = %q, want %q", got, want)
	}
}

func TestTarGZipCodec_Decode_RejectsBothIDAndNewPolicy(t *testing.T) {
	manifest := `{"schema":{"version":"2026-02-14","sha":""},"policies":[{"public_id":"AbC123","new_policy":"limit-prod","sha":"x"}]}`
	codec3 := tarGZipCodec{}
	_, err := codec3.Decode(bytes.NewReader(archiveWith(t, manifest, map[string]string{"AbC123": "x"})))
	if !errors.Is(err, ErrInvalidManifest) {
		t.Errorf("got %v, want %v", err, ErrInvalidManifest)
	}
}

func TestTarGZipCodec_Decode_RejectsEntryWithoutFile(t *testing.T) {
	manifest := `{"schema":{"version":"2026-02-14","sha":""},"policies":[{"new_policy":"limit-prod","sha":"x"}]}`
	codec4 := tarGZipCodec{}
	_, err := codec4.Decode(bytes.NewReader(archiveWith(t, manifest, nil)))
	if !errors.Is(err, ErrInvalidManifest) {
		t.Errorf("got %v, want %v", err, ErrInvalidManifest)
	}
}

// The manifest is authoritative for membership: a policies/*.cedar member with no
// manifest entry is not part of the bundle and is dropped. Omitting the entry is
// how a caller removes a policy; a lingering file does not resurrect it.
func TestTarGZipCodec_Decode_FileWithoutEntryIsDropped(t *testing.T) {
	manifest := `{"schema":{"version":"2026-02-14","sha":""},"policies":[]}`
	body := `permit(principal, action, resource);`
	codec5 := tarGZipCodec{}
	out, err := codec5.Decode(bytes.NewReader(archiveWith(t, manifest, map[string]string{"pol_x": body})))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Manifest.Policies) != 0 {
		t.Errorf("unreferenced file must be absent from manifest: got %v", out.Manifest.Policies)
	}
	if len(out.Policies) != 0 {
		t.Errorf("unreferenced file must be dropped from bundle: got %v", out.Policies)
	}
}

// Decode rejects a manifest key that would escape the policies/ directory.
func TestTarGZipCodec_Decode_RejectsUnsafeKey(t *testing.T) {
	for _, key := range []string{"../evil", "sub/pol", ".."} {
		t.Run(key, func(t *testing.T) {
			manifest := `{"schema":{"version":"2026-02-14","sha":""},"policies":[{"public_id":"` + key + `","sha":""}]}`
			_, err := tarGZipCodec{}.Decode(bytes.NewReader(archiveWith(t, manifest, nil)))
			if !errors.Is(err, ErrInvalidManifest) {
				t.Errorf("key %q: got %v, want ErrInvalidManifest", key, err)
			}
		})
	}
}

// Encode rejects a bundle whose Policies map holds a key the manifest does not
// reference, rather than silently emitting a corrupt policies/.cedar entry.
func TestTarGZipCodec_Encode_PolicyWithoutManifestEntry(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{
			Schema:   SchemaRef{Version: "2026-02-14"},
			Policies: []PolicyRef{{PublicID: "pol_a"}},
		},
		Policies: map[string][]byte{
			"pol_a":      []byte(`permit(principal, action, resource);`),
			"pol_orphan": []byte(`forbid(principal, action, resource);`),
		},
	}
	var buf bytes.Buffer
	if _, err := b.Encode(&buf, MediaTypeTarGzip); !errors.Is(err, ErrInvalidManifest) {
		t.Errorf("got %v, want ErrInvalidManifest", err)
	}
}

// Digest stays deterministic and distinct for id-less entries.
func TestManifest_Digest_NewPolicyOrderIndependent(t *testing.T) {
	a := Manifest{
		Schema:   SchemaRef{Version: "v1"},
		Policies: []PolicyRef{{NewPolicy: "a", SHA: "1"}, {NewPolicy: "b", SHA: "2"}},
	}
	b := Manifest{
		Schema:   SchemaRef{Version: "v1"},
		Policies: []PolicyRef{{NewPolicy: "b", SHA: "2"}, {NewPolicy: "a", SHA: "1"}},
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
		t.Errorf("Digest is not order-independent for new-policy entries: %q vs %q", da, db)
	}
}
