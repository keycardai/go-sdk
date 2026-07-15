package policy

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

const sampleBundleDigestHex = "fc4d480186e8dd3add271fc66e6225d14a8879ea4aaceea5021c1f7e460ad29b"

// writeVFSFile stores content at path in v, failing the test on any error.
func writeVFSFile(t *testing.T, v *VFS, path, content string) {
	t.Helper()
	w, err := v.Create(path)
	if err != nil {
		t.Fatalf("Create %q: %v", path, err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatalf("Write %q: %v", path, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close %q: %v", path, err)
	}
}

// A manifest key that would escape policies/ (path separator or traversal
// segment) is rejected by LoadBundle, before any file is read.
func TestLoadBundle_RejectsUnsafeKey(t *testing.T) {
	for _, key := range []string{"../evil", "sub/pol", `back\slash`, ".", ".."} {
		t.Run(key, func(t *testing.T) {
			v := &VFS{}
			writeVFSFile(t, v, "manifest.json",
				`{"schema":{"version":"v1","sha":""},"policies":[{"public_id":"`+key+`","sha":""}]}`)
			_, err := LoadBundle(v)
			if !errors.Is(err, ErrInvalidManifest) {
				t.Errorf("LoadBundle with key %q: got %v, want ErrInvalidManifest", key, err)
			}
		})
	}
}

// A non-.cedar file in policies/ is unexpected, matching Decode's rejection of
// stray archive entries.
func TestLoadBundle_RejectsUnexpectedFile(t *testing.T) {
	v := &VFS{}
	writeVFSFile(t, v, "manifest.json",
		`{"schema":{"version":"v1","sha":""},"policies":[{"public_id":"pol_a","sha":""}]}`)
	writeVFSFile(t, v, "policies/pol_a.cedar", "permit(principal, action, resource);")
	writeVFSFile(t, v, "policies/README.txt", "hi")

	_, err := LoadBundle(v)
	if !errors.Is(err, ErrUnexpectedEntry) {
		t.Errorf("got %v, want ErrUnexpectedEntry", err)
	}
}

// A .cedar file with no manifest entry is an orphan.
func TestLoadBundle_RejectsOrphanPolicy(t *testing.T) {
	v := &VFS{}
	writeVFSFile(t, v, "manifest.json",
		`{"schema":{"version":"v1","sha":""},"policies":[{"public_id":"pol_a","sha":""}]}`)
	writeVFSFile(t, v, "policies/pol_a.cedar", "permit(principal, action, resource);")
	writeVFSFile(t, v, "policies/pol_orphan.cedar", "forbid(principal, action, resource);")

	_, err := LoadBundle(v)
	if !errors.Is(err, ErrOrphanPolicy) {
		t.Errorf("got %v, want ErrOrphanPolicy", err)
	}
}

// A manifest entry whose policy file is missing makes the manifest invalid.
func TestLoadBundle_RejectsMissingPolicyFile(t *testing.T) {
	v := &VFS{}
	writeVFSFile(t, v, "manifest.json",
		`{"schema":{"version":"v1","sha":""},"policies":[{"public_id":"pol_a","sha":""}]}`)

	_, err := LoadBundle(v)
	if !errors.Is(err, ErrInvalidManifest) {
		t.Errorf("got %v, want ErrInvalidManifest", err)
	}
}

// Unload rejects a bundle whose Policies map holds a key the manifest does not
// reference, rather than silently emitting a corrupt entry.
func TestUnload_PolicyWithoutManifestEntry(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{
			Schema:   SchemaRef{Version: "v1"},
			Policies: []PolicyRef{{PublicID: "pol_a"}},
		},
		Policies: map[string][]byte{
			"pol_a":      []byte(`permit(principal, action, resource);`),
			"pol_orphan": []byte(`forbid(principal, action, resource);`),
		},
	}
	if err := b.Unload(&VFS{}); !errors.Is(err, ErrInvalidManifest) {
		t.Errorf("got %v, want ErrInvalidManifest", err)
	}
}

func TestVFS_WriteAndRead(t *testing.T) {
	v := &VFS{}

	w, err := v.Create("manifest.json")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte(`{"schema":{"version":"v1","sha":""},"policies":[]}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := fs.ReadFile(v, "manifest.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got, want := string(data), `{"schema":{"version":"v1","sha":""},"policies":[]}`; got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestVFS_ReadDir(t *testing.T) {
	v := &VFS{}
	_ = v.MkdirAll("policies", 0o755) // no-op, but valid

	writeVFS := func(path, content string) {
		t.Helper()
		w, err := v.Create(path)
		if err != nil {
			t.Fatalf("Create %q: %v", path, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("Write %q: %v", path, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close %q: %v", path, err)
		}
	}

	writeVFS("policies/pol_a.cedar", "permit(principal, action, resource);")
	writeVFS("policies/pol_b.cedar", "forbid(principal, action, resource);")

	entries, err := fs.ReadDir(v, "policies")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if got := len(entries); got != 2 {
		t.Fatalf("ReadDir returned %d entries, want 2", got)
	}
	if got, want := entries[0].Name(), "pol_a.cedar"; got != want {
		t.Errorf("entries[0].Name() = %q, want %q", got, want)
	}
	if got, want := entries[1].Name(), "pol_b.cedar"; got != want {
		t.Errorf("entries[1].Name() = %q, want %q", got, want)
	}
}

func TestVFS_OpenMissingFile(t *testing.T) {
	v := &VFS{}
	_, err := v.Open("nonexistent.txt")
	if err == nil {
		t.Fatal("Open of missing file should return error")
	}
}

func TestLoadBundle_GoldenDir(t *testing.T) {
	goldenDir := filepath.Join("testdata", sampleBundleDigestHex)
	if _, err := os.Stat(goldenDir); os.IsNotExist(err) {
		t.Skipf("golden dir missing; run with -update to generate: %s", goldenDir)
	}

	got, err := LoadBundle(os.DirFS(goldenDir))
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	want := sampleBundle()
	// Verify manifest fields
	if got.Manifest.Schema.Version != want.Manifest.Schema.Version {
		t.Errorf("schema version = %q, want %q", got.Manifest.Schema.Version, want.Manifest.Schema.Version)
	}
	if got.Manifest.TargetType != want.Manifest.TargetType {
		t.Errorf("target_type = %q, want %q", got.Manifest.TargetType, want.Manifest.TargetType)
	}
	if got.Manifest.TargetID != want.Manifest.TargetID {
		t.Errorf("target_id = %q, want %q", got.Manifest.TargetID, want.Manifest.TargetID)
	}
	// Schema content
	if !bytes.Equal(got.Schema, want.Schema) {
		t.Errorf("schema content mismatch:\ngot  %q\nwant %q", got.Schema, want.Schema)
	}
	// Policy content
	if len(got.Policies) != len(want.Policies) {
		t.Fatalf("len(Policies) = %d, want %d", len(got.Policies), len(want.Policies))
	}
	for key, wantContent := range want.Policies {
		gotContent, ok := got.Policies[key]
		if !ok {
			t.Errorf("policy %q missing", key)
			continue
		}
		if !bytes.Equal(gotContent, wantContent) {
			t.Errorf("policy %q content mismatch", key)
		}
	}
}

// Verify that Unload followed by LoadBundle (via a temp os dir) produces an
// equivalent bundle to a straight Decode.
func TestLoadBundle_UnloadRoundTrip(t *testing.T) {
	in := sampleBundle()

	dir := t.TempDir()
	if err := in.Unload(OsDirFS(dir)); err != nil {
		t.Fatalf("Unload: %v", err)
	}

	out, err := LoadBundle(os.DirFS(dir))
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	// The loaded bundle must encode to the same bytes as the original.
	var buf1, buf2 bytes.Buffer
	if _, err := in.Encode(&buf1, MediaTypeTarGzip); err != nil {
		t.Fatalf("Encode in: %v", err)
	}
	// First round-trip (sampleBundle has empty SHAs; we need a decoded form).
	decoded, err := DecodeBundle(&buf1, MediaTypeTarGzip)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	buf1.Reset()
	if _, err := decoded.Encode(&buf1, MediaTypeTarGzip); err != nil {
		t.Fatalf("Re-encode decoded: %v", err)
	}
	if _, err := out.Encode(&buf2, MediaTypeTarGzip); err != nil {
		t.Fatalf("Encode out: %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("LoadBundle(Unload(bundle)) must re-encode to byte-identical output")
	}
}

func TestLoadBundle_GoldenDir_Unload_IsIdempotent(t *testing.T) {
	goldenDir := filepath.Join("testdata", sampleBundleDigestHex)
	if _, err := os.Stat(goldenDir); os.IsNotExist(err) {
		t.Skipf("golden dir missing; run with -update to generate: %s", goldenDir)
	}

	b, err := LoadBundle(os.DirFS(goldenDir))
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	// Unload to a temp dir, load again, compare encodings.
	dir := t.TempDir()
	if err := b.Unload(OsDirFS(dir)); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	b2, err := LoadBundle(os.DirFS(dir))
	if err != nil {
		t.Fatalf("LoadBundle from temp: %v", err)
	}

	var buf1, buf2 bytes.Buffer
	if _, err := b.Encode(&buf1, MediaTypeTarGzip); err != nil {
		t.Fatalf("Encode b: %v", err)
	}
	if _, err := b2.Encode(&buf2, MediaTypeTarGzip); err != nil {
		t.Fatalf("Encode b2: %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("Unload→LoadBundle must be idempotent")
	}
}

// TestLoadBundle_GoldenDir_update regenerates the testdata golden directory
// when invoked with -update.
func TestLoadBundle_GoldenDir_update(t *testing.T) {
	if !*update {
		t.Skip("skipping golden update; run with -update to regenerate")
	}

	b := sampleBundle()
	goldenDir := filepath.Join("testdata", sampleBundleDigestHex)
	if err := b.Unload(OsDirFS(goldenDir)); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	t.Logf("wrote golden dir: %s", goldenDir)
}
