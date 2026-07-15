package policy

import (
	"bytes"
	"compress/gzip"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

// The golden file pins the uncompressed tar layout. gzip framing is verified by
// the round-trip tests; pinning compressed bytes would be brittle across Go
// versions, whereas the tar stream is fully deterministic given zeroed headers.
func TestTarGZipCodec_GoldenTarLayout(t *testing.T) {
	var encoded bytes.Buffer
	err := tarGZipCodec{}.Encode(&encoded, sampleBundle())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	gr, err := gzip.NewReader(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	tarBytes, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	if err := gr.Close(); err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "bundle.tar")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, tarBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("golden file missing; run: go test ./policy/... -run Golden -update — %v", err)
	}
	if !bytes.Equal(want, tarBytes) {
		t.Error("tar layout drifted; re-run with -update if intentional")
	}
}
