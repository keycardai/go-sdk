package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

type tarEntry struct {
	name     string
	content  string
	typeflag byte
}

func makeArchive(entries ...tarEntry) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		_ = tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.content)),
			Typeflag: tf,
			ModTime:  epoch,
			Format:   tar.FormatUSTAR,
		})
		_, _ = tw.Write([]byte(e.content))
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

func gzipBytes(payload []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(payload)
	_ = gw.Close()
	return buf.Bytes()
}

func TestTarGZipCodec_Decode_MalformedReturnsTypedErrors(t *testing.T) {
	validSchema := tarEntry{name: pathSchema, content: sampleSchema}
	validManifest := tarEntry{name: pathManifest, content: `{"schema":{"version":"2026-02-14","sha":""},"policies":[]}`}

	tests := map[string]struct {
		input   []byte
		wantErr error
	}{
		"not gzip":              {input: []byte("this is plainly not gzip"), wantErr: ErrMalformedArchive},
		"truncated gzip":        {input: gzipBytes([]byte("partial"))[:5], wantErr: ErrMalformedArchive},
		"gzip wrapping non-tar": {input: gzipBytes([]byte("definitely not a tar archive, just some text bytes")), wantErr: ErrMalformedArchive},
		"missing manifest":      {input: makeArchive(validSchema), wantErr: ErrMissingManifest},
		"invalid manifest json": {input: makeArchive(tarEntry{name: pathManifest, content: "{not valid json"}, validSchema), wantErr: ErrInvalidManifest},
		"empty schema version":  {input: makeArchive(tarEntry{name: pathManifest, content: `{"schema":{"version":"","sha":""},"policies":[]}`}, validSchema), wantErr: ErrMissingVersion},
		"unexpected file":       {input: makeArchive(validManifest, validSchema, tarEntry{name: "README.md", content: "hi"}), wantErr: ErrUnexpectedEntry},
		"unexpected dir entry":  {input: makeArchive(validManifest, validSchema, tarEntry{name: policiesPrefix, typeflag: tar.TypeDir}), wantErr: ErrUnexpectedEntry},
		"nested policy path":    {input: makeArchive(validManifest, validSchema, tarEntry{name: policiesPrefix + "nested/pol.cedar", content: "x"}), wantErr: ErrUnexpectedEntry},
		"non-cedar policy file": {input: makeArchive(validManifest, validSchema, tarEntry{name: policiesPrefix + "pol.txt", content: "x"}), wantErr: ErrUnexpectedEntry},
		"duplicate manifest":    {input: makeArchive(validManifest, validManifest, validSchema), wantErr: ErrDuplicateEntry},
		"duplicate schema":      {input: makeArchive(validManifest, validSchema, validSchema), wantErr: ErrDuplicateEntry},
		"duplicate policy":      {input: makeArchive(validManifest, validSchema, tarEntry{name: policiesPrefix + "p.cedar", content: "a"}, tarEntry{name: policiesPrefix + "p.cedar", content: "b"}), wantErr: ErrDuplicateEntry},
	}

	codec := TarGZipCodec{}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := codec.Decode(bytes.NewReader(tc.input))
			if out != nil {
				t.Errorf("expected nil Bundle, got non-nil")
			}
			if err == nil {
				t.Fatalf("expected error wrapping %v, got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want errors.Is(%v)", err, tc.wantErr)
			}
		})
	}
}
