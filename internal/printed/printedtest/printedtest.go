// Package printedtest checks the printed forms of SDK types that hold secrets.
package printedtest

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Check prints value with %v, %+v, %s, %#v, and slog's text and JSON handlers. It
// fails t when %v, %+v, or %s differs from want, or when any form contains one of
// secrets.
func Check(t *testing.T, value any, want string, secrets ...string) {
	t.Helper()
	if len(secrets) == 0 {
		t.Fatal("no secrets to check for")
	}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "v", value)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "v", value)
	forms := []struct{ name, got string }{
		{"%v", fmt.Sprintf("%v", value)},
		{"%+v", fmt.Sprintf("%+v", value)},
		{"%s", fmt.Sprintf("%s", value)},
		{"%#v", fmt.Sprintf("%#v", value)},
		{"slog text", text.String()},
		{"slog JSON", js.String()},
	}
	for _, f := range forms[:3] {
		if f.got != want {
			t.Errorf("%s:\n got %s\nwant %s", f.name, f.got, want)
		}
	}
	for _, s := range secrets {
		if s == "" {
			t.Fatal("empty secret")
		}
		for _, f := range forms {
			if strings.Contains(f.got, s) {
				t.Errorf("%s contains secret %q: %s", f.name, s, f.got)
			}
		}
	}
}
