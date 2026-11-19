package printed

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

// TestStruct checks each form a Struct prints, with exact strings. The types that use
// Struct check only their String output and that no form holds a secret.
func TestStruct(t *testing.T) {
	s := Struct{Type: "oauth.Example", Fields: []Field{
		{Name: "Name", Key: "name", Value: "a b"},
		{Name: "Count", Key: "count", Value: 3},
		{Name: "Keys", Key: "keys", Value: Keys(map[string]int{"y": 1, "x": 2})},
		{Name: "Empty", Key: "empty", Value: Keys[int](nil)},
		{Name: "At", Key: "at", Value: time.Date(2026, 11, 19, 15, 0, 0, 0, time.UTC)},
		{Name: "Type", Key: "type", Value: TypeName(&bytes.Buffer{})},
	}}
	dropTime := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, dropTime)).Info("m", "v", s)
	slog.New(slog.NewJSONHandler(&js, dropTime)).Info("m", "v", s)

	tests := []struct{ name, got, want string }{
		{"String", fmt.Sprintf("%v", s), "{Name:a b Count:3 Keys:[x y] Empty:[] At:2026-11-19 15:00:00 +0000 UTC Type:*bytes.Buffer}"},
		{"GoString", fmt.Sprintf("%#v", s), `oauth.Example{Name:"a b", Count:3, Keys:[]string{"x", "y"}, Empty:[]string{}, ` +
			`At:time.Date(2026, time.November, 19, 15, 0, 0, 0, time.UTC), Type:"*bytes.Buffer"}`},
		{"slog text", text.String(), `level=INFO msg=m v.name="a b" v.count=3 v.keys="[x y]" v.empty=[] ` +
			"v.at=2026-11-19T15:00:00.000Z v.type=*bytes.Buffer\n"},
		{"slog JSON", js.String(), `{"level":"INFO","msg":"m","v":{"name":"a b","count":3,"keys":["x","y"],"empty":[],` +
			`"at":"2026-11-19T15:00:00Z","type":"*bytes.Buffer"}}` + "\n"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, tt.got, tt.want)
		}
	}
}
