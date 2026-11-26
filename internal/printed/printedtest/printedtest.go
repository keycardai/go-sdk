// Package printedtest checks the printed forms of SDK types that hold secrets.
package printedtest

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/keycardai/go-sdk/internal/printed"
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

// Type is a type with a printed form and the exported fields its printed form
// leaves out because they hold a secret.
type Type struct {
	// Value is a value of the type, or a pointer to one.
	Value any
	// Form is the value's printed form.
	Form printed.Struct
	// Secret names the exported fields that Form leaves out.
	Secret []string
}

// CheckFields fails t when an exported field of a type is neither listed in its
// printed form nor named in Secret, when a field named in Secret is listed or is
// not an exported field, or when a type in the package in dir with a printed
// method is missing from types. A new field then has to be shown or marked secret.
func CheckFields(t *testing.T, dir string, types []Type) {
	t.Helper()
	covered := map[string]bool{}
	for _, typ := range types {
		rt := reflect.TypeOf(typ.Value)
		if rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}
		covered[rt.Name()] = true
		listed := map[string]bool{}
		for _, f := range typ.Form.Fields {
			listed[f.Name] = true
		}
		exported := map[string]bool{}
		if rt.Kind() == reflect.Struct {
			for i := 0; i < rt.NumField(); i++ {
				if f := rt.Field(i); f.IsExported() {
					exported[f.Name] = true
				}
			}
		}
		secret := map[string]bool{}
		for _, name := range typ.Secret {
			secret[name] = true
			if listed[name] {
				t.Errorf("%s: secret field %s is listed in the printed form", rt.Name(), name)
			}
			if !exported[name] {
				t.Errorf("%s: secret field %s is not an exported field", rt.Name(), name)
			}
		}
		for name := range exported {
			if !listed[name] && !secret[name] {
				t.Errorf("%s: field %s is neither printed nor marked secret", rt.Name(), name)
			}
		}
	}
	for _, name := range printedTypes(t, dir) {
		if !covered[name] {
			t.Errorf("%s has a printed form and no entry in the field check", name)
		}
	}
}

// printedTypes returns the receiver types of the printed methods declared in the
// non-test Go files in dir, sorted.
func printedTypes(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "printed" {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if ident, ok := recv.(*ast.Ident); ok {
				names = append(names, ident.Name)
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("no printed methods in %s", dir)
	}
	sort.Strings(names)
	return names
}
