// Package printed builds the forms that fmt and log/slog print for SDK types that
// hold secrets: access, refresh, and ID tokens, subject and actor tokens, client
// secrets and assertions, device codes, authorization codes, PKCE verifiers, and
// private keys.
//
// A type lists the fields it shows in a Struct, and its String, GoString, and
// LogValue methods return the Struct's. A field that is not listed is not printed,
// so a new field stays hidden until it is added to the list. NEVER list a field that
// holds a secret. List an interface field, such as a credential or keyring, by its
// type name only, because an implementation outside the SDK may print its secrets.
//
// encoding/json does not use these forms. Types that are persisted as JSON, such as
// a token response or a device authorization, keep their secrets in JSON.
package printed

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// Field is one field of a printed struct.
type Field struct {
	// Name is the Go field name, used by String and GoString.
	Name string
	// Key is the slog attribute key.
	Key string
	// Value is printed with fmt and slog. It must not hold a secret. A value of a
	// type that implements String, GoString, and LogValue with this package is safe.
	Value any
}

// Struct is the printed form of a struct.
type Struct struct {
	// Type is the package-qualified type name, such as "oauth.TokenResponse".
	Type   string
	Fields []Field
}

// String returns the fields as fmt prints a struct with %+v, as in {Name:value}.
func (s Struct) String() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range s.Fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s:%v", f.Name, f.Value)
	}
	b.WriteByte('}')
	return b.String()
}

// GoString returns the fields as fmt prints a struct with %#v.
func (s Struct) GoString() string {
	var b strings.Builder
	b.WriteString(s.Type)
	b.WriteByte('{')
	for i, f := range s.Fields {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s:%#v", f.Name, f.Value)
	}
	b.WriteByte('}')
	return b.String()
}

// LogValue returns a group with one attribute per field.
func (s Struct) LogValue() slog.Value {
	attrs := make([]slog.Attr, len(s.Fields))
	for i, f := range s.Fields {
		attrs[i] = slog.Any(f.Key, f.Value)
	}
	return slog.GroupValue(attrs...)
}

// Keys returns the keys of m, sorted. It is never nil.
func Keys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TypeName returns the dynamic type of v, as fmt prints it with %T.
func TypeName(v any) string {
	return fmt.Sprintf("%T", v)
}
