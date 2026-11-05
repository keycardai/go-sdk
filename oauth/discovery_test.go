package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// knownASMetadataFields must stay in sync with the json-tagged fields of
// AuthorizationServerMetadata: a typed field missing from the list would be duplicated
// into Extra, and a stale entry would silently strip a field that no longer exists.
func TestKnownASMetadataFieldsMatchStruct(t *testing.T) {
	tagged := map[string]bool{}
	rt := reflect.TypeOf(AuthorizationServerMetadata{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		tagged[name] = true
	}

	known := map[string]bool{}
	for _, f := range knownASMetadataFields {
		known[f] = true
	}

	for name := range tagged {
		if !known[name] {
			t.Errorf("struct json field %q is missing from knownASMetadataFields; it would leak into Extra", name)
		}
	}
	for name := range known {
		if !tagged[name] {
			t.Errorf("knownASMetadataFields entry %q has no matching struct json tag", name)
		}
	}
}

func TestFetchAuthorizationServerMetadata(t *testing.T) {
	metadata := AuthorizationServerMetadata{
		TokenEndpoint:         "https://auth.example.com/token",
		JWKSURI:               "https://auth.example.com/.well-known/jwks.json",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()
	// A real authorization server reports its own URL as the issuer.
	metadata.Issuer = server.URL

	result, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Issuer != metadata.Issuer {
		t.Errorf("issuer: got %q, want %q", result.Issuer, metadata.Issuer)
	}
	if result.TokenEndpoint != metadata.TokenEndpoint {
		t.Errorf("token_endpoint: got %q, want %q", result.TokenEndpoint, metadata.TokenEndpoint)
	}
	if result.JWKSURI != metadata.JWKSURI {
		t.Errorf("jwks_uri: got %q, want %q", result.JWKSURI, metadata.JWKSURI)
	}
}

func TestFetchAuthorizationServerMetadata_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error")
	}

	var httpErr *HTTPError
	if ok := err.(*HTTPError); ok == nil {
		t.Errorf("expected HTTPError, got %T", err)
	} else {
		httpErr = ok
		if httpErr.Status != 404 {
			t.Errorf("status: got %d, want 404", httpErr.Status)
		}
	}
}

func TestFetchAuthorizationServerMetadata_MalformedDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()

	_, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	var malformed *InvalidMetadataError
	if !errors.As(err, &malformed) {
		t.Fatalf("want *InvalidMetadataError, got %v", err)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Errorf("JSON cause was dropped: %v", err)
	}
}

func TestFetchAuthorizationServerMetadata_DeviceAuthorizationEndpoint(t *testing.T) {
	cases := map[string]struct {
		advertised string
		want       string
	}{
		"present": {advertised: "/device/authorize", want: "/device/authorize"},
		"absent":  {advertised: "", want: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var serverURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				md := map[string]string{"issuer": serverURL}
				if tc.advertised != "" {
					md["device_authorization_endpoint"] = serverURL + tc.advertised
				}
				_ = json.NewEncoder(w).Encode(md)
			}))
			defer server.Close()
			serverURL = server.URL

			md, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
			if err != nil {
				t.Fatalf("FetchAuthorizationServerMetadata: %v", err)
			}
			want := ""
			if tc.want != "" {
				want = server.URL + tc.want
			}
			if md.DeviceAuthorizationEndpoint != want {
				t.Errorf("DeviceAuthorizationEndpoint: got %q, want %q", md.DeviceAuthorizationEndpoint, want)
			}
			if _, ok := md.Extra["device_authorization_endpoint"]; ok {
				t.Errorf("device_authorization_endpoint leaked into Extra: %v", md.Extra)
			}
		})
	}
}
