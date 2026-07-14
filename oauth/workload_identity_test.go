package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewWorkloadIdentity_RejectsNilSource(t *testing.T) {
	cred, err := NewWorkloadIdentity(nil)

	var cfgErr *WorkloadIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityConfigurationError", err)
	}
	if cred != nil {
		t.Errorf("credential: got %v, want nil on error", cred)
	}
}

func TestWorkloadIdentity_PreparesRequestFromSource(t *testing.T) {
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(_ context.Context) (string, error) {
		return "platform-token", nil
	}))
	if err != nil {
		t.Fatalf("constructing credential: %v", err)
	}

	if auth := cred.Auth("https://zone.example.com"); auth != nil {
		t.Errorf("Auth: got %v, want nil (assertion-based auth)", auth)
	}

	req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
	if err != nil {
		t.Fatalf("preparing request: %v", err)
	}
	if req.ClientAssertion != "platform-token" {
		t.Errorf("client assertion: got %q, want source token", req.ClientAssertion)
	}
	if req.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client assertion type: got %q", req.ClientAssertionType)
	}
	if req.SubjectToken != "subject-token" {
		t.Errorf("subject token: got %q", req.SubjectToken)
	}
	if req.SubjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("subject token type: got %q", req.SubjectTokenType)
	}
	if req.Resource != "https://resource.example.com" {
		t.Errorf("resource: got %q", req.Resource)
	}
}

func TestWorkloadIdentity_FetchesFreshTokenEveryExchange(t *testing.T) {
	calls := 0
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(_ context.Context) (string, error) {
		calls++
		return fmt.Sprintf("token-%d", calls), nil
	}))
	if err != nil {
		t.Fatalf("constructing credential: %v", err)
	}

	for want := 1; want <= 2; want++ {
		req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
		if err != nil {
			t.Fatalf("preparing request %d: %v", want, err)
		}
		if req.ClientAssertion != fmt.Sprintf("token-%d", want) {
			t.Errorf("exchange %d: client assertion %q, want fresh token (the credential must not cache)", want, req.ClientAssertion)
		}
	}
	if calls != 2 {
		t.Errorf("source calls: got %d, want one per exchange", calls)
	}
}

func TestWorkloadIdentity_WrapsCustomSourceError(t *testing.T) {
	cause := errors.New("socket unavailable")
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(_ context.Context) (string, error) {
		return "", cause
	}))
	if err != nil {
		t.Fatalf("constructing credential: %v", err)
	}

	_, err = cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
	var runtimeErr *WorkloadIdentityRuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
	}
	if runtimeErr.Source != "custom" {
		t.Errorf("source: got %q, want %q", runtimeErr.Source, "custom")
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(cause): cause was dropped, got %v", err)
	}
}

func TestWorkloadIdentity_PassesThroughTypedSourceError(t *testing.T) {
	sourceErr := &WorkloadIdentityRuntimeError{Source: "file", Message: "token file is empty: /var/run/token"}
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(_ context.Context) (string, error) {
		return "", sourceErr
	}))
	if err != nil {
		t.Fatalf("constructing credential: %v", err)
	}

	_, err = cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
	var runtimeErr *WorkloadIdentityRuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
	}
	if runtimeErr.Source != "file" {
		t.Errorf("source: got %q, want the source's own identifier preserved", runtimeErr.Source)
	}
}

func TestWorkloadIdentity_RejectsEmptyTokenFromSource(t *testing.T) {
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(func(_ context.Context) (string, error) {
		return "   \n", nil
	}))
	if err != nil {
		t.Fatalf("constructing credential: %v", err)
	}

	_, err = cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
	var runtimeErr *WorkloadIdentityRuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
	}
}

func TestNewFileTokenSource_ExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("projected-token\n"), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}

	source, err := NewFileTokenSource(WithFileTokenPath(path))
	if err != nil {
		t.Fatalf("constructing source: %v", err)
	}

	token, err := source.IdentityToken(context.Background())
	if err != nil {
		t.Fatalf("fetching token: %v", err)
	}
	if token != "projected-token" {
		t.Errorf("token: got %q, want trimmed file contents", token)
	}
}

func TestNewFileTokenSource_ConfigErrorOnMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := NewFileTokenSource(WithFileTokenPath(missing))

	var cfgErr *WorkloadIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityConfigurationError", err)
	}
	if cfgErr.Source != "file" {
		t.Errorf("source: got %q, want %q", cfgErr.Source, "file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("errors.Is(os.ErrNotExist): cause was dropped, got %v", err)
	}
}

func TestNewFileTokenSource_EnvDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("discovered-token"), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}

	discoveryVars := append([]string{"CUSTOM_TOKEN_FILE"}, defaultFileTokenEnvVars...)
	for _, envVar := range discoveryVars {
		t.Run(envVar, func(t *testing.T) {
			for _, v := range discoveryVars {
				t.Setenv(v, "")
			}
			t.Setenv(envVar, path)

			var opts []FileTokenSourceOption
			if envVar == "CUSTOM_TOKEN_FILE" {
				opts = append(opts, WithFileEnvVar(envVar))
			}
			source, err := NewFileTokenSource(opts...)
			if err != nil {
				t.Fatalf("constructing source with %s set: %v", envVar, err)
			}
			token, err := source.IdentityToken(context.Background())
			if err != nil {
				t.Fatalf("fetching token: %v", err)
			}
			if token != "discovered-token" {
				t.Errorf("token: got %q, want token from discovered path", token)
			}
		})
	}
}

func TestNewFileTokenSource_CustomEnvVarWins(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom")
	defaultPath := filepath.Join(dir, "default")
	for path, contents := range map[string]string{customPath: "custom-token", defaultPath: "default-token"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing token file: %v", err)
		}
	}

	t.Setenv("CUSTOM_TOKEN_FILE", customPath)
	t.Setenv("KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE", defaultPath)

	source, err := NewFileTokenSource(WithFileEnvVar("CUSTOM_TOKEN_FILE"))
	if err != nil {
		t.Fatalf("constructing source: %v", err)
	}
	token, err := source.IdentityToken(context.Background())
	if err != nil {
		t.Fatalf("fetching token: %v", err)
	}
	if token != "custom-token" {
		t.Errorf("token: got %q, want the custom env var consulted first", token)
	}
}

func TestNewFileTokenSource_ConfigErrorWithoutPathOrEnv(t *testing.T) {
	for _, envVar := range defaultFileTokenEnvVars {
		t.Setenv(envVar, "")
	}

	_, err := NewFileTokenSource()

	var cfgErr *WorkloadIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityConfigurationError", err)
	}
}

func TestNewEKSWorkloadIdentity_DoesNotDiscoverAzureVar(t *testing.T) {
	// The deprecated EKS constructor keeps the EKS-only discovery list; the
	// AKS variable is discovered only by NewFileTokenSource.
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("azure-token"), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}
	for _, envVar := range defaultFileTokenEnvVars {
		t.Setenv(envVar, "")
	}
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", path)

	if _, err := NewEKSWorkloadIdentity(); err == nil {
		t.Error("NewEKSWorkloadIdentity: got nil error, want configuration error (EKS discovery must not include AZURE_FEDERATED_TOKEN_FILE)")
	}

	if _, err := NewFileTokenSource(); err != nil {
		t.Errorf("NewFileTokenSource: got %v, want AZURE_FEDERATED_TOKEN_FILE discovered", err)
	}
}

func TestGCPMetadataTokenSource_RequiresAudience(t *testing.T) {
	_, err := NewGCPMetadataTokenSource("  ")

	var cfgErr *WorkloadIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityConfigurationError", err)
	}
	if cfgErr.Source != "gcp-metadata" {
		t.Errorf("source: got %q, want %q", cfgErr.Source, "gcp-metadata")
	}
}

func TestGCPMetadataTokenSource_RequestShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("audience"); got != "https://zone.example.com" {
			t.Errorf("audience: got %q", got)
		}
		if got := r.URL.Query().Get("format"); got != "full" {
			t.Errorf("format: got %q, want full", got)
		}
		if got := r.Header.Get("Metadata-Flavor"); got != "Google" {
			t.Errorf("Metadata-Flavor header: got %q, want Google", got)
		}
		_, _ = w.Write([]byte("gcp-identity-token\n"))
	}))
	defer server.Close()

	source, err := NewGCPMetadataTokenSource("https://zone.example.com", WithGCPMetadataURL(server.URL))
	if err != nil {
		t.Fatalf("constructing source: %v", err)
	}

	token, err := source.IdentityToken(context.Background())
	if err != nil {
		t.Fatalf("fetching token: %v", err)
	}
	if token != "gcp-identity-token" {
		t.Errorf("token: got %q, want trimmed response body", token)
	}
}

func TestGCPMetadataTokenSource_RuntimeErrorOnFailure(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "non-200 status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not found", http.StatusNotFound)
			},
		},
		{
			name: "empty body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("  \n"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			source, err := NewGCPMetadataTokenSource("https://zone.example.com", WithGCPMetadataURL(server.URL))
			if err != nil {
				t.Fatalf("constructing source: %v", err)
			}

			_, err = source.IdentityToken(context.Background())
			var runtimeErr *WorkloadIdentityRuntimeError
			if !errors.As(err, &runtimeErr) {
				t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
			}
			if runtimeErr.Source != "gcp-metadata" {
				t.Errorf("source: got %q, want %q", runtimeErr.Source, "gcp-metadata")
			}
		})
	}
}

func TestGCPMetadataTokenSource_RuntimeErrorWhenUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	server.Close() // shut down immediately so the address refuses connections

	source, err := NewGCPMetadataTokenSource("https://zone.example.com", WithGCPMetadataURL(server.URL))
	if err != nil {
		t.Fatalf("constructing source: %v", err)
	}

	_, err = source.IdentityToken(context.Background())
	var runtimeErr *WorkloadIdentityRuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
	}
	if runtimeErr.Err == nil {
		t.Error("Err: got nil, want the underlying transport error preserved")
	}
}

func TestNewWorkloadIdentity_RejectsNilFunc(t *testing.T) {
	cred, err := NewWorkloadIdentity(IdentityTokenFunc(nil))

	var cfgErr *WorkloadIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want WorkloadIdentityConfigurationError", err)
	}
	if cred != nil {
		t.Errorf("credential: got %v, want nil on error", cred)
	}
}

// startFlySocketServer serves handler on a Unix socket and returns the socket
// path. It uses os.MkdirTemp rather than t.TempDir to keep the path under the
// platform's Unix socket path length limit.
func startFlySocketServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "fly")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listening on unix socket: %v", err)
	}

	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return socketPath
}

func TestFlyTokenSource_RequestShape(t *testing.T) {
	socketPath := startFlySocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %q, want POST", r.Method)
		}
		if r.URL.Path != "/v1/tokens/oidc" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type: got %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		if string(body) != `{"aud":"https://zone.example.com"}` {
			t.Errorf("body: got %s, want audience in JSON body", body)
		}
		_, _ = w.Write([]byte("fly-oidc-token\n"))
	}))

	source := NewFlyTokenSource(
		WithFlyAudience("https://zone.example.com"),
		WithFlySocketPath(socketPath),
	)

	token, err := source.IdentityToken(context.Background())
	if err != nil {
		t.Fatalf("fetching token: %v", err)
	}
	if token != "fly-oidc-token" {
		t.Errorf("token: got %q, want trimmed response body", token)
	}
}

func TestFlyTokenSource_EmptyObjectBodyWithoutAudience(t *testing.T) {
	socketPath := startFlySocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		if string(body) != `{}` {
			t.Errorf("body: got %s, want {} when no audience is set", body)
		}
		_, _ = w.Write([]byte("fly-oidc-token"))
	}))

	source := NewFlyTokenSource(WithFlySocketPath(socketPath))

	if _, err := source.IdentityToken(context.Background()); err != nil {
		t.Fatalf("fetching token: %v", err)
	}
}

func TestFlyTokenSource_RuntimeErrorOnFailure(t *testing.T) {
	t.Run("non-200 status", func(t *testing.T) {
		socketPath := startFlySocketServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "machine not found", http.StatusNotFound)
		}))
		source := NewFlyTokenSource(WithFlySocketPath(socketPath))

		_, err := source.IdentityToken(context.Background())
		var runtimeErr *WorkloadIdentityRuntimeError
		if !errors.As(err, &runtimeErr) {
			t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
		}
		if runtimeErr.Source != WorkloadIdentitySourceFly {
			t.Errorf("source: got %q, want %q", runtimeErr.Source, WorkloadIdentitySourceFly)
		}
	})

	t.Run("socket missing", func(t *testing.T) {
		source := NewFlyTokenSource(WithFlySocketPath(filepath.Join(t.TempDir(), "no-such.sock")))

		_, err := source.IdentityToken(context.Background())
		var runtimeErr *WorkloadIdentityRuntimeError
		if !errors.As(err, &runtimeErr) {
			t.Fatalf("error: got %v, want WorkloadIdentityRuntimeError", err)
		}
		if runtimeErr.Err == nil {
			t.Error("Err: got nil, want the underlying dial error preserved")
		}
	})
}

func TestWorkloadIdentity_ClientID(t *testing.T) {
	source := IdentityTokenFunc(func(_ context.Context) (string, error) { return "platform-token", nil })

	t.Run("set", func(t *testing.T) {
		cred, err := NewWorkloadIdentity(source, WithWorkloadClientID("acr_123"))
		if err != nil {
			t.Fatalf("constructing credential: %v", err)
		}
		req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
		if err != nil {
			t.Fatalf("preparing request: %v", err)
		}
		if req.ClientID != "acr_123" {
			t.Errorf("client id: got %q, want the configured credential id", req.ClientID)
		}
	})

	t.Run("unset", func(t *testing.T) {
		cred, err := NewWorkloadIdentity(source)
		if err != nil {
			t.Fatalf("constructing credential: %v", err)
		}
		req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
		if err != nil {
			t.Fatalf("preparing request: %v", err)
		}
		if req.ClientID != "" {
			t.Errorf("client id: got %q, want empty when not configured", req.ClientID)
		}
	})
}
