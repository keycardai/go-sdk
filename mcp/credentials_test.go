package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
)

func TestNewClientSecret_RejectsEmpty(t *testing.T) {
	cases := []struct {
		name         string
		clientID     string
		clientSecret string
		wantErr      bool
	}{
		{name: "valid", clientID: "id", clientSecret: "secret", wantErr: false},
		{name: "empty client_id", clientID: "", clientSecret: "secret", wantErr: true},
		{name: "empty client_secret", clientID: "id", clientSecret: "", wantErr: true},
		{name: "whitespace client_id", clientID: "   ", clientSecret: "secret", wantErr: true},
		{name: "whitespace client_secret", clientID: "id", clientSecret: "\t", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := NewClientSecret(tc.clientID, tc.clientSecret)
			if tc.wantErr {
				var cfgErr *ClientSecretConfigurationError
				if !errors.As(err, &cfgErr) {
					t.Fatalf("error: got %v, want ClientSecretConfigurationError", err)
				}
				if cred != nil {
					t.Errorf("credential: got %v, want nil on error", cred)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cred == nil {
				t.Fatal("credential: got nil, want non-nil")
			}
		})
	}
}

func TestNewMultiZoneClientSecret_RejectsInvalid(t *testing.T) {
	valid := ClientAuth{ClientID: "id", ClientSecret: "secret"}

	cases := []struct {
		name    string
		zones   map[string]ClientAuth
		wantErr bool
	}{
		{name: "valid single zone", zones: map[string]ClientAuth{"https://a.example.com": valid}, wantErr: false},
		{name: "valid two zones", zones: map[string]ClientAuth{"https://a.example.com": valid, "https://b.example.com": valid}, wantErr: false},
		{name: "nil map", zones: nil, wantErr: true},
		{name: "empty map", zones: map[string]ClientAuth{}, wantErr: true},
		{name: "empty issuer", zones: map[string]ClientAuth{"  ": valid}, wantErr: true},
		{name: "missing client_id", zones: map[string]ClientAuth{"https://a.example.com": {ClientSecret: "secret"}}, wantErr: true},
		{name: "missing client_secret", zones: map[string]ClientAuth{"https://a.example.com": {ClientID: "id"}}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := NewMultiZoneClientSecret(tc.zones)
			if tc.wantErr {
				var cfgErr *ClientSecretConfigurationError
				if !errors.As(err, &cfgErr) {
					t.Fatalf("error: got %v, want ClientSecretConfigurationError", err)
				}
				if cred != nil {
					t.Errorf("credential: got %v, want nil on error", cred)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cred.Zones()) != len(tc.zones) {
				t.Errorf("zones: got %d, want %d", len(cred.Zones()), len(tc.zones))
			}
		})
	}
}

func TestNewEKSWorkloadIdentity_ConfigErrorOnMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := NewEKSWorkloadIdentity(WithTokenFilePath(missing))

	var cfgErr *EKSWorkloadIdentityConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want EKSWorkloadIdentityConfigurationError", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("errors.Is(os.ErrNotExist): cause was dropped, got %v", err)
	}
	var runtimeErr *EKSWorkloadIdentityRuntimeError
	if errors.As(err, &runtimeErr) {
		t.Error("construction failure should not be an EKSWorkloadIdentityRuntimeError")
	}
}

func TestEKSWorkloadIdentity_RuntimeErrorAfterConstruction(t *testing.T) {
	// The credential is valid at construction, then the token file is removed or emptied
	// (e.g. rotated away by the platform). A read at request time must surface a runtime
	// error, distinct from the construction-time configuration error.
	cases := []struct {
		name              string
		corrupt           func(t *testing.T, path string)
		wantUnwrapMissing bool // the read returns os.ErrNotExist (vs an empty-but-present file)
	}{
		{
			name: "file removed",
			corrupt: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("removing token file: %v", err)
				}
			},
			wantUnwrapMissing: true,
		},
		{
			name: "file emptied",
			corrupt: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
					t.Fatalf("emptying token file: %v", err)
				}
			},
			wantUnwrapMissing: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "eks-token")
			if err := os.WriteFile(path, []byte("initial-token"), 0o600); err != nil {
				t.Fatalf("writing token file: %v", err)
			}

			cred, err := NewEKSWorkloadIdentity(WithTokenFilePath(path))
			if err != nil {
				t.Fatalf("constructing credential: %v", err)
			}

			tc.corrupt(t, path)

			_, err = cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
			var runtimeErr *EKSWorkloadIdentityRuntimeError
			if !errors.As(err, &runtimeErr) {
				t.Fatalf("error: got %v, want EKSWorkloadIdentityRuntimeError", err)
			}
			var cfgErr *EKSWorkloadIdentityConfigurationError
			if errors.As(err, &cfgErr) {
				t.Error("a read failure at request time should not be an EKSWorkloadIdentityConfigurationError")
			}
			if tc.wantUnwrapMissing && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("errors.Is(os.ErrNotExist): cause was dropped, got %v", err)
			}
		})
	}
}

func TestEKSWorkloadIdentity_PreparesRequestWhenTokenPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eks-token")
	if err := os.WriteFile(path, []byte("eks-pod-token\n"), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}

	cred, err := NewEKSWorkloadIdentity(WithTokenFilePath(path))
	if err != nil {
		t.Fatalf("constructing credential: %v", err)
	}

	req, err := cred.PrepareTokenExchangeRequest(context.Background(), "subject-token", "https://resource.example.com", nil)
	if err != nil {
		t.Fatalf("preparing request: %v", err)
	}
	if req.ClientAssertion != "eks-pod-token" {
		t.Errorf("client assertion: got %q, want trimmed token", req.ClientAssertion)
	}
	if req.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client assertion type: got %q", req.ClientAssertionType)
	}
}

func TestNewEKSWorkloadIdentity_DoesNotDiscoverAzureVar(t *testing.T) {
	// The deprecated EKS constructor keeps the EKS-only discovery list; the
	// AKS variable is discovered only by oauth.NewFileTokenSource.
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("azure-token"), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}
	for _, envVar := range []string{
		"KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AZURE_FEDERATED_TOKEN_FILE",
	} {
		t.Setenv(envVar, "")
	}
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", path)

	if _, err := NewEKSWorkloadIdentity(); err == nil {
		t.Error("NewEKSWorkloadIdentity: got nil error, want configuration error (EKS discovery must not include AZURE_FEDERATED_TOKEN_FILE)")
	}

	if _, err := oauth.NewFileTokenSource(); err != nil {
		t.Errorf("oauth.NewFileTokenSource: got %v, want AZURE_FEDERATED_TOKEN_FILE discovered", err)
	}
}
