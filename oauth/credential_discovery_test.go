package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func setCredentialDiscoveryEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, name := range append([]string{clientIDEnv, clientSecretEnv, credentialTypeEnv, webIdentityStorageEnv}, defaultFileTokenEnvVars...) {
		t.Setenv(name, env[name])
	}
}

func writeDiscoveryToken(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func wantDiscoveredSecret(t *testing.T, env map[string]string, id, secret string) {
	t.Helper()
	cred, err := DiscoverCredential(env)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := cred.(*ClientSecretCredential)
	if !ok {
		t.Fatalf("got %T, want *ClientSecretCredential", cred)
	}
	if auth := client.Auth(""); auth == nil || *auth != (ClientAuth{ClientID: id, ClientSecret: secret}) {
		t.Fatal("discovered client authentication does not match the input")
	}
}

func wantDiscoveredWorkload(t *testing.T, env map[string]string, id, token string) {
	t.Helper()
	cred, err := DiscoverCredential(env)
	if err != nil {
		t.Fatal(err)
	}
	workload, ok := cred.(*WorkloadIdentityCredential)
	if !ok {
		t.Fatalf("got %T, want *WorkloadIdentityCredential", cred)
	}
	if got := workload.ClientID(); got != id {
		t.Errorf("ClientID = %q, want %q", got, id)
	}
	if _, ok := workload.source.(*FileTokenSource); !ok {
		t.Fatalf("source = %T, want *FileTokenSource", workload.source)
	}
	req, err := workload.PrepareTokenExchangeRequest(context.Background(), "subject", "resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.ClientAssertion != token {
		t.Error("client assertion does not match the token file")
	}
}

func wantDiscoveredWebIdentity(t *testing.T, env map[string]string, dir string, opts ...CredentialDiscoveryOption) *WebIdentityCredential {
	t.Helper()
	cred, err := DiscoverCredential(env, opts...)
	if err != nil {
		t.Fatal(err)
	}
	web, ok := cred.(*WebIdentityCredential)
	if !ok {
		t.Fatalf("got %T, want *WebIdentityCredential", cred)
	}
	storage, ok := web.keyManager.storage.(*FilePrivateKeyStorage)
	if !ok {
		t.Fatalf("storage = %T, want *FilePrivateKeyStorage", web.keyManager.storage)
	}
	if storage.storageDir != dir {
		t.Errorf("storage directory = %q, want %q", storage.storageDir, dir)
	}
	return web
}

func wantCredentialDiscoveryError(t *testing.T, env map[string]string, reason CredentialDiscoveryReason, resolvable []string) *CredentialDiscoveryError {
	t.Helper()
	cred, err := DiscoverCredential(env)
	var discoveryErr *CredentialDiscoveryError
	if cred != nil || !errors.As(err, &discoveryErr) {
		t.Fatalf("got (%T, %v), want nil credential and *CredentialDiscoveryError", cred, err)
	}
	if discoveryErr.Reason != reason || !slices.Equal(discoveryErr.Resolvable, resolvable) {
		t.Errorf("reason = %q, resolvable = %v; want %q, %v", discoveryErr.Reason, discoveryErr.Resolvable, reason, resolvable)
	}
	return discoveryErr
}

// Spec row 1: discover a client secret from its environment variables.
func TestDiscoverCredentialClientSecret(t *testing.T) {
	setCredentialDiscoveryEnv(t, map[string]string{"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret"})
	wantDiscoveredSecret(t, nil, "client", "secret")
}

// Spec row 2: each token-file variable configures a workload identity.
func TestDiscoverCredentialWorkloadFromEachTokenFileVar(t *testing.T) {
	path := writeDiscoveryToken(t, "projected")
	for _, name := range []string{
		"KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AZURE_FEDERATED_TOKEN_FILE",
	} {
		t.Run(name, func(t *testing.T) {
			wantDiscoveredWorkload(t, map[string]string{name: path}, "", "projected")
		})
	}
}

// Spec row 3: an empty process environment has no credential.
func TestDiscoverCredentialEmptyEnvironment(t *testing.T) {
	setCredentialDiscoveryEnv(t, nil)
	t.Setenv("KEYCARD_ZONE_URL", "https://zone.example")
	wantCredentialDiscoveryError(t, nil, "absent", nil)
}

// Spec row 4: a secret without an ID is incomplete without a selector.
func TestDiscoverCredentialSecretWithoutID(t *testing.T) {
	env := map[string]string{"KEYCARD_CLIENT_SECRET": "secret"}
	wantCredentialDiscoveryError(t, env, "incomplete", nil)
	env["AWS_WEB_IDENTITY_TOKEN_FILE"] = writeDiscoveryToken(t, "projected")
	wantCredentialDiscoveryError(t, env, "incomplete", []string{"workload_identity"})
	env["KEYCARD_APPLICATION_CREDENTIAL_TYPE"] = "workload_identity"
	wantDiscoveredWorkload(t, env, "", "projected")
}

// Spec row 5: client secret and workload identity are ambiguous without a selector.
func TestDiscoverCredentialAmbiguous(t *testing.T) {
	err := wantCredentialDiscoveryError(t, map[string]string{
		"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret",
		"AWS_WEB_IDENTITY_TOKEN_FILE": writeDiscoveryToken(t, "projected"),
	}, "ambiguous", []string{"client_secret", "workload_identity"})
	for _, fragment := range []string{"KEYCARD_APPLICATION_CREDENTIAL_TYPE", "client_secret", "workload_identity"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("message %q does not contain %q", err, fragment)
		}
	}
}

// Spec row 6: each valid selector, including the alias, selects its type.
func TestDiscoverCredentialExplicitType(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret",
		"AWS_WEB_IDENTITY_TOKEN_FILE":          writeDiscoveryToken(t, "projected"),
		"KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR": dir,
	}
	for _, selector := range []string{"client_secret", "workload_identity", "eks_workload_identity", "web_identity"} {
		t.Run(selector, func(t *testing.T) {
			env["KEYCARD_APPLICATION_CREDENTIAL_TYPE"] = selector
			switch selector {
			case "client_secret":
				wantDiscoveredSecret(t, env, "client", "secret")
			case "workload_identity", "eks_workload_identity":
				wantDiscoveredWorkload(t, env, "client", "projected")
			case "web_identity":
				wantDiscoveredWebIdentity(t, env, dir)
			}
		})
	}
}

// Spec row 7: an unknown selector is rejected and lists the canonical types.
func TestDiscoverCredentialUnknownType(t *testing.T) {
	err := wantCredentialDiscoveryError(t, map[string]string{"KEYCARD_APPLICATION_CREDENTIAL_TYPE": "unsupported"}, "unknown_type", nil)
	for _, name := range []string{"client_secret", "workload_identity", "web_identity"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("message %q does not contain %q", err, name)
		}
	}
}

// Spec row 8: an unknown selector wins over a configured client secret.
func TestDiscoverCredentialUnknownTypeWinsOverClientSecret(t *testing.T) {
	wantCredentialDiscoveryError(t, map[string]string{
		"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret",
		"KEYCARD_APPLICATION_CREDENTIAL_TYPE": "unsupported",
	}, "unknown_type", []string{"client_secret"})
}

// Spec row 9: an explicit client secret without the secret is not satisfiable.
func TestDiscoverCredentialExplicitClientSecretWithoutSecret(t *testing.T) {
	wantCredentialDiscoveryError(t, map[string]string{
		"KEYCARD_APPLICATION_CREDENTIAL_TYPE": "client_secret",
		"KEYCARD_CLIENT_ID":                   "client", "KEYCARD_CLIENT_SECRET": "",
	}, "not_satisfiable", nil)
}

// Spec row 10: an explicit workload identity without a token file is not satisfiable.
func TestDiscoverCredentialExplicitWorkloadWithoutTokenFile(t *testing.T) {
	wantCredentialDiscoveryError(t, map[string]string{
		"KEYCARD_APPLICATION_CREDENTIAL_TYPE": "workload_identity",
	}, "not_satisfiable", nil)
}

// Spec row 11: a client ID without a secret attaches to a workload identity.
func TestDiscoverCredentialWorkloadAttachesClientID(t *testing.T) {
	wantDiscoveredWorkload(t, map[string]string{
		"KEYCARD_CLIENT_ID": "client", "AWS_WEB_IDENTITY_TOKEN_FILE": writeDiscoveryToken(t, "projected"),
	}, "client", "projected")
}

// Spec row 12: a client ID alone does not configure a credential.
func TestDiscoverCredentialClientIDAlone(t *testing.T) {
	wantCredentialDiscoveryError(t, map[string]string{"KEYCARD_CLIENT_ID": "client"}, "absent", nil)
}

// Spec row 13: the first non-empty file variable wins under the legacy selector.
func TestDiscoverCredentialExplicitWorkloadPrefersKeycardTokenFile(t *testing.T) {
	env := map[string]string{
		"KEYCARD_APPLICATION_CREDENTIAL_TYPE":      "eks_workload_identity",
		"KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE": writeDiscoveryToken(t, "keycard"),
		"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE":   writeDiscoveryToken(t, "container"),
		"AWS_WEB_IDENTITY_TOKEN_FILE":              writeDiscoveryToken(t, "irsa"),
		"AZURE_FEDERATED_TOKEN_FILE":               writeDiscoveryToken(t, "aks"),
	}
	wantDiscoveredWorkload(t, env, "", "keycard")
	env["KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE"] = ""
	wantDiscoveredWorkload(t, env, "", "container")
}

// Spec row 14: missing and empty token files surface the token source's error.
func TestDiscoverCredentialInvalidTokenFile(t *testing.T) {
	for _, tt := range []struct {
		name, path string
		cause      error
	}{
		{"missing", filepath.Join(t.TempDir(), "missing"), os.ErrNotExist},
		{"empty", writeDiscoveryToken(t, ""), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := DiscoverCredential(map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": tt.path})
			var fileErr *WorkloadIdentityConfigurationError
			var discoveryErr *CredentialDiscoveryError
			if cred != nil || !errors.As(err, &fileErr) || errors.As(err, &discoveryErr) {
				t.Fatalf("got (%T, %v), want nil credential and *WorkloadIdentityConfigurationError", cred, err)
			}
			if !errors.Is(fileErr.Unwrap(), tt.cause) {
				t.Errorf("cause = %v, want %v", fileErr.Unwrap(), tt.cause)
			}
		})
	}
}

// Spec row 15: an explicit map replaces the process environment.
func TestDiscoverCredentialExplicitEnvironment(t *testing.T) {
	setCredentialDiscoveryEnv(t, map[string]string{
		"KEYCARD_CLIENT_ID": "process", "KEYCARD_CLIENT_SECRET": "process",
		"KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE": writeDiscoveryToken(t, "process"),
		"KEYCARD_APPLICATION_CREDENTIAL_TYPE":      "client_secret",
	})
	wantDiscoveredWorkload(t, map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": writeDiscoveryToken(t, "explicit")}, "", "explicit")
}

// Spec row 16: web identity uses the supplied directory and server name.
func TestDiscoverCredentialNamedWebIdentity(t *testing.T) {
	dir := t.TempDir()
	cred := wantDiscoveredWebIdentity(t, map[string]string{"KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR": dir}, dir, WithWebIdentityServerName("my-server"))
	if got := cred.keyManager.keyID; got != "my-server" {
		t.Errorf("key ID = %q, want my-server", got)
	}
}

// Spec row 17: web identity has a default key ID when no server name is supplied.
func TestDiscoverCredentialUnnamedWebIdentity(t *testing.T) {
	dir := t.TempDir()
	cred := wantDiscoveredWebIdentity(t, map[string]string{"KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR": dir}, dir)
	if cred.keyManager.keyID == "" {
		t.Error("web identity has no default key ID")
	}
}

// Spec row 18: a client secret and a web identity are ambiguous.
func TestDiscoverCredentialAmbiguousClientSecretAndWeb(t *testing.T) {
	wantCredentialDiscoveryError(t, map[string]string{
		"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret",
		"KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR": t.TempDir(),
	}, "ambiguous", []string{"client_secret", "web_identity"})
}

// Spec row 19: a workload identity and a web identity are ambiguous.
func TestDiscoverCredentialAmbiguousWorkloadAndWeb(t *testing.T) {
	wantCredentialDiscoveryError(t, map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE":          writeDiscoveryToken(t, "projected"),
		"KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR": t.TempDir(),
	}, "ambiguous", []string{"workload_identity", "web_identity"})
}

// Spec row 20: explicit web identity can use its default directory.
func TestDiscoverCredentialExplicitWebIdentityUsesDefaultDirectory(t *testing.T) {
	wantDiscoveredWebIdentity(t, map[string]string{"KEYCARD_APPLICATION_CREDENTIAL_TYPE": "web_identity"}, resolveWebIdentityStorageDir())
}

// Spec row 21: an explicit map configures web identity instead of the process credential.
func TestDiscoverCredentialExplicitEnvironmentBuildsWebIdentity(t *testing.T) {
	setCredentialDiscoveryEnv(t, map[string]string{"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret"})
	dir := t.TempDir()
	wantDiscoveredWebIdentity(t, map[string]string{"KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR": dir}, dir)
}

// Spec row 22: an empty explicit map reports absent even with a process credential.
func TestDiscoverCredentialEmptyExplicitEnvironmentIsAbsent(t *testing.T) {
	setCredentialDiscoveryEnv(t, map[string]string{"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret"})
	wantCredentialDiscoveryError(t, map[string]string{}, "absent", nil)
}

// Spec rows 23 and 24: web identity discovery carries an optional client ID.
func TestDiscoverCredentialWebIdentityClientID(t *testing.T) {
	dir := t.TempDir()
	for _, selection := range []struct {
		name, key, value, wantDir string
	}{
		{"inferred", webIdentityStorageEnv, dir, dir},
		{"explicit default storage", credentialTypeEnv, webIdentityType, resolveWebIdentityStorageDir()},
	} {
		t.Run(selection.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, id string
				set      bool
			}{
				{"row 23 set", "client", true},
				{"row 24 unset", "", false},
				{"row 24 empty", "", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					env := map[string]string{selection.key: selection.value}
					if tc.set {
						env[clientIDEnv] = tc.id
					}
					cred := wantDiscoveredWebIdentity(t, env, selection.wantDir)
					if got := cred.ClientID(); got != tc.id {
						t.Errorf("ClientID = %q, want %q", got, tc.id)
					}
				})
			}
		})
	}
}

func TestCredentialDiscoveryErrorUnwrap(t *testing.T) {
	cause := errors.New("cause")
	err := fmt.Errorf("startup: %w", &CredentialDiscoveryError{Message: "discovery failed", Err: cause})
	var discoveryErr *CredentialDiscoveryError
	if !errors.As(err, &discoveryErr) || !errors.Is(err, cause) {
		t.Fatalf("error chain does not contain discovery error and cause: %v", err)
	}
	if got := discoveryErr.Error(); got != "discovery failed: cause" {
		t.Errorf("error message = %q, want discovery failed: cause", got)
	}
}

// Spec integration row 1: a client secret from the process environment exchanges a token.
func TestDiscoverCredentialClientSecretExchange(t *testing.T) {
	req := exchangeWithDiscoveredCredential(t, map[string]string{
		"KEYCARD_CLIENT_ID": "client", "KEYCARD_CLIENT_SECRET": "secret",
	})
	id, secret, ok := (&http.Request{Header: req.header}).BasicAuth()
	if !ok || id != "client" || secret != "secret" || req.form.Get("client_assertion") != "" {
		t.Error("token request does not use the discovered client secret")
	}
}

// Spec integration row 2: a projected token file exchanges a token on the same path.
func TestDiscoverCredentialWorkloadExchange(t *testing.T) {
	req := exchangeWithDiscoveredCredential(t, map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE": writeDiscoveryToken(t, "projected"),
	})
	if req.header.Get("Authorization") != "" || req.form.Get("client_assertion") != "projected" ||
		req.form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Error("token request does not use the discovered workload identity")
	}
}

func exchangeWithDiscoveredCredential(t *testing.T, env map[string]string) recordedRequest {
	t.Helper()
	zone := newFakeZone(t)
	zone.script(stepToken)
	setCredentialDiscoveryEnv(t, env)
	t.Setenv("KEYCARD_ZONE_URL", zone.URL)
	cred, err := DiscoverCredential(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := NewTokenExchangeClient(os.Getenv("KEYCARD_ZONE_URL"), WithTokenExchangeCredential(cred))
	token, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{SubjectToken: "subject", Resource: "resource"})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access-1" {
		t.Errorf("access token = %q, want access-1", token.AccessToken)
	}
	calls := zone.tokenCalls()
	if len(calls) != 1 {
		t.Fatalf("token calls = %d, want 1", len(calls))
	}
	return calls[0]
}
