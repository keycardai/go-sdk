package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Source identifiers carried in the Source field of
// WorkloadIdentityConfigurationError and WorkloadIdentityRuntimeError, for
// branching on which token source failed.
const (
	WorkloadIdentitySourceFile        = "file"
	WorkloadIdentitySourceGCPMetadata = "gcp-metadata"
	WorkloadIdentitySourceFly         = "fly"
	WorkloadIdentitySourceCustom      = "custom"
)

// defaultFileTokenEnvVars is the env-var discovery order for
// NewFileTokenSource: the EKS pod-identity variables followed by the AKS
// federated-token variable.
var defaultFileTokenEnvVars = []string{
	"KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AZURE_FEDERATED_TOKEN_FILE",
}

// FileTokenSource reads a platform-projected OIDC token from a mounted file,
// fresh on every call (platforms rotate projected tokens). It covers EKS pod
// identity, AKS workload identity, any Kubernetes projected service-account
// token, and CI providers that write the token to a file.
type FileTokenSource struct {
	tokenFilePath string
}

type fileTokenSourceConfig struct {
	tokenFilePath string
	envVarName    string
}

// FileTokenSourceOption configures a FileTokenSource.
type FileTokenSourceOption func(*fileTokenSourceConfig)

// WithFileTokenPath sets the token file path directly, skipping env-var
// discovery.
func WithFileTokenPath(path string) FileTokenSourceOption {
	return func(cfg *fileTokenSourceConfig) { cfg.tokenFilePath = path }
}

// WithFileEnvVar adds an environment variable to consult first during
// discovery, ahead of the default list.
func WithFileEnvVar(name string) FileTokenSourceOption {
	return func(cfg *fileTokenSourceConfig) { cfg.envVarName = name }
}

// NewFileTokenSource creates a FileTokenSource. When no explicit path is
// given, the path is discovered from the first set environment variable,
// checking the variable given via WithFileEnvVar first, then
// KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE,
// AWS_WEB_IDENTITY_TOKEN_FILE, and AZURE_FEDERATED_TOKEN_FILE. It returns a
// WorkloadIdentityConfigurationError when no path can be resolved or the
// resolved file is missing, unreadable, or empty.
func NewFileTokenSource(opts ...FileTokenSourceOption) (*FileTokenSource, error) {
	cfg := fileTokenSourceConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return newFileTokenSource(defaultFileTokenEnvVars, cfg)
}

func newFileTokenSource(discoveryEnvVars []string, cfg fileTokenSourceConfig) (*FileTokenSource, error) {
	tokenFilePath := cfg.tokenFilePath
	if tokenFilePath == "" {
		envVars := discoveryEnvVars
		if cfg.envVarName != "" {
			envVars = append([]string{cfg.envVarName}, envVars...)
		}

		for _, envVar := range envVars {
			if v := os.Getenv(envVar); v != "" {
				tokenFilePath = v
				break
			}
		}

		if tokenFilePath == "" {
			return nil, &WorkloadIdentityConfigurationError{
				Source: WorkloadIdentitySourceFile,
				Message: fmt.Sprintf("could not find token file path in environment variables; checked: %s",
					strings.Join(envVars, ", ")),
			}
		}
	}

	// Validate that the token file exists and is non-empty
	data, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return nil, &WorkloadIdentityConfigurationError{
			Source:  WorkloadIdentitySourceFile,
			Message: fmt.Sprintf("error reading token file %q", tokenFilePath),
			Err:     err,
		}
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, &WorkloadIdentityConfigurationError{
			Source:  WorkloadIdentitySourceFile,
			Message: fmt.Sprintf("token file is empty: %s", tokenFilePath),
		}
	}

	return &FileTokenSource{tokenFilePath: tokenFilePath}, nil
}

// IdentityToken re-reads the token file and returns its trimmed contents.
func (f *FileTokenSource) IdentityToken(_ context.Context) (string, error) {
	data, err := os.ReadFile(f.tokenFilePath)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFile,
			Message: fmt.Sprintf("reading token file %q", f.tokenFilePath),
			Err:     err,
		}
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFile,
			Message: fmt.Sprintf("token file is empty: %s", f.tokenFilePath),
		}
	}
	return token, nil
}

const (
	defaultGCPMetadataURL     = "http://metadata.google.internal"
	defaultGCPMetadataTimeout = 5 * time.Second
	gcpMetadataIdentityPath   = "/computeMetadata/v1/instance/service-accounts/default/identity"
)

// GCPMetadataTokenSource fetches an OIDC identity token for the default
// service account from the GCP metadata server. It covers GKE, GCE, and
// Cloud Run.
type GCPMetadataTokenSource struct {
	audience    string
	metadataURL string
	httpClient  *http.Client
	timeout     time.Duration
}

// GCPMetadataOption configures a GCPMetadataTokenSource.
type GCPMetadataOption func(*GCPMetadataTokenSource)

// WithGCPMetadataURL overrides the metadata server base URL (for testing).
func WithGCPMetadataURL(u string) GCPMetadataOption {
	return func(g *GCPMetadataTokenSource) { g.metadataURL = u }
}

// WithGCPTimeout overrides the per-call deadline for metadata requests.
func WithGCPTimeout(d time.Duration) GCPMetadataOption {
	return func(g *GCPMetadataTokenSource) { g.timeout = d }
}

// NewGCPMetadataTokenSource creates a GCPMetadataTokenSource that requests
// tokens for the given audience, typically the Keycard zone URL. It returns a
// WorkloadIdentityConfigurationError if audience is empty.
func NewGCPMetadataTokenSource(audience string, opts ...GCPMetadataOption) (*GCPMetadataTokenSource, error) {
	if strings.TrimSpace(audience) == "" {
		return nil, &WorkloadIdentityConfigurationError{
			Source:  WorkloadIdentitySourceGCPMetadata,
			Message: "audience must not be empty",
		}
	}

	g := &GCPMetadataTokenSource{
		audience:    audience,
		metadataURL: defaultGCPMetadataURL,
		httpClient:  &http.Client{},
		timeout:     defaultGCPMetadataTimeout,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g, nil
}

// IdentityToken requests a GCP-signed OIDC JWT from the metadata server.
func (g *GCPMetadataTokenSource) IdentityToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	metaURL := g.metadataURL + gcpMetadataIdentityPath +
		"?audience=" + url.QueryEscape(g.audience) + "&format=full"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceGCPMetadata,
			Message: "building metadata request",
			Err:     err,
		}
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceGCPMetadata,
			Message: fmt.Sprintf("calling metadata server at %s (is this running on GCP?)", g.metadataURL),
			Err:     err,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceGCPMetadata,
			Message: "reading metadata response",
			Err:     err,
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceGCPMetadata,
			Message: fmt.Sprintf("metadata server returned status %d", resp.StatusCode),
		}
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceGCPMetadata,
			Message: "metadata server returned an empty token",
		}
	}
	return token, nil
}

const (
	defaultFlySocketPath = "/.fly/api"
	flyOIDCTokenURL      = "http://localhost/v1/tokens/oidc"
	flyRequestTimeout    = 5 * time.Second
)

// FlyTokenSource fetches an OIDC token from the Fly.io Machines API over the
// local Unix socket. It covers workloads running on Fly Machines.
type FlyTokenSource struct {
	audience   string
	socketPath string
	httpClient *http.Client
}

// FlyTokenSourceOption configures a FlyTokenSource.
type FlyTokenSourceOption func(*FlyTokenSource)

// WithFlyAudience sets the audience claim for the requested token, typically
// the Keycard zone URL.
func WithFlyAudience(audience string) FlyTokenSourceOption {
	return func(f *FlyTokenSource) { f.audience = audience }
}

// WithFlySocketPath overrides the Machines API socket path (default /.fly/api).
func WithFlySocketPath(path string) FlyTokenSourceOption {
	return func(f *FlyTokenSource) { f.socketPath = path }
}

// NewFlyTokenSource creates a FlyTokenSource. The socket is not probed at
// construction; an unreachable Machines API surfaces as a
// WorkloadIdentityRuntimeError at the first fetch.
func NewFlyTokenSource(opts ...FlyTokenSourceOption) *FlyTokenSource {
	f := &FlyTokenSource{socketPath: defaultFlySocketPath}
	for _, opt := range opts {
		opt(f)
	}
	f.httpClient = &http.Client{
		Timeout: flyRequestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", f.socketPath)
			},
		},
	}
	return f
}

// IdentityToken requests a Fly-signed OIDC JWT from the Machines API.
func (f *FlyTokenSource) IdentityToken(ctx context.Context) (string, error) {
	payload := struct {
		Aud string `json:"aud,omitempty"`
	}{Aud: f.audience}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFly,
			Message: "encoding token request",
			Err:     err,
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, flyOIDCTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFly,
			Message: "building token request",
			Err:     err,
		}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFly,
			Message: fmt.Sprintf("calling Machines API socket %s (is this running on a Fly Machine?)", f.socketPath),
			Err:     err,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFly,
			Message: "reading token response",
			Err:     err,
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFly,
			Message: fmt.Sprintf("Machines API returned status %d", resp.StatusCode),
		}
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", &WorkloadIdentityRuntimeError{
			Source:  WorkloadIdentitySourceFly,
			Message: "Machines API returned an empty token",
		}
	}
	return token, nil
}
