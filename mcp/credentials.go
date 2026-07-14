// Application credentials live in the oauth package; this file re-exports them
// for backward compatibility. Everything here is a deprecated alias.
package mcp

import (
	"time"

	"github.com/keycardai/go-sdk/oauth"
)

// ClientAuth holds client_id and client_secret for HTTP basic auth.
//
// Deprecated: use [oauth.ClientAuth].
type ClientAuth = oauth.ClientAuth

// PrepareOptions provides optional context for token exchange request preparation.
//
// Deprecated: use [oauth.PrepareOptions].
type PrepareOptions = oauth.PrepareOptions

// ApplicationCredential authenticates the application to the authorization
// server during token exchange.
//
// Deprecated: use [oauth.ApplicationCredential].
type ApplicationCredential = oauth.ApplicationCredential

// MultiZoneCredential is implemented by credentials that carry per-zone client
// credentials keyed by zone issuer URL.
//
// Deprecated: use [oauth.MultiZoneCredential].
type MultiZoneCredential = oauth.MultiZoneCredential

// ClientSecretCredential implements ApplicationCredential using client_id/client_secret
// basic auth.
//
// Deprecated: use [oauth.ClientSecretCredential].
type ClientSecretCredential = oauth.ClientSecretCredential

// NewClientSecret creates a single-zone ClientSecretCredential.
//
// Deprecated: use [oauth.NewClientSecret].
func NewClientSecret(clientID, clientSecret string) (*ClientSecretCredential, error) {
	return oauth.NewClientSecret(clientID, clientSecret)
}

// NewMultiZoneClientSecret creates a multi-zone ClientSecretCredential from a map of
// zone issuer URL to that zone's client credentials.
//
// Deprecated: use [oauth.NewMultiZoneClientSecret].
func NewMultiZoneClientSecret(zones map[string]ClientAuth) (*ClientSecretCredential, error) {
	return oauth.NewMultiZoneClientSecret(zones)
}

// WebIdentityCredential implements ApplicationCredential using RFC 7523 private_key_jwt.
//
// Deprecated: use [oauth.WebIdentityCredential].
type WebIdentityCredential = oauth.WebIdentityCredential

// WebIdentityOption configures a WebIdentityCredential.
//
// Deprecated: use [oauth.WebIdentityOption].
type WebIdentityOption = oauth.WebIdentityOption

// WithServerName sets the server name (used to derive key ID if not set).
//
// Deprecated: use [oauth.WithServerName].
func WithServerName(name string) WebIdentityOption {
	return oauth.WithServerName(name)
}

// WithStorage sets the private key storage implementation.
//
// Deprecated: use [oauth.WithStorage].
func WithStorage(s PrivateKeyStorage) WebIdentityOption {
	return oauth.WithStorage(s)
}

// WithStorageDir sets the directory for file-based private key storage.
//
// Deprecated: use [oauth.WithStorageDir].
func WithStorageDir(dir string) WebIdentityOption {
	return oauth.WithStorageDir(dir)
}

// WithKeyID sets the key ID explicitly.
//
// Deprecated: use [oauth.WithKeyID].
func WithKeyID(kid string) WebIdentityOption {
	return oauth.WithKeyID(kid)
}

// WithClientID sets the registered OAuth client id used as the assertion's iss and sub
// claims.
//
// Deprecated: use [oauth.WithClientID].
func WithClientID(clientID string) WebIdentityOption {
	return oauth.WithClientID(clientID)
}

// WithAudienceConfig overrides the assertion audience.
//
// Deprecated: use [oauth.WithAudienceConfig].
func WithAudienceConfig(audience string) WebIdentityOption {
	return oauth.WithAudienceConfig(audience)
}

// NewWebIdentity creates a WebIdentityCredential.
//
// Deprecated: use [oauth.NewWebIdentity].
func NewWebIdentity(opts ...WebIdentityOption) *WebIdentityCredential {
	return oauth.NewWebIdentity(opts...)
}

// PrivateKeyStorage persists WebIdentity keypairs.
//
// Deprecated: use [oauth.PrivateKeyStorage].
type PrivateKeyStorage = oauth.PrivateKeyStorage

// FilePrivateKeyStorage stores WebIdentity keypairs on the local filesystem.
//
// Deprecated: use [oauth.FilePrivateKeyStorage].
type FilePrivateKeyStorage = oauth.FilePrivateKeyStorage

// NewFilePrivateKeyStorage creates file-based private key storage rooted at dir.
//
// Deprecated: use [oauth.NewFilePrivateKeyStorage].
func NewFilePrivateKeyStorage(dir string) *FilePrivateKeyStorage {
	return oauth.NewFilePrivateKeyStorage(dir)
}

// PrivateKeyManager manages a WebIdentity keypair and signs client assertions.
//
// Deprecated: use [oauth.PrivateKeyManager].
type PrivateKeyManager = oauth.PrivateKeyManager

// NewPrivateKeyManager creates a PrivateKeyManager backed by storage.
//
// Deprecated: use [oauth.NewPrivateKeyManager].
func NewPrivateKeyManager(storage PrivateKeyStorage, keyID string) *PrivateKeyManager {
	return oauth.NewPrivateKeyManager(storage, keyID)
}

// IdentityTokenSource supplies a platform-signed OIDC token for use as a client
// assertion during token exchange.
//
// Deprecated: use [oauth.IdentityTokenSource].
type IdentityTokenSource = oauth.IdentityTokenSource

// IdentityTokenFunc adapts a function to a IdentityTokenSource.
//
// Deprecated: use [oauth.IdentityTokenFunc].
type IdentityTokenFunc = oauth.IdentityTokenFunc

// WorkloadIdentityCredential implements ApplicationCredential using a
// platform-signed OIDC token obtained from a IdentityTokenSource.
//
// Deprecated: use [oauth.WorkloadIdentityCredential].
type WorkloadIdentityCredential = oauth.WorkloadIdentityCredential

// WorkloadIdentityOption configures a WorkloadIdentityCredential.
//
// Deprecated: use [oauth.WorkloadIdentityOption].
type WorkloadIdentityOption = oauth.WorkloadIdentityOption

// WithWorkloadClientID sets the ID of the Keycard application credential this
// workload authenticates as.
//
// Deprecated: use [oauth.WithWorkloadClientID].
func WithWorkloadClientID(clientID string) WorkloadIdentityOption {
	return oauth.WithWorkloadClientID(clientID)
}

// NewWorkloadIdentity creates a WorkloadIdentityCredential backed by source.
//
// Deprecated: use [oauth.NewWorkloadIdentity].
func NewWorkloadIdentity(source IdentityTokenSource, opts ...WorkloadIdentityOption) (*WorkloadIdentityCredential, error) {
	return oauth.NewWorkloadIdentity(source, opts...)
}

// Source identifiers carried in the Source field of
// WorkloadIdentityConfigurationError and WorkloadIdentityRuntimeError.
//
// Deprecated: use the oauth package's constants.
const (
	WorkloadIdentitySourceFile        = oauth.WorkloadIdentitySourceFile
	WorkloadIdentitySourceGCPMetadata = oauth.WorkloadIdentitySourceGCPMetadata
	WorkloadIdentitySourceFly         = oauth.WorkloadIdentitySourceFly
	WorkloadIdentitySourceCustom      = oauth.WorkloadIdentitySourceCustom
)

// FileTokenSource reads a platform-projected OIDC token from a mounted file.
//
// Deprecated: use [oauth.FileTokenSource].
type FileTokenSource = oauth.FileTokenSource

// FileTokenSourceOption configures a FileTokenSource.
//
// Deprecated: use [oauth.FileTokenSourceOption].
type FileTokenSourceOption = oauth.FileTokenSourceOption

// WithFileTokenPath sets the token file path directly, skipping env-var discovery.
//
// Deprecated: use [oauth.WithFileTokenPath].
func WithFileTokenPath(path string) FileTokenSourceOption {
	return oauth.WithFileTokenPath(path)
}

// WithFileEnvVar adds an environment variable to consult first during discovery.
//
// Deprecated: use [oauth.WithFileEnvVar].
func WithFileEnvVar(name string) FileTokenSourceOption {
	return oauth.WithFileEnvVar(name)
}

// NewFileTokenSource creates a FileTokenSource.
//
// Deprecated: use [oauth.NewFileTokenSource].
func NewFileTokenSource(opts ...FileTokenSourceOption) (*FileTokenSource, error) {
	return oauth.NewFileTokenSource(opts...)
}

// GCPMetadataTokenSource fetches an OIDC identity token from the GCP metadata server.
//
// Deprecated: use [oauth.GCPMetadataTokenSource].
type GCPMetadataTokenSource = oauth.GCPMetadataTokenSource

// GCPMetadataOption configures a GCPMetadataTokenSource.
//
// Deprecated: use [oauth.GCPMetadataOption].
type GCPMetadataOption = oauth.GCPMetadataOption

// WithGCPMetadataURL overrides the metadata server base URL (for testing).
//
// Deprecated: use [oauth.WithGCPMetadataURL].
func WithGCPMetadataURL(u string) GCPMetadataOption {
	return oauth.WithGCPMetadataURL(u)
}

// WithGCPTimeout overrides the per-call deadline for metadata requests.
//
// Deprecated: use [oauth.WithGCPTimeout].
func WithGCPTimeout(d time.Duration) GCPMetadataOption {
	return oauth.WithGCPTimeout(d)
}

// NewGCPMetadataTokenSource creates a GCPMetadataTokenSource for the given audience.
//
// Deprecated: use [oauth.NewGCPMetadataTokenSource].
func NewGCPMetadataTokenSource(audience string, opts ...GCPMetadataOption) (*GCPMetadataTokenSource, error) {
	return oauth.NewGCPMetadataTokenSource(audience, opts...)
}

// FlyTokenSource fetches an OIDC token from the Fly.io Machines API.
//
// Deprecated: use [oauth.FlyTokenSource].
type FlyTokenSource = oauth.FlyTokenSource

// FlyTokenSourceOption configures a FlyTokenSource.
//
// Deprecated: use [oauth.FlyTokenSourceOption].
type FlyTokenSourceOption = oauth.FlyTokenSourceOption

// WithFlyAudience sets the audience claim for the requested token.
//
// Deprecated: use [oauth.WithFlyAudience].
func WithFlyAudience(audience string) FlyTokenSourceOption {
	return oauth.WithFlyAudience(audience)
}

// WithFlySocketPath overrides the Machines API socket path.
//
// Deprecated: use [oauth.WithFlySocketPath].
func WithFlySocketPath(path string) FlyTokenSourceOption {
	return oauth.WithFlySocketPath(path)
}

// NewFlyTokenSource creates a FlyTokenSource.
//
// Deprecated: use [oauth.NewFlyTokenSource].
func NewFlyTokenSource(opts ...FlyTokenSourceOption) *FlyTokenSource {
	return oauth.NewFlyTokenSource(opts...)
}

// EKSWorkloadIdentityCredential authenticates with an AWS EKS pod-identity
// (projected service-account) token read from a mounted file.
//
// Deprecated: use [oauth.NewWorkloadIdentity] with [oauth.NewFileTokenSource].
type EKSWorkloadIdentityCredential = oauth.WorkloadIdentityCredential

// EKSWorkloadIdentityOption configures NewEKSWorkloadIdentity.
//
// Deprecated: use [oauth.FileTokenSourceOption] with [oauth.NewFileTokenSource].
type EKSWorkloadIdentityOption = oauth.EKSWorkloadIdentityOption

// WithTokenFilePath sets the path to the EKS token file directly.
//
// Deprecated: use [oauth.WithFileTokenPath] with [oauth.NewFileTokenSource].
func WithTokenFilePath(path string) EKSWorkloadIdentityOption {
	return oauth.WithTokenFilePath(path)
}

// WithEnvVarName adds a custom environment variable name to check for the token file path.
//
// Deprecated: use [oauth.WithFileEnvVar] with [oauth.NewFileTokenSource].
func WithEnvVarName(name string) EKSWorkloadIdentityOption {
	return oauth.WithEnvVarName(name)
}

// NewEKSWorkloadIdentity creates a workload identity credential that reads the
// EKS projected token file.
//
// Deprecated: use [oauth.NewWorkloadIdentity] with [oauth.NewFileTokenSource].
func NewEKSWorkloadIdentity(opts ...EKSWorkloadIdentityOption) (*EKSWorkloadIdentityCredential, error) {
	return oauth.NewEKSWorkloadIdentity(opts...)
}
