package oauth

import (
	"context"
	"errors"
)

// WebIdentityConfigurationError indicates a WebIdentity client assertion could not be
// prepared because a required value was missing at request time: the client id (iss/sub)
// or the token endpoint (aud).
type WebIdentityConfigurationError struct {
	Message string
}

func (e *WebIdentityConfigurationError) Error() string {
	return e.Message
}

// WorkloadIdentityConfigurationError indicates a workload identity credential
// or token source was misconfigured at construction: a nil source, a missing,
// unreadable, or empty token file, no discovery environment variable set, or
// a missing required audience. Source identifies the token source ("file",
// "gcp-metadata", "fly"; empty when the fault is in the credential itself). Err
// carries the underlying cause (e.g. os.ErrNotExist or os.ErrPermission from
// reading a token file) for errors.Is/errors.As, and is nil when there is no
// underlying error.
type WorkloadIdentityConfigurationError struct {
	Source  string
	Message string
	Err     error
}

func (e *WorkloadIdentityConfigurationError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *WorkloadIdentityConfigurationError) Unwrap() error { return e.Err }

// WorkloadIdentityRuntimeError indicates that the identity token source fails
// at request time (e.g. the token file is empty or the platform endpoint is
// unreachable). Source identifies the token source ("file",
// "gcp-metadata", "fly", or "custom" for a source whose error is not one of
// this package's typed errors). Err carries the
// underlying cause for errors.Is/errors.As, and is nil when there is no
// underlying error (e.g. an empty token).
type WorkloadIdentityRuntimeError struct {
	Source  string
	Message string
	Err     error
}

func (e *WorkloadIdentityRuntimeError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *WorkloadIdentityRuntimeError) Unwrap() error { return e.Err }

// Retryable reports whether the source fails with a transient transport error.
func (e *WorkloadIdentityRuntimeError) Retryable() bool {
	var status *HTTPError
	if errors.As(e.Err, &status) {
		return retryableHTTPStatus(status.Status)
	}
	return e.Err != nil && !errors.Is(e.Err, context.Canceled) && retryableMetadataFailure(e.Err)
}

// ClientSecretConfigurationError means a ClientSecretCredential is misconfigured.
// Returned by constructors when client_id, client_secret or zone map are empty.
// Returned by ClientAuthentication when the issuer has no entry in the multi-zone map.
type ClientSecretConfigurationError struct {
	Message string
}

func (e *ClientSecretConfigurationError) Error() string {
	return e.Message
}

// CredentialDiscoveryReason identifies why DiscoverCredential cannot select a credential.
type CredentialDiscoveryReason string

const (
	// CredentialDiscoveryAbsent means no supported credential is configured.
	CredentialDiscoveryAbsent CredentialDiscoveryReason = "absent"
	// CredentialDiscoveryAmbiguous means multiple types are configured without a selector.
	CredentialDiscoveryAmbiguous CredentialDiscoveryReason = "ambiguous"
	// CredentialDiscoveryIncomplete means a client secret is set without a client ID or selector.
	CredentialDiscoveryIncomplete CredentialDiscoveryReason = "incomplete"
	// CredentialDiscoveryUnknownType means the selector names an unsupported type.
	CredentialDiscoveryUnknownType CredentialDiscoveryReason = "unknown_type"
	// CredentialDiscoveryNotSatisfiable means the selected type lacks required inputs.
	CredentialDiscoveryNotSatisfiable CredentialDiscoveryReason = "not_satisfiable"
)

// CredentialDiscoveryError indicates that the environment does not select one
// usable application credential. Resolvable lists the canonical type names
// with complete environment inputs, before constructor validation. Err holds
// an underlying cause, if any, for errors.Is and errors.As.
type CredentialDiscoveryError struct {
	Reason     CredentialDiscoveryReason
	Resolvable []string
	Message    string
	Err        error
}

// Error returns the discovery message and any underlying cause.
func (e *CredentialDiscoveryError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

// Unwrap returns the underlying cause, if any.
func (e *CredentialDiscoveryError) Unwrap() error { return e.Err }

func (*WebIdentityConfigurationError) keycardError()      {}
func (*WorkloadIdentityConfigurationError) keycardError() {}
func (*WorkloadIdentityRuntimeError) keycardError()       {}
func (*ClientSecretConfigurationError) keycardError()     {}
func (*CredentialDiscoveryError) keycardError()           {}
