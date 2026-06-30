package mcp

import "github.com/keycardai/credentials-go/oauth"

// ResourceAccessError is re-exported from the oauth package (where it now lives alongside
// AccessContext) for backward compatibility.
type ResourceAccessError = oauth.ResourceAccessError

// AuthProviderConfigurationError indicates invalid AuthProvider configuration.
type AuthProviderConfigurationError struct {
	Message string
}

func (e *AuthProviderConfigurationError) Error() string {
	return e.Message
}

// EKSWorkloadIdentityConfigurationError indicates invalid EKS workload identity configuration
// detected at construction (e.g. no token file path, or the file is missing or empty). Err
// carries the underlying cause (e.g. os.ErrNotExist or os.ErrPermission from reading the
// token file) for errors.Is/errors.As, and is nil when there is no underlying error.
type EKSWorkloadIdentityConfigurationError struct {
	Message string
	Err     error
}

func (e *EKSWorkloadIdentityConfigurationError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *EKSWorkloadIdentityConfigurationError) Unwrap() error { return e.Err }

// EKSWorkloadIdentityRuntimeError indicates the EKS token could not be read at request
// time (e.g. the token file was rotated away or emptied after construction). It is
// distinct from EKSWorkloadIdentityConfigurationError, which is a construction-time fault.
// Err carries the underlying read cause (e.g. os.ErrNotExist or os.ErrPermission) for
// errors.Is/errors.As, and is nil when there is no underlying error (e.g. an empty token).
type EKSWorkloadIdentityRuntimeError struct {
	Message string
	Err     error
}

func (e *EKSWorkloadIdentityRuntimeError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *EKSWorkloadIdentityRuntimeError) Unwrap() error { return e.Err }

// ClientSecretConfigurationError indicates a ClientSecretCredential was constructed with
// invalid configuration, such as an empty client_id or client_secret, or an empty
// multi-zone map.
type ClientSecretConfigurationError struct {
	Message string
}

func (e *ClientSecretConfigurationError) Error() string {
	return e.Message
}
