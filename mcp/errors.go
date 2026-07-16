package mcp

import "github.com/keycardai/go-sdk/oauth"

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

// WebIdentityConfigurationError indicates a WebIdentity client assertion could not
// be prepared because a required value was missing at request time.
//
// Deprecated: use [oauth.WebIdentityConfigurationError].
type WebIdentityConfigurationError = oauth.WebIdentityConfigurationError

// WorkloadIdentityConfigurationError indicates a workload identity credential or
// token source was misconfigured at construction.
//
// Deprecated: use [oauth.WorkloadIdentityConfigurationError].
type WorkloadIdentityConfigurationError = oauth.WorkloadIdentityConfigurationError

// WorkloadIdentityRuntimeError indicates the subject token could not be obtained
// at request time.
//
// Deprecated: use [oauth.WorkloadIdentityRuntimeError].
type WorkloadIdentityRuntimeError = oauth.WorkloadIdentityRuntimeError

// EKSWorkloadIdentityConfigurationError indicates invalid workload identity
// configuration at construction.
//
// Deprecated: use [oauth.WorkloadIdentityConfigurationError].
type EKSWorkloadIdentityConfigurationError = oauth.WorkloadIdentityConfigurationError

// EKSWorkloadIdentityRuntimeError indicates the token could not be read at
// request time.
//
// Deprecated: use [oauth.WorkloadIdentityRuntimeError].
type EKSWorkloadIdentityRuntimeError = oauth.WorkloadIdentityRuntimeError

// ClientSecretConfigurationError indicates a ClientSecretCredential was
// constructed with invalid configuration.
//
// Deprecated: use [oauth.ClientSecretConfigurationError].
type ClientSecretConfigurationError = oauth.ClientSecretConfigurationError
