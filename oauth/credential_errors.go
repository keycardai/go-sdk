package oauth

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

// WorkloadIdentityRuntimeError indicates the subject token could not be
// obtained at request time (e.g. the token file was rotated away or emptied
// after construction, or the platform endpoint was unreachable). It is
// distinct from WorkloadIdentityConfigurationError, which is a
// construction-time fault. Source identifies the token source ("file",
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

// ClientSecretConfigurationError indicates a ClientSecretCredential was constructed with
// invalid configuration, such as an empty client_id or client_secret, or an empty
// multi-zone map.
type ClientSecretConfigurationError struct {
	Message string
}

func (e *ClientSecretConfigurationError) Error() string {
	return e.Message
}

func (*WebIdentityConfigurationError) keycardError()      {}
func (*WorkloadIdentityConfigurationError) keycardError() {}
func (*WorkloadIdentityRuntimeError) keycardError()       {}
func (*ClientSecretConfigurationError) keycardError()     {}
