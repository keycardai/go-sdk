package a2a

import "fmt"

// ConfigurationError indicates a delegation client or invocation was given invalid
// configuration, such as an empty issuer, credential, or subject token.
type ConfigurationError struct {
	Message string
}

func (e *ConfigurationError) Error() string {
	return "a2a: " + e.Message
}

// Retryable reports whether the same configuration may succeed on retry.
func (e *ConfigurationError) Retryable() bool { return false }

// DiscoveryError indicates a target agent's card could not be resolved: the card
// could not be fetched, was not valid JSON, or was missing the required name field.
type DiscoveryError struct {
	Message string
	Err     error
}

func (e *DiscoveryError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("a2a discovery: %s: %v", e.Message, e.Err)
	}
	return "a2a discovery: " + e.Message
}

func (e *DiscoveryError) Unwrap() error {
	return e.Err
}

// InvocationError indicates a JSON-RPC invocation of a target agent failed: the
// transport returned an HTTP error, the response could not be decoded, or the agent
// returned a JSON-RPC error response. Code carries the JSON-RPC error code when the
// failure came from a JSON-RPC error response.
type InvocationError struct {
	Message string
	Code    int
	Err     error
}

func (e *InvocationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("a2a invocation: %s: %v", e.Message, e.Err)
	}
	return "a2a invocation: " + e.Message
}

func (e *InvocationError) Unwrap() error {
	return e.Err
}
