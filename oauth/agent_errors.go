package oauth

import "errors"

// The Connect error codes the local Keycard agent answers IssueToken with, in
// the snake_case spelling Connect puts on the wire. The Is* predicates are the
// usual way to read them; the codes are exported so a caller can branch on one
// that has no predicate.
const (
	AgentCodePermissionDenied   = "permission_denied"
	AgentCodeResourceExhausted  = "resource_exhausted"
	AgentCodeFailedPrecondition = "failed_precondition"
	AgentCodeUnauthenticated    = "unauthenticated"
	AgentCodeNotFound           = "not_found"
	AgentCodeUnavailable        = "unavailable"
	AgentCodeInvalidArgument    = "invalid_argument"
)

// AgentError is a refusal from the local Keycard agent: a non-200 response
// carrying a Connect error. Code is the Connect error code, one of the
// AgentCode* constants or a code this package does not know yet. Message is the
// agent's explanation, which names the remedy where there is one.
type AgentError struct {
	Code    string
	Message string
}

func (e *AgentError) Error() string {
	return "keycard agent: " + e.Code + ": " + e.Message
}

// Retryable reports whether repeating the request unchanged could succeed: true
// for resource_exhausted and unavailable, false for every other code.
func (e *AgentError) Retryable() bool {
	return e.Code == AgentCodeResourceExhausted || e.Code == AgentCodeUnavailable
}

// AgentResponseError indicates the agent answered 200 with a body that cannot be
// used: not JSON, a token that is absent, empty, not a string, or contains a
// control character, or an expiresAt that does not parse. It is distinct from
// AgentError, which is the agent refusing. Message never includes the token. Err
// carries the underlying decode or parse cause, when there is one, for
// errors.Is/errors.As.
type AgentResponseError struct {
	Message string
	Err     error
}

func (e *AgentResponseError) Error() string {
	if e.Err != nil {
		return "keycard agent: " + e.Message + ": " + e.Err.Error()
	}
	return "keycard agent: " + e.Message
}

func (e *AgentResponseError) Unwrap() error { return e.Err }

// Retryable reports false: the agent answered, and asking again gets the same
// answer.
func (*AgentResponseError) Retryable() bool { return false }

func (*AgentError) keycardError()         {}
func (*AgentResponseError) keycardError() {}

// IsDeclined reports whether err is, or wraps, an AgentError with code
// permission_denied: the human declined, the prompt expired or failed, the
// authorization server rejected the exchange, or the agent holds no session for
// the requested org and zone. Do not retry automatically: the agent remembers
// approvals but not declines, so a retry puts the same prompt in front of the
// human again.
func IsDeclined(err error) bool { return agentCode(err) == AgentCodePermissionDenied }

// IsRateLimited reports whether err is, or wraps, an AgentError with code
// resource_exhausted: the agent is bounding how often it interrupts the human,
// or too many prompts are already waiting. Back off.
func IsRateLimited(err error) bool { return agentCode(err) == AgentCodeResourceExhausted }

// IsPrompterUnavailable reports whether err is, or wraps, an AgentError with
// code failed_precondition: the host has no way to ask a human. Retrying will
// not help; a caller with another credential falls back to it.
func IsPrompterUnavailable(err error) bool { return agentCode(err) == AgentCodeFailedPrecondition }

// IsAuthorizationRequired reports whether err is, or wraps, an AgentError with
// code unauthenticated: the developer must sign in, authorize the resource
// interactively, or repair an unusable zone session or device key first.
// [AgentError.Message] names the command.
func IsAuthorizationRequired(err error) bool { return agentCode(err) == AgentCodeUnauthenticated }

// IsApplicationNotFound reports whether err is, or wraps, an AgentError with
// code not_found: the id passed to [WithAgentAppID] names no application in the
// zone.
func IsApplicationNotFound(err error) bool { return agentCode(err) == AgentCodeNotFound }

// IsUnavailable reports whether err is, or wraps, an AgentError with code
// unavailable: a service behind the agent could not be reached. Transient.
func IsUnavailable(err error) bool { return agentCode(err) == AgentCodeUnavailable }

func agentCode(err error) string {
	var e *AgentError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
