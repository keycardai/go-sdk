package oauth

import "fmt"

// AccessContextStatus represents the overall status of a set of token exchanges.
type AccessContextStatus string

const (
	StatusSuccess      AccessContextStatus = "success"
	StatusPartialError AccessContextStatus = "partial_error"
	StatusError        AccessContextStatus = "error"
)

// ErrorDetail describes an error during token exchange.
type ErrorDetail struct {
	Message     string `json:"message"`
	Code        string `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
	RawError    string `json:"raw_error,omitempty"`
}

// ResourceAccessError is returned when a resource's token is unavailable.
type ResourceAccessError struct {
	Message string
}

func (e *ResourceAccessError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "resource access error"
}

func (*ResourceAccessError) keycardError() {}

// AccessContext holds the results of token exchanges for multiple resources. It is a
// non-throwing result container: callers check status before accessing tokens.
type AccessContext struct {
	tokens         map[string]*TokenResponse
	resourceErrors map[string]ErrorDetail
	globalError    *ErrorDetail
}

// NewAccessContext creates a new empty AccessContext.
func NewAccessContext() *AccessContext {
	return &AccessContext{
		tokens:         make(map[string]*TokenResponse),
		resourceErrors: make(map[string]ErrorDetail),
	}
}

// SetToken sets a successful token for a resource (clears any error for that resource).
func (ac *AccessContext) SetToken(resource string, token *TokenResponse) {
	ac.tokens[resource] = token
	delete(ac.resourceErrors, resource)
}

// SetBulkTokens sets multiple tokens at once.
func (ac *AccessContext) SetBulkTokens(tokens map[string]*TokenResponse) {
	for resource, token := range tokens {
		ac.tokens[resource] = token
	}
}

// SetResourceError sets an error for a specific resource (clears any token for that resource).
func (ac *AccessContext) SetResourceError(resource string, detail ErrorDetail) {
	ac.resourceErrors[resource] = detail
	delete(ac.tokens, resource)
}

// SetError sets a global error.
func (ac *AccessContext) SetError(detail ErrorDetail) {
	ac.globalError = &detail
}

// Merge folds another AccessContext into this one, for stacked grants. Tokens and
// resource errors from other are applied entry by entry (preserving the token-or-error
// invariant per resource); other's global error is adopted only if this one has none.
func (ac *AccessContext) Merge(other *AccessContext) {
	if other == nil {
		return
	}
	for resource, token := range other.tokens {
		ac.SetToken(resource, token)
	}
	for resource, detail := range other.resourceErrors {
		ac.SetResourceError(resource, detail)
	}
	if ac.globalError == nil && other.globalError != nil {
		ac.globalError = other.globalError
	}
}

// Access returns the token for the given resource, or a *ResourceAccessError if the
// resource has an error or no token.
func (ac *AccessContext) Access(resource string) (*TokenResponse, error) {
	if ac.globalError != nil {
		return nil, &ResourceAccessError{Message: ac.globalError.Message}
	}
	if _, hasErr := ac.resourceErrors[resource]; hasErr {
		return nil, &ResourceAccessError{Message: ac.resourceErrors[resource].Message}
	}
	token, ok := ac.tokens[resource]
	if !ok {
		return nil, &ResourceAccessError{Message: fmt.Sprintf("no token for resource %q", resource)}
	}
	return token, nil
}

// Status returns the overall status of the context.
func (ac *AccessContext) Status() AccessContextStatus {
	if ac.globalError != nil {
		return StatusError
	}
	if len(ac.resourceErrors) > 0 {
		return StatusPartialError
	}
	return StatusSuccess
}

// HasErrors returns true if any errors occurred (global or per-resource).
func (ac *AccessContext) HasErrors() bool {
	return ac.globalError != nil || len(ac.resourceErrors) > 0
}

// HasError returns true if a global error is set.
func (ac *AccessContext) HasError() bool {
	return ac.globalError != nil
}

// HasResourceError returns true if the specific resource had an error.
func (ac *AccessContext) HasResourceError(resource string) bool {
	_, ok := ac.resourceErrors[resource]
	return ok
}

// GetError returns the global error, or nil.
func (ac *AccessContext) GetError() *ErrorDetail {
	return ac.globalError
}

// GetResourceError returns the error for a specific resource, or nil.
func (ac *AccessContext) GetResourceError(resource string) *ErrorDetail {
	if detail, ok := ac.resourceErrors[resource]; ok {
		return &detail
	}
	return nil
}

// GetErrors returns all errors (global + per-resource).
func (ac *AccessContext) GetErrors() (resources map[string]ErrorDetail, globalError *ErrorDetail) {
	result := make(map[string]ErrorDetail, len(ac.resourceErrors))
	for k, v := range ac.resourceErrors {
		result[k] = v
	}
	return result, ac.globalError
}

// SuccessfulResources returns the list of resources with successful token exchanges.
func (ac *AccessContext) SuccessfulResources() []string {
	resources := make([]string, 0, len(ac.tokens))
	for r := range ac.tokens {
		resources = append(resources, r)
	}
	return resources
}

// FailedResources returns the list of resources with failed token exchanges.
func (ac *AccessContext) FailedResources() []string {
	resources := make([]string, 0, len(ac.resourceErrors))
	for r := range ac.resourceErrors {
		resources = append(resources, r)
	}
	return resources
}
