package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// newFormRequest returns a POST of form to endpoint with header, asking for a JSON
// response.
func newFormRequest(ctx context.Context, endpoint string, header http.Header, form url.Values) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

// errorFromResponse returns an *OAuthError for an RFC 6749 section 5.2 error body, and
// an *HTTPError otherwise.
func errorFromResponse(resp *http.Response, what string) error {
	if oauthErr := parseOAuthErrorResponse(resp); oauthErr != nil {
		return oauthErr
	}
	return &HTTPError{Message: what + " returned an error", Status: resp.StatusCode}
}

// issuerOrMetadata returns issuer, or the metadata's issuer when issuer is empty. It
// returns a ConfigurationError when there is no issuer, or when issuer and the
// metadata's issuer differ by more than a trailing slash.
func issuerOrMetadata(issuer string, md *AuthorizationServerMetadata) (string, error) {
	switch {
	case md == nil && issuer == "":
		return "", &ConfigurationError{Message: "an issuer or metadata is required"}
	case md == nil:
		return issuer, nil
	case md.Issuer == "":
		return "", &ConfigurationError{Message: "metadata has no issuer"}
	case issuer == "":
		return md.Issuer, nil
	case strings.TrimRight(issuer, "/") != strings.TrimRight(md.Issuer, "/"):
		return "", &ConfigurationError{Message: fmt.Sprintf("issuer %q does not match the metadata issuer %q", issuer, md.Issuer)}
	}
	return issuer, nil
}
