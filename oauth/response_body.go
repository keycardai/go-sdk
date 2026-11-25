package oauth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// MaxResponseBodyBytes is the maximum number of decoded bytes read from an
// authorization-server HTTP response (1 MiB).
const MaxResponseBodyBytes int64 = 1 << 20

// ErrResponseBodyTooLarge is wrapped in errors returned when a decoded
// authorization-server HTTP response body exceeds MaxResponseBodyBytes.
var ErrResponseBodyTooLarge = errors.New("response body exceeded 1 MiB decoded size limit")

// readBoundedBody reads at most MaxResponseBodyBytes decoded bytes from r.
// Reading stops once MaxResponseBodyBytes+1 bytes are read and returns
// ErrResponseBodyTooLarge without buffering or parsing a larger body.
func readBoundedBody(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxResponseBodyBytes {
		return nil, ErrResponseBodyTooLarge
	}
	return data, nil
}

func readMetadataBody(resp *http.Response) ([]byte, error) {
	if !isSuccessStatus(resp.StatusCode) {
		return nil, nil
	}
	data, err := readBoundedBody(resp.Body)
	if errors.Is(err, ErrResponseBodyTooLarge) {
		status := &HTTPError{Status: resp.StatusCode, Message: "reading metadata response"}
		return nil, fmt.Errorf("%w: %w", status, err)
	}
	return data, err
}

func isSuccessStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func oversizedOAuthError(status int) *OAuthError {
	return &OAuthError{
		ErrorCode: "invalid_response",
		Message:   fmt.Sprintf("response body exceeded %d-byte decoded size limit (HTTP %d)", MaxResponseBodyBytes, status),
		Status:    status,
		Err:       ErrResponseBodyTooLarge,
	}
}
