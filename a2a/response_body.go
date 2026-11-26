package a2a

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/keycardai/go-sdk/oauth"
)

const defaultPeerResponseBytes int64 = 64 << 20

// ResponseBodyTooLargeError reports an oversized decoded reply from a peer.
// It carries the invalid_response code and wraps oauth.ErrResponseBodyTooLarge.
type ResponseBodyTooLargeError struct {
	*oauth.OAuthError
	Limit      int64
	invocation bool
}

func (e *ResponseBodyTooLargeError) Error() string {
	return e.Message
}

// Retryable reports whether the status permits retrying the failed operation.
func (e *ResponseBodyTooLargeError) Retryable() bool {
	if e.invocation && e.Status >= 200 && e.Status < 300 {
		return false
	}
	return e.OAuthError.Retryable()
}

func readPeerBody(resp *http.Response, limit int64, invocation bool) (io.Reader, error) {
	bounded := &io.LimitedReader{R: resp.Body, N: limit}
	body, err := io.ReadAll(bounded)
	if err != nil {
		return nil, err
	}
	if bounded.N == 0 {
		var extra [1]byte
		if _, err := io.ReadFull(resp.Body, extra[:]); err == nil {
			return nil, &ResponseBodyTooLargeError{
				OAuthError: &oauth.OAuthError{
					ErrorCode: "invalid_response",
					Message:   fmt.Sprintf("peer response exceeded the %d-byte decoded size limit (HTTP %d)", limit, resp.StatusCode),
					Status:    resp.StatusCode,
					Err:       oauth.ErrResponseBodyTooLarge,
				},
				Limit:      limit,
				invocation: invocation,
			}
		} else if err != io.EOF {
			return nil, err
		}
	}
	return bytes.NewReader(body), nil
}
