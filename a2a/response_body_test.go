package a2a

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
)

const mib = 1 << 20

var peerPadding = strings.Repeat(" ", mib)

func peerReply(t *testing.T, status, padding int, encoded bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Writer = w
		if encoded {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			body = gz
		}
		w.WriteHeader(status)
		if r.URL.Path == agentCardPath {
			_, _ = io.WriteString(body, `{"name":"Peer"}`)
		} else {
			_, _ = io.WriteString(body, `{"jsonrpc":"2.0","result":{"message":{"messageId":"reply","role":"ROLE_AGENT","parts":[{"text":"ok"}]}}}`)
		}
		for remaining := padding; remaining > 0; {
			n := min(remaining, len(peerPadding))
			if _, err := io.WriteString(body, peerPadding[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func readPeerReply(t *testing.T, target string, invoke bool, limit int64) error {
	t.Helper()
	if !invoke {
		var opts []DiscoveryOption
		if limit != 0 {
			opts = append(opts, WithDiscoveryMaxPeerResponseBytes(limit))
		}
		_, err := NewServiceDiscovery(opts...).GetCard(context.Background(), target)
		return err
	}
	var opts []DelegationOption
	if limit != 0 {
		opts = append(opts, WithMaxPeerResponseBytes(limit))
	}
	client, err := NewDelegationClient("https://zone.example.test", "id", "secret", opts...)
	if err != nil {
		t.Fatal(err)
	}
	targetOrigin, _ := endpointOrigin(target, false)
	_, _, err = client.invoke(context.Background(), target, targetOrigin, target, "token", NewTextMessage("ping"))
	return err
}

func assertPeerOverflow(t *testing.T, err error, limit int64, status int, retryable bool) {
	t.Helper()
	var sizeErr *ResponseBodyTooLargeError
	if !errors.As(err, &sizeErr) || !errors.Is(err, oauth.ErrResponseBodyTooLarge) {
		t.Fatalf("expected typed response overflow, got %v", err)
	}
	if sizeErr.ErrorCode != "invalid_response" || sizeErr.Status != status ||
		sizeErr.Limit != limit || sizeErr.Retryable() != retryable {
		t.Fatalf("wrong overflow classification: %+v, limit %d, retryable %v",
			sizeErr, sizeErr.Limit, sizeErr.Retryable())
	}
}

// Spec row 9: the default accepts peers larger than 1 MiB.
func TestPeerResponseDefaultAcceptsMoreThanOneMiB(t *testing.T) {
	server := peerReply(t, http.StatusOK, mib, false)
	for _, invoke := range []bool{false, true} {
		if err := readPeerReply(t, server.URL, invoke, 0); err != nil {
			t.Fatal(err)
		}
	}
}

// Spec row 10: gzip is bounded by decoded bytes.
func TestPeerResponseDecodedGzipLimit(t *testing.T) {
	server := peerReply(t, http.StatusOK, 1024, true)
	for _, invoke := range []bool{false, true} {
		assertPeerOverflow(t, readPeerReply(t, server.URL, invoke, 512), 512, http.StatusOK, !invoke)
	}
}

// Spec row 10a: an oversized reply keeps status-specific retryability.
func TestPeerResponseOverflowClassification(t *testing.T) {
	for _, status := range []int{200, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := peerReply(t, status, 512, false)
			for _, invoke := range []bool{false, true} {
				assertPeerOverflow(t, readPeerReply(t, server.URL, invoke, 256), 256, status, !invoke || status != 200)
			}
		})
	}
}

// Spec row 11: the peer option can lower or raise the cap.
func TestPeerResponseConfigurableLimit(t *testing.T) {
	small := peerReply(t, http.StatusOK, 256, false)
	large := peerReply(t, http.StatusOK, 64*mib, false)
	for _, invoke := range []bool{false, true} {
		if err := readPeerReply(t, small.URL, invoke, 0); err != nil {
			t.Fatal(err)
		}
		assertPeerOverflow(t, readPeerReply(t, small.URL, invoke, 128), 128, http.StatusOK, !invoke)
		assertPeerOverflow(t, readPeerReply(t, large.URL, invoke, 0), defaultPeerResponseBytes, http.StatusOK, !invoke)
		if err := readPeerReply(t, large.URL, invoke, 65*mib); err != nil {
			t.Fatal(err)
		}
	}
}

// Spec row 11: the peer option does not change the token exchange cap.
func TestPeerResponseLimitDoesNotAffectTokenExchange(t *testing.T) {
	var zone *httptest.Server
	zone = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, zone.URL, zone.URL+"/token")
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"token","token_type":"bearer"}`)
		_, _ = io.WriteString(w, peerPadding)
	}))
	t.Cleanup(zone.Close)
	peer := peerReply(t, http.StatusOK, 0, false)
	for _, limit := range []int64{128, 65 * mib} {
		client, err := NewDelegationClient(zone.URL, "id", "secret", WithMaxPeerResponseBytes(limit))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Invoke(context.Background(), peer.URL, "caller", NewTextMessage("ping"))
		var oauthErr *oauth.OAuthError
		if !errors.As(err, &oauthErr) || !errors.Is(err, oauth.ErrResponseBodyTooLarge) ||
			!strings.Contains(err.Error(), "1048576-byte decoded size limit") {
			t.Fatalf("expected 1 MiB token exchange overflow, got %v", err)
		}
	}
}
