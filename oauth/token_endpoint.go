package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	defaultDiscoveryTTL = time.Hour
	defaultNegativeTTL  = time.Minute
	defaultFetchTimeout = 10 * time.Second
)

// Detached from the caller's cancellation so one caller cannot poison the shared fetch.
func sharedFetch(ctx context.Context, g *singleflight.Group, key string, timeout time.Duration, fn func(context.Context) (any, error)) (any, error) {
	ch := g.DoChan(key, func() (any, error) {
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		return fn(fetchCtx)
	})
	select {
	case r := <-ch:
		return r.Val, r.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type tokenEndpointResolver struct {
	issuer       string
	httpClient   *http.Client
	discoveryTTL time.Duration
	negativeTTL  time.Duration
	fetchTimeout time.Duration
	now          func() time.Time

	mu        sync.Mutex
	endpoint  string
	err       error
	expiresAt time.Time
	group     singleflight.Group
}

func newTokenEndpointResolver(issuer string, httpClient *http.Client, discoveryTTL, negativeTTL, fetchTimeout time.Duration) tokenEndpointResolver {
	return tokenEndpointResolver{
		issuer:       issuer,
		httpClient:   httpClient,
		discoveryTTL: discoveryTTL,
		negativeTTL:  negativeTTL,
		fetchTimeout: fetchTimeout,
		now:          time.Now,
	}
}

func (r *tokenEndpointResolver) Endpoint(ctx context.Context) (string, error) {
	r.mu.Lock()
	if r.now().Before(r.expiresAt) {
		ep, err := r.endpoint, r.err
		r.mu.Unlock()
		return ep, err
	}
	r.mu.Unlock()

	v, err := sharedFetch(ctx, &r.group, "", r.fetchTimeout, func(fetchCtx context.Context) (any, error) {
		ep, err := resolveTokenEndpoint(fetchCtx, r.issuer, r.httpClient)
		r.store(ep, err)
		return ep, err
	})
	if err != nil {
		var disc *TokenEndpointDiscoveryError
		if !errors.As(err, &disc) {
			return "", &TokenEndpointDiscoveryError{Message: fmt.Sprintf("discovering token endpoint for %q", r.issuer), Err: err}
		}
		return "", err
	}
	return v.(string), nil
}

func (r *tokenEndpointResolver) store(endpoint string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case err == nil:
		r.endpoint, r.err = endpoint, nil
		r.expiresAt = r.now().Add(r.discoveryTTL)
	case r.negativeTTL > 0 && isDeterministicDiscoveryFailure(err):
		r.endpoint, r.err = "", err
		r.expiresAt = r.now().Add(min(r.negativeTTL, r.discoveryTTL))
	}
}

// Transport errors, timeouts, 5xx and 429 are transient and never cached.
func isDeterministicDiscoveryFailure(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Status >= 400 && httpErr.Status < 500 && httpErr.Status != http.StatusTooManyRequests
	}
	var mismatch *IssuerMismatchError
	if errors.As(err, &mismatch) {
		return true
	}
	var malformed *InvalidMetadataError
	if errors.As(err, &malformed) {
		return true
	}
	var disc *TokenEndpointDiscoveryError
	return errors.As(err, &disc) && disc.Err == nil
}

func resolveTokenEndpoint(ctx context.Context, issuer string, httpClient *http.Client) (string, error) {
	metadata, err := FetchAuthorizationServerMetadata(ctx, issuer, WithDiscoveryHTTPClient(httpClient))
	if err != nil {
		return "", &TokenEndpointDiscoveryError{Message: "discovering token endpoint", Err: err}
	}
	if metadata.TokenEndpoint == "" {
		return "", &TokenEndpointDiscoveryError{Message: fmt.Sprintf("authorization server %q does not advertise a token_endpoint", issuer)}
	}
	return metadata.TokenEndpoint, nil
}
