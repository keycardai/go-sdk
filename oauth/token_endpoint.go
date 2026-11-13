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

// withDefaultTimeout bounds ctx by d when the caller set no deadline of its own, so a
// request to the zone cannot wait forever while a caller's longer deadline still wins.
func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok || d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// sharedFetch runs fn once for concurrent callers with the same key. fn runs under its
// own timeout, detached from any one caller's cancellation, so a caller that gives up
// does not cancel the fetch for the others.
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

// discoveryCache holds one discovered value for an issuer. A success is kept for
// discoveryTTL. A deterministic failure is kept for at most negativeTTL, never longer
// than discoveryTTL. Transient failures are never kept. Concurrent callers on a cold
// cache share one fetch.
type discoveryCache[T any] struct {
	discoveryTTL time.Duration
	negativeTTL  time.Duration
	fetchTimeout time.Duration
	now          func() time.Time

	mu        sync.Mutex
	value     T
	err       error
	expiresAt time.Time
	group     singleflight.Group
}

func newDiscoveryCache[T any](discoveryTTL, negativeTTL, fetchTimeout time.Duration) discoveryCache[T] {
	return discoveryCache[T]{
		discoveryTTL: discoveryTTL,
		negativeTTL:  negativeTTL,
		fetchTimeout: fetchTimeout,
		now:          time.Now,
	}
}

func (c *discoveryCache[T]) get(ctx context.Context, fetch func(context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	if c.now().Before(c.expiresAt) {
		v, err := c.value, c.err
		c.mu.Unlock()
		return v, err
	}
	c.mu.Unlock()

	var zero T
	v, err := sharedFetch(ctx, &c.group, "", c.fetchTimeout, func(fetchCtx context.Context) (any, error) {
		v, err := fetch(fetchCtx)
		c.store(v, err)
		return v, err
	})
	if err != nil {
		return zero, err
	}
	return v.(T), nil
}

func (c *discoveryCache[T]) store(value T, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero T
	switch {
	case err == nil:
		c.value, c.err = value, nil
		c.expiresAt = c.now().Add(c.discoveryTTL)
	case c.negativeTTL > 0 && isDeterministicDiscoveryFailure(err):
		c.value, c.err = zero, err
		c.expiresAt = c.now().Add(min(c.negativeTTL, c.discoveryTTL))
	}
}

type tokenEndpointResolver struct {
	issuer     string
	httpClient *http.Client
	discoveryCache[string]
}

func newTokenEndpointResolver(issuer string, httpClient *http.Client, discoveryTTL, negativeTTL, fetchTimeout time.Duration) tokenEndpointResolver {
	return tokenEndpointResolver{
		issuer:         issuer,
		httpClient:     httpClient,
		discoveryCache: newDiscoveryCache[string](discoveryTTL, negativeTTL, fetchTimeout),
	}
}

func (r *tokenEndpointResolver) Endpoint(ctx context.Context) (string, error) {
	ep, err := r.get(ctx, func(fetchCtx context.Context) (string, error) {
		return resolveTokenEndpoint(fetchCtx, r.issuer, r.httpClient)
	})
	if err != nil {
		var disc *TokenEndpointDiscoveryError
		if !errors.As(err, &disc) {
			return "", &TokenEndpointDiscoveryError{Message: fmt.Sprintf("discovering token endpoint for %q", r.issuer), Err: err}
		}
		return "", err
	}
	return ep, nil
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
	var cfgErr *ConfigurationError
	if errors.As(err, &cfgErr) {
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
