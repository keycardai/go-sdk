package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	agentCardPath           = "/.well-known/agent-card.json"
	defaultCacheTTL         = 15 * time.Minute
	defaultDiscoveryTimeout = 10 * time.Second
)

// ServiceDiscovery resolves an agent's base URL to its agent card and caches the
// result. Cards are cached for a configurable TTL (default 15 minutes) and can be
// refreshed on demand. A ServiceDiscovery is safe for concurrent use.
type ServiceDiscovery struct {
	httpClient *http.Client
	ttl        time.Duration

	mu    sync.Mutex
	cache map[string]cardEntry
	group singleflight.Group
}

type cardEntry struct {
	card      AgentCard
	expiresAt time.Time
}

// DiscoveryOption configures a ServiceDiscovery.
type DiscoveryOption func(*ServiceDiscovery)

// WithDiscoveryHTTPClient sets the HTTP client used to fetch agent cards.
func WithDiscoveryHTTPClient(c *http.Client) DiscoveryOption {
	return func(d *ServiceDiscovery) { d.httpClient = c }
}

// WithCacheTTL sets how long a fetched agent card is served from cache.
func WithCacheTTL(ttl time.Duration) DiscoveryOption {
	return func(d *ServiceDiscovery) { d.ttl = ttl }
}

// NewServiceDiscovery creates a ServiceDiscovery with a default HTTP client and cache TTL.
func NewServiceDiscovery(opts ...DiscoveryOption) *ServiceDiscovery {
	d := &ServiceDiscovery{
		ttl:   defaultCacheTTL,
		cache: make(map[string]cardEntry),
	}
	for _, opt := range opts {
		opt(d)
	}
	if d.httpClient == nil {
		d.httpClient = &http.Client{Timeout: defaultDiscoveryTimeout}
	}
	return d
}

// GetCard returns the target agent's card, serving a cached copy while it is fresh and
// fetching otherwise. Concurrent misses for the same target share a single fetch. It
// validates that the card carries a name.
func (d *ServiceDiscovery) GetCard(ctx context.Context, baseURL string) (AgentCard, error) {
	key := strings.TrimRight(baseURL, "/")

	if card, ok := d.cachedFresh(key); ok {
		return card, nil
	}

	v, err, _ := d.group.Do(key, func() (any, error) {
		// Another flight may have populated the cache while this one waited.
		if card, ok := d.cachedFresh(key); ok {
			return card, nil
		}
		return d.fetchAndCache(ctx, baseURL)
	})
	if err != nil {
		return AgentCard{}, err
	}
	return v.(AgentCard), nil
}

// Refresh fetches the target agent's card, bypassing the cache, validates it, and
// stores it in the cache.
func (d *ServiceDiscovery) Refresh(ctx context.Context, baseURL string) (AgentCard, error) {
	return d.fetchAndCache(ctx, baseURL)
}

// cachedFresh returns a cached card for key if present and not yet expired.
func (d *ServiceDiscovery) cachedFresh(key string) (AgentCard, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry, ok := d.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		return entry.card, true
	}
	return AgentCard{}, false
}

func (d *ServiceDiscovery) fetchAndCache(ctx context.Context, baseURL string) (AgentCard, error) {
	key := strings.TrimRight(baseURL, "/")
	cardURL := key + agentCardPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return AgentCard{}, &DiscoveryError{Message: "building agent card request", Err: err}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return AgentCard{}, &DiscoveryError{Message: fmt.Sprintf("fetching %s", cardURL), Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AgentCard{}, &DiscoveryError{Message: fmt.Sprintf("agent card %s returned HTTP %d", cardURL, resp.StatusCode)}
	}

	var card AgentCard
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return AgentCard{}, &DiscoveryError{Message: fmt.Sprintf("decoding agent card %s", cardURL), Err: err}
	}
	if strings.TrimSpace(card.Name) == "" {
		return AgentCard{}, &DiscoveryError{Message: fmt.Sprintf("agent card %s is missing the required name field", cardURL)}
	}

	d.mu.Lock()
	d.cache[key] = cardEntry{card: card, expiresAt: time.Now().Add(d.ttl)}
	d.mu.Unlock()

	return card, nil
}

// ClearCache discards all cached agent cards.
func (d *ServiceDiscovery) ClearCache() {
	d.mu.Lock()
	d.cache = make(map[string]cardEntry)
	d.mu.Unlock()
}
