package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cardServer is a fake agent that serves its card at the well-known path and counts
// how many times the card was fetched.
func cardServer(t *testing.T, card map[string]any, status int) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentCardPath {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&hits, 1)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// Spec test 1: discover a healthy agent; the card is returned and a second lookup is
// served from cache.
func TestServiceDiscovery_GetCard_CachesHealthyCard(t *testing.T) {
	srv, hits := cardServer(t, map[string]any{"name": "Target Agent"}, http.StatusOK)

	d := NewServiceDiscovery()
	card, err := d.GetCard(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("GetCard: %v", err)
	}
	if card.Name != "Target Agent" {
		t.Errorf("name: got %q, want Target Agent", card.Name)
	}

	if _, err := d.GetCard(context.Background(), srv.URL); err != nil {
		t.Fatalf("second GetCard: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("card fetches: got %d, want 1 (second lookup should be cached)", got)
	}
}

// Spec test 2: discover a card missing name; a discovery error surfaces.
func TestServiceDiscovery_GetCard_MissingName(t *testing.T) {
	srv, _ := cardServer(t, map[string]any{"url": "https://agent.example.com/a2a/jsonrpc"}, http.StatusOK)

	d := NewServiceDiscovery()
	_, err := d.GetCard(context.Background(), srv.URL)

	var discErr *DiscoveryError
	if !errors.As(err, &discErr) {
		t.Fatalf("error: got %v, want DiscoveryError", err)
	}
}

func TestServiceDiscovery_GetCard_HTTPError(t *testing.T) {
	srv, _ := cardServer(t, nil, http.StatusInternalServerError)

	d := NewServiceDiscovery()
	_, err := d.GetCard(context.Background(), srv.URL)

	var discErr *DiscoveryError
	if !errors.As(err, &discErr) {
		t.Fatalf("error: got %v, want DiscoveryError", err)
	}
}

func TestServiceDiscovery_Refresh_BypassesCache(t *testing.T) {
	srv, hits := cardServer(t, map[string]any{"name": "Target Agent"}, http.StatusOK)

	d := NewServiceDiscovery()
	if _, err := d.GetCard(context.Background(), srv.URL); err != nil {
		t.Fatalf("GetCard: %v", err)
	}
	if _, err := d.Refresh(context.Background(), srv.URL); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("card fetches: got %d, want 2 (Refresh should bypass cache)", got)
	}
}

// Review #3: concurrent first-time lookups for the same target share one fetch.
func TestServiceDiscovery_GetCard_SingleFlight(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentCardPath {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&hits, 1)
		time.Sleep(100 * time.Millisecond) // hold the flight open so concurrent callers join it
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "Target Agent"})
	}))
	defer server.Close()

	d := NewServiceDiscovery()
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.GetCard(context.Background(), server.URL); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("GetCard: %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("card fetches: got %d, want 1 (concurrent misses should share one fetch)", got)
	}
}

func TestServiceDiscovery_GetCard_RefetchesAfterTTL(t *testing.T) {
	srv, hits := cardServer(t, map[string]any{"name": "Target Agent"}, http.StatusOK)

	d := NewServiceDiscovery(WithCacheTTL(5 * time.Millisecond))
	if _, err := d.GetCard(context.Background(), srv.URL); err != nil {
		t.Fatalf("GetCard: %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := d.GetCard(context.Background(), srv.URL); err != nil {
		t.Fatalf("second GetCard: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("card fetches: got %d, want 2 (cache should expire after TTL)", got)
	}
}
