package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// advance moves the fake clock forward by d without a wait.
func (c *fakeDeviceClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Discovered metadata without a device endpoint is a deterministic failure. The client
// keeps it for the negative TTL of 1 minute, then discovers again.
func TestDeviceDiscovery_MissingEndpointCachedForNegativeTTL(t *testing.T) {
	zone := newFakeZone(t)
	zone.omitDeviceEndpoint.Store(true)
	clock := newFakeDeviceClock()
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(clock))
	request := func() error {
		_, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})
		return err
	}

	steps := []struct {
		name          string
		advance       time.Duration
		advertise     bool
		wantConfig    bool
		wantDiscovery int32
	}{
		{name: "first call", wantConfig: true, wantDiscovery: 1},
		{name: "within the negative TTL", advance: 59 * time.Second, advertise: true, wantConfig: true, wantDiscovery: 1},
		{name: "after the negative TTL", advance: 2 * time.Second, advertise: true, wantDiscovery: 2},
	}
	for _, step := range steps {
		clock.advance(step.advance)
		zone.omitDeviceEndpoint.Store(!step.advertise)

		err := request()

		var cfgErr *ConfigurationError
		if got := errors.As(err, &cfgErr); got != step.wantConfig {
			t.Errorf("%s: error %v, want ConfigurationError: %t", step.name, err, step.wantConfig)
		}
		if !step.wantConfig && err != nil {
			t.Errorf("%s: %v, want success", step.name, err)
		}
		if got := zone.discoveryRequests.Load(); got != step.wantDiscovery {
			t.Errorf("%s: discovery requests: got %d, want %d", step.name, got, step.wantDiscovery)
		}
	}
}

// Spec row 37 (device authorization): a 503 Retry-After gates only later discovery.
func TestDeviceDiscovery_RetryAfter(t *testing.T) {
	zone := newFakeZone(t)
	zone.discoveryStatus.Store(http.StatusServiceUnavailable)
	zone.discoveryRetryAfter = "5"
	clock := newFakeDeviceClock()
	client := mustDeviceClient(t, zone.URL,
		WithDeviceHTTPClient(zone.httpClient()),
		WithDevicePublicClient("public-1"),
		WithDeviceClock(clock))

	for call := 1; call <= 2; call++ {
		_, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{})

		var discErr *DeviceAuthorizationDiscoveryError
		if !errors.As(err, &discErr) {
			t.Fatalf("call %d: error %v (%T), want *DeviceAuthorizationDiscoveryError", call, err, err)
		}
		wantHTTPError(t, err, http.StatusServiceUnavailable)
		if got := zone.discoveryRequests.Load(); got != 1 {
			t.Errorf("call %d: discovery requests: got %d, want 1", call, got)
		}
	}
	if n := len(zone.deviceCalls()); n != 0 {
		t.Errorf("device authorization requests: got %d, want 0", n)
	}
	clock.advance(5 * time.Second)
	zone.discoveryStatus.Store(0)
	if _, err := client.RequestDeviceAuthorization(context.Background(), DeviceAuthorizationRequest{}); err != nil {
		t.Fatalf("at expiry: %v", err)
	}
	if got := zone.discoveryRequests.Load(); got != 2 {
		t.Errorf("discovery requests: got %d, want 2", got)
	}
}
