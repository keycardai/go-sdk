package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// Spec row 23: each exchange sends the source's current token as a JWT.
func TestTokenExchangeClient_FetchesActorPerExchange(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepToken)
	tokens := []string{"first-actor", "second-actor"}
	calls := 0
	actor := IdentityTokenFunc(func(context.Context) (string, error) {
		if calls >= len(tokens) {
			t.Fatal("actor source called more than once per exchange")
		}
		token := tokens[calls]
		calls++
		return token, nil
	})
	client := NewTokenExchangeClient(zone.URL, WithTokenExchangeActor(actor))
	req := TokenExchangeRequest{SubjectToken: "subject"}
	for i := range tokens {
		if _, err := client.ExchangeToken(context.Background(), req); err != nil {
			t.Fatalf("exchange %d: %v", i+1, err)
		}
		if calls != i+1 {
			t.Errorf("after exchange %d: actor source called %d times", i+1, calls)
		}
	}

	requests := zone.tokenCalls()
	if len(requests) != len(tokens) {
		t.Fatalf("token requests = %d, want %d", len(requests), len(tokens))
	}
	for i, want := range tokens {
		if got := requests[i].form.Get("actor_token"); got != want {
			t.Errorf("exchange %d: actor_token = %q, want %q", i+1, got, want)
		}
		if got := requests[i].form.Get("actor_token_type"); got != "urn:ietf:params:oauth:token-type:jwt" {
			t.Errorf("exchange %d: actor_token_type = %q, want JWT", i+1, got)
		}
	}
}

// Spec row 24: explicit actor values win without calling the source.
func TestTokenExchangeClient_ExplicitActorOverridesSource(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepToken)
	actor := IdentityTokenFunc(func(context.Context) (string, error) {
		t.Fatal("actor source called with an explicit actor token")
		return "", nil
	})
	client := NewTokenExchangeClient(zone.URL, WithTokenExchangeActor(actor))
	req := TokenExchangeRequest{
		SubjectToken:   "subject",
		ActorToken:     "explicit-actor",
		ActorTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}
	if _, err := client.ExchangeToken(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	requests := zone.tokenCalls()
	if len(requests) != 1 {
		t.Fatalf("token requests = %d, want 1", len(requests))
	}
	form := requests[0].form
	if form.Get("actor_token") != req.ActorToken || form.Get("actor_token_type") != req.ActorTokenType {
		t.Errorf("actor fields = %q, %q; want %q, %q", form.Get("actor_token"), form.Get("actor_token_type"), req.ActorToken, req.ActorTokenType)
	}
}

// Spec row 25: impersonation skips the source and sends no actor fields.
func TestTokenExchangeClient_ImpersonationSkipsActor(t *testing.T) {
	zone := newFakeZone(t)
	zone.script(stepToken)
	actor := IdentityTokenFunc(func(context.Context) (string, error) {
		t.Fatal("actor source called for impersonation")
		return "", nil
	})
	client := NewTokenExchangeClient(zone.URL, WithTokenExchangeActor(actor))
	if _, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "user",
		Resource:       "https://resource.example",
	}); err != nil {
		t.Fatal(err)
	}
	requests := zone.tokenCalls()
	if len(requests) != 1 {
		t.Fatalf("token requests = %d, want 1", len(requests))
	}
	if form := requests[0].form; form.Has("actor_token") || form.Has("actor_token_type") {
		t.Error("impersonation request contains actor fields")
	}
}

// Spec row 26: typed source errors pass through, and untyped errors keep their cause.
func TestTokenExchangeClient_ActorFailureSendsNoRequest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cause     error
		typed     bool
		retryable bool
	}{
		{name: "configuration", cause: &WorkloadIdentityConfigurationError{Source: "file", Message: "missing file"}, typed: true},
		{name: "runtime", cause: &WorkloadIdentityRuntimeError{Source: "file", Message: "empty file"}, typed: true},
		{name: "plain", cause: errors.New("source failed")},
		{name: "timeout", cause: context.DeadlineExceeded},
		{name: "rate limited", cause: &HTTPError{Status: http.StatusTooManyRequests}},
		{name: "server error", cause: &HTTPError{Status: http.StatusServiceUnavailable}},
		{name: "marked runtime", cause: &WorkloadIdentityRuntimeError{Source: "test-source", Transient: true}, typed: true, retryable: true},
		{name: "client error", cause: &HTTPError{Status: http.StatusBadRequest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zone := newFakeZone(t)
			actor := IdentityTokenFunc(func(context.Context) (string, error) { return "", tc.cause })
			client := NewTokenExchangeClient(zone.URL, WithTokenExchangeActor(actor))
			_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{SubjectToken: "subject"})
			if discovery, tokens := zone.discoveryRequests.Load(), len(zone.tokenCalls()); discovery != 0 || tokens != 0 {
				t.Errorf("requests on actor source failure: discovery=%d token=%d", discovery, tokens)
			}
			if tc.typed {
				if err != tc.cause {
					t.Errorf("error = %v, want original %v", err, tc.cause)
				}
				return
			}
			var runtimeErr *WorkloadIdentityRuntimeError
			if !errors.As(err, &runtimeErr) {
				t.Fatalf("error = %v, want WorkloadIdentityRuntimeError", err)
			}
			if runtimeErr.Source != "custom" || !errors.Is(err, tc.cause) {
				t.Errorf("error = %v, want custom source with cause %v", err, tc.cause)
			}
			if got := runtimeErr.Retryable(); got != tc.retryable {
				t.Errorf("Retryable() = %t, want %t", got, tc.retryable)
			}
		})
	}
}

func TestTokenExchangeClient_ActorSourceUsesRequestTimeout(t *testing.T) {
	zone := newFakeZone(t)
	actor := IdentityTokenFunc(func(ctx context.Context) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
			return "", errors.New("actor source context did not expire")
		}
	})
	client := NewTokenExchangeClient(zone.URL, WithTokenExchangeActor(actor), WithTokenExchangeRequestTimeout(10*time.Millisecond))
	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{SubjectToken: "subject"})
	var runtimeErr *WorkloadIdentityRuntimeError
	if !errors.As(err, &runtimeErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want WorkloadIdentityRuntimeError wrapping a deadline error", err)
	}
	if discovery, tokens := zone.discoveryRequests.Load(), len(zone.tokenCalls()); discovery != 0 || tokens != 0 {
		t.Errorf("requests on actor source timeout: discovery=%d token=%d", discovery, tokens)
	}
}

func TestTokenExchangeClient_NilActorSourceDisablesLookup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nilSource IdentityTokenSource
	}{
		{name: "nil interface"},
		{name: "nil function", nilSource: IdentityTokenFunc(nil)},
		{name: "nil pointer", nilSource: (*FileTokenSource)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zone := newFakeZone(t)
			zone.script(stepToken)
			actor := IdentityTokenFunc(func(context.Context) (string, error) {
				t.Fatal("actor source called after disabling it")
				return "", nil
			})
			client := NewTokenExchangeClient(zone.URL, WithTokenExchangeActor(actor), WithTokenExchangeActor(tc.nilSource))
			if _, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{SubjectToken: "subject"}); err != nil {
				t.Fatal(err)
			}
			requests := zone.tokenCalls()
			if len(requests) != 1 {
				t.Fatalf("token requests = %d, want 1", len(requests))
			}
			if form := requests[0].form; form.Has("actor_token") || form.Has("actor_token_type") {
				t.Error("request contains actor fields with a disabled source")
			}
		})
	}
}
