package mcp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/keycardai/go-sdk/oauth"
)

func TestToolScopes(t *testing.T) {
	granted := &AuthInfo{Token: "tok", ClientID: "client-1", Scopes: []string{"files:read", "files:write"}}

	tests := []struct {
		name          string
		info          *AuthInfo // nil leaves the context unauthenticated
		required      []string
		wantMissing   []string
		wantErrSubstr string // empty means the call must succeed
	}{
		{
			name:        "all scopes satisfied",
			info:        granted,
			required:    []string{"files:read", "files:write"},
			wantMissing: []string{},
		},
		{
			name:          "one of several scopes missing",
			info:          granted,
			required:      []string{"files:read", "admin:billing", "files:write"},
			wantMissing:   []string{"admin:billing"},
			wantErrSubstr: "admin:billing",
		},
		{
			name:          "unauthenticated context",
			info:          nil,
			required:      []string{"repo:clone", "repo:push"},
			wantMissing:   []string{"repo:clone", "repo:push"},
			wantErrSubstr: "unauthenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.info != nil {
				ctx = ContextWithAuthInfo(ctx, tt.info)
			}

			if got := MissingToolScopes(ctx, tt.required...); !reflect.DeepEqual(got, tt.wantMissing) {
				t.Errorf("MissingToolScopes: got %v, want %v", got, tt.wantMissing)
			}

			info, err := RequireToolScopes(ctx, tt.required...)
			if tt.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("RequireToolScopes: unexpected error %v", err)
				}
				if info != tt.info {
					t.Errorf("RequireToolScopes should return the context's AuthInfo, got %p want %p", info, tt.info)
				}
				return
			}
			if info != nil {
				t.Errorf("RequireToolScopes should return nil AuthInfo on failure, got %+v", info)
			}
			var ise *oauth.InsufficientScopeError
			if !errors.As(err, &ise) {
				t.Fatalf("expected *oauth.InsufficientScopeError, got %T: %v", err, err)
			}
			if !strings.Contains(ise.Message, tt.wantErrSubstr) {
				t.Errorf("error %q should mention %q", ise.Message, tt.wantErrSubstr)
			}
			if tt.info != nil && strings.Contains(ise.Message, "files:read") {
				t.Errorf("error %q should name only the missing scopes", ise.Message)
			}
		})
	}
}
