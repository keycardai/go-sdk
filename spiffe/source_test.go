package spiffe

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keycardai/go-sdk/oauth"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	audience = "https://example.keycard.cloud"
	spiffeID = "spiffe://example.org/service"
)

// Spec rows 11 and 15: construction does not connect; an unreachable agent
// yields a retryable runtime error with the connection timeout as its cause.
func TestLazyConnectionAndTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	source := newSource(t, WithSocketPath(path), WithInitTimeout(50*time.Millisecond))
	if source.conn != nil {
		t.Fatal("construction opens a connection")
	}
	_, err := source.IdentityToken(fetchContext(t))
	requireRuntimeError(t, err, true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want an init timeout", err)
	}
}

func TestFetchRetriesWhenAgentStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	source := newSource(t, WithSocketPath(path), WithInitTimeout(250*time.Millisecond))
	_, err := source.IdentityToken(fetchContext(t))
	requireRuntimeError(t, err, true)

	serveWorkloadAPIAt(t, path, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		return svidResponse("header.payload.signature"), nil
	})
	requireToken(t, source, "header.payload.signature")
}

// Spec row 12: a missing audience fails construction.
func TestMissingAudience(t *testing.T) {
	for _, value := range []string{"", " \t"} {
		_, err := NewSpiffeJwtSvidSource(value)
		requireConfigurationError(t, err)
	}
}

// Spec row 13: resolve SPIFFE_ENDPOINT_SOCKET on first fetch when no path is set.
func TestSocketFallback(t *testing.T) {
	t.Setenv(workloadapi.SocketEnv, "")
	source := newSource(t)
	_, err := source.IdentityToken(fetchContext(t))
	requireConfigurationError(t, err)

	path := serveWorkloadAPI(t, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		return svidResponse("header.payload.signature"), nil
	})
	t.Setenv(workloadapi.SocketEnv, "unix:"+path)
	requireToken(t, source, "header.payload.signature")
}

// Spec row 14: the request carries the audience and optional SPIFFE ID, and
// the response is an opaque compact token. The first SVID is the default.
func TestFetchJWT(t *testing.T) {
	t.Setenv(workloadapi.SocketEnv, "not a socket")
	for _, tc := range []struct{ name, id string }{{"default identity", ""}, {"explicit identity", spiffeID}} {
		t.Run(tc.name, func(t *testing.T) {
			path := serveWorkloadAPI(t, func(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
				if !reflect.DeepEqual(req.GetAudience(), []string{audience}) || req.GetSpiffeId() != tc.id {
					t.Errorf("request = %v, want audience %q and SPIFFE ID %q", req, audience, tc.id)
				}
				md, _ := metadata.FromIncomingContext(ctx)
				if header := md.Get("workload.spiffe.io"); !reflect.DeepEqual(header, []string{"true"}) {
					t.Errorf("workload header = %q, want [true]", header)
				}
				if tc.id == "" {
					return svidResponse("header.payload.signature", "other.svid.token"), nil
				}
				return svidResponse("header.payload.signature"), nil
			})
			source := newSource(t, WithSocketPath(path), WithSpiffeID(tc.id))
			requireToken(t, source, "header.payload.signature")
		})
	}
}

// Spec row 15: failures to issue an SVID are retryable and preserve their cause.
func TestNoSVID(t *testing.T) {
	t.Run("empty set", func(t *testing.T) {
		path := serveWorkloadAPI(t, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
			return svidResponse(), nil
		})
		_, err := newSource(t, WithSocketPath(path)).IdentityToken(fetchContext(t))
		requireRuntimeError(t, err, true)
		if !errors.Is(err, errNoSVID) {
			t.Fatalf("error = %v, want no SVID cause", err)
		}
	})
	t.Run("agent error", func(t *testing.T) {
		cause := status.Error(codes.PermissionDenied, "no SVID for the requested identity")
		path := serveWorkloadAPI(t, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
			return nil, cause
		})
		_, err := newSource(t, WithSocketPath(path), WithSpiffeID(spiffeID)).IdentityToken(fetchContext(t))
		runtimeErr := requireRuntimeError(t, err, true)
		if got := status.Convert(errors.Unwrap(runtimeErr)); got.Code() != codes.PermissionDenied || got.Message() != status.Convert(cause).Message() {
			t.Fatalf("cause = %v, want %v", got, cause)
		}
	})
}

// Spec row 16: a rotated SVID is used on the next fetch.
func TestRotatedSVID(t *testing.T) {
	var requests atomic.Int32
	path := serveWorkloadAPI(t, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		if requests.Add(1) == 1 {
			return svidResponse("header.first.signature"), nil
		}
		return svidResponse("header.second.signature"), nil
	})
	source := newSource(t, WithSocketPath(path))
	requireToken(t, source, "header.first.signature")
	requireToken(t, source, "header.second.signature")
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

func TestClose(t *testing.T) {
	path := serveWorkloadAPI(t, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		return svidResponse("header.payload.signature"), nil
	})
	source := newSource(t, WithSocketPath(path))
	requireToken(t, source, "header.payload.signature")
	conn := source.conn
	for range 2 {
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := workload.NewSpiffeWorkloadAPIClient(conn).FetchJWTSVID(fetchContext(t), &workload.JWTSVIDRequest{}); status.Code(err) != codes.Canceled {
		t.Fatalf("RPC on closed connection = %v, want Canceled", err)
	}
	requireToken(t, source, "header.payload.signature")
}

func TestConfigurationErrors(t *testing.T) {
	for _, option := range []SpiffeJwtSvidSourceOption{WithSpiffeID("not a SPIFFE ID"), WithInitTimeout(0)} {
		_, err := NewSpiffeJwtSvidSource(audience, option)
		requireConfigurationError(t, err)
	}
	_, err := newSource(t, WithSocketPath("not a socket")).IdentityToken(fetchContext(t))
	requireConfigurationError(t, err)
}

func TestUnixSocketURIRejectsHost(t *testing.T) {
	source := newSource(t, WithSocketPath("unix://host/path"), WithInitTimeout(50*time.Millisecond))
	_, err := source.IdentityToken(fetchContext(t))
	requireConfigurationError(t, err)
}

func TestEmptyToken(t *testing.T) {
	path := serveWorkloadAPI(t, func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		return svidResponse(""), nil
	})
	_, err := newSource(t, WithSocketPath(path)).IdentityToken(fetchContext(t))
	requireRuntimeError(t, err, false)
}

type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	fetch func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error)
}

func (f fakeWorkloadAPI) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return f.fetch(ctx, req)
}

func serveWorkloadAPI(t *testing.T, fetch func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.sock")
	serveWorkloadAPIAt(t, path, fetch)
	return path
}

func serveWorkloadAPIAt(t *testing.T, path string, fetch func(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error)) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, fakeWorkloadAPI{fetch: fetch})
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(listener) }()
}

func svidResponse(tokens ...string) *workload.JWTSVIDResponse {
	resp := &workload.JWTSVIDResponse{}
	for _, token := range tokens {
		resp.Svids = append(resp.Svids, &workload.JWTSVID{Svid: token})
	}
	return resp
}

func newSource(t *testing.T, opts ...SpiffeJwtSvidSourceOption) *SpiffeJwtSvidSource {
	t.Helper()
	source, err := NewSpiffeJwtSvidSource(audience, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	return source
}

func fetchContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func requireToken(t *testing.T, source *SpiffeJwtSvidSource, want string) {
	t.Helper()
	got, err := source.IdentityToken(fetchContext(t))
	if err != nil || got != want {
		t.Fatalf("IdentityToken() = %q, %v; want %q", got, err, want)
	}
}

func requireConfigurationError(t *testing.T, err error) {
	t.Helper()
	var configErr *oauth.WorkloadIdentityConfigurationError
	if !errors.As(err, &configErr) || configErr.Source != "spiffe" {
		t.Fatalf("error = %v, want WorkloadIdentityConfigurationError from spiffe", err)
	}
}

func requireRuntimeError(t *testing.T, err error, retryable bool) *oauth.WorkloadIdentityRuntimeError {
	t.Helper()
	var runtimeErr *oauth.WorkloadIdentityRuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Source != "spiffe" || runtimeErr.Retryable() != retryable {
		t.Fatalf("error = %v, want WorkloadIdentityRuntimeError from spiffe (retryable: %v)", err, retryable)
	}
	return runtimeErr
}
