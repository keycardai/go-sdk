// Package spiffe provides a SPIFFE Workload API token source for the Keycard OAuth SDK.
package spiffe

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/keycardai/go-sdk/oauth"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// WorkloadIdentitySourceSpiffe identifies errors from the SPIFFE token source.
const WorkloadIdentitySourceSpiffe = "spiffe"

const defaultInitTimeout = 10 * time.Second

var errNoSVID = errors.New("the agent returned no JWT-SVID for the requested identity")

// SpiffeJwtSvidSource fetches JWT-SVIDs from a local SPIFFE Workload API.
// It opens the connection on first use and is safe for concurrent fetches.
type SpiffeJwtSvidSource struct {
	config spiffeJwtSvidConfig

	mu   sync.Mutex
	conn *grpc.ClientConn
}

var _ oauth.IdentityTokenSource = (*SpiffeJwtSvidSource)(nil)

type spiffeJwtSvidConfig struct {
	audience    string
	spiffeID    string
	socketPath  string
	initTimeout time.Duration
}

// SpiffeJwtSvidSourceOption configures a SpiffeJwtSvidSource.
type SpiffeJwtSvidSourceOption func(*spiffeJwtSvidConfig)

// WithSpiffeID selects an identity when the workload has multiple SPIFFE IDs.
// If unset, the source uses the first JWT-SVID returned by the agent.
func WithSpiffeID(id string) SpiffeJwtSvidSourceOption {
	return func(cfg *spiffeJwtSvidConfig) { cfg.spiffeID = id }
}

// WithSocketPath sets an absolute Unix socket path or a unix: Workload API URI.
// If unset, the source uses SPIFFE_ENDPOINT_SOCKET when it opens the connection.
func WithSocketPath(path string) SpiffeJwtSvidSourceOption {
	return func(cfg *spiffeJwtSvidConfig) { cfg.socketPath = path }
}

// WithInitTimeout bounds the wait for a Workload API connection. The timeout
// must be positive and defaults to 10 seconds.
func WithInitTimeout(timeout time.Duration) SpiffeJwtSvidSourceOption {
	return func(cfg *spiffeJwtSvidConfig) { cfg.initTimeout = timeout }
}

// NewSpiffeJwtSvidSource creates a source for the required audience without
// opening the Workload API connection.
func NewSpiffeJwtSvidSource(audience string, opts ...SpiffeJwtSvidSourceOption) (*SpiffeJwtSvidSource, error) {
	if strings.TrimSpace(audience) == "" {
		return nil, configurationError("audience must not be empty", nil)
	}
	cfg := spiffeJwtSvidConfig{audience: audience, initTimeout: defaultInitTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.spiffeID != "" {
		if _, err := spiffeid.FromString(cfg.spiffeID); err != nil {
			return nil, configurationError("invalid SPIFFE ID", err)
		}
	}
	if cfg.initTimeout <= 0 {
		return nil, configurationError("init timeout must be positive", nil)
	}
	return &SpiffeJwtSvidSource{config: cfg}, nil
}

// IdentityToken fetches a new JWT-SVID and returns its compact JWT unchanged.
func (s *SpiffeJwtSvidSource) IdentityToken(ctx context.Context) (string, error) {
	conn, err := s.connection()
	if err != nil {
		return "", err
	}
	initCtx, cancel := context.WithTimeout(ctx, s.config.initTimeout)
	err = waitForConnection(initCtx, conn)
	cancel()
	if err != nil {
		return "", runtimeError("connecting to the SPIFFE Workload API", err, true)
	}

	// Use the official RPC directly to keep the assertion opaque.
	client := workload.NewSpiffeWorkloadAPIClient(conn)
	ctx = metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")
	resp, err := client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{
		Audience: []string{s.config.audience},
		SpiffeId: s.config.spiffeID,
	})
	if err != nil {
		return "", runtimeError("fetching JWT-SVID from the SPIFFE Workload API", err, true)
	}
	svids := resp.GetSvids()
	if len(svids) == 0 {
		return "", runtimeError("fetching JWT-SVID from the SPIFFE Workload API", errNoSVID, true)
	}
	if token := svids[0].GetSvid(); token != "" {
		return token, nil
	}
	return "", runtimeError("the SPIFFE Workload API returned an empty JWT-SVID", nil, false)
}

func (s *SpiffeJwtSvidSource) connection() (*grpc.ClientConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn, nil
	}
	addr := s.config.socketPath
	if addr == "" {
		addr, _ = workloadapi.GetDefaultAddress()
	}
	if strings.TrimSpace(addr) == "" {
		return nil, configurationError("no SPIFFE Workload API socket path or SPIFFE_ENDPOINT_SOCKET is set", nil)
	}
	if strings.HasPrefix(addr, "/") {
		addr = (&url.URL{Scheme: "unix", Path: addr}).String()
	}
	target, err := workloadapi.TargetFromAddress(addr)
	if err != nil {
		return nil, configurationError("invalid SPIFFE Workload API socket address", err)
	}
	if !strings.HasPrefix(target, "unix:") {
		return nil, configurationError("the SPIFFE Workload API address must use a Unix socket", nil)
	}
	socket, err := url.Parse(target)
	if err != nil {
		return nil, configurationError("invalid SPIFFE Workload API socket address", err)
	}
	if socket.Host != "" {
		return nil, configurationError("the SPIFFE Workload API Unix socket address must not include a host", nil)
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, configurationError("invalid SPIFFE Workload API socket address", err)
	}
	s.conn = conn
	return conn, nil
}

func waitForConnection(ctx context.Context, conn *grpc.ClientConn) error {
	resetBackoff := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return errors.New("the SPIFFE Workload API connection is closed")
		case connectivity.Idle:
			conn.Connect()
		case connectivity.TransientFailure:
			if !resetBackoff {
				conn.ResetConnectBackoff()
				resetBackoff = true
			}
		}
		if !conn.WaitForStateChange(ctx, state) {
			return ctx.Err()
		}
	}
}

// Close releases the Workload API connection. A later fetch opens a new one.
func (s *SpiffeJwtSvidSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

func configurationError(message string, err error) error {
	return &oauth.WorkloadIdentityConfigurationError{Source: WorkloadIdentitySourceSpiffe, Message: message, Err: err}
}

func runtimeError(message string, err error, transient bool) error {
	return &oauth.WorkloadIdentityRuntimeError{Source: WorkloadIdentitySourceSpiffe, Message: message, Err: err, Transient: transient}
}
