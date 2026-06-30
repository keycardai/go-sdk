package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ProtectedResourceMetadata represents OAuth Protected Resource Metadata.
type ProtectedResourceMetadata struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	ResourceName          string   `json:"resource_name,omitempty"`
	ResourceDocumentation string   `json:"resource_documentation,omitempty"`
}

// MetadataOption configures auth metadata handlers.
type MetadataOption func(*metadataConfig)

type metadataConfig struct {
	issuer                string
	scopesSupported       []string
	resourceName          string
	resourceDocumentation string
	httpClient            *http.Client
}

// WithIssuer sets the authorization server issuer URL.
func WithIssuer(issuer string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.issuer = issuer }
}

// WithScopesSupported sets the scopes supported by the protected resource.
func WithScopesSupported(scopes []string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.scopesSupported = scopes }
}

// WithResourceName sets the human-readable name of the protected resource.
func WithResourceName(name string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.resourceName = name }
}

// WithServiceDocumentationURL sets the URL for the service documentation.
func WithServiceDocumentationURL(docURL string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.resourceDocumentation = docURL }
}

// WithMetadataHTTPClient sets the HTTP client used to fetch upstream authorization server metadata.
func WithMetadataHTTPClient(c *http.Client) MetadataOption {
	return func(cfg *metadataConfig) { cfg.httpClient = c }
}

// AuthMetadataHandler returns an http.Handler that serves both
// /.well-known/oauth-protected-resource and /.well-known/oauth-authorization-server endpoints.
//
// An issuer (WithIssuer) is effectively required for a usable deployment: without it the
// protected-resource metadata advertises no authorization_servers and the
// authorization-server proxy route is not registered, leaving clients no way to discover
// the authorization server.
func AuthMetadataHandler(opts ...MetadataOption) http.Handler {
	cfg := metadataConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}

	mux := http.NewServeMux()

	// protectedResource serves the Protected Resource Metadata (RFC 9728). It is registered
	// for both the bare well-known path (origin resource) and the path-inserted form
	// (e.g. /.well-known/oauth-protected-resource/mcp), so a resource mounted at a sub-path
	// advertises and resolves to its full URL rather than the bare origin.
	protectedResource := func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)

		scheme := requestScheme(r)
		baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

		// The resource is the origin plus the path that follows the well-known prefix:
		// "" for the origin resource, "/mcp" for the path-inserted form. A trailing slash
		// (e.g. the bare path-inserted form ".../oauth-protected-resource/") normalizes to
		// the origin so the advertised resource matches an origin-bound audience exactly.
		resource := baseURL + strings.TrimRight(strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource"), "/")

		metadata := ProtectedResourceMetadata{
			Resource:              resource,
			ScopesSupported:       cfg.scopesSupported,
			ResourceName:          cfg.resourceName,
			ResourceDocumentation: cfg.resourceDocumentation,
		}
		if cfg.issuer != "" {
			metadata.AuthorizationServers = []string{cfg.issuer}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
	// Two routes: the exact bare path (origin resource) and the subtree for the
	// path-inserted form (.../oauth-protected-resource/mcp). The handler derives the
	// resource from r.URL.Path, so no path wildcard binding is needed.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", protectedResource)

	if cfg.issuer != "" {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
			setCORSHeaders(w)

			scheme := requestScheme(r)
			baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

			// Fetch upstream authorization server metadata
			issuerMetadataURL := cfg.issuer + "/.well-known/oauth-authorization-server"
			fetchReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, issuerMetadataURL, nil)
			if err != nil {
				http.Error(w, "failed to create metadata request", http.StatusInternalServerError)
				return
			}
			fetchReq.Header.Set("Accept", "application/json")

			resp, err := cfg.httpClient.Do(fetchReq)
			if err != nil {
				http.Error(w, "failed to fetch authorization server metadata", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				http.Error(w, fmt.Sprintf("authorization server returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
				return
			}

			var metadata map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
				http.Error(w, "failed to decode authorization server metadata", http.StatusBadGateway)
				return
			}

			// Rewrite authorization_endpoint to include resource parameter
			if authEndpoint, ok := metadata["authorization_endpoint"].(string); ok {
				authURL, err := url.Parse(authEndpoint)
				if err == nil {
					q := authURL.Query()
					q.Set("resource", baseURL)
					authURL.RawQuery = q.Encode()
					metadata["authorization_endpoint"] = authURL.String()
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		})
	}

	// Handle CORS preflight
	mux.HandleFunc("OPTIONS /.well-known/", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		return fwd
	}
	return "http"
}
