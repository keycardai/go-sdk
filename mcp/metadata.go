package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ProtectedResourceMetadata represents OAuth Protected Resource Metadata.
type ProtectedResourceMetadata struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers,omitempty"`
	JWKSURI               string   `json:"jwks_uri,omitempty"`
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
	publicJWKS            map[string]any
}

// WithIssuer sets the authorization server issuer URL for AuthMetadataHandler.
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

// WithPublicJWKS serves the given JWKS document (e.g. from WebIdentityCredential.PublicJWKS())
// at /.well-known/jwks.json, so an authorization server can fetch this resource's public keys
// to verify its private_key_jwt client assertions. When unset, the route is not registered.
func WithPublicJWKS(jwks map[string]any) MetadataOption {
	return func(cfg *metadataConfig) { cfg.publicJWKS = jwks }
}

// AuthMetadataHandler returns an http.Handler that serves both
// /.well-known/oauth-protected-resource and /.well-known/oauth-authorization-server endpoints.
//
// An issuer (WithIssuer) is effectively required for a usable deployment: without it the
// protected-resource metadata advertises no authorization_servers and the
// authorization-server proxy route is not registered, leaving clients no way to discover
// the authorization server.
func AuthMetadataHandler(opts ...MetadataOption) http.Handler {
	warnLegacyResourceBinding()
	return authMetadataHandler(nil, opts)
}

// MetadataHandler serves the binding's discovery and auxiliary metadata.
// Register it at the host-root /.well-known/ paths, or forward those public
// paths to it. The handler cannot inspect the application's router. The
// binding's issuer takes precedence; WithIssuer applies only when the binding
// has none.
func (b *ResourceBinding) MetadataHandler(opts ...MetadataOption) http.Handler {
	return authMetadataHandler(b, opts)
}

func authMetadataHandler(binding *ResourceBinding, opts []MetadataOption) http.Handler {
	cfg := metadataConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if binding != nil && binding.issuer != "" {
		cfg.issuer = binding.issuer
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}

	mux := http.NewServeMux()

	protectedResource := func(w http.ResponseWriter, resource, baseURL string, issuers []string) {
		setCORSHeaders(w)

		metadata := ProtectedResourceMetadata{
			Resource:              resource,
			AuthorizationServers:  issuers,
			ScopesSupported:       cfg.scopesSupported,
			ResourceName:          cfg.resourceName,
			ResourceDocumentation: cfg.resourceDocumentation,
		}
		// When this server publishes its JWKS, advertise its location (RFC 9728 jwks_uri)
		// so the one WithPublicJWKS option both serves and advertises, as Python couples them.
		if cfg.publicJWKS != nil {
			metadata.JWKSURI = baseURL + "/.well-known/jwks.json"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
	legacy := binding == nil || binding.legacy
	var issuerList []string
	if cfg.issuer != "" {
		issuerList = []string{cfg.issuer}
	}
	if legacy {
		legacyResource := func(w http.ResponseWriter, r *http.Request) {
			baseURL := fmt.Sprintf("%s://%s", requestScheme(r), r.Host)
			resource := baseURL + strings.TrimRight(strings.TrimPrefix(r.URL.Path, protectedResourcePath), "/")
			protectedResource(w, resource, baseURL, issuerList)
		}
		mux.HandleFunc("GET "+protectedResourcePath, legacyResource)
		mux.HandleFunc("GET "+protectedResourcePath+"/", legacyResource)
	}

	const authorizationServerPath = "/.well-known/oauth-authorization-server"
	if cfg.issuer != "" {
		proxy := func(w http.ResponseWriter, r *http.Request, issuer string) {
			setCORSHeaders(w)

			// Fetch upstream authorization server metadata and return it unmodified
			issuerMetadataURL := issuer + authorizationServerPath
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

			body, err := io.ReadAll(resp.Body)
			var metadata map[string]json.RawMessage
			if err != nil || json.Unmarshal(body, &metadata) != nil {
				http.Error(w, "failed to decode authorization server metadata", http.StatusBadGateway)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}
		if binding != nil && binding.zones != nil {
			zoneProxy := func(w http.ResponseWriter, r *http.Request) {
				issuer, ok := binding.zoneIssuers[r.PathValue("zone")]
				if !ok {
					http.NotFound(w, r)
					return
				}
				proxy(w, r, issuer)
			}
			mux.HandleFunc("GET "+authorizationServerPath+"/{zone}", zoneProxy)
			mux.HandleFunc("GET "+authorizationServerPath+"/{zone}/{rest...}", zoneProxy)
		} else {
			mux.HandleFunc("GET "+authorizationServerPath, func(w http.ResponseWriter, r *http.Request) {
				proxy(w, r, cfg.issuer)
			})
		}
	}

	if cfg.publicJWKS != nil {
		mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
			setCORSHeaders(w)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cfg.publicJWKS)
		})
	}

	preflight := func(w http.ResponseWriter, _ *http.Request) {
		setCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
	}

	if legacy {
		mux.HandleFunc("OPTIONS /.well-known/", preflight)
		return mux
	}
	type document struct {
		id      resourceIdentifier
		issuers []string
	}
	documents := map[string][]document{}
	addDocument := func(id resourceIdentifier, issuers []string) {
		if id.metadata != nil {
			target := id.metadata.RequestURI()
			documents[target] = append(documents[target], document{id, issuers})
		}
	}
	switch {
	case binding.zones == nil:
		addDocument(binding.single, issuerList)
	case binding.multi:
		addDocument(binding.single, binding.trustedZoneIssuers())
	default:
		for zone, id := range binding.zones {
			addDocument(id, []string{binding.zoneIssuers[zone]})
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && strings.HasPrefix(r.URL.Path, "/.well-known/") {
			preflight(w, r)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			matches := documents[r.URL.RequestURI()]
			var selected *document
			for i := range matches {
				doc := &matches[i]
				if len(matches) == 1 || strings.EqualFold(r.Host, doc.id.metadata.Host) {
					selected = doc
					break
				}
				if canonicalAuthority(doc.id.metadata.Scheme, r.Host) == canonicalAuthority(doc.id.metadata.Scheme, doc.id.metadata.Host) {
					selected = doc
				}
			}
			if selected != nil {
				baseURL := selected.id.public.Scheme + "://" + selected.id.public.Host
				protectedResource(w, selected.id.value, baseURL, selected.issuers)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
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
