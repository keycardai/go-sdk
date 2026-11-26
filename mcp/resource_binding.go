package mcp

import (
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/keycardai/go-sdk/oauth"
)

const protectedResourcePath = "/.well-known/oauth-protected-resource"

type resourceIdentifier struct {
	value    string
	public   *url.URL
	metadata *url.URL
}

func parseResourceIdentifier(value string) (resourceIdentifier, error) {
	u, err := url.Parse(value)
	if err != nil || strings.ContainsAny(value, "# \\<>\t\r\n\"") {
		return resourceIdentifier{}, configurationError("invalid resource_identifier")
	}
	id := resourceIdentifier{value: value}
	switch u.Scheme {
	case "urn":
		namespace, name, ok := strings.Cut(u.Opaque, ":")
		if !ok || namespace == "" || name == "" {
			return resourceIdentifier{}, configurationError("invalid URN resource_identifier")
		}
	case "http", "https":
		if u.Hostname() == "" || u.User != nil {
			return resourceIdentifier{}, configurationError("invalid HTTP(S) resource_identifier")
		}
		metadata := *u
		metadata.Path, metadata.RawPath = protectedResourcePath, ""
		if u.Path != "" && u.EscapedPath() != "/" {
			metadata.Path += u.Path
			metadata.RawPath = protectedResourcePath + u.EscapedPath()
		}
		id.public, id.metadata = u, &metadata
	default:
		return resourceIdentifier{}, configurationError("resource_identifier must be an HTTP(S) URL or URN")
	}
	return id, nil
}

func receivedTarget(r *http.Request) *url.URL {
	if target, err := url.ParseRequestURI(r.RequestURI); err == nil {
		return target
	}
	return r.URL
}

func sameRequestQuery(a, b *url.URL) bool {
	return a.RawQuery == b.RawQuery && a.ForceQuery == b.ForceQuery
}

func (id resourceIdentifier) challengeMetadataURL(r *http.Request) string {
	if id.public == nil {
		return ""
	}
	path := id.public.EscapedPath()
	if path == "" {
		path = "/"
	}
	target := receivedTarget(r)
	if target.EscapedPath() != path || !sameRequestQuery(target, id.public) {
		return ""
	}
	return id.metadata.String()
}

// ResourceBindingOption configures the resource server's audience and discovery mode.
type ResourceBindingOption func(*resourceBindingConfig)

type resourceBindingConfig struct {
	single      *string
	zones       *map[string]string
	audiences   []string
	audienceSet bool
	multi       bool
	allowAny    bool
}

// WithResourceIdentifier binds authentication and discovery to one HTTP(S) URL
// or binds authentication alone to a URN.
func WithResourceIdentifier(identifier string) ResourceBindingOption {
	return func(cfg *resourceBindingConfig) { cfg.single = &identifier }
}

// WithResourceIdentifiersByZone configures a resource identifier for each trusted
// zone. Combine it with WithMultiResource for token-keyed shared discovery.
func WithResourceIdentifiersByZone(identifiers map[string]string) ResourceBindingOption {
	return func(cfg *resourceBindingConfig) { cfg.zones = &identifiers }
}

// WithMultiResource selects list-based verification, with no discovery unless
// combined with a zone map whose entries all name the same public URL.
func WithMultiResource(enabled bool) ResourceBindingOption {
	return func(cfg *resourceBindingConfig) { cfg.multi = enabled }
}

// WithResourceAudiences configures the list of audiences for multi-resource
// verification. Shared discovery requires a singleton list of the shared URL.
func WithResourceAudiences(audiences ...string) ResourceBindingOption {
	return func(cfg *resourceBindingConfig) {
		cfg.audiences = audiences
		cfg.audienceSet = true
	}
}

// WithAllowAnyAudience disables the audience check without enabling discovery.
func WithAllowAnyAudience(enabled bool) ResourceBindingOption {
	return func(cfg *resourceBindingConfig) { cfg.allowAny = enabled }
}

// ResourceBinding is the immutable configuration shared by bearer middleware
// and authentication metadata for one resource server.
type ResourceBinding struct {
	issuer      string
	zoneIssuers map[string]string
	single      resourceIdentifier
	zones       map[string]resourceIdentifier
	audiences   []string
	multi       bool
	legacy      bool
}

// NewResourceBinding validates a resource server configuration. issuer is the
// zone issuer in single-resource mode and the base issuer in zone-map modes.
// A standalone metadata handler may omit issuer unless publishing a zone map.
func NewResourceBinding(issuer string, opts ...ResourceBindingOption) (*ResourceBinding, error) {
	var cfg resourceBindingConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.single != nil && (cfg.zones != nil || cfg.multi || cfg.allowAny || cfg.audienceSet) ||
		cfg.allowAny && (cfg.multi || cfg.zones != nil || cfg.audienceSet) ||
		cfg.zones != nil && !cfg.multi && cfg.audienceSet {
		return nil, configurationError("conflicting resource binding options")
	}
	if cfg.audienceSet && len(cfg.audiences) == 0 {
		return nil, configurationError("resource audiences must not be empty")
	}
	b := &ResourceBinding{
		issuer: issuer, audiences: slices.Clone(cfg.audiences), multi: cfg.multi,
		legacy: cfg.single == nil && cfg.zones == nil && !cfg.multi && !cfg.allowAny,
	}
	if cfg.single != nil {
		id, err := parseResourceIdentifier(*cfg.single)
		if err != nil {
			return nil, err
		}
		b.single = id
		b.audiences = []string{id.value}
	}
	if cfg.zones != nil {
		if err := b.configureZones(*cfg.zones); err != nil {
			return nil, err
		}
		if cfg.multi && cfg.audienceSet && (len(b.audiences) != 1 || b.audiences[0] != b.single.value) {
			return nil, configurationError("shared discovery requires the shared resource_identifier as its sole audience")
		}
	}
	if b.legacy {
		warnLegacyResourceBinding()
	}
	return b, nil
}

func (b *ResourceBinding) configureZones(zones map[string]string) error {
	if len(zones) == 0 {
		return configurationError("resource_identifiers_by_zone must not be empty")
	}
	b.zones = make(map[string]resourceIdentifier, len(zones))
	b.zoneIssuers = make(map[string]string, len(zones))
	metadataURLs := make(map[string]bool, len(zones))
	if b.issuer != "" {
		base, err := url.Parse(b.issuer)
		if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" || base.User != nil ||
			strings.Contains(base.Hostname(), ":") || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" ||
			(base.Path != "" && base.Path != "/") {
			return configurationError("invalid base issuer for resource_identifiers_by_zone")
		}
	}
	for zone, value := range zones {
		if !validZoneID(zone) {
			return configurationError("zone ID must be a lowercase DNS label")
		}
		id, err := parseResourceIdentifier(value)
		if err != nil {
			return err
		}
		if id.metadata != nil && b.issuer == "" {
			return configurationError("HTTP(S) zone resources require a base issuer")
		}
		if b.multi {
			if id.metadata == nil || (b.single.value != "" && b.single.value != id.value) {
				return configurationError("shared discovery requires identical HTTP(S) resource identifiers")
			}
			b.single = id
		} else if id.metadata != nil {
			key := canonicalAuthority(id.metadata.Scheme, id.metadata.Host) + id.metadata.RequestURI()
			if metadataURLs[key] {
				return configurationError("multiple zones publish the same protected-resource metadata URL")
			}
			metadataURLs[key] = true
		}
		b.zones[zone] = id
		if b.issuer != "" {
			b.zoneIssuers[zone] = buildZoneURL(zone, b.issuer)
		}
	}
	return nil
}

// canonicalAuthority lowercases host and drops the scheme's default port, so
// "a.example:443" and "A.example" select the same https document.
func canonicalAuthority(scheme, host string) string {
	host = strings.ToLower(host)
	switch strings.ToLower(scheme) {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	return host
}

func validZoneID(zone string) bool {
	if len(zone) == 0 || len(zone) > 63 || zone[0] == '-' || zone[len(zone)-1] == '-' {
		return false
	}
	for _, c := range zone {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (b *ResourceBinding) trustedZoneIssuers() []string {
	issuers := make([]string, 0, len(b.zoneIssuers))
	for _, zone := range slices.Sorted(maps.Keys(b.zoneIssuers)) {
		issuers = append(issuers, b.zoneIssuers[zone])
	}
	return issuers
}

func configurationError(message string) error {
	return &oauth.ConfigurationError{Message: message}
}

func warnLegacyResourceBinding() {
	slog.Warn("keycard: legacy resource binding is deprecated; configure resource_identifier or select an explicit audience mode")
}
