package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

// wellKnownPath is the OIDC discovery document path appended to the issuer.
//
// OpenID Connect Discovery 1.0 §4.1.
const wellKnownPath = "/.well-known/openid-configuration"

// maxBodyBytes caps the discovery response read into memory. A discovery
// document is a small JSON object; this guards against a malicious or
// misconfigured issuer streaming an unbounded body (memory-exhaustion DoS).
const maxBodyBytes = 1 << 20 // 1 MiB

// ProviderConfiguration is the parsed OpenID Connect provider metadata
// document (OIDC Discovery 1.0 §3). Fields not modelled here are preserved in
// Extra so unknown metadata is ignored rather than rejected (DISC-009).
type ProviderConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`

	// Extra holds any provider metadata fields not modelled above. Unknown
	// fields are ignored (not rejected) per OIDC Discovery 1.0 §3.
	Extra map[string]json.RawMessage `json:"-"`
}

// modelledJSONFields is the set of JSON names decoded into named
// [ProviderConfiguration] fields. They are excluded from Extra so that Extra
// holds only unmodelled metadata, honouring its documented contract (DISC-009).
var modelledJSONFields = map[string]struct{}{
	"issuer":                                {},
	"authorization_endpoint":                {},
	"token_endpoint":                        {},
	"userinfo_endpoint":                     {},
	"jwks_uri":                              {},
	"registration_endpoint":                 {},
	"introspection_endpoint":                {},
	"revocation_endpoint":                   {},
	"end_session_endpoint":                  {},
	"response_types_supported":              {},
	"response_modes_supported":              {},
	"subject_types_supported":               {},
	"id_token_signing_alg_values_supported": {},
	"scopes_supported":                      {},
	"claims_supported":                      {},
	"grant_types_supported":                 {},
	"token_endpoint_auth_methods_supported": {},
	"code_challenge_methods_supported":      {},
}

// requiredField pairs a metadata field's JSON name with an accessor used to
// detect whether the parsed document populated it.
type requiredField struct {
	name    string
	present func(*ProviderConfiguration) bool
}

// requiredFields is the set of metadata fields that MUST be present per the
// conformance contract (spec/vectors/discovery.json "required_fields",
// DISC-002). token_endpoint is included per the conformance superset.
var requiredFields = []requiredField{
	{"issuer", func(c *ProviderConfiguration) bool { return c.Issuer != "" }},
	{"authorization_endpoint", func(c *ProviderConfiguration) bool { return c.AuthorizationEndpoint != "" }},
	{"token_endpoint", func(c *ProviderConfiguration) bool { return c.TokenEndpoint != "" }},
	{"jwks_uri", func(c *ProviderConfiguration) bool { return c.JWKSURI != "" }},
	{"response_types_supported", func(c *ProviderConfiguration) bool { return len(c.ResponseTypesSupported) > 0 }},
	{"subject_types_supported", func(c *ProviderConfiguration) bool { return len(c.SubjectTypesSupported) > 0 }},
	{"id_token_signing_alg_values_supported", func(c *ProviderConfiguration) bool { return len(c.IDTokenSigningAlgValuesSupported) > 0 }},
}

// Client fetches and caches OIDC provider metadata. It holds its options and
// owns its cache, so two clients never share cached documents. A Client is safe
// for concurrent use.
type Client struct {
	cfg       *config
	transport *transport.Transport
	cache     *cache
}

// NewClient returns a client with opts applied over the defaults. An invalid
// option value is a [*ConfigError]; it is never replaced by its default.
func NewClient(opts ...Option) (*Client, error) {
	cfg, tr, err := newConfig(opts...)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, transport: tr, cache: newCache(cfg.cacheTTL, cfg.maxEntries)}, nil
}

// defaultClient backs the package-level [FetchConfiguration]. The defaults are
// valid, so building it cannot fail.
var defaultClient = func() *Client {
	c, err := NewClient()
	if err != nil {
		panic(err)
	}
	return c
}()

// FetchConfiguration fetches, validates and caches the OIDC provider metadata
// for issuerURL using a client built from the defaults. See
// [Client.FetchConfiguration].
func FetchConfiguration(ctx context.Context, issuerURL string) (*ProviderConfiguration, error) {
	return defaultClient.FetchConfiguration(ctx, issuerURL)
}

// FetchConfiguration fetches, validates and caches the OIDC provider metadata
// for issuerURL. It requests {issuerURL}/.well-known/openid-configuration,
// validates the required fields and the issuer match, then returns the parsed
// [ProviderConfiguration].
//
// The document is cached for the response's Cache-Control max-age, clamped to
// 60 seconds – 24 hours, or for [WithCacheTTL] when there is none; a no-store
// or no-cache response is not cached. A cache hit makes no HTTP request
// (DISC-004), and concurrent calls for the same issuer share one in-flight
// request (singleflight).
func (c *Client) FetchConfiguration(ctx context.Context, issuerURL string) (*ProviderConfiguration, error) {
	return c.cache.fetch(ctx, issuerURL, func(ctx context.Context) (*ProviderConfiguration, string, error) {
		return c.fetchAndValidate(ctx, issuerURL)
	})
}

// fetchAndValidate performs the HTTP request, parses the body and validates the
// document. It returns the response's Cache-Control header for the cache. It
// contains no caching logic so it can be invoked once per singleflight group.
func (c *Client) fetchAndValidate(ctx context.Context, issuerURL string) (*ProviderConfiguration, string, error) {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil, "", &ParseError{Err: fmt.Errorf("issuer URL is empty")}
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return nil, "", &ParseError{Err: fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)}
	}
	// DISC-010: require HTTPS in production; http:// only with WithInsecureAllowHTTP.
	if parsed.Scheme != "https" && !(c.cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, "", &HTTPSRequiredError{Issuer: issuerURL}
	}

	endpoint := issuer + wellKnownPath
	resp, err := c.transport.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("discovery: fetch %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	// Cap the body to guard against an unbounded response (memory-exhaustion
	// DoS). The LimitReader bounds memory regardless of status; read one extra
	// byte so an oversized body can be detected below.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("discovery: read body: %w", err)
	}

	// DISC-006: non-2xx is a transport error carrying the status code. Check
	// this before the size check so a large error page still surfaces as an
	// HTTPError (with its status) rather than a misleading parse error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", &HTTPError{StatusCode: resp.StatusCode, URL: endpoint}
	}

	if len(body) > maxBodyBytes {
		return nil, "", &ParseError{Err: fmt.Errorf("discovery document exceeds %d bytes", maxBodyBytes)}
	}

	// DISC-007: a non-JSON body (or a JSON value that is not an object) is a
	// parse error.
	var doc ProviderConfiguration
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", &ParseError{Err: err}
	}
	// DISC-009: preserve only unmodelled metadata in Extra. Decoding into a map
	// then dropping the modelled keys keeps Extra true to its contract — it
	// must not duplicate fields already exposed as named struct fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", &ParseError{Err: err}
	}
	for name := range raw {
		if _, modelled := modelledJSONFields[name]; modelled {
			delete(raw, name)
		}
	}
	if len(raw) > 0 {
		doc.Extra = raw
	}

	// DISC-008 / DISC-002: every required field must be present.
	if missing := doc.missingRequiredFields(); len(missing) > 0 {
		return nil, "", &MissingFieldsError{Fields: missing}
	}

	// DISC-003: the response issuer must match the requested issuer. Compare
	// with trailing slashes trimmed on both sides so the requested and returned
	// forms are normalised symmetrically (a difference only in a trailing slash
	// is not a mismatch).
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, "", &IssuerMismatchError{Requested: issuer, Returned: doc.Issuer}
	}

	return &doc, resp.Header.Get("Cache-Control"), nil
}

// missingRequiredFields returns the JSON names of any required fields that the
// parsed document failed to populate, in spec order.
func (c *ProviderConfiguration) missingRequiredFields() []string {
	var missing []string
	for _, f := range requiredFields {
		if !f.present(c) {
			missing = append(missing, f.name)
		}
	}
	return missing
}
