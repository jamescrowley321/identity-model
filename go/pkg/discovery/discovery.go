package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// wellKnownPath is the OIDC discovery document path appended to the issuer.
//
// OpenID Connect Discovery 1.0 §4.1.
const wellKnownPath = "/.well-known/openid-configuration"

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

// requiredField pairs a metadata field's JSON name with an accessor used to
// detect whether the parsed document populated it.
type requiredField struct {
	name    string
	present func(*ProviderConfiguration) bool
}

// requiredFields is the set of metadata fields that MUST be present per the
// conformance contract (spec/conformance/discovery.json "required_fields",
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

// FetchConfiguration fetches, validates and caches the OIDC provider metadata
// for issuerURL. It requests {issuerURL}/.well-known/openid-configuration,
// validates the required fields and the issuer match, then returns the parsed
// [ProviderConfiguration].
//
// Results are cached with a configurable TTL (default 24h, see
// [WithCacheTTL]); a cache hit within the TTL makes no HTTP request
// (DISC-004), and concurrent calls for the same issuer are deduplicated to a
// single in-flight request (singleflight).
func FetchConfiguration(ctx context.Context, issuerURL string, opts ...Option) (*ProviderConfiguration, error) {
	cfg := newConfig(opts...)
	return globalCache.fetch(ctx, issuerURL, cfg)
}

// fetchAndValidate performs the HTTP request, parses the body and validates the
// document. It contains no caching logic so it can be invoked once per
// singleflight group.
func fetchAndValidate(ctx context.Context, issuerURL string, cfg *config) (*ProviderConfiguration, error) {
	issuer := strings.TrimRight(issuerURL, "/")

	parsed, err := url.Parse(issuer)
	if err != nil {
		return nil, &ParseError{Err: fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)}
	}
	// DISC-010: require HTTPS in production; http:// only with WithInsecureAllowHTTP.
	if parsed.Scheme != "https" && !(cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, &HTTPSRequiredError{Issuer: issuerURL}
	}

	reqCtx := ctx
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}

	endpoint := issuer + wellKnownPath
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: fetch %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("discovery: read body: %w", err)
	}

	// DISC-006: non-2xx is a transport error carrying the status code.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{StatusCode: resp.StatusCode, URL: endpoint}
	}

	// DISC-007: a non-JSON body is a parse error.
	var doc ProviderConfiguration
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &ParseError{Err: err}
	}
	// DISC-009: capture unknown fields in Extra (decoded but not rejected).
	_ = json.Unmarshal(body, &doc.Extra)

	// DISC-008 / DISC-002: every required field must be present.
	if missing := doc.missingRequiredFields(); len(missing) > 0 {
		return nil, &MissingFieldsError{Fields: missing}
	}

	// DISC-003: the response issuer must exactly match the requested issuer.
	if doc.Issuer != issuer {
		return nil, &IssuerMismatchError{Requested: issuer, Returned: doc.Issuer}
	}

	return &doc, nil
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
