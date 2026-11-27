"""Unit tests for DiscoveryPolicy and discovery_document_url."""

import httpx
import pytest
import respx

import py_identity_model
from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryErrorKind,
    DiscoveryPolicy,
    HTTPClient,
    ValidationCache,
    get_discovery_document,
)
from py_identity_model import aio as aio_api
from py_identity_model import sync as sync_api
from py_identity_model.aio import AsyncHTTPClient, AsyncValidationCache
from py_identity_model.aio.discovery import (
    get_discovery_document as async_get_discovery_document,
)
from py_identity_model.aio.token_validation import (
    _get_disco_response as async_get_disco_response,
)
from py_identity_model.core.discovery_policy import (
    DiscoveryLocation,
    discovery_document_url,
    is_loopback,
    resolve_discovery_policy,
    validate_url_scheme,
)
from py_identity_model.core.response_processors import (
    _validate_endpoint_authority,
)
from py_identity_model.core.validators import (
    validate_https_url_with_policy,
    validate_issuer_with_policy,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    DiscoveryValidationError,
)
from py_identity_model.sync.token_validation import _get_disco_response


@pytest.mark.unit
class TestIsLoopback:
    def test_localhost(self):
        assert is_loopback("localhost") is True

    def test_ipv4_loopback(self):
        assert is_loopback("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert is_loopback("::1") is True

    def test_127_x(self):
        assert is_loopback("127.0.0.2") is True
        assert is_loopback("127.1.2.3") is True

    def test_not_loopback(self):
        assert is_loopback("example.com") is False
        assert is_loopback("192.168.1.1") is False
        assert is_loopback("10.0.0.1") is False

    def test_dns_spoofed_loopback_rejected(self):
        """127.evil.com must not match as loopback (S2 fix)."""
        assert is_loopback("127.evil.com") is False
        assert is_loopback("127.0.0.1.evil.com") is False


OIDC = DiscoveryLocation.OPENID_CONFIGURATION
OAUTH = DiscoveryLocation.OAUTH_AUTHORIZATION_SERVER


@pytest.mark.unit
class TestDiscoveryDocumentUrl:
    """Issuer-to-URL derivation: OIDC Discovery 1.0 §4.1 and RFC 8414 §3.1."""

    @pytest.mark.parametrize(
        ("issuer", "expected"),
        [
            ("https://op", "https://op/.well-known/openid-configuration"),
            ("https://op/", "https://op/.well-known/openid-configuration"),
            ("https://op/t", "https://op/t/.well-known/openid-configuration"),
            ("https://op/t/", "https://op/t/.well-known/openid-configuration"),
            ("https://op/a/b", "https://op/a/b/.well-known/openid-configuration"),
            (
                "http://localhost:8080",
                "http://localhost:8080/.well-known/openid-configuration",
            ),
        ],
    )
    def test_openid_configuration_appends_well_known_path(self, issuer, expected):
        assert discovery_document_url(issuer) == expected
        assert discovery_document_url(issuer, OIDC) == expected

    @pytest.mark.parametrize(
        ("issuer", "expected"),
        [
            ("https://op", "https://op/.well-known/oauth-authorization-server"),
            ("https://op/", "https://op/.well-known/oauth-authorization-server"),
            ("https://op/t", "https://op/.well-known/oauth-authorization-server/t"),
            ("https://op/t/", "https://op/.well-known/oauth-authorization-server/t"),
            (
                "https://op/a/b",
                "https://op/.well-known/oauth-authorization-server/a/b",
            ),
            (
                "http://localhost:8080/t",
                "http://localhost:8080/.well-known/oauth-authorization-server/t",
            ),
            (
                "https://user@op:8443/t",
                "https://user@op:8443/.well-known/oauth-authorization-server/t",
            ),
        ],
    )
    def test_oauth_authorization_server_inserts_well_known_path(self, issuer, expected):
        assert discovery_document_url(issuer, OAUTH) == expected

    @pytest.mark.parametrize("location", [OIDC, OAUTH], ids=["oidc", "oauth"])
    @pytest.mark.parametrize(
        ("issuer", "message"),
        [
            ("", r"^Issuer cannot be empty$"),
            ("auth.example.com", r"^Issuer must be an HTTP or HTTPS URL$"),
            ("ftp://user:secret@evil.com", r"^Issuer must be an HTTP or HTTPS URL$"),
            ("file:///etc/passwd", r"^Issuer must be an HTTP or HTTPS URL$"),
            ("https://", r"^Issuer must include a host$"),
            ("https:///t", r"^Issuer must include a host$"),
            ("https://:443", r"^Issuer must include a host$"),
            ("https://user@", r"^Issuer must include a host$"),
            ("https://[op.example", r"^Issuer is not a valid URL$"),
            (" https://auth.example.com", r"^Issuer is not a valid URL$"),
            ("https://auth.example.com\n", r"^Issuer is not a valid URL$"),
            ("https://auth.ex\tample.com", r"^Issuer is not a valid URL$"),
            ("https://auth.example.com/\x00", r"^Issuer is not a valid URL$"),
            ("https://auth.example.com/\x7f", r"^Issuer is not a valid URL$"),
            (
                "https://auth.example.com?evil=1",
                r"^Issuer must not contain query or fragment components$",
            ),
            (
                "https://auth.example.com?",
                r"^Issuer must not contain query or fragment components$",
            ),
            (
                "https://auth.example.com#fragment",
                r"^Issuer must not contain query or fragment components$",
            ),
            (
                "https://auth.example.com/t#",
                r"^Issuer must not contain query or fragment components$",
            ),
            (
                "https://op/.well-known/openid-configuration",
                r"^Expected an issuer, got a discovery document URL$",
            ),
            (
                "https://op/.well-known/openid-configuration/",
                r"^Expected an issuer, got a discovery document URL$",
            ),
            (
                "https://op/t/.well-known/openid-configuration",
                r"^Expected an issuer, got a discovery document URL$",
            ),
            (
                "https://op/.well-known/oauth-authorization-server",
                r"^Expected an issuer, got a discovery document URL$",
            ),
            (
                "https://op/.well-known/oauth-authorization-server/",
                r"^Expected an issuer, got a discovery document URL$",
            ),
            (
                "https://op/t/.well-known/oauth-authorization-server",
                r"^Expected an issuer, got a discovery document URL$",
            ),
            (
                "https://op/.well-known/oauth-authorization-server/t",
                r"^Expected an issuer, got a discovery document URL$",
            ),
        ],
    )
    def test_rejects_non_issuer(self, issuer, message, location):
        with pytest.raises(ConfigurationException, match=message) as excinfo:
            discovery_document_url(issuer, location)
        assert type(excinfo.value) is ConfigurationException

    @pytest.mark.parametrize("issuer", [None, 5])
    def test_rejects_non_string(self, issuer):
        with pytest.raises(ConfigurationException, match=r"^Issuer cannot be empty$"):
            discovery_document_url(issuer)

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://op/.well-knownx",
            "https://op/x.well-known/openid-configuration-x",
            "https://op/.well-known/oauth-authorization-serverx",
        ],
    )
    def test_similar_paths_are_issuers(self, issuer):
        assert discovery_document_url(issuer) == (
            issuer + "/.well-known/openid-configuration"
        )


@pytest.mark.unit
class TestDiscoveryExports:
    @pytest.mark.parametrize(
        "module", [py_identity_model, sync_api, aio_api], ids=["top", "sync", "aio"]
    )
    def test_discovery_location_is_exported(self, module):
        assert module.DiscoveryLocation is DiscoveryLocation
        assert "DiscoveryLocation" in module.__all__

    @pytest.mark.parametrize(
        "module", [py_identity_model, sync_api, aio_api], ids=["top", "sync", "aio"]
    )
    def test_discovery_document_url_is_not_exported(self, module):
        assert not hasattr(module, "discovery_document_url")
        assert "discovery_document_url" not in module.__all__

    def test_default_location_is_openid_configuration(self):
        assert DiscoveryPolicy().location is OIDC


def _document(issuer: str) -> dict:
    return {
        "issuer": issuer,
        "jwks_uri": "https://op/jwks",
        "authorization_endpoint": "https://op/authorize",
        "token_endpoint": "https://op/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@pytest.mark.unit
class TestDiscoveryFetchLocation:
    """``get_discovery_document`` fetches from the URL built under ``location``."""

    @pytest.mark.parametrize(
        ("issuer", "location", "url"),
        [
            (
                "https://op/t",
                OAUTH,
                "https://op/.well-known/oauth-authorization-server/t",
            ),
            ("https://op", OAUTH, "https://op/.well-known/oauth-authorization-server"),
            ("https://op/t", OIDC, "https://op/t/.well-known/openid-configuration"),
        ],
    )
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_fetches_the_location_url(self, asynchronous, issuer, location, url):
        request = DiscoveryDocumentRequest(
            issuer=issuer, policy=DiscoveryPolicy(location=location)
        )

        with respx.mock(assert_all_mocked=True) as router:
            route = router.get(url).mock(
                return_value=httpx.Response(200, json=_document(issuer))
            )
            if asynchronous:
                response = await async_get_discovery_document(request)
            else:
                response = get_discovery_document(request)
            assert route.call_count == 1
            assert router.calls.call_count == 1

        assert response.is_successful, response.error
        assert response.issuer == issuer


class _CountingIssuerOP:
    """Serves each requested issuer's document, echoing its trailing slash."""

    def __init__(self, issuers: dict[str, str]) -> None:
        self.issuers = issuers
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        return httpx.Response(200, json=_document(self.issuers[str(request.url)]))


@pytest.mark.unit
class TestDiscoveryCacheKeyedByIssuer:
    """``https://op`` and ``https://op/`` share a URL (§4.1) but not a cache entry."""

    URL = "https://op/.well-known/openid-configuration"

    def test_sync_issuers_do_not_share_a_document(self):
        op = _CountingIssuerOP({self.URL: "https://op"})
        client = HTTPClient(httpx.Client(transport=httpx.MockTransport(op)))
        cache = ValidationCache()

        bare = _get_disco_response("https://op", DiscoveryPolicy(), client, cache)
        slashed = _get_disco_response("https://op/", DiscoveryPolicy(), client, cache)

        assert bare.is_successful, bare.error
        assert bare.issuer == "https://op"
        assert slashed.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH
        assert op.requests == [self.URL, self.URL]

    def test_sync_each_issuer_gets_its_own_document(self):
        op = _CountingIssuerOP({self.URL: "https://op/"})
        client = HTTPClient(httpx.Client(transport=httpx.MockTransport(op)))
        cache = ValidationCache()

        slashed = _get_disco_response("https://op/", DiscoveryPolicy(), client, cache)
        op.issuers[self.URL] = "https://op"
        bare = _get_disco_response("https://op", DiscoveryPolicy(), client, cache)
        slashed_again = _get_disco_response(
            "https://op/", DiscoveryPolicy(), client, cache
        )

        assert (slashed.issuer, bare.issuer, slashed_again.issuer) == (
            "https://op/",
            "https://op",
            "https://op/",
        )
        assert op.requests == [self.URL, self.URL]

    async def test_async_issuers_do_not_share_a_document(self):
        op = _CountingIssuerOP({self.URL: "https://op"})
        client = AsyncHTTPClient(httpx.AsyncClient(transport=httpx.MockTransport(op)))
        cache = AsyncValidationCache()

        bare = await async_get_disco_response(
            "https://op", DiscoveryPolicy(), client, cache
        )
        slashed = await async_get_disco_response(
            "https://op/", DiscoveryPolicy(), client, cache
        )

        assert bare.is_successful, bare.error
        assert bare.issuer == "https://op"
        assert slashed.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH
        assert op.requests == [self.URL, self.URL]

    async def test_async_each_issuer_gets_its_own_document(self):
        op = _CountingIssuerOP({self.URL: "https://op/"})
        client = AsyncHTTPClient(httpx.AsyncClient(transport=httpx.MockTransport(op)))
        cache = AsyncValidationCache()

        slashed = await async_get_disco_response(
            "https://op/", DiscoveryPolicy(), client, cache
        )
        op.issuers[self.URL] = "https://op"
        bare = await async_get_disco_response(
            "https://op", DiscoveryPolicy(), client, cache
        )
        slashed_again = await async_get_disco_response(
            "https://op/", DiscoveryPolicy(), client, cache
        )

        assert (slashed.issuer, bare.issuer, slashed_again.issuer) == (
            "https://op/",
            "https://op",
            "https://op/",
        )
        assert op.requests == [self.URL, self.URL]


@pytest.mark.unit
class TestValidateUrlScheme:
    def test_https_always_ok(self):
        policy = DiscoveryPolicy()
        validate_url_scheme("https://auth.example.com", policy)

    def test_http_rejected_by_default(self):
        policy = DiscoveryPolicy()
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_url_scheme("http://auth.example.com", policy)

    def test_http_allowed_on_loopback(self):
        policy = DiscoveryPolicy(allow_http_on_loopback=True)
        validate_url_scheme("http://localhost:5000", policy)
        validate_url_scheme("http://127.0.0.1:8080", policy)

    def test_http_rejected_on_loopback_when_disabled(self):
        policy = DiscoveryPolicy(allow_http_on_loopback=False)
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_url_scheme("http://localhost:5000", policy)

    def test_http_allowed_when_https_not_required(self):
        policy = DiscoveryPolicy(require_https=False)
        validate_url_scheme("http://auth.example.com", policy)

    def test_ftp_rejected_even_when_https_not_required(self):
        """Non-HTTP(S) schemes rejected regardless of require_https (BLOCK-1)."""
        policy = DiscoveryPolicy(require_https=False)
        with pytest.raises(ConfigurationException, match="HTTP or HTTPS"):
            validate_url_scheme("ftp://evil.com/keys", policy)

    def test_file_rejected_even_when_https_not_required(self):
        """file:// scheme rejected regardless of require_https (BLOCK-1)."""
        policy = DiscoveryPolicy(require_https=False)
        with pytest.raises(ConfigurationException, match="HTTP or HTTPS"):
            validate_url_scheme("file:///etc/passwd", policy)

    def test_empty_url_rejected(self):
        """Empty URL raises ConfigurationException."""
        policy = DiscoveryPolicy()
        with pytest.raises(ConfigurationException, match="empty"):
            validate_url_scheme("", policy)

    def test_none_url_rejected(self):
        """None URL raises ConfigurationException."""
        policy = DiscoveryPolicy()
        with pytest.raises(ConfigurationException, match="empty"):
            validate_url_scheme(None, policy)


@pytest.mark.unit
class TestValidateIssuerWithPolicy:
    def test_none_policy_uses_strict(self):
        validate_issuer_with_policy("https://auth.example.com", None)

    def test_none_policy_rejects_http(self):
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_issuer_with_policy("http://auth.example.com", None)

    def test_policy_disables_issuer_validation(self):
        policy = DiscoveryPolicy(validate_issuer=False)
        validate_issuer_with_policy("http://anything.com", policy)

    def test_policy_disabled_still_requires_non_empty(self):
        policy = DiscoveryPolicy(validate_issuer=False)
        with pytest.raises(ConfigurationException, match="required"):
            validate_issuer_with_policy("", policy)


@pytest.mark.unit
class TestValidateHttpsUrlWithPolicy:
    def test_none_policy_uses_strict(self):
        validate_https_url_with_policy(
            "https://auth.example.com/token", "token_endpoint", None
        )

    def test_policy_relaxed_allows_http(self):
        policy = DiscoveryPolicy(require_https=False)
        validate_https_url_with_policy(
            "http://auth.example.com/token", "token_endpoint", policy
        )

    def test_policy_loopback_allows_http(self):
        policy = DiscoveryPolicy()
        validate_https_url_with_policy(
            "http://localhost:8080/token", "token_endpoint", policy
        )

    def test_policy_rejects_http_non_loopback(self):
        policy = DiscoveryPolicy()
        with pytest.raises(ConfigurationException, match="HTTPS"):
            validate_https_url_with_policy(
                "http://auth.example.com/token", "token_endpoint", policy
            )

    def test_policy_validates_endpoints_disabled(self):
        policy = DiscoveryPolicy(validate_endpoints=False)
        validate_https_url_with_policy("not-even-a-url", "whatever", policy)

    def test_empty_url_skipped(self):
        policy = DiscoveryPolicy()
        validate_https_url_with_policy("", "optional_endpoint", policy)


ISSUER = "https://auth.example.com"


@pytest.mark.unit
class TestValidateEndpointAuthority:
    """Allowed authorities: the configured issuer's, ``policy.authority`` and
    ``policy.additional_endpoint_base_addresses``."""

    def test_matching_issuer_authority_passes(self):
        _validate_endpoint_authority(
            "https://auth.example.com/token",
            "token_endpoint",
            DiscoveryPolicy(),
            ISSUER,
        )

    def test_issuer_with_path_allows_its_authority(self):
        _validate_endpoint_authority(
            "https://auth.example.com/other/token",
            "token_endpoint",
            DiscoveryPolicy(),
            "https://auth.example.com/tenant/",
        )

    def test_mismatched_authority_raises(self):
        with pytest.raises(
            DiscoveryValidationError,
            match=r"^token_endpoint authority 'https://evil\.com' does not match",
        ):
            _validate_endpoint_authority(
                "https://evil.com/token", "token_endpoint", DiscoveryPolicy(), ISSUER
            )

    def test_port_is_part_of_the_authority(self):
        with pytest.raises(DiscoveryValidationError, match="authority"):
            _validate_endpoint_authority(
                "https://auth.example.com:8443/token",
                "token_endpoint",
                DiscoveryPolicy(),
                ISSUER,
            )

    def test_additional_base_addresses_accepted(self):
        policy = DiscoveryPolicy(
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys", "jwks_uri", policy, ISSUER
        )

    def test_additional_base_addresses_trailing_slash(self):
        policy = DiscoveryPolicy(
            additional_endpoint_base_addresses=["https://cdn.example.com/"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys", "jwks_uri", policy, ISSUER
        )

    def test_additional_base_addresses_rejects_unlisted(self):
        policy = DiscoveryPolicy(
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        with pytest.raises(DiscoveryValidationError, match="authority"):
            _validate_endpoint_authority(
                "https://attacker.com/keys", "jwks_uri", policy, ISSUER
            )

    def test_explicit_authority_is_allowed(self):
        policy = DiscoveryPolicy(authority="https://gateway.example.com")
        _validate_endpoint_authority(
            "https://gateway.example.com/token", "token_endpoint", policy, ISSUER
        )

    def test_explicit_authority_keeps_the_issuer_allowed(self):
        """``policy.authority`` adds an authority; the issuer's stays allowed."""
        policy = DiscoveryPolicy(authority="https://gateway.example.com")
        _validate_endpoint_authority(
            "https://auth.example.com/token", "token_endpoint", policy, ISSUER
        )

    def test_explicit_authority_rejects_others(self):
        policy = DiscoveryPolicy(authority="https://gateway.example.com")
        with pytest.raises(DiscoveryValidationError, match="authority"):
            _validate_endpoint_authority(
                "https://evil.com/token", "token_endpoint", policy, ISSUER
            )

    def test_explicit_authority_plus_additional(self):
        policy = DiscoveryPolicy(
            authority="https://gateway.example.com",
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys", "jwks_uri", policy, ISSUER
        )

    def test_case_insensitive_authority_comparison(self):
        """Authority comparison is case-insensitive per RFC 3986 §3.2.2."""
        _validate_endpoint_authority(
            "https://auth.example.com/token",
            "token_endpoint",
            DiscoveryPolicy(),
            "HTTPS://AUTH.EXAMPLE.COM",
        )

    def test_case_insensitive_additional_addresses(self):
        policy = DiscoveryPolicy(
            additional_endpoint_base_addresses=["HTTPS://CDN.EXAMPLE.COM"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys", "jwks_uri", policy, ISSUER
        )


class TestDiscoveryPolicyCacheKey:
    """``DiscoveryPolicy.cache_key`` is the cache-partitioning identity that
    prevents a lax-policy discovery response from being served to a stricter
    caller. It must be hashable and distinguish every validation-affecting
    field."""

    def test_default_key_is_hashable(self):
        """The key must be usable as a dict key (hashable, no list fields)."""
        key = DiscoveryPolicy().cache_key()
        assert hash(key) is not None
        # Round-trips as a dict key.
        assert {(("addr",), key): 1}[(("addr",), key)] == 1

    def test_location_is_part_of_the_key(self):
        oidc = DiscoveryPolicy(location=DiscoveryLocation.OPENID_CONFIGURATION)
        oauth = DiscoveryPolicy(location=DiscoveryLocation.OAUTH_AUTHORIZATION_SERVER)
        assert oidc.cache_key() == DiscoveryPolicy().cache_key()
        assert oauth.cache_key() != oidc.cache_key()
        assert DiscoveryLocation.OAUTH_AUTHORIZATION_SERVER in oauth.cache_key()

    def test_equal_policies_produce_equal_keys(self):
        assert DiscoveryPolicy().cache_key() == DiscoveryPolicy().cache_key()
        a = DiscoveryPolicy(additional_endpoint_base_addresses=["https://cdn"])
        b = DiscoveryPolicy(additional_endpoint_base_addresses=["https://cdn"])
        assert a.cache_key() == b.cache_key()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"require_https": False},
            {"allow_http_on_loopback": False},
            {"validate_issuer": False},
            {"validate_endpoints": False},
            {"additional_endpoint_base_addresses": ["https://cdn.example"]},
            {"authority": "https://auth.example"},
            {"allow_loopback_endpoints": True},
            {"location": DiscoveryLocation.OAUTH_AUTHORIZATION_SERVER},
        ],
    )
    def test_each_field_changes_the_key(self, kwargs):
        """Every validation-affecting field must move the key, else two policies
        that validate differently could collide onto one cache entry."""
        assert DiscoveryPolicy(**kwargs).cache_key() != DiscoveryPolicy().cache_key()


class TestResolveDiscoveryPolicy:
    """``resolve_discovery_policy`` encodes the single precedence rule shared by
    the sync/async cached ``validate_token`` paths: an explicit policy wins over
    the legacy ``require_https`` bool."""

    def test_none_derives_from_require_https_true(self):
        assert resolve_discovery_policy(None, True) == DiscoveryPolicy(
            require_https=True
        )

    def test_none_derives_from_require_https_false(self):
        resolved = resolve_discovery_policy(None, False)
        assert resolved.require_https is False

    def test_explicit_policy_takes_precedence(self):
        """The explicit policy is returned as-is; the require_https arg is
        ignored (the policy's own require_https governs)."""
        policy = DiscoveryPolicy(require_https=False, validate_issuer=False)
        assert resolve_discovery_policy(policy, True) is policy
