"""Unit tests for DiscoveryPolicy and DiscoveryEndpoint."""

import pytest

from py_identity_model import DiscoveryPolicy
from py_identity_model.core.discovery_policy import (
    is_loopback,
    parse_discovery_url,
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
    DiscoveryException,
)


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


@pytest.mark.unit
class TestParseDiscoveryUrl:
    def test_base_url(self):
        result = parse_discovery_url("https://auth.example.com")
        assert result.url == "https://auth.example.com/.well-known/openid-configuration"
        assert result.authority == "https://auth.example.com"

    def test_full_wellknown_url(self):
        result = parse_discovery_url(
            "https://auth.example.com/.well-known/openid-configuration"
        )
        assert result.url == "https://auth.example.com/.well-known/openid-configuration"
        assert result.authority == "https://auth.example.com"

    def test_with_path(self):
        result = parse_discovery_url("https://auth.example.com/tenant1")
        assert "/.well-known/openid-configuration" in result.url
        assert result.authority == "https://auth.example.com"

    def test_empty_url(self):
        with pytest.raises(ConfigurationException, match="empty"):
            parse_discovery_url("")

    def test_no_scheme(self):
        with pytest.raises(ConfigurationException, match="scheme"):
            parse_discovery_url("auth.example.com")

    def test_no_host(self):
        with pytest.raises(ConfigurationException, match="host"):
            parse_discovery_url("https://")

    def test_trailing_slash(self):
        result = parse_discovery_url("https://auth.example.com/")
        assert result.url == "https://auth.example.com/.well-known/openid-configuration"

    def test_query_string_rejected(self):
        """URLs with query strings are rejected (WARN-8)."""
        with pytest.raises(ConfigurationException, match="query or fragment"):
            parse_discovery_url("https://auth.example.com?evil=1")

    def test_fragment_rejected(self):
        """URLs with fragments are rejected (WARN-8)."""
        with pytest.raises(ConfigurationException, match="query or fragment"):
            parse_discovery_url("https://auth.example.com#fragment")

    def test_non_http_scheme_rejected(self):
        """Non-HTTP(S) schemes are rejected."""
        with pytest.raises(ConfigurationException, match="HTTP or HTTPS"):
            parse_discovery_url("ftp://evil.com")


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


@pytest.mark.unit
class TestValidateEndpointAuthority:
    """Tests for _validate_endpoint_authority (M2 & M3 coverage)."""

    def _make_response(self, issuer: str = "https://auth.example.com") -> dict:
        return {"issuer": issuer}

    def test_matching_issuer_authority_passes(self):
        """Endpoint with same authority as issuer passes validation."""
        policy = DiscoveryPolicy(validate_endpoints=True)
        _validate_endpoint_authority(
            "https://auth.example.com/token",
            "token_endpoint",
            self._make_response(),
            policy,
        )

    def test_mismatched_authority_raises(self):
        """Endpoint from different authority than issuer is rejected."""
        policy = DiscoveryPolicy(validate_endpoints=True)
        with pytest.raises(DiscoveryException, match="authority"):
            _validate_endpoint_authority(
                "https://evil.com/token",
                "token_endpoint",
                self._make_response(),
                policy,
            )

    def test_additional_base_addresses_accepted(self):
        """Endpoint from additional_endpoint_base_addresses passes (M2)."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys",
            "jwks_uri",
            self._make_response(),
            policy,
        )

    def test_additional_base_addresses_trailing_slash(self):
        """Trailing slashes on additional addresses are normalized."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            additional_endpoint_base_addresses=["https://cdn.example.com/"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys",
            "jwks_uri",
            self._make_response(),
            policy,
        )

    def test_additional_base_addresses_rejects_unlisted(self):
        """Endpoint not in issuer or additional addresses is rejected."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        with pytest.raises(DiscoveryException, match="authority"):
            _validate_endpoint_authority(
                "https://attacker.com/keys",
                "jwks_uri",
                self._make_response(),
                policy,
            )

    def test_explicit_authority_overrides_issuer(self):
        """policy.authority takes precedence over issuer (M3)."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            authority="https://gateway.example.com",
        )
        # Endpoint matches explicit authority, not issuer
        _validate_endpoint_authority(
            "https://gateway.example.com/token",
            "token_endpoint",
            self._make_response("https://auth.example.com"),
            policy,
        )

    def test_explicit_authority_rejects_issuer(self):
        """When authority is set, issuer's authority alone is not enough."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            authority="https://gateway.example.com",
        )
        with pytest.raises(DiscoveryException, match="authority"):
            _validate_endpoint_authority(
                "https://auth.example.com/token",
                "token_endpoint",
                self._make_response("https://auth.example.com"),
                policy,
            )

    def test_explicit_authority_plus_additional(self):
        """Both authority and additional_endpoint_base_addresses are checked."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            authority="https://gateway.example.com",
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        # CDN address accepted alongside explicit authority
        _validate_endpoint_authority(
            "https://cdn.example.com/keys",
            "jwks_uri",
            self._make_response(),
            policy,
        )

    def test_empty_issuer_no_allowed_set_raises(self):
        """Empty issuer with no authority constraint raises DiscoveryException."""
        policy = DiscoveryPolicy(validate_endpoints=True)
        with pytest.raises(
            DiscoveryException, match="no authority constraint available"
        ):
            _validate_endpoint_authority(
                "https://anything.com/keys",
                "jwks_uri",
                {"issuer": ""},
                policy,
            )

    def test_case_insensitive_authority_comparison(self):
        """Authority comparison is case-insensitive per RFC 3986 §3.2.2."""
        policy = DiscoveryPolicy(validate_endpoints=True)
        # Mixed-case issuer should match lowercase endpoint
        _validate_endpoint_authority(
            "https://auth.example.com/token",
            "token_endpoint",
            {"issuer": "HTTPS://AUTH.EXAMPLE.COM"},
            policy,
        )

    def test_case_insensitive_additional_addresses(self):
        """additional_endpoint_base_addresses comparison is case-insensitive."""
        policy = DiscoveryPolicy(
            validate_endpoints=True,
            additional_endpoint_base_addresses=["HTTPS://CDN.EXAMPLE.COM"],
        )
        _validate_endpoint_authority(
            "https://cdn.example.com/keys",
            "jwks_uri",
            self._make_response(),
            policy,
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
            {"require_key_set": False},
            {"additional_endpoint_base_addresses": ["https://cdn.example"]},
            {"authority": "https://auth.example"},
            {"allow_loopback_endpoints": True},
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
