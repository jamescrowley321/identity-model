"""Unit tests for JWKS cache TTL logic — parsing, resolution, expiry, and concurrency."""
# ruff: noqa: PLR2004

import time
from unittest.mock import MagicMock

from py_identity_model import Config
from py_identity_model.core.jwks_cache import (
    DEFAULT_JWKS_CACHE_TTL_SECONDS,
    MAX_CACHE_TTL_SECONDS,
    MIN_CACHE_TTL_SECONDS,
    JwksCacheEntry,
    is_cache_expired,
    is_uncacheable,
    is_uncacheable_for_jwks,
    parse_max_age,
    resolve_ttl,
)


# A configured fallback TTL distinct from every max-age used below, so a test
# that expects the header to win would fail if the fallback leaked through.
CONFIGURED_TTL = 7200.0
CONFIGURED = Config(jwks_cache_ttl=CONFIGURED_TTL)


class TestParseMaxAge:
    def test_standard_header(self):
        assert parse_max_age("max-age=3600") == 3600.0

    def test_with_other_directives(self):
        assert parse_max_age("public, max-age=19800, must-revalidate") == 19800.0

    def test_case_insensitive(self):
        assert parse_max_age("Max-Age=300") == 300.0

    def test_no_max_age(self):
        assert parse_max_age("no-cache, no-store") is None

    def test_none_header(self):
        assert parse_max_age(None) is None

    def test_empty_string(self):
        assert parse_max_age("") is None

    def test_zero(self):
        assert parse_max_age("max-age=0") == 0.0


class TestResolveTtl:
    def test_uses_cache_control_when_present(self):
        ttl = resolve_ttl("max-age=3600", CONFIGURED.jwks_cache_ttl)
        assert ttl == 3600.0

    def test_clamps_to_minimum(self):
        ttl = resolve_ttl("max-age=5", CONFIGURED.jwks_cache_ttl)
        assert ttl == MIN_CACHE_TTL_SECONDS

    def test_clamps_to_maximum(self):
        ttl = resolve_ttl("max-age=999999", CONFIGURED.jwks_cache_ttl)
        assert ttl == MAX_CACHE_TTL_SECONDS

    def test_falls_back_to_config_default(self):
        ttl = resolve_ttl(None, Config().jwks_cache_ttl)
        assert ttl == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_falls_back_to_configured_ttl(self):
        ttl = resolve_ttl(None, CONFIGURED.jwks_cache_ttl)
        assert ttl == CONFIGURED_TTL

    def test_no_max_age_directive_falls_back_to_configured_ttl(self):
        ttl = resolve_ttl("public, must-revalidate", CONFIGURED.jwks_cache_ttl)
        assert ttl == CONFIGURED_TTL

    def test_google_typical_value(self):
        """Google JWKS uses max-age=19800 (5.5 hours)."""
        ttl = resolve_ttl("public, max-age=19800", CONFIGURED.jwks_cache_ttl)
        assert ttl == 19800.0

    def test_zero_max_age_clamps_to_minimum(self):
        ttl = resolve_ttl("max-age=0", CONFIGURED.jwks_cache_ttl)
        assert ttl == MIN_CACHE_TTL_SECONDS


class TestCacheEntry:
    def _make_entry(self, age_seconds: float = 0, ttl: float = 300) -> JwksCacheEntry:
        mock_response = MagicMock()
        return JwksCacheEntry(
            response=mock_response,
            cached_at=time.monotonic() - age_seconds,
            ttl=ttl,
        )

    def test_fresh_entry_not_expired(self):
        entry = self._make_entry(age_seconds=0, ttl=300)
        assert not is_cache_expired(entry)

    def test_expired_entry(self):
        entry = self._make_entry(age_seconds=301, ttl=300)
        assert is_cache_expired(entry)

    def test_exactly_at_ttl_is_expired(self):
        entry = self._make_entry(age_seconds=300, ttl=300)
        assert is_cache_expired(entry)

    def test_entry_stores_custom_ttl(self):
        entry = self._make_entry(ttl=7200)
        assert entry.ttl == 7200


class TestIsUncacheable:
    def test_no_store(self):
        assert is_uncacheable("no-store") is True

    def test_no_cache(self):
        assert is_uncacheable("no-cache") is True

    def test_no_store_with_max_age(self):
        """Per RFC 7234 §5.2.2.5, no-store overrides max-age."""
        assert is_uncacheable("no-store, max-age=600") is True

    def test_no_cache_with_max_age(self):
        assert is_uncacheable("no-cache, max-age=600") is True

    def test_descope_combined_directives(self):
        """Real-world: Descope sends both no-store and no-cache on JWKS."""
        assert is_uncacheable("no-store, no-cache") is True

    def test_case_insensitive(self):
        assert is_uncacheable("No-Store") is True
        assert is_uncacheable("NO-CACHE") is True

    def test_plain_max_age_is_cacheable(self):
        assert is_uncacheable("max-age=3600") is False

    def test_public_max_age_is_cacheable(self):
        assert is_uncacheable("public, max-age=19800") is False

    def test_none_header(self):
        assert is_uncacheable(None) is False

    def test_empty_string(self):
        assert is_uncacheable("") is False


class TestIsUncacheableForJwks:
    """JWKS-specific policy: ignore no-cache/no-store on public keys.

    See ``is_uncacheable_for_jwks`` docstring and issue #396 for
    rationale. JWKS responses are public material and the strict
    interpretation causes self-DoS at meaningful traffic levels.
    """

    def test_no_store_is_still_cacheable(self):
        assert is_uncacheable_for_jwks("no-store") is False

    def test_no_cache_is_still_cacheable(self):
        assert is_uncacheable_for_jwks("no-cache") is False

    def test_ory_combined_directives_still_cacheable(self):
        """Real-world: Ory sends 'private, no-cache, no-store, must-revalidate'."""
        assert (
            is_uncacheable_for_jwks("private, no-cache, no-store, must-revalidate")
            is False
        )

    def test_descope_combined_directives_still_cacheable(self):
        assert is_uncacheable_for_jwks("no-store, no-cache") is False

    def test_max_age_still_cacheable(self):
        assert is_uncacheable_for_jwks("max-age=3600") is False

    def test_none_header_still_cacheable(self):
        assert is_uncacheable_for_jwks(None) is False

    def test_empty_string_still_cacheable(self):
        assert is_uncacheable_for_jwks("") is False


class TestMultiProviderCacheIsolation:
    """Verify that cache entries for different providers don't interfere."""

    def test_different_ttls_per_provider(self):
        """Two providers with different Cache-Control values get separate TTLs."""
        google_ttl = resolve_ttl("max-age=19800", CONFIGURED.jwks_cache_ttl)
        auth0_ttl = resolve_ttl("max-age=3600", CONFIGURED.jwks_cache_ttl)

        google_entry = JwksCacheEntry(
            response=MagicMock(), cached_at=time.monotonic(), ttl=google_ttl
        )
        auth0_entry = JwksCacheEntry(
            response=MagicMock(), cached_at=time.monotonic(), ttl=auth0_ttl
        )

        assert google_entry.ttl == 19800.0
        assert auth0_entry.ttl == 3600.0
        assert not is_cache_expired(google_entry)
        assert not is_cache_expired(auth0_entry)

    def test_one_provider_expired_other_not(self):
        """Provider with short TTL expires while long-TTL provider stays cached."""
        now = time.monotonic()
        short_entry = JwksCacheEntry(response=MagicMock(), cached_at=now - 120, ttl=60)
        long_entry = JwksCacheEntry(response=MagicMock(), cached_at=now - 120, ttl=3600)

        assert is_cache_expired(short_entry)
        assert not is_cache_expired(long_entry)
