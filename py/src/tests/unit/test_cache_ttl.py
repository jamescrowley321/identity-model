"""Tests for TTL-based cache expiry on discovery and JWKS."""

import time
from unittest.mock import MagicMock

import pytest

from py_identity_model import Config
from py_identity_model.aio.token_validation import (
    _get_disco_response as _get_disco_response_async,
)
from py_identity_model.core.jwks_cache import (
    DEFAULT_DISCO_CACHE_TTL_SECONDS,
    MAX_CACHE_TTL_SECONDS,
    MIN_CACHE_TTL_SECONDS,
    DiscoCacheEntry,
    is_cache_expired,
    resolve_disco_ttl,
)
from py_identity_model.core.models import DiscoveryDocumentResponse
from py_identity_model.exceptions import ConfigurationException
from py_identity_model.sync.token_validation import _get_disco_response


# A configured fallback distinct from the max-age values below, so a test that
# expects the header to win would fail if the fallback leaked through.
CONFIGURED_DISCO_TTL = 900.0
CONFIGURED = Config(discovery_cache_ttl=CONFIGURED_DISCO_TTL)


class TestDiscoCacheTTL:
    """Test discovery cache TTL resolution and expiry."""

    def test_resolve_disco_ttl_from_cache_control(self):
        """Cache-Control max-age takes priority."""
        expected = 1800.0
        ttl = resolve_disco_ttl("public, max-age=1800", CONFIGURED.discovery_cache_ttl)
        assert ttl == expected

    def test_resolve_disco_ttl_default(self):
        """Default is 3600s (1 hour) when no header and a default Config."""
        ttl = resolve_disco_ttl(None, Config().discovery_cache_ttl)
        assert ttl == DEFAULT_DISCO_CACHE_TTL_SECONDS

    def test_resolve_disco_ttl_configured(self):
        """Without max-age, Config.discovery_cache_ttl is used."""
        ttl = resolve_disco_ttl(None, CONFIGURED.discovery_cache_ttl)
        assert ttl == CONFIGURED_DISCO_TTL

    def test_resolve_disco_ttl_clamped_maximum(self):
        """TTL from max-age is clamped to maximum 86400s."""
        ttl = resolve_disco_ttl("max-age=999999", CONFIGURED.discovery_cache_ttl)
        assert ttl == MAX_CACHE_TTL_SECONDS

    def test_resolve_disco_ttl_clamped_minimum(self):
        """TTL is clamped to minimum 60s."""
        ttl = resolve_disco_ttl("max-age=5", CONFIGURED.discovery_cache_ttl)
        assert ttl == MIN_CACHE_TTL_SECONDS

    def test_disco_cache_entry_expires(self):
        """DiscoCacheEntry should expire after its TTL."""
        response = MagicMock(spec=DiscoveryDocumentResponse)
        entry = DiscoCacheEntry(
            response=response,
            cached_at=time.monotonic() - 3700,  # 3700s ago, default TTL is 3600
            ttl=DEFAULT_DISCO_CACHE_TTL_SECONDS,
        )
        assert is_cache_expired(entry) is True

    def test_disco_cache_entry_fresh(self):
        """DiscoCacheEntry should not be expired within TTL."""
        response = MagicMock(spec=DiscoveryDocumentResponse)
        entry = DiscoCacheEntry(
            response=response,
            cached_at=time.monotonic(),
            ttl=DEFAULT_DISCO_CACHE_TTL_SECONDS,
        )
        assert is_cache_expired(entry) is False


class TestNoneAddressRejected:
    """Regression test for #351 -- None disco_doc_address must not reach cache."""

    def test_sync_none_address_raises(self):
        """Sync path rejects None disco_doc_address."""
        with pytest.raises(ConfigurationException):
            _get_disco_response(None)

    @pytest.mark.asyncio
    async def test_async_none_address_raises(self):
        """Async path rejects None disco_doc_address."""
        with pytest.raises(ConfigurationException):
            await _get_disco_response_async(None)
