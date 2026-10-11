"""Tests for resource limits and concurrency fixes (Batch 5).

Covers:
- #353: JWKS response size limit
- #357: Async cleanup lock race
- #376: JWKS max key count limit and KeyError guard
"""

import asyncio
import json
from typing import ClassVar

import httpx
import pytest

from py_identity_model import Config, ConfigError
from py_identity_model.aio.http_client import (
    _get_default,
    _reset_async_http_client,
    close_async_http_client,
    get_async_http_client,
)
from py_identity_model.core.http_utils import (
    DEFAULT_MAX_JWKS_KEYS,
    DEFAULT_MAX_JWKS_SIZE,
)
from py_identity_model.core.response_processors import parse_jwks_response


DEFAULT_CONFIG = Config()
SMALL_MAX_JWKS_SIZE = 100
TINY_MAX_JWKS_SIZE = 50
SMALL_MAX_JWKS_KEYS = 5


# ============================================================================
# #353 — JWKS response size limit
# ============================================================================


class TestJwksSizeLimit:
    """Verify JWKS responses are rejected when too large."""

    _SMALL_JWKS: ClassVar[dict] = {
        "keys": [{"kty": "RSA", "kid": "k1", "n": "n", "e": "AQAB"}]
    }

    def test_accepts_small_response(self):
        response = httpx.Response(
            200,
            json=self._SMALL_JWKS,
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is True

    def test_rejects_large_content_length(self):
        response = httpx.Response(
            200,
            content=b'{"keys": []}',
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(DEFAULT_MAX_JWKS_SIZE + 1),
            },
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "too large" in result.error

    def test_rejects_large_body(self):
        """Body larger than limit is rejected even without Content-Length."""
        config = Config(jwks_max_size=SMALL_MAX_JWKS_SIZE)
        big_body = json.dumps(
            {
                "keys": [
                    {"kty": "RSA", "n": "x" * (2 * SMALL_MAX_JWKS_SIZE), "e": "AQAB"}
                ]
            }
        )
        response = httpx.Response(
            200,
            content=big_body.encode(),
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, config)
        assert result.is_successful is False
        assert result.error is not None
        assert "too large" in result.error

    def test_respects_config_max_size(self):
        config = Config(jwks_max_size=TINY_MAX_JWKS_SIZE)
        response = httpx.Response(
            200,
            content=b'{"keys": [{"kty": "RSA", "n": "long_value", "e": "AQAB"}]}',
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, config)
        assert result.is_successful is False
        assert result.error is not None
        assert "too large" in result.error

    def test_non_success_skips_size_check(self):
        """Non-2xx responses report HTTP error, not size."""
        response = httpx.Response(
            500,
            content=b"x" * (DEFAULT_MAX_JWKS_SIZE + 1),
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "500" in result.error


# ============================================================================
# #376 — JWKS max key count limit and missing "keys" guard
# ============================================================================


class TestJwksKeyCountLimit:
    """Verify JWKS responses are rejected when they contain too many keys.

    Attack scenario: An attacker controlling a JWKS endpoint returns a
    response with thousands of minimal keys that stays under the 512 KB body
    size limit. Each key triggers expensive cryptographic processing (modulus
    calculation), causing CPU/memory exhaustion.
    """

    @staticmethod
    def _make_keys(n: int) -> list[dict]:
        """Generate n minimal RSA JWK dicts."""
        return [{"kty": "RSA", "kid": f"k{i}", "n": "n", "e": "AQAB"} for i in range(n)]

    def test_cpu_exhaustion_via_many_keys_blocked(self):
        """JWKS with 1000+ keys is rejected before any key processing."""
        keys = self._make_keys(1001)
        response = httpx.Response(
            200,
            json={"keys": keys},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "too many keys" in result.error
        assert "1001" in result.error

    def test_rejects_keys_over_default_limit(self):
        """JWKS with 101 keys exceeds default limit of 100."""
        keys = self._make_keys(DEFAULT_MAX_JWKS_KEYS + 1)
        response = httpx.Response(
            200,
            json={"keys": keys},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "too many keys" in result.error

    def test_accepts_keys_at_limit(self):
        """JWKS with exactly 100 keys (the default limit) is accepted."""
        keys = self._make_keys(DEFAULT_MAX_JWKS_KEYS)
        response = httpx.Response(
            200,
            json={"keys": keys},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is True

    def test_accepts_empty_keys_list(self):
        """JWKS with empty keys list is valid (0 < limit)."""
        response = httpx.Response(
            200,
            json={"keys": []},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is True

    def test_max_keys_config_override(self):
        """Config.jwks_max_keys overrides the default limit."""
        config = Config(jwks_max_keys=SMALL_MAX_JWKS_KEYS)
        key_count = SMALL_MAX_JWKS_KEYS + 1
        keys = self._make_keys(key_count)
        response = httpx.Response(
            200,
            json={"keys": keys},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, config)
        assert result.is_successful is False
        assert result.error is not None
        assert "too many keys" in result.error
        assert str(key_count) in result.error
        assert str(SMALL_MAX_JWKS_KEYS) in result.error


class TestJwksMissingKeysField:
    """Verify missing 'keys' field returns a descriptive error, not a raw KeyError.

    Attack scenario: Attacker returns a valid JSON object without the
    expected 'keys' field, causing a raw KeyError that may leak stack traces
    or crash the application.
    """

    def test_missing_keys_field_blocked(self):
        """JWKS response without 'keys' field returns descriptive error."""
        response = httpx.Response(
            200,
            json={"not_keys": []},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "missing required 'keys' field" in result.error

    def test_empty_object_missing_keys(self):
        """Empty JSON object (no 'keys') returns descriptive error."""
        response = httpx.Response(
            200,
            json={},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "missing required 'keys' field" in result.error

    def test_keys_field_null_handled_gracefully(self):
        """'keys': null returns descriptive error, not a raw TypeError."""
        response = httpx.Response(
            200,
            json={"keys": None},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "keys" in result.error.lower()

    def test_response_json_is_list_blocked(self):
        """JWKS response that is a JSON array (not object) is rejected."""
        response = httpx.Response(
            200,
            json=[{"kty": "RSA", "kid": "k1", "n": "n", "e": "AQAB"}],
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "expected a JSON object" in result.error

    def test_non_dict_key_element_blocked(self):
        """JWKS response with non-dict key elements is rejected."""
        response = httpx.Response(
            200,
            json={"keys": ["not-a-dict", 42]},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is False
        assert result.error is not None
        assert "not a JSON object" in result.error

    def test_malformed_content_length_ignored(self):
        """Malformed Content-Length header doesn't crash parsing."""
        response = httpx.Response(
            200,
            json={"keys": []},
            headers={
                "Content-Type": "application/json",
                "Content-Length": "invalid",
            },
        )
        result = parse_jwks_response(response, DEFAULT_CONFIG)
        assert result.is_successful is True

    @pytest.mark.parametrize("max_keys", [0, -5])
    def test_non_positive_max_keys_is_rejected(self, max_keys):
        """A key limit below 1 (which would reject every JWKS) is an invalid Config."""
        with pytest.raises(ConfigError) as exc_info:
            Config(jwks_max_keys=max_keys)

        assert [issue.setting for issue in exc_info.value.issues] == ["jwks_max_keys"]

    def test_max_keys_of_one_accepts_single_key(self):
        """The smallest valid key limit still accepts a single-key JWKS."""
        response = httpx.Response(
            200,
            json={"keys": [{"kty": "RSA", "kid": "k1", "n": "n", "e": "AQAB"}]},
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response, Config(jwks_max_keys=1))
        assert result.is_successful is True


# ============================================================================
# #357 — Async cleanup lock race
# ============================================================================


class TestAsyncCleanupLock:
    """Verify the async cleanup lock is eagerly initialized."""

    def test_cleanup_lock_is_eagerly_created(self):
        """The default client's cleanup lock exists before any close, not lazily."""
        assert isinstance(_get_default()._cleanup_lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_concurrent_close_does_not_race(self):
        """Multiple concurrent close calls should not raise."""
        _reset_async_http_client()
        _ = get_async_http_client()

        # Close concurrently from multiple coroutines
        await asyncio.gather(
            close_async_http_client(),
            close_async_http_client(),
            close_async_http_client(),
        )
        # No error = no race

    @pytest.mark.asyncio
    async def test_close_then_recreate(self):
        """Client can be recreated after closing."""
        _reset_async_http_client()
        client1 = get_async_http_client()
        await close_async_http_client()
        client2 = get_async_http_client()
        assert client2 is not client1
        _reset_async_http_client()
