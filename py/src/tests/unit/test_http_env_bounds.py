"""Tests that out-of-range HTTP env vars degrade safely instead of breaking the client.

Every value here is parsed from the ambient environment, so a single typo in a
deployment reaches every entry point the library offers. The failures these guard
against are silent or misleading rather than loud: a negative retry count made the
request loop run zero times and then raised "No response received after retries",
and a non-numeric size limit raised ValueError out of a response parser.
"""

import httpx
import pytest

from py_identity_model.aio.http_client import retry_with_backoff_async
from py_identity_model.core.http_utils import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_JWKS_KEYS,
    DEFAULT_MAX_JWKS_SIZE,
    DEFAULT_RETRY_BASE_DELAY,
    DEFAULT_RETRY_MAX_ATTEMPTS,
    get_max_jwks_keys,
    get_max_jwks_size,
    get_retry_config,
    get_timeout,
)
from py_identity_model.sync.http_client import retry_with_backoff


HTTP_OK = 200
URL = "https://issuer.example.com/.well-known/openid-configuration"
RETRIES_DISABLED = 0
SINGLE_ATTEMPT = 1
EXPLICIT_RETRY_ATTEMPTS = 2


class TestRetryCountBounds:
    """A retry count below zero must not cancel the request itself."""

    def test_negative_retry_count_still_makes_one_attempt(self, monkeypatch):
        """Test that HTTP_RETRY_MAX_ATTEMPTS=-1 still issues the request."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "-1")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        attempts = 0
        expected = httpx.Response(HTTP_OK, request=httpx.Request("GET", URL))

        @retry_with_backoff()
        def request():
            nonlocal attempts
            attempts += 1
            return expected

        # Before the bound, range(retries + 1) was range(0): the body never ran
        # and the decorator raised RuntimeError("No response received after
        # retries") having made no request at all.
        assert request() is expected
        assert attempts == SINGLE_ATTEMPT

    def test_negative_retry_count_clamps_to_disabled(self, monkeypatch):
        """Test that a negative retry count is reported as zero retries."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "-1")

        max_retries, _ = get_retry_config()

        assert max_retries == RETRIES_DISABLED

    def test_zero_retries_remains_the_documented_opt_out(self, monkeypatch):
        """Test that an explicit 0 still disables retries rather than defaulting."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "0")

        max_retries, _ = get_retry_config()

        assert max_retries == RETRIES_DISABLED

    def test_non_numeric_retry_count_falls_back_to_default(self, monkeypatch):
        """Test that a non-numeric retry count does not raise ValueError."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "three")

        max_retries, _ = get_retry_config()

        assert max_retries == DEFAULT_RETRY_MAX_ATTEMPTS

    def test_explicit_retry_count_is_honored(self, monkeypatch):
        """Test that a valid retry count is passed through unchanged."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", str(EXPLICIT_RETRY_ATTEMPTS))

        max_retries, _ = get_retry_config()

        assert max_retries == EXPLICIT_RETRY_ATTEMPTS


class TestRetryDelayBounds:
    """A delay that is negative or non-finite must not reach time.sleep()."""

    @pytest.mark.parametrize("raw", ["-1.0", "not-a-number", "nan", "inf"])
    def test_invalid_base_delay_falls_back_to_default(self, monkeypatch, raw):
        """Test that an unusable base delay resolves to the default."""
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", raw)

        _, base_delay = get_retry_config()

        assert base_delay == DEFAULT_RETRY_BASE_DELAY


class TestTimeoutBounds:
    """A timeout of zero or less disables the request; garbage must not crash."""

    @pytest.mark.parametrize("raw", ["0", "-5", "abc", "nan", "inf"])
    def test_unusable_timeout_falls_back_to_default(self, monkeypatch, raw):
        """Test that an unusable HTTP_TIMEOUT resolves to the default."""
        monkeypatch.setenv("HTTP_TIMEOUT", raw)

        assert get_timeout() == DEFAULT_HTTP_TIMEOUT


class TestJwksSizeBounds:
    """MAX_JWKS_SIZE is a DoS guard, so a typo must not remove the bound."""

    def test_non_numeric_size_falls_back_to_default(self, monkeypatch):
        """Test that a non-numeric MAX_JWKS_SIZE does not raise ValueError."""
        monkeypatch.setenv("MAX_JWKS_SIZE", "512KB")

        assert get_max_jwks_size() == DEFAULT_MAX_JWKS_SIZE

    def test_zero_or_negative_size_falls_back_to_default(self, monkeypatch):
        """Test that a non-positive MAX_JWKS_SIZE does not disable JWKS fetching."""
        monkeypatch.setenv("MAX_JWKS_SIZE", "0")

        assert get_max_jwks_size() == DEFAULT_MAX_JWKS_SIZE

    def test_non_numeric_key_count_falls_back_to_default(self, monkeypatch):
        """Test that a non-numeric MAX_JWKS_KEYS does not raise ValueError."""
        monkeypatch.setenv("MAX_JWKS_KEYS", "lots")

        assert get_max_jwks_keys() == DEFAULT_MAX_JWKS_KEYS


class TestAsyncRetryCountBounds:
    """The async twin resolves the same env var through the same parse site."""

    async def test_negative_retry_count_still_makes_one_attempt(self, monkeypatch):
        """Test that HTTP_RETRY_MAX_ATTEMPTS=-1 still issues the async request."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "-1")
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "0.01")

        attempts = 0
        expected = httpx.Response(HTTP_OK, request=httpx.Request("GET", URL))

        @retry_with_backoff_async()
        async def request():
            nonlocal attempts
            attempts += 1
            return expected

        assert await request() is expected
        assert attempts == SINGLE_ATTEMPT


class TestAliasResolution:
    """HTTP_RETRY_COUNT is the documented alias; blank primaries fall through."""

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_primary_falls_through_to_alias(self, monkeypatch, blank):
        """Test that a blank primary does not mask a set alias."""
        alias_value = 7
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", blank)
        monkeypatch.setenv("HTTP_RETRY_COUNT", str(alias_value))

        max_retries, _ = get_retry_config()

        assert max_retries == alias_value

    def test_primary_wins_over_alias(self, monkeypatch):
        """Test that a set primary takes precedence over the alias."""
        primary, alias = 4, 9
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", str(primary))
        monkeypatch.setenv("HTTP_RETRY_COUNT", str(alias))

        max_retries, _ = get_retry_config()

        assert max_retries == primary


class TestJwksKeysFloorIsPreserved:
    """max(1, ...) is deliberate and specified; only the warning is new."""

    @pytest.mark.parametrize("raw", ["0", "-5"])
    def test_non_positive_key_count_clamps_to_one(self, monkeypatch, raw):
        """Test that the specified clamp-to-1 behaviour is unchanged."""
        monkeypatch.setenv("MAX_JWKS_KEYS", raw)

        assert get_max_jwks_keys() == 1
