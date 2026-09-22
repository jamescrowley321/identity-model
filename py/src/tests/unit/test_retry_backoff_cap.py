"""The documented per-wait ceiling must hold, and must stay overridable.

``MAX_RETRY_DELAY_SECONDS`` is documented as the bound on a single retry wait,
but only the response path (429/5xx, via ``resolve_retry_delay``) applied it.
The connection-error path calls ``calculate_delay`` directly, so
``base * 2**attempt`` grew without limit -- and the sync client spends that in
``time.sleep``, holding an OS thread and the striped per-URI JWKS fetch lock
with it.

The ceiling is a default, not a hard limit: a deployment that deliberately wants
longer waits raises ``HTTP_RETRY_MAX_DELAY`` and gets them.
"""

import logging
import os
from unittest import mock

import httpx
import pytest

from py_identity_model.aio.http_client import retry_with_backoff_async
from py_identity_model.core.http_utils import (
    _WARNED,
    DEFAULT_RETRY_BASE_DELAY,
    MAX_RETRY_DELAY_SECONDS,
    calculate_delay,
    get_max_retry_delay,
    get_timeout,
)
from py_identity_model.sync.http_client import retry_with_backoff


# 2**9 * 1.0 == 512s uncapped: the attempt index a retry-hardened deployment
# reaches after raising HTTP_RETRY_MAX_ATTEMPTS, which carries no ceiling.
LATE_ATTEMPT = 9
EARLY_ATTEMPT = 3
EXPECTED_EARLY_DELAY = 8.0
HTTP_OK = 200
URL = "https://issuer.example.com/.well-known/openid-configuration"
SINGLE_ATTEMPT = 1
RAISED_CEILING = 600.0
UNCLAMPED_LATE_DELAY = 512.0
EXPLICIT_CEILING = 5.0


class TestBackoffRespectsTheCeiling:
    """No single wait may exceed the effective ceiling."""

    @pytest.mark.parametrize("attempt", range(25))
    def test_no_attempt_exceeds_the_default_ceiling(self, attempt):
        """Test that the default ceiling holds at every attempt index."""
        assert calculate_delay(DEFAULT_RETRY_BASE_DELAY, attempt) <= (
            MAX_RETRY_DELAY_SECONDS
        )

    def test_late_attempt_saturates_at_the_ceiling(self):
        """Test that a late attempt returns the ceiling, not 512s."""
        assert (
            calculate_delay(DEFAULT_RETRY_BASE_DELAY, LATE_ATTEMPT)
            == MAX_RETRY_DELAY_SECONDS
        )

    def test_a_large_base_delay_cannot_exceed_the_ceiling(self):
        """Test that the ceiling bounds the product, not just the base."""
        # 120 * 2**9 == 61440s (~17 hours) unbounded.
        assert (
            calculate_delay(MAX_RETRY_DELAY_SECONDS, LATE_ATTEMPT)
            == MAX_RETRY_DELAY_SECONDS
        )

    def test_ordinary_backoff_is_unchanged(self):
        """Test that delays below the ceiling keep their exponential value."""
        assert (
            calculate_delay(DEFAULT_RETRY_BASE_DELAY, EARLY_ATTEMPT)
            == EXPECTED_EARLY_DELAY
        )


class TestCeilingIsADefaultNotALimit:
    """A configured ceiling must win over the built-in default."""

    def test_configured_ceiling_is_honored(self, monkeypatch):
        """Test that HTTP_RETRY_MAX_DELAY raises the ceiling above the default."""
        monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", str(RAISED_CEILING))

        # A deployment that deliberately wants longer waits gets them rather
        # than being silently held at a number it did not choose. At attempt 9
        # the natural backoff is 512s: under the default ceiling it would be
        # clamped to 120, and under the raised one it is left alone.
        assert get_max_retry_delay() == RAISED_CEILING
        assert (
            calculate_delay(DEFAULT_RETRY_BASE_DELAY, LATE_ATTEMPT)
            == UNCLAMPED_LATE_DELAY
        )
        assert UNCLAMPED_LATE_DELAY > MAX_RETRY_DELAY_SECONDS

    def test_explicit_argument_overrides_the_resolved_ceiling(self, monkeypatch):
        """Test that a passed max_delay wins over the environment."""
        monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", str(RAISED_CEILING))

        assert (
            calculate_delay(
                DEFAULT_RETRY_BASE_DELAY, LATE_ATTEMPT, max_delay=EXPLICIT_CEILING
            )
            == EXPLICIT_CEILING
        )

    def test_unset_ceiling_falls_back_to_the_documented_default(self, monkeypatch):
        """Test that the default applies when nothing is configured."""
        monkeypatch.delenv("HTTP_RETRY_MAX_DELAY", raising=False)

        assert get_max_retry_delay() == MAX_RETRY_DELAY_SECONDS

    @pytest.mark.parametrize("raw", ["0", "-5", "abc", "nan"])
    def test_unusable_ceiling_falls_back_to_the_default(self, monkeypatch, raw):
        """Test that an unusable ceiling does not disable retry pacing."""
        monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", raw)

        assert get_max_retry_delay() == MAX_RETRY_DELAY_SECONDS


class TestArgumentPathIsGuardedToo:
    """The decorator takes these values directly, bypassing the env bounds."""

    def test_negative_max_retries_argument_still_issues_the_request(self):
        """Test that retry_with_backoff(max_retries=-1) does not cancel the call."""
        attempts = 0
        expected = httpx.Response(HTTP_OK, request=httpx.Request("GET", URL))

        @retry_with_backoff(max_retries=-1)
        def request():
            nonlocal attempts
            attempts += 1
            return expected

        # get_retry_config clamps the env path, but the decorator argument
        # reaches range(retries + 1) directly -- the guard there is what this
        # exercises, and deleting it leaves the env tests green.
        assert request() is expected
        assert attempts == SINGLE_ATTEMPT

    async def test_negative_max_retries_argument_on_the_async_twin(self):
        """Test that the async decorator guards the same argument."""
        attempts = 0
        expected = httpx.Response(HTTP_OK, request=httpx.Request("GET", URL))

        @retry_with_backoff_async(max_retries=-1)
        async def request():
            nonlocal attempts
            attempts += 1
            return expected

        assert await request() is expected
        assert attempts == SINGLE_ATTEMPT

    def test_negative_base_delay_argument_never_reaches_sleep(self):
        """Test that a negative base_delay cannot raise out of time.sleep()."""
        # min() alone bounded the top; a negative base produced a negative delay
        # that raised ValueError from inside the RequestError handler, masking
        # the network error being retried.
        assert calculate_delay(-1.0, EARLY_ATTEMPT) >= 0.0

    def test_a_huge_attempt_count_does_not_overflow(self):
        """Test that 2**attempt cannot raise OverflowError out of the decorator."""
        # HTTP_RETRY_MAX_ATTEMPTS has no ceiling by design, so attempt can reach
        # values where 2**attempt stops converting to float.
        assert calculate_delay(DEFAULT_RETRY_BASE_DELAY, 4096) == (
            MAX_RETRY_DELAY_SECONDS
        )


class TestMisconfigurationIsVisible:
    """A silent fallback is the failure mode these warnings exist to prevent."""

    def test_invalid_value_warns_naming_the_variable(self, caplog):
        """Test that an unparseable value logs a warning naming the variable."""
        _WARNED.clear()
        with (
            caplog.at_level(logging.WARNING),
            mock.patch.dict(os.environ, {"HTTP_TIMEOUT": "abc"}, clear=True),
        ):
            get_timeout()

        assert "HTTP_TIMEOUT" in caplog.text

    def test_the_warning_fires_only_once(self, caplog):
        """Test that a per-request getter does not warn on every call."""
        _WARNED.clear()
        with (
            caplog.at_level(logging.WARNING),
            mock.patch.dict(os.environ, {"HTTP_TIMEOUT": "abc"}, clear=True),
        ):
            get_timeout()
            first = len(caplog.records)
            get_timeout()
            get_timeout()

        # These run on every HTTP request; warning per call would bury the line
        # that explains the misconfiguration.
        assert first == 1
        assert len(caplog.records) == first
