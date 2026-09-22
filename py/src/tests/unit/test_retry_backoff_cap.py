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
import math
import os
import sys
import time
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
    get_retry_config,
    get_timeout,
)
from py_identity_model.sync import http_client as sync_http_client
from py_identity_model.sync.http_client import (
    SLEEP_SLICE_SECONDS,
    _sleep,
    retry_with_backoff,
)


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
# The smallest positive float and the largest finite one: both are valid under
# spec/config.md (`>= 0` and `> 0`, no upper bound), and their ratio is not a
# finite float.
SMALLEST_BASE = math.ulp(0.0)
LARGEST_CEILING = sys.float_info.max
# 2**attempt stops converting to float at this exponent.
FLOAT_EXPONENT_LIMIT = sys.float_info.max_exp
# The first attempt at which SMALLEST_BASE * 2**attempt is no longer a finite
# float, so the delay must already read as LARGEST_CEILING.
SUBNORMAL_TO_MAX_ATTEMPT = FLOAT_EXPONENT_LIMIT - math.frexp(SMALLEST_BASE)[1] + 1
UNUSABLE_CEILINGS = [-5.0, 0.0, float("nan"), float("inf"), float("-inf")]
# time.sleep() converts its argument to a signed 64-bit nanosecond count and
# raises OverflowError at or past this many seconds, on every platform.
PYTIME_LIMIT_SECONDS = (2**63 - 1) / 1_000_000_000
# A wait time.sleep() cannot take in one call, but far too small to loop for
# long when sliced against a fake clock.
UNREPRESENTABLE_WAIT = PYTIME_LIMIT_SECONDS * 2
EXTREME_PAIRS = [
    (SMALLEST_BASE, LARGEST_CEILING),
    (sys.float_info.min, LARGEST_CEILING),
    (1e-300, 1e300),
    (LARGEST_CEILING / 2, LARGEST_CEILING),
    (SMALLEST_BASE, SMALLEST_BASE * 4),
    (DEFAULT_RETRY_BASE_DELAY, MAX_RETRY_DELAY_SECONDS),
]
BOUNDARY_ATTEMPTS = [
    0,
    1,
    EARLY_ATTEMPT,
    FLOAT_EXPONENT_LIMIT - 1,
    FLOAT_EXPONENT_LIMIT,
    SUBNORMAL_TO_MAX_ATTEMPT - 1,
    SUBNORMAL_TO_MAX_ATTEMPT,
    SUBNORMAL_TO_MAX_ATTEMPT * 2,
]


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


class TestCalculateDelayCannotRaise:
    """calculate_delay runs inside the RequestError handler.

    Anything it raises replaces the network error the caller was going to see,
    so every argument combination must return a number in [0, ceiling].
    """

    @pytest.mark.parametrize("bad_ceiling", UNUSABLE_CEILINGS, ids=repr)
    def test_unusable_max_delay_argument_uses_the_resolved_ceiling(
        self, bad_ceiling, monkeypatch
    ):
        """Test that a bad explicit ceiling falls back like a bad env value."""
        monkeypatch.delenv("HTTP_RETRY_MAX_DELAY", raising=False)
        _WARNED.clear()
        # get_max_retry_delay() already refuses these from the environment;
        # the argument bypassed that and reached time.sleep() (negative) or
        # math.ceil() (nan / inf).
        expected = calculate_delay(DEFAULT_RETRY_BASE_DELAY, LATE_ATTEMPT)
        assert expected == MAX_RETRY_DELAY_SECONDS
        assert (
            calculate_delay(
                DEFAULT_RETRY_BASE_DELAY, LATE_ATTEMPT, max_delay=bad_ceiling
            )
            == expected
        )

    def test_unusable_max_delay_argument_warns_once(self, caplog):
        """Test that the fallback is visible, and not once per retry."""
        _WARNED.clear()
        with caplog.at_level(logging.WARNING):
            calculate_delay(DEFAULT_RETRY_BASE_DELAY, EARLY_ATTEMPT, max_delay=-1.0)
            calculate_delay(DEFAULT_RETRY_BASE_DELAY, EARLY_ATTEMPT, max_delay=-1.0)

        assert len(caplog.records) == 1
        assert "max_delay" in caplog.text

    @pytest.mark.parametrize("attempt", BOUNDARY_ATTEMPTS)
    @pytest.mark.parametrize(("base", "ceiling"), EXTREME_PAIRS)
    def test_extreme_finite_settings_stay_within_bounds(self, base, ceiling, attempt):
        """Test that no valid base/ceiling pair can raise out of the arithmetic."""
        # ceiling / base overflowed to inf for the first pair, and math.ceil(inf)
        # raised OverflowError -- with both values valid under the spec.
        delay = calculate_delay(base, attempt, max_delay=ceiling)
        assert 0.0 <= delay <= ceiling

    @pytest.mark.parametrize(("base", "ceiling"), EXTREME_PAIRS)
    def test_delay_never_decreases_and_reaches_the_ceiling(self, base, ceiling):
        """Test that backoff is monotone and saturates, for every extreme pair."""
        delays = [
            calculate_delay(base, attempt, max_delay=ceiling)
            for attempt in range(SUBNORMAL_TO_MAX_ATTEMPT + 1)
        ]
        assert delays == sorted(delays)
        assert delays[0] == base
        assert delays[-1] == ceiling

    def test_extreme_environment_values_cannot_raise_on_the_request_path(
        self, monkeypatch
    ):
        """Test the crash through the env path: both values are documented valid."""
        monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", repr(SMALLEST_BASE))
        monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", repr(LARGEST_CEILING))
        _, base_delay = get_retry_config()
        assert base_delay == SMALLEST_BASE
        assert get_max_retry_delay() == LARGEST_CEILING

        delay = calculate_delay(base_delay, EARLY_ATTEMPT)
        assert 0.0 <= delay <= LARGEST_CEILING


class FakeClock:
    """A time.sleep that records and totals instead of waiting.

    It enforces the same limit CPython's real one does, so a test that passes
    here would not crash against the real clock either.
    """

    def __init__(self) -> None:
        self.now = 0.0
        self.slices: list[float] = []

    def sleep(self, seconds: float) -> None:
        if seconds >= PYTIME_LIMIT_SECONDS:
            raise OverflowError("timestamp out of range for C PyTime_t")
        self.slices.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(sync_http_client.time, "sleep", clock.sleep)
    return clock


class TestAnyFiniteWaitIsExecutable:
    """HTTP_RETRY_MAX_DELAY is documented `> 0` with no upper bound.

    That was untrue in execution: time.sleep() raises OverflowError past the
    signed 64-bit nanosecond range, so a ceiling such as 1e308 -- valid under
    the spec, accepted by get_max_retry_delay() -- crashed the sync retry loop
    from inside the RequestError handler, replacing the network error.
    """

    def test_the_platform_sleep_rejects_a_spec_valid_wait(self):
        """Test the stdlib fact the sliced sleep exists for."""
        with pytest.raises(OverflowError):
            time.sleep(LARGEST_CEILING)

    def test_short_waits_are_a_single_sleep(self, fake_clock):
        """Test that ordinary delays still map to one time.sleep() call."""
        _sleep(EXPECTED_EARLY_DELAY)
        assert fake_clock.slices == [EXPECTED_EARLY_DELAY]

    def test_a_non_positive_wait_does_not_sleep(self, fake_clock):
        """Test that a zero or negative wait returns without calling sleep."""
        _sleep(0.0)
        _sleep(-1.0)
        assert fake_clock.slices == []

    def test_a_long_wait_is_sliced_to_what_sleep_accepts(self, fake_clock):
        """Test that no slice exceeds the bound and the slices sum to the wait."""
        _sleep(UNREPRESENTABLE_WAIT)
        assert max(fake_clock.slices) <= SLEEP_SLICE_SECONDS
        assert math.isclose(sum(fake_clock.slices), UNREPRESENTABLE_WAIT)
        assert fake_clock.now == pytest.approx(UNREPRESENTABLE_WAIT)

    def test_sync_retry_survives_an_unrepresentable_ceiling(
        self, fake_clock, monkeypatch
    ):
        """Test that the network error, not OverflowError, reaches the caller."""
        monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", repr(UNREPRESENTABLE_WAIT))
        _WARNED.clear()
        request = httpx.Request("GET", URL)

        @retry_with_backoff(max_retries=SINGLE_ATTEMPT, base_delay=UNREPRESENTABLE_WAIT)
        def unreachable():
            raise httpx.ConnectError("refused", request=request)

        # Reverting the sliced sleep makes this raise OverflowError instead:
        # the FakeClock enforces the same bound the real time.sleep() does.
        with pytest.raises(httpx.ConnectError):
            unreachable()
        assert fake_clock.now == pytest.approx(UNREPRESENTABLE_WAIT)


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
