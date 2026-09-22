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

import pytest

from py_identity_model.core.http_utils import (
    DEFAULT_RETRY_BASE_DELAY,
    MAX_RETRY_DELAY_SECONDS,
    calculate_delay,
    get_max_retry_delay,
)


# 2**9 * 1.0 == 512s uncapped: the attempt index a retry-hardened deployment
# reaches after raising HTTP_RETRY_MAX_ATTEMPTS, which carries no ceiling.
LATE_ATTEMPT = 9
EARLY_ATTEMPT = 3
EXPECTED_EARLY_DELAY = 8.0
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
