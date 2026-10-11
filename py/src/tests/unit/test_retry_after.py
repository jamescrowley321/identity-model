"""Tests for ``Retry-After`` handling in the HTTP retry logic."""

from datetime import UTC, datetime
from email.utils import format_datetime

import httpx
import pytest

from py_identity_model import Config
from py_identity_model.core.http_utils import (
    MAX_RETRY_DELAY_SECONDS,
    parse_retry_after,
    resolve_retry_delay,
)
from py_identity_model.sync.http_client import retry_with_backoff
from py_identity_model.sync.managed_client import HTTPClient


# Reference epoch for deterministic HTTP-date parsing
FIXED_NOW = 1_000_000.0
RETRY_AFTER_DELTA = 45.0
PAST_DELTA = 60.0

# resolve_retry_delay expectations
BACKOFF_BASE = 1.0
BACKOFF_AT_ATTEMPT_1 = 2.0  # 1.0 * 2**1
BACKOFF_AT_ATTEMPT_3 = 8.0  # 1.0 * 2**3
RETRY_AFTER_SMALL = 10.0
HTTP_OK = 200
SLEEP_SECONDS = 7.0


def _response(headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(429, headers=headers or {})


class TestParseRetryAfter:
    """``parse_retry_after`` covers the RFC 9110 delta-seconds + HTTP-date forms."""

    def test_absent_returns_none(self):
        assert parse_retry_after(None) is None

    def test_blank_returns_none(self):
        assert parse_retry_after("   ") is None

    def test_delta_seconds(self):
        assert parse_retry_after("30") == pytest.approx(30.0)

    def test_unparseable_returns_none(self):
        assert parse_retry_after("not-a-date") is None

    def test_http_date_future(self):
        future = datetime.fromtimestamp(FIXED_NOW + RETRY_AFTER_DELTA, tz=UTC)
        assert parse_retry_after(
            format_datetime(future), now=FIXED_NOW
        ) == pytest.approx(RETRY_AFTER_DELTA, abs=1.0)

    def test_http_date_in_past_clamps_to_zero(self):
        past = datetime.fromtimestamp(FIXED_NOW - PAST_DELTA, tz=UTC)
        assert parse_retry_after(format_datetime(past), now=FIXED_NOW) == 0.0


class TestResolveRetryDelay:
    """``resolve_retry_delay`` honors Retry-After but never below the backoff."""

    def test_no_header_uses_backoff(self):
        assert resolve_retry_delay(
            _response(), base_delay=BACKOFF_BASE, attempt=1
        ) == pytest.approx(BACKOFF_AT_ATTEMPT_1)

    def test_retry_after_larger_than_backoff_wins(self):
        delay = resolve_retry_delay(
            _response({"Retry-After": "10"}), base_delay=BACKOFF_BASE, attempt=0
        )
        assert delay == pytest.approx(RETRY_AFTER_SMALL)

    def test_backoff_larger_than_retry_after_wins(self):
        delay = resolve_retry_delay(
            _response({"Retry-After": "2"}), base_delay=BACKOFF_BASE, attempt=3
        )
        assert delay == pytest.approx(BACKOFF_AT_ATTEMPT_3)

    def test_retry_after_capped(self):
        delay = resolve_retry_delay(
            _response({"Retry-After": "99999"}), base_delay=BACKOFF_BASE, attempt=0
        )
        assert delay == pytest.approx(MAX_RETRY_DELAY_SECONDS)


class TestSyncRetryHonorsRetryAfter:
    """The sync retry decorator waits for the Retry-After interval on a 429."""

    def test_sleep_uses_retry_after(self, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr(
            "py_identity_model.sync.http_client.time.sleep", slept.append
        )

        responses = [
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(HTTP_OK),
        ]

        @retry_with_backoff()
        def call(_client: httpx.Client) -> httpx.Response:
            return responses.pop(0)

        config = Config(http_retry_max_attempts=1, http_retry_base_delay=0)
        with HTTPClient(config=config) as client:
            result = call(client)

        assert result.status_code == HTTP_OK
        # base_delay is 0, so without Retry-After the wait would be 0; it is 7.
        assert slept == [SLEEP_SECONDS]
