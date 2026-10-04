"""
Proves the JWKS/discovery cache and the kid-miss cooldown use ``time.monotonic``
for all interval arithmetic, so wall-clock back-steps (NTP slew, container
clock-skew correction, manual sysadmin action) cannot:

- Leave a cache entry permanently "fresh" because ``time.time() - cached_at``
  goes negative.
- Wedge the kid-miss cooldown so a single dropped fetch suppresses every
  subsequent refresh attempt for the cooldown window.

Also pins the lock-ordering fix in ``_refresh_jwks``: ``request_time`` must be
captured *inside* the per-URI fetch lock so the ``cached_at >= request_time``
comparison reflects "now in the critical section" rather than "the moment
the caller decided to refresh, captured outside the lock and stale by the
time the lock was acquired."

See:
- https://github.com/jamescrowley321/identity-model/issues/400 (monotonic)
- https://github.com/jamescrowley321/identity-model/issues/404 (request_time race)
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.token_validation import (
    _kid_miss_last_attempt as async_kid_miss_last_attempt,
)
from py_identity_model.aio.token_validation import (
    _refresh_jwks as async_refresh_jwks,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.core.jwks_cache import (
    DiscoCacheEntry,
    JwksCacheEntry,
    _reset_env_for_testing,
    get_kid_miss_cooldown,
    is_cache_expired,
)
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    TokenValidationConfig,
)
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _kid_miss_last_attempt as sync_kid_miss_last_attempt,
)
from py_identity_model.sync.token_validation import (
    _refresh_jwks as sync_refresh_jwks,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    DISCO_URL,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = "https://example.com/jwks"
CLOCK_BACKSTEP_SECONDS = 60.0


@pytest.fixture(autouse=True)
async def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    _reset_env_for_testing()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    _reset_env_for_testing()


# ============================================================================
# is_cache_expired uses time.monotonic, not time.time.
#
# Pre-fix: ``time.time() - cached_at`` could go negative under NTP back-step,
# making the entry appear permanently fresh. Post-fix: ``time.monotonic()``
# is unaffected by wall-clock manipulation.
# ============================================================================


class TestCacheExpiryUsesMonotonicClock:
    def test_jwks_entry_expires_via_monotonic_when_walltime_steps_back(self):
        """Pre-fix this test would have failed: ``cached_at`` is a wall-clock
        timestamp, ``time.time()`` steps back by 60s, and ``age = time.time() -
        cached_at`` is negative for the remainder of the window — entry never
        appears expired. Post-fix: ``cached_at`` is monotonic; ``time.time()``
        manipulation is decoupled from expiry."""
        # Anchor a monotonic instant; the entry's TTL is 60s and we'll
        # advance only the monotonic clock past it.
        monotonic_base = time.monotonic()
        entry = JwksCacheEntry(
            response=MagicMock(),
            cached_at=monotonic_base,
            ttl=60.0,
        )

        # Step wall-clock backward by 60s — the kind of NTP slew that broke
        # the pre-fix logic. Independently advance monotonic past the TTL.
        walltime_back = time.time() - CLOCK_BACKSTEP_SECONDS
        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.time.return_value = walltime_back
            mock_time.monotonic.return_value = monotonic_base + 61.0
            assert is_cache_expired(entry) is True

    def test_jwks_entry_stays_fresh_when_only_walltime_advances(self):
        """The dual of the test above: wall-clock can race forward to past
        the TTL boundary while monotonic stays put, and the entry must NOT
        be considered expired — proving wall-clock is not consulted."""
        monotonic_base = time.monotonic()
        entry = JwksCacheEntry(
            response=MagicMock(),
            cached_at=monotonic_base,
            ttl=60.0,
        )

        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 86400.0
            mock_time.monotonic.return_value = monotonic_base + 30.0
            assert is_cache_expired(entry) is False

    def test_disco_entry_obeys_monotonic(self):
        """Symmetric coverage for ``DiscoCacheEntry`` since both share
        ``is_cache_expired``."""
        monotonic_base = time.monotonic()
        entry = DiscoCacheEntry(
            response=MagicMock(spec=DiscoveryDocumentResponse),
            cached_at=monotonic_base,
            ttl=300.0,
        )

        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.time.return_value = time.time() - 600.0
            mock_time.monotonic.return_value = monotonic_base + 301.0
            assert is_cache_expired(entry) is True


# ============================================================================
# Kid-miss cooldown uses monotonic, not wall-clock.
#
# Pre-fix: ``now - last`` after an NTP back-step is negative, so
# ``(now - last) >= cooldown`` is False forever (until wall-clock catches up).
# Post-fix: both ``now`` and ``last`` come from ``time.monotonic`` — back-step
# does not affect interval arithmetic.
# ============================================================================


class TestCooldownUsesMonotonicClock:
    @respx.mock
    def test_sync_cooldown_elapses_despite_wall_clock_backstep(self):
        """Stamp the cooldown via the real refresh path; then step wall-clock
        backward and advance monotonic past the cooldown window. The next
        kid-miss must refresh — pre-fix it would have been suppressed for
        the entire interval that wall-clock spent catching back up."""
        defender_kd, _ = generate_rsa_keypair()
        defender_kd["kid"] = "defender-kid"
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_kd]})
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        # Forge an unknown kid → triggers kid-miss → refresh → stamps cooldown
        # (because the refreshed JWKS still lacks the unknown kid).
        _, attacker_pem = generate_rsa_keypair()
        attacker_token = sign_jwt(
            attacker_pem,
            {"sub": "attacker", "iss": "https://example.com"},
            headers={"kid": "ghost-kid"},
        )
        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=attacker_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert JWKS_URL in sync_kid_miss_last_attempt
        # 1 prime + 1 kid-miss refresh.
        baseline_fetches = 2
        assert jwks_route.call_count == baseline_fetches

        cooldown = get_kid_miss_cooldown()

        # Wall-clock back-step paired with monotonic advance past cooldown.
        # The cooldown stamp itself was set with time.monotonic, so simulate
        # the elapse by mutating the stamp dict directly (it's just a float).
        sync_kid_miss_last_attempt[JWKS_URL] = time.monotonic() - cooldown - 1.0
        with patch("py_identity_model.sync.token_validation.time") as mock_time:
            mock_time.time.return_value = time.time() - CLOCK_BACKSTEP_SECONDS
            mock_time.monotonic.side_effect = time.monotonic

            with pytest.raises(TokenValidationException):
                validate_token(
                    jwt=attacker_token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )

        # A second refresh must have fired despite the wall-clock back-step,
        # because the cooldown elapsed on the monotonic clock.
        cooldown_elapsed_fetches = 3
        assert jwks_route.call_count == cooldown_elapsed_fetches

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_cooldown_elapses_despite_wall_clock_backstep(self):
        defender_kd, _ = generate_rsa_keypair()
        defender_kd["kid"] = "defender-kid"
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_kd]})
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        _, attacker_pem = generate_rsa_keypair()
        attacker_token = sign_jwt(
            attacker_pem,
            {"sub": "attacker", "iss": "https://example.com"},
            headers={"kid": "ghost-kid"},
        )
        with pytest.raises(TokenValidationException):
            await async_validate_token(
                jwt=attacker_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert JWKS_URL in async_kid_miss_last_attempt
        baseline_fetches = 2
        assert jwks_route.call_count == baseline_fetches

        cooldown = get_kid_miss_cooldown()
        async_kid_miss_last_attempt[JWKS_URL] = time.monotonic() - cooldown - 1.0

        with patch("py_identity_model.aio.token_validation.time") as mock_time:
            mock_time.time.return_value = time.time() - CLOCK_BACKSTEP_SECONDS
            mock_time.monotonic.side_effect = time.monotonic

            with pytest.raises(TokenValidationException):
                await async_validate_token(
                    jwt=attacker_token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )

        cooldown_elapsed_fetches = 3
        assert jwks_route.call_count == cooldown_elapsed_fetches


# ============================================================================
# _refresh_jwks captures request_time INSIDE the fetch lock.
#
# Pre-fix: ``request_time = time.time()`` was captured before the lock
# acquisition, so under contention the comparison ``cached_at >= request_time``
# was evaluated against a stale timestamp. Post-fix: ``request_time`` is
# captured after lock acquisition so the comparison is well-defined relative
# to the current critical section.
#
# Strategy: wrap the per-URI fetch lock so its acquisition appends an event;
# wrap ``time.monotonic`` so its calls append events too. Assert the first
# ``time.monotonic`` call inside ``_refresh_jwks`` happens AFTER the lock
# was acquired.
# ============================================================================


class _EventRecorder:
    def __init__(self) -> None:
        self.events: list[str] = []
        self._sync_event_lock = threading.Lock()

    def append(self, event: str) -> None:
        with self._sync_event_lock:
            self.events.append(event)


class _TrackedSyncLock:
    """Context-manager-only lock wrapper — production code uses ``with
    fetch_lock:`` so explicit acquire/release pass-throughs aren't needed."""

    def __init__(self, recorder: _EventRecorder) -> None:
        self._lock = threading.Lock()
        self._recorder = recorder

    def __enter__(self) -> Any:
        self._lock.acquire()
        self._recorder.append("lock_acquired")
        return self

    def __exit__(self, *exc: object) -> None:
        self._recorder.append("lock_released")
        self._lock.release()


class _TrackedAsyncLock:
    def __init__(self, recorder: _EventRecorder) -> None:
        self._lock = asyncio.Lock()
        self._recorder = recorder

    async def __aenter__(self) -> Any:
        await self._lock.acquire()
        self._recorder.append("lock_acquired")
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._recorder.append("lock_released")
        self._lock.release()


class TestRefreshJwksRequestTimeInsideLock:
    @respx.mock
    def test_sync_request_time_captured_after_lock_acquired(self, monkeypatch):
        """The first ``time.monotonic`` call from inside ``_refresh_jwks``
        must follow lock acquisition. Pre-fix the call was emitted BEFORE
        ``with fetch_lock:`` and this assertion would have failed."""
        key_dict = generate_rsa_keypair()[0]
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        recorder = _EventRecorder()
        tracked_lock = _TrackedSyncLock(recorder)
        monkeypatch.setattr(sync_tv, "_get_jwks_fetch_lock", lambda _uri: tracked_lock)

        real_monotonic = time.monotonic

        def recording_monotonic() -> float:
            recorder.append("monotonic_called")
            return real_monotonic()

        monkeypatch.setattr(sync_tv.time, "monotonic", recording_monotonic)

        sync_refresh_jwks(JWKS_URL)

        # The very first lock_acquired event must precede the first
        # monotonic_called event.
        first_lock = recorder.events.index("lock_acquired")
        first_monotonic = recorder.events.index("monotonic_called")
        assert first_lock < first_monotonic, (
            "request_time must be captured inside the fetch lock; observed "
            f"event order: {recorder.events}"
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_request_time_captured_after_lock_acquired(self, monkeypatch):
        key_dict = generate_rsa_keypair()[0]
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        recorder = _EventRecorder()
        tracked_lock = _TrackedAsyncLock(recorder)
        monkeypatch.setattr(aio_tv, "_get_jwks_fetch_lock", lambda _uri: tracked_lock)

        real_monotonic = time.monotonic

        def recording_monotonic() -> float:
            recorder.append("monotonic_called")
            return real_monotonic()

        monkeypatch.setattr(aio_tv.time, "monotonic", recording_monotonic)

        await async_refresh_jwks(JWKS_URL)

        first_lock = recorder.events.index("lock_acquired")
        first_monotonic = recorder.events.index("monotonic_called")
        assert first_lock < first_monotonic, (
            "request_time must be captured inside the fetch lock; observed "
            f"event order: {recorder.events}"
        )
