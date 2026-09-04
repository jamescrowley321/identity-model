"""
Asynchronous token validation with TTL-based JWKS and discovery caching.

This module provides asynchronous token validation using discovery and JWKS,
with automatic cache expiry and forced JWKS refresh on key rotation.
"""

import asyncio
from collections import OrderedDict
import threading
import time
from weakref import WeakKeyDictionary

from ..core.cache_metrics import get_cache_counters
from ..core.discovery_policy import (
    DiscoveryPolicy,
    resolve_discovery_policy,
    validate_url_scheme,
)
from ..core.jwks_cache import (
    DiscoCacheEntry,
    JwksCacheEntry,
    apply_disco_cache_outcome,
    apply_jwks_cache_outcome,
    clear_cache_locked,
    is_cache_expired,
    should_attempt_kid_miss_refresh,
    touch_cache_entry,
)
from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
)
from ..core.parsers import (
    extract_jwt_header_fields,
    find_key_by_kid,
)
from ..core.token_validation_logic import (
    build_resolved_config,
    decode_with_config,
    log_validation_start,
    log_validation_success,
    validate_async_claims,
    validate_config_for_manual_validation,
    validate_disco_response,
    validate_jwks_response,
    validate_jwks_uri,
)
from ..core.validators import validate_token_config
from ..exceptions import ConfigurationException, SignatureVerificationException
from ..logging_config import logger
from .discovery import get_discovery_document
from .jwks import get_jwks
from .managed_client import AsyncHTTPClient


# ============================================================================
# Upstream-fetch accounting
# ============================================================================


def _upstream_fetch_attempted(address: str, policy: DiscoveryPolicy) -> bool:
    """Return ``True`` when an upstream fetch was actually attempted for *address*.

    ``get_discovery_document`` / ``get_jwks`` short-circuit to an *unsuccessful*
    response **before any network I/O** only when the pre-flight scheme check
    (:func:`validate_url_scheme`) rejects the address. Every other unsuccessful
    outcome — a ``429``/``5xx`` upstream response, a connection error/timeout —
    followed a real network round trip.

    The fetch-volume counters must count those round trips *including the failed
    ones*: a ``429``/``5xx`` during an upstream outage is exactly the signal an
    operator watches this metric for, and gating on ``response.is_successful``
    silently drops it (the outage reads as zero upstream fetches). So gate the
    miss/refresh increment on "did we get past the scheme check" — which is a
    pure, side-effect-free re-parse of the same policy the fetch itself applied —
    rather than on the response status. A scheme-rejected request (zero upstream
    work, e.g. a forged plaintext ``http://`` URI) is the only excluded case, so
    it still cannot inflate the tally.
    """
    try:
        validate_url_scheme(address, policy)
    except ConfigurationException:
        return False
    return True


# ============================================================================
# Discovery TTL cache
# ============================================================================

# Discovery TTL cache — keyed by (address, policy.cache_key()) to prevent policy
# bypass: a response admitted under a lax policy must never be served to a caller
# running a stricter one. (Formerly keyed on the require_https bool alone; the
# full-policy key generalises that guard now that any policy knob is injectable.)
# OrderedDict (not a plain dict) so read hits can refresh LRU recency via
# ``touch_cache_entry``; eviction targets the least recently *used* entry (#397).
_disco_cache: OrderedDict[tuple[str, tuple], DiscoCacheEntry] = OrderedDict()

# Per-event-loop lock storage. Module-level ``asyncio.Lock()`` instances bind
# to whichever event loop first calls ``.acquire()`` (Python 3.10+), so any
# embed or test runner that creates a new loop per scope hits
# ``RuntimeError: <Lock> is bound to a different event loop``. Keying locks
# on the running loop via ``WeakKeyDictionary`` gives each loop its own
# independent lock set, and the entries get reclaimed when a loop is closed.
# ``_lock_creation_lock`` is a plain ``threading.Lock`` so creation is safe
# from any thread regardless of which loop is running. See #399.
_DISCO_LOCK_STRIPES = 32
_JWKS_LOCK_STRIPES = 32
_disco_cache_write_locks: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    WeakKeyDictionary()
)
_disco_fetch_locks_by_loop: WeakKeyDictionary[
    asyncio.AbstractEventLoop, list[asyncio.Lock]
] = WeakKeyDictionary()
_jwks_cache_write_locks: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    WeakKeyDictionary()
)
_jwks_fetch_locks_by_loop: WeakKeyDictionary[
    asyncio.AbstractEventLoop, list[asyncio.Lock]
] = WeakKeyDictionary()
_lock_creation_lock = threading.Lock()


def _get_disco_cache_write_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _disco_cache_write_locks.get(loop)
    if lock is None:
        with _lock_creation_lock:
            lock = _disco_cache_write_locks.get(loop)
            if lock is None:
                lock = asyncio.Lock()
                _disco_cache_write_locks[loop] = lock
    return lock


def _get_disco_fetch_lock(cache_key: tuple[str, tuple]) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    stripes = _disco_fetch_locks_by_loop.get(loop)
    if stripes is None:
        with _lock_creation_lock:
            stripes = _disco_fetch_locks_by_loop.get(loop)
            if stripes is None:
                stripes = [asyncio.Lock() for _ in range(_DISCO_LOCK_STRIPES)]
                _disco_fetch_locks_by_loop[loop] = stripes
    return stripes[hash(cache_key) % _DISCO_LOCK_STRIPES]


async def _get_disco_response(
    disco_doc_address: str | None,
    policy: DiscoveryPolicy | None = None,
) -> DiscoveryDocumentResponse:
    """Cached async discovery document fetching with TTL.

    Cache-aside with per-URI single-flight: a fresh cached entry returns
    without acquiring any lock; only the upstream fetch on a cache miss
    is serialized, and only against other requests for the same address.

    ``policy`` (default: strict :class:`DiscoveryPolicy`) both governs
    validation of the fetched document and partitions the cache, so callers
    with different policies never share an entry.
    """
    if disco_doc_address is None:
        raise ConfigurationException(
            "disco_doc_address is required when perform_disco is True"
        )

    if policy is None:
        policy = DiscoveryPolicy()
    cache_key = (disco_doc_address, policy.cache_key())
    entry = _disco_cache.get(cache_key)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency — touch_cache_entry serializes the reorder against
        # _enforce_size_limit via the process-wide structure lock. The async
        # write locks are keyed per event loop, so they cannot guard reordering
        # against an eviction on another loop sharing this module-global cache;
        # the process-wide lock inside touch_cache_entry does (#397).
        touch_cache_entry(_disco_cache, cache_key)
        get_cache_counters().record_disco_hit()
        return entry.response

    fetch_lock = _get_disco_fetch_lock(cache_key)
    async with fetch_lock:
        entry = _disco_cache.get(cache_key)
        if entry is not None and not is_cache_expired(entry):
            # Double-checked hit: another coroutine populated the entry while we
            # waited on the fetch lock. This is a genuine cache hit, not a miss —
            # counting it as a miss would inflate the miss rate under concurrent
            # warmup.
            touch_cache_entry(_disco_cache, cache_key)
            get_cache_counters().record_disco_hit()
            return entry.response

        response = await get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
        )
        # Count the miss whenever an upstream fetch was actually attempted —
        # including a 429/5xx or a connection error (a real round trip whose
        # volume this counter exists to surface during an outage). Only a
        # scheme-rejected address does zero network work and is excluded; see
        # _upstream_fetch_attempted. Gating on response.is_successful instead
        # would silently drop failed fetches and make an upstream outage read as
        # zero upstream volume.
        if _upstream_fetch_attempted(disco_doc_address, policy):
            get_cache_counters().record_disco_miss()
        async with _get_disco_cache_write_lock():
            apply_disco_cache_outcome(
                _disco_cache, cache_key, response, time.monotonic()
            )
        return response


async def clear_discovery_cache() -> None:
    """Clear the discovery cache.

    **Breaking change (v3.0.0):** this helper is now ``async`` so it can
    acquire the disco-cache write lock before clearing. The previous
    synchronous version mutated state guarded by an ``asyncio.Lock``
    without awaiting it, so a coroutine mid-flight in ``_refresh_jwks``
    could write its result back *after* ``clear()`` ran, leaving the
    "cleared" cache holding an entry. Callers must now ``await``.

    Acquires the *current loop's* write lock. The cache dict itself is
    process-shared, so the clear is visible to operations on any loop;
    in-flight writes on a different loop are not coordinated with this
    clear, which matches the prior (single-lock) semantics modulo the
    per-loop lock plumbing for #399.
    """
    async with _get_disco_cache_write_lock():
        clear_cache_locked(_disco_cache)


# ============================================================================
# TTL-aware JWKS cache (replaces @alru_cache for JWKS)
# ============================================================================

_jwks_cache: OrderedDict[str, JwksCacheEntry] = OrderedDict()

# See sync._kid_miss_last_attempt for rationale. Guarded by the per-loop
# JWKS cache write lock.
_kid_miss_last_attempt: dict[str, float] = {}


def _get_jwks_cache_write_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _jwks_cache_write_locks.get(loop)
    if lock is None:
        with _lock_creation_lock:
            lock = _jwks_cache_write_locks.get(loop)
            if lock is None:
                lock = asyncio.Lock()
                _jwks_cache_write_locks[loop] = lock
    return lock


def _get_jwks_fetch_lock(jwks_uri: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    stripes = _jwks_fetch_locks_by_loop.get(loop)
    if stripes is None:
        with _lock_creation_lock:
            stripes = _jwks_fetch_locks_by_loop.get(loop)
            if stripes is None:
                stripes = [asyncio.Lock() for _ in range(_JWKS_LOCK_STRIPES)]
                _jwks_fetch_locks_by_loop[loop] = stripes
    return stripes[hash(jwks_uri) % _JWKS_LOCK_STRIPES]


async def _get_cached_jwks(
    jwks_uri: str, policy: DiscoveryPolicy | None = None
) -> JwksResponse:
    """Return cached JWKS response if fresh, otherwise fetch and cache.

    Cache-aside with per-URI single-flight (see ``_get_disco_response``).
    """
    if policy is None:
        policy = DiscoveryPolicy()
    entry = _jwks_cache.get(jwks_uri)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency (see _get_disco_response) — self-serializing via
        # the process-wide structure lock, no per-loop write lock needed.
        touch_cache_entry(_jwks_cache, jwks_uri)
        get_cache_counters().record_jwks_hit()
        return entry.response

    fetch_lock = _get_jwks_fetch_lock(jwks_uri)
    async with fetch_lock:
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and not is_cache_expired(entry):
            # Double-checked hit populated by a concurrent fetch (see
            # _get_disco_response) — count as a hit, not a miss.
            touch_cache_entry(_jwks_cache, jwks_uri)
            get_cache_counters().record_jwks_hit()
            return entry.response

        # The jwks_uri was already vetted against this policy when the
        # discovery document was processed; thread it through so the
        # pre-flight scheme check inside get_jwks() does not double-reject.
        response = await get_jwks(JwksRequest(address=jwks_uri, policy=policy))
        # Count the miss whenever an upstream fetch was attempted, including a
        # 429/5xx round trip (fetch volume during an outage is the signal). Only
        # a scheme-rejected URI (e.g. plaintext http:// under the default policy)
        # does zero network work and is excluded; see _upstream_fetch_attempted.
        if _upstream_fetch_attempted(jwks_uri, policy):
            get_cache_counters().record_jwks_miss()
        async with _get_jwks_cache_write_lock():
            apply_jwks_cache_outcome(
                _jwks_cache,
                jwks_uri,
                response,
                time.monotonic(),
                cooldown=_kid_miss_last_attempt,
            )
        return response


async def _refresh_jwks(
    jwks_uri: str, policy: DiscoveryPolicy | None = None
) -> tuple[JwksResponse, bool]:
    """Force re-fetch JWKS and update cache (key rotation).

    Uses the per-URI fetch lock to coalesce concurrent refreshes for the
    same URI while leaving unrelated URIs unblocked. The ``request_time``
    guard catches the case where another coroutine for *this* URI completed
    a refresh while we were blocked.

    ``request_time`` is captured *inside* the lock so a coroutine that races
    a just-released lock cannot observe its own ``request_time`` as older
    than the entry the prior coroutine just wrote (causing a spurious
    re-fetch).

    See sync._refresh_jwks for the ``from_retained_cache`` semantics — a
    successful-but-empty upstream response is surfaced as the retained
    cache entry instead of the empty response, and callers must treat the
    flag as "no new information from upstream" (no cooldown stamp).
    """
    if policy is None:
        policy = DiscoveryPolicy()
    fetch_lock = _get_jwks_fetch_lock(jwks_uri)
    async with fetch_lock:
        request_time = time.monotonic()
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and entry.cached_at >= request_time:
            return entry.response, False

        logger.info("Forcing JWKS refresh for %s (possible key rotation)", jwks_uri)
        response = await get_jwks(JwksRequest(address=jwks_uri, policy=policy))
        # Count only the branch that issues the upstream GET, whenever that GET
        # was actually attempted (a 429/5xx re-fetch is still an upstream round
        # trip). The coalesced early return above returns another coroutine's
        # just-fetched result and never reaches here; a scheme-rejected refresh
        # does zero network work and is excluded via _upstream_fetch_attempted.
        if _upstream_fetch_attempted(jwks_uri, policy):
            get_cache_counters().record_jwks_refresh()
        async with _get_jwks_cache_write_lock():
            apply_jwks_cache_outcome(
                _jwks_cache,
                jwks_uri,
                response,
                time.monotonic(),
                cooldown=_kid_miss_last_attempt,
            )
            if response.is_successful and not response.keys:
                retained = _jwks_cache.get(jwks_uri)
                if retained is not None and retained.response.keys:
                    logger.info(
                        "JWKS refresh for %s returned 200 with empty keys; "
                        "falling back to retained cache entry for in-flight "
                        "validation",
                        jwks_uri,
                    )
                    return retained.response, True
        return response, False


async def clear_jwks_cache() -> None:
    """Clear the JWKS cache. Useful for testing.

    **Breaking change (v3.0.0):** this helper is now ``async`` so it can
    acquire the JWKS-cache write lock before clearing. The previous
    synchronous version mutated state guarded by an ``asyncio.Lock``
    without awaiting it, so a coroutine mid-flight in ``_refresh_jwks``
    could write its result back *after* ``clear()`` ran, leaving the
    "cleared" cache holding an entry. The cooldown sidecar
    (``_kid_miss_last_attempt``) is cleared under the same lock for the
    same reason. Callers must now ``await``.

    Acquires the current loop's write lock; see ``clear_discovery_cache``
    for the cross-loop semantics added in the #399 per-loop lock plumbing.
    """
    async with _get_jwks_cache_write_lock():
        clear_cache_locked(_jwks_cache)
        _kid_miss_last_attempt.clear()


# ============================================================================
# Token validation
# ============================================================================

# See sync mirror for rationale. Uses ``threading.Lock`` rather than
# ``asyncio.Lock`` so the once-per-process check is callable from a sync
# context (the helper itself doesn't await) and works under any event loop.
_injected_http_client_warning_emitted = False
_injected_http_client_warning_lock = threading.Lock()


def _maybe_warn_injected_http_client() -> None:
    """Emit a one-shot warning when an injected ``http_client`` is first used.

    Mirror of the sync helper — the warning state is per-module (sync and
    aio each fire at most once per process) so a deployment that uses both
    APIs sees at most two warnings, not one per call.
    """
    global _injected_http_client_warning_emitted  # noqa: PLW0603
    if _injected_http_client_warning_emitted:
        return
    with _injected_http_client_warning_lock:
        if _injected_http_client_warning_emitted:
            return
        _injected_http_client_warning_emitted = True
        logger.warning(
            "validate_token invoked with an injected http_client: discovery "
            "cache, JWKS cache, kid-miss cooldown, and signature-failure "
            "cooldown are all bypassed for this code path. Every call "
            "re-fetches from the upstream provider and an attacker forging "
            "unknown kids or wrong signatures can drive 1:1 upstream fetches. "
            "This warning fires once per process; subsequent injected-client "
            "calls are silent."
        )


def _reset_injected_http_client_warning_for_testing() -> None:
    """Test helper: clear the one-shot warning flag so a test can re-trigger."""
    global _injected_http_client_warning_emitted  # noqa: PLW0603
    with _injected_http_client_warning_lock:
        _injected_http_client_warning_emitted = False


async def _discover_and_resolve_key(
    jwt: str,
    disco_doc_address: str | None,
    http_client: AsyncHTTPClient | None,
    policy: DiscoveryPolicy,
) -> tuple[dict, str, DiscoveryDocumentResponse, bool]:
    """Fetch discovery + JWKS and resolve the signing key.

    ``policy`` is the effective :class:`DiscoveryPolicy` resolved from the
    caller's config; it governs validation on both the injected-client and
    cached paths and partitions the discovery cache.

    Returns (key_dict, alg, disco_response, is_cached_path).
    """
    if http_client is not None:
        _maybe_warn_injected_http_client()
        if disco_doc_address is None:
            raise ConfigurationException(
                "disco_doc_address is required when perform_disco is True"
            )
        disco_doc_response = await get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
            http_client=http_client,
        )
        validate_disco_response(disco_doc_response)
        jwks_uri = validate_jwks_uri(disco_doc_response)
        jwks_response = await get_jwks(
            JwksRequest(address=jwks_uri, policy=policy), http_client=http_client
        )
        validate_jwks_response(jwks_response)
        kid, jwt_alg = extract_jwt_header_fields(jwt)
        key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
        return key_dict, alg, disco_doc_response, False

    # Cached path with TTL
    disco_doc_response = await _get_disco_response(disco_doc_address, policy)
    validate_disco_response(disco_doc_response)
    jwks_uri = validate_jwks_uri(disco_doc_response)
    jwks_response = await _get_cached_jwks(jwks_uri, policy)
    validate_jwks_response(jwks_response)
    kid, jwt_alg = extract_jwt_header_fields(jwt)
    # OP key rotation: if the JWT's kid is not in the cached JWKS, the cache
    # is stale. Force a refresh before lookup so rotation is handled without
    # waiting for a signature failure on a key we don't have. The cooldown
    # gate prevents an unauthenticated attacker from amplifying inbound JWT
    # traffic into upstream JWKS fetches by spamming random kids.
    cached_keys = jwks_response.keys or []
    if kid is not None and not any(k.kid == kid for k in cached_keys):
        if should_attempt_kid_miss_refresh(
            _kid_miss_last_attempt,
            jwks_uri,
            has_cached_keys=bool(cached_keys),
            now=time.monotonic(),
        ):
            logger.info(
                "kid %s not present in cached JWKS; refreshing (possible key rotation)",
                kid,
            )
            # See sync._discover_and_resolve_key for the rationale.
            jwks_response, from_retained_cache = await _refresh_jwks(jwks_uri, policy)
            if jwks_response.is_successful:
                refreshed_keys = jwks_response.keys or []
                kid_found = any(k.kid == kid for k in refreshed_keys)
                # Skip cooldown bookkeeping when refresh degraded to a
                # retained-cache fallback (empty upstream is not
                # attacker-amplifiable). Mirror of sync.
                if not from_retained_cache:
                    async with _get_jwks_cache_write_lock():
                        if kid_found:
                            _kid_miss_last_attempt.pop(jwks_uri, None)
                        else:
                            _kid_miss_last_attempt[jwks_uri] = time.monotonic()
            else:
                kid_found = False
            validate_jwks_response(jwks_response)
            if not kid_found:
                logger.warning(
                    "kid %s still absent after JWKS refresh of %s", kid, jwks_uri
                )
        else:
            logger.debug(
                "kid %s not in cached JWKS for %s but refresh cooldown active; "
                "falling through to no-matching-kid error",
                kid,
                jwks_uri,
            )
    key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
    return key_dict, alg, disco_doc_response, True


async def _retry_with_refreshed_jwks(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_response: DiscoveryDocumentResponse,
    http_client: AsyncHTTPClient | None = None,
) -> dict:
    """Re-fetch JWKS and retry decode once (key rotation recovery).

    See sync._retry_with_refreshed_jwks for the rationale. Shares
    ``_kid_miss_last_attempt`` with the kid-miss path so an attacker
    forging signatures against cached kids can't bypass the cooldown.
    """
    logger.warning("Signature verification failed; retrying with refreshed keys")
    jwks_uri = validate_jwks_uri(disco_doc_response)
    policy = resolve_discovery_policy(
        token_validation_config.discovery_policy,
        token_validation_config.require_https,
    )
    if http_client is not None:
        jwks_response = await get_jwks(
            JwksRequest(address=jwks_uri, policy=policy), http_client=http_client
        )
        validate_jwks_response(jwks_response)
        kid, jwt_alg = extract_jwt_header_fields(jwt)
        key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)
        return decode_with_config(jwt, resolved_config, disco_doc_response.issuer)

    if not should_attempt_kid_miss_refresh(
        _kid_miss_last_attempt,
        jwks_uri,
        has_cached_keys=True,
        now=time.monotonic(),
    ):
        logger.debug(
            "Signature-failure retry suppressed for %s: refresh cooldown active",
            jwks_uri,
        )
        raise SignatureVerificationException(
            "Signature verification failed; refresh cooldown active"
        )

    jwks_response, from_retained_cache = await _refresh_jwks(jwks_uri, policy)
    # See sync._retry_with_refreshed_jwks — transient failures must not
    # stamp the cooldown.
    validate_jwks_response(jwks_response)

    try:
        kid, jwt_alg = extract_jwt_header_fields(jwt)
        key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)
        decoded = decode_with_config(jwt, resolved_config, disco_doc_response.issuer)
    except Exception:
        # Skip cooldown stamp when refresh degraded to a retained-cache
        # fallback. See sync._retry_with_refreshed_jwks.
        if not from_retained_cache:
            async with _get_jwks_cache_write_lock():
                _kid_miss_last_attempt[jwks_uri] = time.monotonic()
        raise
    if not from_retained_cache:
        async with _get_jwks_cache_write_lock():
            _kid_miss_last_attempt.pop(jwks_uri, None)
    return decoded


async def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: AsyncHTTPClient | None = None,
) -> dict:
    """
    Validate a JWT token (async).

    Args:
        jwt: The JWT token to validate
        token_validation_config: Token validation configuration
        disco_doc_address: Discovery document address (required if perform_disco=True)
        http_client: Optional managed HTTP client. When ``None`` (the default),
            uses the module-level singleton with the full TTL cache + cooldown
            stack. When provided, **all of the following are bypassed**:

            - **Discovery document cache** — every call re-fetches the
              ``.well-known/openid-configuration`` document.
            - **JWKS cache** — every call re-fetches the JWKS.
            - **Kid-miss cooldown** — an attacker forging tokens with unknown
              ``kid`` headers drives 1:1 upstream JWKS fetches with no rate
              limit.
            - **Signature-failure cooldown** — an attacker forging signatures
              against cached kids drives 1:1 upstream JWKS fetches on the
              retry path with no rate limit.

            The injected-client path is appropriate for one-off validations
            (CLI tooling, tests) and for callers that have implemented their
            own caching layer over the HTTP client. It is **not** appropriate
            for high-volume request paths exposed to untrusted JWTs.

            A ``logger.warning`` is emitted the first time an injected client
            is used in the process so accidental opt-out is detectable in
            production logs.

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If configuration is invalid
    """
    log_validation_start(jwt, token_validation_config)
    validate_token_config(token_validation_config)

    if token_validation_config.perform_disco:
        policy = resolve_discovery_policy(
            token_validation_config.discovery_policy,
            token_validation_config.require_https,
        )
        key_dict, alg, disco_doc_response, _is_cached = await _discover_and_resolve_key(
            jwt, disco_doc_address, http_client, policy
        )
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)

        try:
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
        except SignatureVerificationException:
            decoded_token = await _retry_with_refreshed_jwks(
                jwt, token_validation_config, disco_doc_response, http_client
            )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    await validate_async_claims(decoded_token, token_validation_config)
    log_validation_success(decoded_token)
    return decoded_token


__all__ = [
    "TokenValidationConfig",
    "clear_discovery_cache",
    "clear_jwks_cache",
    "validate_token",
]
