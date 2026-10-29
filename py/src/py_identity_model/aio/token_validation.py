"""
Asynchronous token validation with TTL-based JWKS and discovery caching.

This module provides asynchronous token validation using discovery and JWKS,
with automatic cache expiry and forced JWKS refresh on key rotation. The
caches and the kid-miss cooldown state live on the :class:`AsyncValidationCache`
passed as ``cache=`` (the process-wide default cache when none is passed),
never on the HTTP client. Cached documents are keyed by the client's
:attr:`~py_identity_model.aio.managed_client.AsyncHTTPClient.trust_scope`;
the cooldown is keyed by ``jwks_uri`` alone.
"""

import time

from ..core.cache_metrics import get_cache_counters
from ..core.discovery_policy import (
    DiscoveryPolicy,
    resolve_discovery_policy,
    validate_url_scheme,
)
from ..core.jwks_cache import (
    apply_disco_cache_outcome,
    clear_cache_locked,
    is_cache_expired,
    should_attempt_kid_miss_refresh,
    store_jwks_response,
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
    is_signing_key,
)
from ..core.token_binding import (
    TokenPresentation,
    check_token_binding,
    require_presentation,
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
from .http_client import get_default_async_http_client
from .jwks import get_jwks
from .managed_client import AsyncHTTPClient
from .validation_cache import AsyncValidationCache, get_default_async_validation_cache


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


def _resolve_client(http_client: AsyncHTTPClient | None) -> AsyncHTTPClient:
    return http_client if http_client is not None else get_default_async_http_client()


def _resolve_cache(cache: AsyncValidationCache | None) -> AsyncValidationCache:
    return cache if cache is not None else get_default_async_validation_cache()


async def _get_disco_response(
    disco_doc_address: str | None,
    policy: DiscoveryPolicy | None = None,
    http_client: AsyncHTTPClient | None = None,
    cache: AsyncValidationCache | None = None,
) -> DiscoveryDocumentResponse:
    """Cached async discovery document fetching with TTL.

    Cache-aside with per-URI single-flight: a fresh cached entry returns
    without acquiring any lock; only the upstream fetch on a cache miss
    is serialized, and only against other requests for the same address.

    ``policy`` (default: strict :class:`DiscoveryPolicy`) both governs
    validation of the fetched document and partitions the cache, so callers
    with different policies never share an entry. The client's trust scope
    partitions it too (see the sync ``_get_disco_response``).
    """
    if disco_doc_address is None:
        raise ConfigurationException(
            "disco_doc_address is required when perform_disco is True"
        )

    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    if policy is None:
        policy = DiscoveryPolicy()
    cache_key = (client.trust_scope, disco_doc_address, policy.cache_key())
    entry = cache.disco.get(cache_key)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency — touch_cache_entry serializes the reorder against
        # _enforce_size_limit via the process-wide structure lock. The async
        # write locks are keyed per event loop, so they cannot guard reordering
        # against an eviction on another loop sharing this cache;
        # the process-wide lock inside touch_cache_entry does (#397).
        touch_cache_entry(cache.disco, cache_key)
        get_cache_counters().record_disco_hit()
        return entry.response

    async with cache.disco_fetch_lock(cache_key):
        entry = cache.disco.get(cache_key)
        if entry is not None and not is_cache_expired(entry):
            # Double-checked hit: another coroutine populated the entry while we
            # waited on the fetch lock. This is a genuine cache hit, not a miss —
            # counting it as a miss would inflate the miss rate under concurrent
            # warmup.
            touch_cache_entry(cache.disco, cache_key)
            get_cache_counters().record_disco_hit()
            return entry.response

        response = await get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
            http_client=client,
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
        async with cache.disco_write_lock():
            apply_disco_cache_outcome(
                cache.disco, cache_key, response, time.monotonic(), cache.config
            )
        return response


async def clear_discovery_cache(cache: AsyncValidationCache | None = None) -> None:
    """Clear the discovery cache of *cache* (default: the default cache).

    Async so it can acquire the disco-cache write lock before clearing: a
    coroutine mid-flight could otherwise write its result back *after* the
    clear, leaving the "cleared" cache holding an entry. Callers must
    ``await``.

    Acquires the *current loop's* write lock. The cache is shared by
    every loop, so the clear is visible to operations on any loop; in-flight
    writes on a different loop are not coordinated with this clear (#399).
    """
    cache = _resolve_cache(cache)
    async with cache.disco_write_lock():
        clear_cache_locked(cache.disco)


# ============================================================================
# TTL-aware JWKS cache (replaces @alru_cache for JWKS)
# ============================================================================


async def _get_cached_jwks(
    jwks_uri: str,
    policy: DiscoveryPolicy | None = None,
    http_client: AsyncHTTPClient | None = None,
    cache: AsyncValidationCache | None = None,
) -> JwksResponse:
    """Return cached JWKS response if fresh, otherwise fetch and cache.

    Cache-aside with per-URI single-flight (see ``_get_disco_response``).
    """
    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    if policy is None:
        policy = DiscoveryPolicy()
    cache_key = (client.trust_scope, jwks_uri)
    entry = cache.jwks.get(cache_key)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency (see _get_disco_response) — self-serializing via
        # the process-wide structure lock, no per-loop write lock needed.
        touch_cache_entry(cache.jwks, cache_key)
        get_cache_counters().record_jwks_hit()
        return entry.response

    async with cache.jwks_fetch_lock(cache_key):
        entry = cache.jwks.get(cache_key)
        if entry is not None and not is_cache_expired(entry):
            # Double-checked hit populated by a concurrent fetch (see
            # _get_disco_response) — count as a hit, not a miss.
            touch_cache_entry(cache.jwks, cache_key)
            get_cache_counters().record_jwks_hit()
            return entry.response

        # The jwks_uri was already vetted against this policy when the
        # discovery document was processed; thread it through so the
        # pre-flight scheme check inside get_jwks() does not double-reject.
        response = await get_jwks(
            JwksRequest(address=jwks_uri, policy=policy), http_client=client
        )
        # Count the miss whenever an upstream fetch was attempted, including a
        # 429/5xx round trip (fetch volume during an outage is the signal). Only
        # a scheme-rejected URI (e.g. plaintext http:// under the default policy)
        # does zero network work and is excluded; see _upstream_fetch_attempted.
        if _upstream_fetch_attempted(jwks_uri, policy):
            get_cache_counters().record_jwks_miss()
        async with cache.jwks_write_lock():
            store_jwks_response(
                cache.jwks,
                cache.kid_miss_last_attempt,
                cache_key,
                response,
                cache.config,
            )
        return response


async def _refresh_jwks(
    jwks_uri: str,
    policy: DiscoveryPolicy | None = None,
    http_client: AsyncHTTPClient | None = None,
    cache: AsyncValidationCache | None = None,
    *,
    stale_response: JwksResponse | None = None,
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
    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    if policy is None:
        policy = DiscoveryPolicy()
    cache_key = (client.trust_scope, jwks_uri)
    async with cache.jwks_fetch_lock(cache_key):
        request_time = time.monotonic()
        entry = cache.jwks.get(cache_key)
        # A waiter whose stale entry another refresh replaced while it was
        # blocked returns the replacement. The stale entry itself is never
        # returned: only a successful, non-empty fetch replaces an entry.
        if entry is not None and (
            entry.cached_at >= request_time
            or (stale_response is not None and entry.response is not stale_response)
        ):
            return entry.response, False

        logger.info("Forcing JWKS refresh for %s (possible key rotation)", jwks_uri)
        response = await get_jwks(
            JwksRequest(address=jwks_uri, policy=policy), http_client=client
        )
        # Count only the branch that issues the upstream GET, whenever that GET
        # was actually attempted (a 429/5xx re-fetch is still an upstream round
        # trip). The coalesced early return above returns another coroutine's
        # just-fetched result and never reaches here; a scheme-rejected refresh
        # does zero network work and is excluded via _upstream_fetch_attempted.
        if _upstream_fetch_attempted(jwks_uri, policy):
            get_cache_counters().record_jwks_refresh()
        async with cache.jwks_write_lock():
            store_jwks_response(
                cache.jwks,
                cache.kid_miss_last_attempt,
                cache_key,
                response,
                cache.config,
            )
            if response.is_successful and not response.keys:
                retained = cache.jwks.get(cache_key)
                if retained is not None and retained.response.keys:
                    logger.info(
                        "JWKS refresh for %s returned 200 with empty keys; "
                        "falling back to retained cache entry for in-flight "
                        "validation",
                        jwks_uri,
                    )
                    return retained.response, True
        return response, False


async def clear_jwks_cache(cache: AsyncValidationCache | None = None) -> None:
    """Clear the JWKS cache and kid-miss state of *cache*.

    Clears the default cache's when *cache* is ``None``. Async so it
    can acquire the JWKS-cache write lock before clearing (see
    ``clear_discovery_cache``); the cooldown sidecar is cleared under the same
    lock for the same reason. Callers must ``await``.
    """
    cache = _resolve_cache(cache)
    async with cache.jwks_write_lock():
        clear_cache_locked(cache.jwks)
        cache.kid_miss_last_attempt.clear()


# ============================================================================
# Token validation
# ============================================================================


async def _discover_and_resolve_key(
    jwt: str,
    disco_doc_address: str | None,
    client: AsyncHTTPClient,
    policy: DiscoveryPolicy,
    cache: AsyncValidationCache,
) -> tuple[dict, str, DiscoveryDocumentResponse]:
    """Fetch discovery + JWKS through *client* into *cache* and resolve the key.

    ``policy`` is the effective :class:`DiscoveryPolicy` resolved from the
    caller's config; it governs validation and partitions the discovery cache.

    Returns (key_dict, alg, disco_response).
    """
    disco_doc_response = await _get_disco_response(
        disco_doc_address, policy, client, cache
    )
    validate_disco_response(disco_doc_response)
    jwks_uri = validate_jwks_uri(disco_doc_response)
    jwks_response = await _get_cached_jwks(jwks_uri, policy, client, cache)
    validate_jwks_response(jwks_response)
    kid, jwt_alg = extract_jwt_header_fields(jwt)
    # OP key rotation: if the JWT's kid names no signing key in the cached
    # JWKS (a ``use: enc`` key does not count, RFC 7517 §4.2), the cache
    # is stale. Force a refresh before lookup so rotation is handled without
    # waiting for a signature failure on a key we don't have. The cooldown
    # gate prevents an unauthenticated attacker from amplifying inbound JWT
    # traffic into upstream JWKS fetches by spamming random kids.
    cached_keys = jwks_response.keys or []
    if kid is not None and not any(
        k.kid == kid and is_signing_key(k) for k in cached_keys
    ):
        if should_attempt_kid_miss_refresh(
            cache.kid_miss_last_attempt,
            jwks_uri,
            has_cached_keys=bool(cached_keys),
            now=time.monotonic(),
            cooldown=cache.config.jwks_kid_miss_cooldown,
        ):
            logger.info(
                "kid %s not present in cached JWKS; refreshing (possible key rotation)",
                kid,
            )
            # See sync._discover_and_resolve_key for the rationale.
            jwks_response, from_retained_cache = await _refresh_jwks(
                jwks_uri, policy, client, cache, stale_response=jwks_response
            )
            if jwks_response.is_successful:
                refreshed_keys = jwks_response.keys or []
                kid_found = any(
                    k.kid == kid and is_signing_key(k) for k in refreshed_keys
                )
                # Skip cooldown bookkeeping when refresh degraded to a
                # retained-cache fallback (empty upstream is not
                # attacker-amplifiable). Mirror of sync.
                if not from_retained_cache:
                    async with cache.jwks_write_lock():
                        if kid_found:
                            cache.kid_miss_last_attempt.pop(jwks_uri, None)
                        else:
                            cache.kid_miss_last_attempt[jwks_uri] = time.monotonic()
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
    return key_dict, alg, disco_doc_response


async def _retry_with_refreshed_jwks(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_response: DiscoveryDocumentResponse,
    client: AsyncHTTPClient,
    cache: AsyncValidationCache,
) -> dict:
    """Re-fetch JWKS and retry decode once (key rotation recovery).

    See sync._retry_with_refreshed_jwks for the rationale. Shares the
    cache's kid-miss cooldown state with the kid-miss path so an attacker
    forging signatures against cached kids can't bypass the cooldown.
    """
    logger.warning("Signature verification failed; retrying with refreshed keys")
    jwks_uri = validate_jwks_uri(disco_doc_response)
    policy = resolve_discovery_policy(
        token_validation_config.discovery_policy,
        token_validation_config.require_https,
    )
    if not should_attempt_kid_miss_refresh(
        cache.kid_miss_last_attempt,
        jwks_uri,
        has_cached_keys=True,
        now=time.monotonic(),
        cooldown=cache.config.jwks_kid_miss_cooldown,
    ):
        logger.debug(
            "Signature-failure retry suppressed for %s: refresh cooldown active",
            jwks_uri,
        )
        raise SignatureVerificationException(
            "Signature verification failed; refresh cooldown active"
        )

    jwks_response, from_retained_cache = await _refresh_jwks(
        jwks_uri, policy, client, cache
    )
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
            async with cache.jwks_write_lock():
                cache.kid_miss_last_attempt[jwks_uri] = time.monotonic()
        raise
    if not from_retained_cache:
        async with cache.jwks_write_lock():
            cache.kid_miss_last_attempt.pop(jwks_uri, None)
    return decoded


async def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: AsyncHTTPClient | None = None,
    *,
    cache: AsyncValidationCache | None = None,
    presentation: TokenPresentation | None = None,
) -> dict:
    """
    Validate a JWT token (async).

    Args:
        jwt: The JWT token to validate
        token_validation_config: Token validation configuration
        disco_doc_address: Discovery document address (required if perform_disco=True)
        http_client: Optional managed HTTP client. When ``None`` (the default),
            the library default client is used. It sends the discovery and
            JWKS requests; its ``Config`` sets the timeout, retries, TLS and
            JWKS size limits.
        cache: Optional :class:`AsyncValidationCache` holding the discovery
            document, the JWKS and the kid-miss cooldown. Its ``Config`` sets
            their TTLs, size and cooldown. When ``None`` (the default), the
            process-wide default cache is used, whichever client is passed.
        presentation: How the token arrived on the request
            (:class:`TokenPresentation`: scheme, method, URL, ``DPoP`` proof,
            client certificate). When given, a sender-constrained token is
            checked against it after decoding (RFC 9449 §7.1, RFC 8705 §3);
            required when ``required_binding`` is not ``NONE``.

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails, including
            ``DPoPValidationError`` / ``CertificateBindingError`` when the
            sender constraint does not hold
        ConfigurationException: If configuration is invalid
        RuntimeError: If *http_client* has been closed
    """
    log_validation_start(jwt, token_validation_config)
    validate_token_config(token_validation_config)
    require_presentation(token_validation_config, presentation)

    if token_validation_config.perform_disco:
        policy = resolve_discovery_policy(
            token_validation_config.discovery_policy,
            token_validation_config.require_https,
        )
        client = _resolve_client(http_client)
        # A cache hit never touches client.client, where the closed guard
        # lives, so check here: a closed client must not keep validating.
        client.ensure_open()
        cache = _resolve_cache(cache)
        key_dict, alg, disco_doc_response = await _discover_and_resolve_key(
            jwt, disco_doc_address, client, policy, cache
        )
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)

        try:
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
        except SignatureVerificationException:
            decoded_token = await _retry_with_refreshed_jwks(
                jwt, token_validation_config, disco_doc_response, client, cache
            )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    check_token_binding(decoded_token, jwt, token_validation_config, presentation)
    await validate_async_claims(decoded_token, token_validation_config)
    log_validation_success(decoded_token)
    return decoded_token


__all__ = [
    "TokenValidationConfig",
    "clear_discovery_cache",
    "clear_jwks_cache",
    "validate_token",
]
