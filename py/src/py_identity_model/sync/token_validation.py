"""
Synchronous token validation with TTL-based JWKS and discovery caching.

This module provides synchronous token validation using discovery and JWKS,
with automatic cache expiry and forced JWKS refresh on key rotation. The
caches and the kid-miss cooldown state live on the :class:`ValidationCache`
passed as ``cache=`` (the process-wide default cache when none is passed),
never on the HTTP client.
"""

import time

from ..core.discovery_policy import DiscoveryPolicy, resolve_discovery_policy
from ..core.jwks_cache import (
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
    is_signing_key,
)
from ..core.token_validation_logic import (
    build_resolved_config,
    decode_with_config,
    log_validation_start,
    log_validation_success,
    validate_claims,
    validate_config_for_manual_validation,
    validate_disco_response,
    validate_jwks_response,
    validate_jwks_uri,
)
from ..core.validators import validate_token_config
from ..exceptions import ConfigurationException, SignatureVerificationException
from ..logging_config import logger
from .discovery import get_discovery_document
from .http_client import get_default_http_client
from .jwks import get_jwks
from .managed_client import HTTPClient
from .validation_cache import ValidationCache, get_default_validation_cache


def _resolve_client(http_client: HTTPClient | None) -> HTTPClient:
    return http_client if http_client is not None else get_default_http_client()


def _resolve_cache(cache: ValidationCache | None) -> ValidationCache:
    return cache if cache is not None else get_default_validation_cache()


def _get_disco_response(
    disco_doc_address: str | None,
    policy: DiscoveryPolicy | None = None,
    http_client: HTTPClient | None = None,
    cache: ValidationCache | None = None,
) -> DiscoveryDocumentResponse:
    """Cached discovery document fetching with TTL.

    Uses cache-aside with per-URI single-flight: a fresh cached entry is
    returned without any lock; only the upstream fetch on a cache miss is
    serialized, and only against other requests for the same address. The
    cache-wide write lock covers only the brief cache write + eviction and
    never spans the upstream fetch.

    ``policy`` (default: strict :class:`DiscoveryPolicy`) both governs
    validation of the fetched document and partitions the cache, so callers
    with different policies never share an entry.
    """
    if disco_doc_address is None:
        raise ConfigurationException(
            "disco_doc_address is required when perform_disco is True"
        )

    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    if policy is None:
        policy = DiscoveryPolicy()
    cache_key = (disco_doc_address, policy.cache_key())
    # Cheap atomic dict read — no lock required for a single .get() in CPython.
    entry = cache.disco.get(cache_key)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency — touch_cache_entry self-serializes the reorder
        # against _enforce_size_limit via the process-wide structure lock, so
        # the read hot-path takes no write lock (#397).
        touch_cache_entry(cache.disco, cache_key)
        return entry.response

    with cache.disco_fetch_lock(cache_key):
        # Re-check under the URI lock — another thread may have populated
        # the entry while we waited.
        entry = cache.disco.get(cache_key)
        if entry is not None and not is_cache_expired(entry):
            touch_cache_entry(cache.disco, cache_key)
            return entry.response

        response = get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
            http_client=client,
        )
        with cache.disco_write_lock:
            apply_disco_cache_outcome(
                cache.disco, cache_key, response, time.monotonic(), cache.config
            )
        return response


def clear_discovery_cache(cache: ValidationCache | None = None) -> None:
    """Clear the discovery cache of *cache* (default: the default cache)."""
    cache = _resolve_cache(cache)
    with cache.disco_write_lock:
        clear_cache_locked(cache.disco)


# ============================================================================
# TTL-aware JWKS cache
# ============================================================================


def _get_cached_jwks(
    jwks_uri: str,
    policy: DiscoveryPolicy | None = None,
    http_client: HTTPClient | None = None,
    cache: ValidationCache | None = None,
) -> JwksResponse:
    """Return cached JWKS response if fresh, otherwise fetch and cache.

    Cache-aside with per-URI single-flight (see ``_get_disco_response``).
    """
    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    if policy is None:
        policy = DiscoveryPolicy()
    entry = cache.jwks.get(jwks_uri)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency (see _get_disco_response) — self-serializing, no
        # write lock on the read hot-path.
        touch_cache_entry(cache.jwks, jwks_uri)
        return entry.response

    with cache.jwks_fetch_lock(jwks_uri):
        entry = cache.jwks.get(jwks_uri)
        if entry is not None and not is_cache_expired(entry):
            touch_cache_entry(cache.jwks, jwks_uri)
            return entry.response

        # The jwks_uri was already vetted against this policy when the
        # discovery document was processed; thread it through so the
        # pre-flight scheme check inside get_jwks() does not double-reject.
        response = get_jwks(
            JwksRequest(address=jwks_uri, policy=policy), http_client=client
        )
        with cache.jwks_write_lock:
            for gone in apply_jwks_cache_outcome(
                cache.jwks, jwks_uri, response, time.monotonic(), cache.config
            ):
                cache.kid_miss_last_attempt.pop(gone, None)
        return response


def _refresh_jwks(
    jwks_uri: str,
    policy: DiscoveryPolicy | None = None,
    http_client: HTTPClient | None = None,
    cache: ValidationCache | None = None,
    *,
    stale_response: JwksResponse | None = None,
) -> tuple[JwksResponse, bool]:
    """Force re-fetch JWKS and update cache (key rotation).

    Uses the per-URI fetch lock to coalesce concurrent refresh requests for
    the same URI while leaving unrelated URIs unblocked. The ``request_time``
    guard catches the case where another caller for *this* URI completed a
    refresh while we were blocked.

    ``request_time`` is captured *inside* the lock so a thread that races a
    just-released lock cannot observe its own ``request_time`` as older than
    the entry that thread A just wrote (causing a spurious re-fetch).

    Returns:
        ``(response, from_retained_cache)``. When ``from_retained_cache`` is
        ``True``, the upstream refresh returned a successful-but-empty body
        and we surface the retained cache entry instead of the empty
        response (the cached working keys are sitting there; raising "no
        keys available" with usable keys in hand is the wrong UX, and
        stamping the kid-miss cooldown on an empty-but-not-attacker-driven
        refresh wedges legitimate traffic for the cooldown window). Callers
        treat this flag as "no new information from upstream" — i.e. do not
        update the kid-miss cooldown, since the empty response isn't
        attacker-amplifiable.
    """
    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    if policy is None:
        policy = DiscoveryPolicy()
    with cache.jwks_fetch_lock(jwks_uri):
        request_time = time.monotonic()
        entry = cache.jwks.get(jwks_uri)
        # A waiter whose stale entry another refresh replaced while it was
        # blocked returns the replacement. The stale entry itself is never
        # returned: only a successful, non-empty fetch replaces an entry.
        if entry is not None and (
            entry.cached_at >= request_time
            or (stale_response is not None and entry.response is not stale_response)
        ):
            return entry.response, False

        logger.info("Forcing JWKS refresh for %s (possible key rotation)", jwks_uri)
        response = get_jwks(
            JwksRequest(address=jwks_uri, policy=policy), http_client=client
        )
        with cache.jwks_write_lock:
            for gone in apply_jwks_cache_outcome(
                cache.jwks, jwks_uri, response, time.monotonic(), cache.config
            ):
                cache.kid_miss_last_attempt.pop(gone, None)
            # apply_jwks_cache_outcome retains the existing entry on an
            # empty-successful response. Surface that retained entry so
            # the in-flight validation has usable keys to work with.
            if response.is_successful and not response.keys:
                retained = cache.jwks.get(jwks_uri)
                if retained is not None and retained.response.keys:
                    logger.info(
                        "JWKS refresh for %s returned 200 with empty keys; "
                        "falling back to retained cache entry for in-flight "
                        "validation",
                        jwks_uri,
                    )
                    return retained.response, True
        return response, False


def clear_jwks_cache(cache: ValidationCache | None = None) -> None:
    """Clear the JWKS cache and kid-miss state of *cache*.

    Clears the default cache's when *cache* is ``None``.
    """
    cache = _resolve_cache(cache)
    with cache.jwks_write_lock:
        clear_cache_locked(cache.jwks)
        cache.kid_miss_last_attempt.clear()


# ============================================================================
# Token validation
# ============================================================================


def _discover_and_resolve_key(
    jwt: str,
    disco_doc_address: str | None,
    client: HTTPClient,
    policy: DiscoveryPolicy,
    cache: ValidationCache,
) -> tuple[dict, str, DiscoveryDocumentResponse]:
    """Fetch discovery + JWKS through *client* into *cache* and resolve the key.

    ``policy`` is the effective :class:`DiscoveryPolicy` resolved from the
    caller's config; it governs validation and partitions the discovery cache.

    Returns (key_dict, alg, disco_response).
    """
    disco_doc_response = _get_disco_response(disco_doc_address, policy, client, cache)
    validate_disco_response(disco_doc_response)
    jwks_uri = validate_jwks_uri(disco_doc_response)
    jwks_response = _get_cached_jwks(jwks_uri, policy, client, cache)
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
            # Stamping is deferred until after the refresh: transient
            # upstream failures (network errors are wrapped into
            # is_successful=False by get_jwks) must not wedge the cooldown,
            # so a single dropped packet does not stretch a rotation outage
            # by the cooldown window.
            jwks_response, from_retained_cache = _refresh_jwks(
                jwks_uri, policy, client, cache, stale_response=jwks_response
            )
            if jwks_response.is_successful:
                refreshed_keys = jwks_response.keys or []
                kid_found = any(
                    k.kid == kid and is_signing_key(k) for k in refreshed_keys
                )
                # Skip the cooldown bookkeeping entirely when the refresh
                # degraded to a retained-cache fallback. The upstream's
                # empty response is not attacker-amplifiable, so the
                # DoS-stamp framing does not apply; and we must not pop
                # a legitimate prior stamp on what was effectively a
                # no-op refresh.
                if not from_retained_cache:
                    with cache.jwks_write_lock:
                        if kid_found:
                            # Refresh produced the missing kid — legitimate
                            # rotation absorbed. Drop the stamp so a
                            # back-to-back second rotation within the
                            # cooldown window can still refresh.
                            cache.kid_miss_last_attempt.pop(jwks_uri, None)
                        else:
                            # Refresh completed and produced a response
                            # but the kid is still absent — DoS amplifier
                            # case (the attacker drove an upstream fetch
                            # we couldn't turn into a successful
                            # validation). Stamp the cooldown to suppress
                            # repeats in the window.
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


def _retry_with_refreshed_jwks(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_response: DiscoveryDocumentResponse,
    client: HTTPClient,
    cache: ValidationCache,
) -> dict:
    """Re-fetch JWKS and retry decode once (key rotation recovery).

    Shares the cache's kid-miss cooldown state with the kid-miss path: an attacker
    forging JWTs signed with the wrong key for a *cached* kid can drive
    one upstream JWKS fetch per request without this gate, since the kid
    is present in the cache and the signature failure is the only trigger
    for the refresh. The signature-failure variant is morally identical
    to the kid-miss variant — both are attacker-triggerable force-refresh
    paths — so they share the same cooldown budget.

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

    jwks_response, from_retained_cache = _refresh_jwks(jwks_uri, policy, client, cache)
    # Transient upstream failures (wrapped as is_successful=False) must not
    # stamp the cooldown — let validate_jwks_response raise naturally so
    # the next attempt can retry once upstream recovers.
    validate_jwks_response(jwks_response)

    try:
        kid, jwt_alg = extract_jwt_header_fields(jwt)
        key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)
        decoded = decode_with_config(jwt, resolved_config, disco_doc_response.issuer)
    except Exception:
        # Refresh delivered a usable response but the chain (find_key,
        # decode) still failed — DoS amplifier case. Stamp to suppress
        # retry storms. Skip the stamp when the refresh degraded to a
        # retained-cache fallback (empty upstream response is not
        # attacker-amplifiable).
        if not from_retained_cache:
            with cache.jwks_write_lock:
                cache.kid_miss_last_attempt[jwks_uri] = time.monotonic()
        raise
    # Refreshed keys verified the JWT — real rotation absorbed. Clear the
    # stamp so a subsequent legitimate rotation isn't suppressed. Only do
    # this for real refreshes; a cache-fallback success would have worked
    # with the cached keys all along and tells us nothing new about
    # rotation state.
    if not from_retained_cache:
        with cache.jwks_write_lock:
            cache.kid_miss_last_attempt.pop(jwks_uri, None)
    return decoded


def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: HTTPClient | None = None,
    *,
    cache: ValidationCache | None = None,
) -> dict:
    """
    Validate a JWT token.

    Args:
        jwt: The JWT token to validate
        token_validation_config: Token validation configuration
        disco_doc_address: Discovery document address (required if perform_disco=True)
        http_client: Optional managed HTTP client. When ``None`` (the default),
            the library default client is used. It sends the discovery and
            JWKS requests; its ``Config`` sets the timeout, retries, TLS and
            JWKS size limits.
        cache: Optional :class:`ValidationCache` holding the discovery
            document, the JWKS and the kid-miss cooldown. Its ``Config`` sets
            their TTLs, size and cooldown. When ``None`` (the default), the
            process-wide default cache is used, whichever client is passed.

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If configuration is invalid
        RuntimeError: If *http_client* has been closed
    """
    log_validation_start(jwt, token_validation_config)
    validate_token_config(token_validation_config)

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
        key_dict, alg, disco_doc_response = _discover_and_resolve_key(
            jwt, disco_doc_address, client, policy, cache
        )
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)

        try:
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
        except SignatureVerificationException:
            decoded_token = _retry_with_refreshed_jwks(
                jwt, token_validation_config, disco_doc_response, client, cache
            )
    else:
        validate_config_for_manual_validation(token_validation_config)
        decoded_token = decode_with_config(jwt, token_validation_config)

    validate_claims(decoded_token, token_validation_config)
    log_validation_success(decoded_token)
    return decoded_token


__all__ = [
    "TokenValidationConfig",
    "clear_discovery_cache",
    "clear_jwks_cache",
    "validate_token",
]
