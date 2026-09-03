"""
Synchronous token validation with TTL-based JWKS and discovery caching.

This module provides synchronous token validation using discovery and JWKS,
with automatic cache expiry and forced JWKS refresh on key rotation.
"""

# ============================================================================
# Discovery TTL cache
# ============================================================================
from collections import OrderedDict
import threading
import time

from ..core.discovery_policy import DiscoveryPolicy, resolve_discovery_policy
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
from .jwks import get_jwks
from .managed_client import HTTPClient


# Discovery TTL cache — keyed by (address, policy.cache_key()) to prevent policy
# bypass: a response admitted under a lax policy must never be served to a caller
# running a stricter one. (Formerly keyed on the require_https bool alone; the
# full-policy key generalises that guard now that any policy knob is injectable.)
# OrderedDict (not a plain dict) so read hits can refresh LRU recency via
# ``touch_cache_entry``; eviction targets the least recently *used* entry (#397).
_disco_cache: OrderedDict[tuple[str, tuple], DiscoCacheEntry] = OrderedDict()
# Global lock used only for the brief cache write + eviction critical section.
# It does NOT span the upstream HTTP fetch — see ``_get_disco_response`` for
# the cache-aside pattern that lets fetches for distinct addresses proceed in
# parallel rather than serializing on this single lock.
_disco_cache_write_lock = threading.Lock()
# Per-URI locks (striped) protect the fetch+populate critical section so two
# requests for the same address coalesce into one upstream fetch, while two
# requests for *different* addresses do not block each other.
_DISCO_LOCK_STRIPES = 32
_disco_fetch_locks: list[threading.Lock] = [
    threading.Lock() for _ in range(_DISCO_LOCK_STRIPES)
]


def _get_disco_fetch_lock(cache_key: tuple[str, tuple]) -> threading.Lock:
    return _disco_fetch_locks[hash(cache_key) % _DISCO_LOCK_STRIPES]


def _get_disco_response(
    disco_doc_address: str | None,
    policy: DiscoveryPolicy | None = None,
) -> DiscoveryDocumentResponse:
    """Cached discovery document fetching with TTL.

    Uses cache-aside with per-URI single-flight: a fresh cached entry is
    returned without any lock; only the upstream fetch on a cache miss is
    serialized, and only against other requests for the same address.

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
    # Cheap atomic dict read — no lock required for a single .get() in CPython.
    entry = _disco_cache.get(cache_key)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency — touch_cache_entry self-serializes the reorder
        # against _enforce_size_limit via the process-wide structure lock, so
        # the read hot-path takes no write lock (#397).
        touch_cache_entry(_disco_cache, cache_key)
        return entry.response

    fetch_lock = _get_disco_fetch_lock(cache_key)
    with fetch_lock:
        # Re-check under the URI lock — another thread may have populated
        # the entry while we waited.
        entry = _disco_cache.get(cache_key)
        if entry is not None and not is_cache_expired(entry):
            touch_cache_entry(_disco_cache, cache_key)
            return entry.response

        response = get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy)
        )
        with _disco_cache_write_lock:
            apply_disco_cache_outcome(
                _disco_cache, cache_key, response, time.monotonic()
            )
        return response


def clear_discovery_cache() -> None:
    """Clear the discovery cache."""
    with _disco_cache_write_lock:
        clear_cache_locked(_disco_cache)


# ============================================================================
# TTL-aware JWKS cache (replaces @lru_cache for JWKS)
# ============================================================================

_jwks_cache: OrderedDict[str, JwksCacheEntry] = OrderedDict()
# See _disco_cache_write_lock — same factoring: brief CPU-only write lock,
# per-URI fetch locks for the actual single-flight semantics.
_jwks_cache_write_lock = threading.Lock()
_JWKS_LOCK_STRIPES = 32
_jwks_fetch_locks: list[threading.Lock] = [
    threading.Lock() for _ in range(_JWKS_LOCK_STRIPES)
]

# Tracks the last time each jwks_uri was force-refreshed because of a kid
# miss. Used by ``should_attempt_kid_miss_refresh`` to bound DoS amplification
# from attacker-controlled JWT headers. Guarded by ``_jwks_cache_write_lock``
# since every mutation happens adjacent to a cache mutation.
_kid_miss_last_attempt: dict[str, float] = {}


def _get_jwks_fetch_lock(jwks_uri: str) -> threading.Lock:
    return _jwks_fetch_locks[hash(jwks_uri) % _JWKS_LOCK_STRIPES]


def _get_cached_jwks(
    jwks_uri: str, policy: DiscoveryPolicy | None = None
) -> JwksResponse:
    """Return cached JWKS response if fresh, otherwise fetch and cache.

    Cache-aside with per-URI single-flight (see ``_get_disco_response``).
    """
    if policy is None:
        policy = DiscoveryPolicy()
    entry = _jwks_cache.get(jwks_uri)
    if entry is not None and not is_cache_expired(entry):
        # Refresh LRU recency (see _get_disco_response) — self-serializing, no
        # write lock on the read hot-path.
        touch_cache_entry(_jwks_cache, jwks_uri)
        return entry.response

    fetch_lock = _get_jwks_fetch_lock(jwks_uri)
    with fetch_lock:
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and not is_cache_expired(entry):
            touch_cache_entry(_jwks_cache, jwks_uri)
            return entry.response

        # The jwks_uri was already vetted against this policy when the
        # discovery document was processed; thread it through so the
        # pre-flight scheme check inside get_jwks() does not double-reject.
        response = get_jwks(JwksRequest(address=jwks_uri, policy=policy))
        with _jwks_cache_write_lock:
            apply_jwks_cache_outcome(
                _jwks_cache,
                jwks_uri,
                response,
                time.monotonic(),
                cooldown=_kid_miss_last_attempt,
            )
        return response


def _refresh_jwks(
    jwks_uri: str, policy: DiscoveryPolicy | None = None
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
    if policy is None:
        policy = DiscoveryPolicy()
    fetch_lock = _get_jwks_fetch_lock(jwks_uri)
    with fetch_lock:
        request_time = time.monotonic()
        entry = _jwks_cache.get(jwks_uri)
        if entry is not None and entry.cached_at >= request_time:
            return entry.response, False

        logger.info("Forcing JWKS refresh for %s (possible key rotation)", jwks_uri)
        response = get_jwks(JwksRequest(address=jwks_uri, policy=policy))
        with _jwks_cache_write_lock:
            apply_jwks_cache_outcome(
                _jwks_cache,
                jwks_uri,
                response,
                time.monotonic(),
                cooldown=_kid_miss_last_attempt,
            )
            # apply_jwks_cache_outcome retains the existing entry on an
            # empty-successful response. Surface that retained entry so
            # the in-flight validation has usable keys to work with.
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


def clear_jwks_cache() -> None:
    """Clear the JWKS cache. Useful for testing."""
    with _jwks_cache_write_lock:
        clear_cache_locked(_jwks_cache)
        _kid_miss_last_attempt.clear()


# ============================================================================
# Token validation
# ============================================================================

# Tracks whether the injected-``http_client`` bypass warning has already been
# emitted in this process. Guarded by ``_injected_http_client_warning_lock``
# so the warning fires exactly once per process even under concurrent first
# use. Reset via ``_reset_injected_http_client_warning_for_testing``.
_injected_http_client_warning_emitted = False
_injected_http_client_warning_lock = threading.Lock()


def _maybe_warn_injected_http_client() -> None:
    """Emit a one-shot warning when an injected ``http_client`` is first used.

    The injected-client code path bypasses the discovery cache, the JWKS
    cache, the kid-miss cooldown, and the signature-failure cooldown. The
    docstring documents this; the runtime warning lets operators detect
    accidental opt-out (e.g., a middleware that forwards an ambient client
    into every call) without reading the docs.
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


def _discover_and_resolve_key(
    jwt: str,
    disco_doc_address: str | None,
    http_client: HTTPClient | None,
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
        disco_doc_response = get_discovery_document(
            DiscoveryDocumentRequest(address=disco_doc_address, policy=policy),
            http_client=http_client,
        )
        validate_disco_response(disco_doc_response)
        jwks_uri = validate_jwks_uri(disco_doc_response)
        jwks_response = get_jwks(
            JwksRequest(address=jwks_uri, policy=policy),
            http_client=http_client,
        )
        validate_jwks_response(jwks_response)
        kid, jwt_alg = extract_jwt_header_fields(jwt)
        key_dict, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
        return key_dict, alg, disco_doc_response, False

    # Cached path with TTL
    disco_doc_response = _get_disco_response(disco_doc_address, policy)
    validate_disco_response(disco_doc_response)
    jwks_uri = validate_jwks_uri(disco_doc_response)
    jwks_response = _get_cached_jwks(jwks_uri, policy)
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
            # Stamping is deferred until after the refresh: transient
            # upstream failures (network errors are wrapped into
            # is_successful=False by get_jwks) must not wedge the cooldown,
            # so a single dropped packet does not stretch a rotation outage
            # by the cooldown window.
            jwks_response, from_retained_cache = _refresh_jwks(jwks_uri, policy)
            if jwks_response.is_successful:
                refreshed_keys = jwks_response.keys or []
                kid_found = any(k.kid == kid for k in refreshed_keys)
                # Skip the cooldown bookkeeping entirely when the refresh
                # degraded to a retained-cache fallback. The upstream's
                # empty response is not attacker-amplifiable, so the
                # DoS-stamp framing does not apply; and we must not pop
                # a legitimate prior stamp on what was effectively a
                # no-op refresh.
                if not from_retained_cache:
                    with _jwks_cache_write_lock:
                        if kid_found:
                            # Refresh produced the missing kid — legitimate
                            # rotation absorbed. Drop the stamp so a
                            # back-to-back second rotation within the
                            # cooldown window can still refresh.
                            _kid_miss_last_attempt.pop(jwks_uri, None)
                        else:
                            # Refresh completed and produced a response
                            # but the kid is still absent — DoS amplifier
                            # case (the attacker drove an upstream fetch
                            # we couldn't turn into a successful
                            # validation). Stamp the cooldown to suppress
                            # repeats in the window.
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


def _retry_with_refreshed_jwks(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_response: DiscoveryDocumentResponse,
    http_client: HTTPClient | None = None,
) -> dict:
    """Re-fetch JWKS and retry decode once (key rotation recovery).

    Shares ``_kid_miss_last_attempt`` with the kid-miss path: an attacker
    forging JWTs signed with the wrong key for a *cached* kid can drive
    one upstream JWKS fetch per request without this gate, since the kid
    is present in the cache and the signature failure is the only trigger
    for the refresh. The signature-failure variant is morally identical
    to the kid-miss variant — both are attacker-triggerable force-refresh
    paths — so they share the same cooldown budget.

    Cooldown is consulted only on the cached path; the injected
    ``http_client`` path documents its own bypass.
    """
    logger.warning("Signature verification failed; retrying with refreshed keys")
    jwks_uri = validate_jwks_uri(disco_doc_response)
    policy = resolve_discovery_policy(
        token_validation_config.discovery_policy,
        token_validation_config.require_https,
    )
    if http_client is not None:
        jwks_response = get_jwks(
            JwksRequest(address=jwks_uri, policy=policy),
            http_client=http_client,
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

    jwks_response, from_retained_cache = _refresh_jwks(jwks_uri, policy)
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
            with _jwks_cache_write_lock:
                _kid_miss_last_attempt[jwks_uri] = time.monotonic()
        raise
    # Refreshed keys verified the JWT — real rotation absorbed. Clear the
    # stamp so a subsequent legitimate rotation isn't suppressed. Only do
    # this for real refreshes; a cache-fallback success would have worked
    # with the cached keys all along and tells us nothing new about
    # rotation state.
    if not from_retained_cache:
        with _jwks_cache_write_lock:
            _kid_miss_last_attempt.pop(jwks_uri, None)
    return decoded


def validate_token(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: HTTPClient | None = None,
) -> dict:
    """
    Validate a JWT token.

    Args:
        jwt: The JWT token to validate
        token_validation_config: Token validation configuration
        disco_doc_address: Discovery document address (required if perform_disco=True)
        http_client: Optional managed HTTP client. When ``None`` (the default),
            uses the thread-local default with the full TTL cache + cooldown
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
        key_dict, alg, disco_doc_response, _is_cached = _discover_and_resolve_key(
            jwt, disco_doc_address, http_client, policy
        )
        resolved_config = build_resolved_config(token_validation_config, key_dict, alg)

        try:
            decoded_token = decode_with_config(
                jwt, resolved_config, disco_doc_response.issuer
            )
        except SignatureVerificationException:
            decoded_token = _retry_with_refreshed_jwks(
                jwt, token_validation_config, disco_doc_response, http_client
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
