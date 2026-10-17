"""
Proves the kid-miss refresh cooldown bounds DoS amplification.

Threat model: an unauthenticated attacker spams JWTs with random unknown
``kid`` values against the token-validation endpoint. Each kid-miss triggers
a forced JWKS refresh from the cache layer. Without a cooldown, the
amplification factor is 1:1 — attacker controls a per-request JWKS fetch
against the upstream OP. At ~100 RPS this trivially trips the upstream's
rate limit and breaks validation for legitimate traffic too.

These tests pin the contract:
- 1 prime + 1 refresh covers an arbitrary number of attacker requests
  inside the cooldown window (regardless of distinct kids used).
- Cooldown does NOT block when the cache has no keys to fall back on.
- Cooldown does NOT block legitimate tokens with cached kids.
- Cooldown expires after its window; rotation propagates within one window.
- The cooldown is per ``jwks_uri`` — an attacker against one OP cannot
  suppress refreshes for a different OP.
"""

import asyncio
import time

import httpx
import pytest
import respx

from py_identity_model import Config
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.aio.validation_cache import (
    AsyncValidationCache,
    get_default_async_validation_cache,
)
from py_identity_model.core.jwks_cache import (
    DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    MAX_KID_MISS_COOLDOWN_SECONDS,
    JwksCacheEntry,
    apply_jwks_cache_outcome,
    should_attempt_kid_miss_refresh,
)
from py_identity_model.core.models import (
    JsonWebKey,
    JwksResponse,
    TokenValidationConfig,
)
from py_identity_model.exceptions import (
    KeyNotFoundException,
    SignatureVerificationException,
    TokenValidationException,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    _get_cached_jwks as sync_get_cached_jwks,
)
from py_identity_model.sync.token_validation import (
    _refresh_jwks as sync_refresh_jwks,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)
from py_identity_model.sync.validation_cache import (
    ValidationCache,
    get_default_validation_cache,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = "https://example.com/jwks"


@pytest.fixture(autouse=True)
async def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


def _sync_caches() -> ValidationCache:
    """The default sync cache + cooldown state (no ``cache=``)."""
    return get_default_validation_cache()


def _async_caches() -> AsyncValidationCache:
    """The default async cache + cooldown state (no ``cache=``)."""
    return get_default_async_validation_cache()


def _sign_unknown_kid_token(kid: str) -> str:
    """Forge a JWT header advertising the given kid but sign with a fresh
    keypair the verifier will never see — exercises the kid-miss path."""
    _, pem = generate_rsa_keypair()
    return sign_jwt(
        pem,
        {"sub": "attacker", "iss": "https://example.com"},
        headers={"kid": kid},
    )


# Kid-miss cooldown pinned to the maximum so ``EXPECTED_FETCH_COUNT``
# assertions are independent of wall-clock time. The cooldown is measured
# against real ``time.monotonic()``. The amplification/isolation tests below
# fire a 25-request attacker loop and assert exactly one prime + one forced
# refresh — which only holds if the whole loop completes inside the cooldown
# window. With the 5s default and a per-request RSA keygen, under
# ``pytest -n auto`` CPU contention the loop can outlast 5s and a second
# refresh fires, flaking the count. Pinning to the max (well above any loop
# duration) removes the timing dependency without weakening what the test
# proves (that the cooldown coalesces a burst into a single refresh). Tests
# that need it validate through a cache built from this config.
HIGH_COOLDOWN_CONFIG = Config(jwks_kid_miss_cooldown=MAX_KID_MISS_COOLDOWN_SECONDS)
# Transport settings for the injected HTTP clients: no retry backoff sleeps.
NO_RETRY_DELAY_CONFIG = Config(http_retry_base_delay=0)


# ============================================================================
# Pure-function semantics for the gate. Decouples the contract from the
# sync/async plumbing so a flipped predicate would fail here too.
# ============================================================================


COOLDOWN = DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS


class TestShouldAttemptKidMissRefreshContract:
    def test_proceeds_when_no_prior_attempt(self):
        assert should_attempt_kid_miss_refresh(
            last_attempts={},
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0,
            cooldown=COOLDOWN,
        )

    def test_proceeds_when_no_cached_keys_even_inside_cooldown(self):
        recent = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=JWKS_URL,
            has_cached_keys=False,
            now=100.5,
            cooldown=COOLDOWN,
        )

    def test_blocks_when_recent_attempt_with_cached_keys(self):
        recent = {JWKS_URL: 100.0}
        assert not should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0 + COOLDOWN / 2,
            cooldown=COOLDOWN,
        )

    def test_proceeds_after_cooldown_elapsed(self):
        old = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=old,
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0 + COOLDOWN + 0.01,
            cooldown=COOLDOWN,
        )

    def test_zero_cooldown_never_blocks(self):
        """``jwks_kid_miss_cooldown=0`` is the documented opt-out."""
        recent = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=JWKS_URL,
            has_cached_keys=True,
            now=100.0,
            cooldown=0.0,
        )

    def test_cooldown_is_per_jwks_uri(self):
        """An attacker against OP-A cannot suppress refreshes for OP-B."""
        other_uri = "https://other.example/jwks"
        recent = {JWKS_URL: 100.0}
        assert should_attempt_kid_miss_refresh(
            last_attempts=recent,
            jwks_uri=other_uri,
            has_cached_keys=True,
            now=100.0,
            cooldown=COOLDOWN,
        )


# ============================================================================
# End-to-end: under sustained kid-miss attack, only 1 prime + 1 refresh
# reach the upstream JWKS endpoint, regardless of attacker request volume.
# ============================================================================

ATTACKER_REQUEST_COUNT = 25
EXPECTED_FETCH_COUNT = 2  # 1 prime + 1 refresh inside cooldown window


class TestKidMissCooldownBoundsAmplification:
    @respx.mock
    def test_sync_cooldown_caps_fetches_under_attack(self):
        defender_key_dict, _defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        attacker_kids = [f"attacker-kid-{i}" for i in range(ATTACKER_REQUEST_COUNT)]
        tokens = [_sign_unknown_kid_token(kid) for kid in attacker_kids]

        rejections = 0
        cache = ValidationCache(config=HIGH_COOLDOWN_CONFIG)
        with HTTPClient(config=NO_RETRY_DELAY_CONFIG) as client:
            for token in tokens:
                try:
                    validate_token(
                        jwt=token,
                        token_validation_config=config,
                        disco_doc_address=DISCO_URL,
                        http_client=client,
                        cache=cache,
                    )
                except TokenValidationException:
                    rejections += 1

        # Every attacker request must fail (no matching kid).
        assert rejections == ATTACKER_REQUEST_COUNT
        # And the upstream JWKS endpoint sees at most 1 prime + 1 refresh,
        # not one fetch per attacker request.
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_cooldown_caps_fetches_under_attack(self):
        defender_key_dict, _defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        attacker_kids = [f"attacker-kid-{i}" for i in range(ATTACKER_REQUEST_COUNT)]
        tokens = [_sign_unknown_kid_token(kid) for kid in attacker_kids]

        cache = AsyncValidationCache(config=HIGH_COOLDOWN_CONFIG)
        async with AsyncHTTPClient(config=NO_RETRY_DELAY_CONFIG) as client:

            async def _try(token: str) -> bool:
                try:
                    await async_validate_token(
                        jwt=token,
                        token_validation_config=config,
                        disco_doc_address=DISCO_URL,
                        http_client=client,
                        cache=cache,
                    )
                    return False
                except TokenValidationException:
                    return True

            results = await asyncio.gather(*(_try(t) for t in tokens))
        assert all(results)
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT


# ============================================================================
# Cooldown must NOT block legitimate validation: tokens with already-cached
# kids never trigger the cooldown, and a real key rotation propagates within
# one cooldown window.
# ============================================================================


class TestCooldownDoesNotBlockLegitimateTraffic:
    @respx.mock
    def test_cached_kid_does_not_trip_cooldown(self):
        """Validating a token whose kid IS in the cache must not consume
        cooldown budget — kid-miss path never fires."""
        key_dict, pem = generate_rsa_keypair()
        key_dict["kid"] = "cached-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        legitimate_token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "cached-kid"},
        )

        for _ in range(10):
            validate_token(
                jwt=legitimate_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        # Single prime fetch, no refreshes, cooldown dict never populated.
        assert jwks_route.call_count == 1
        assert JWKS_URL not in _sync_caches().kid_miss_last_attempt

    @respx.mock
    def test_rotation_propagates_after_cooldown_elapses(self):
        """A real rotation (new key on upstream) must propagate on the very
        next kid-miss after the cooldown window — proving the cooldown is
        bounded, not permanent."""
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        # First fetch returns old; second fetch returns new (rotation).
        jwks_route = respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        rotation_token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )

        # 1st attempt: cache has only old-kid → kid-miss → refresh fires →
        # upstream still serves old-kid → rotation_token can't validate yet.
        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=rotation_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert jwks_route.call_count == 2  # noqa: PLR2004

        # 2nd attempt inside cooldown: refresh suppressed, still fails.
        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=rotation_token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert jwks_route.call_count == 2  # noqa: PLR2004

        # Simulate cooldown elapse by backdating the last-attempt timestamp
        # on the same monotonic clock the production code uses.
        cooldown = _sync_caches().config.jwks_kid_miss_cooldown
        _sync_caches().kid_miss_last_attempt[JWKS_URL] = (
            time.monotonic() - cooldown - 1.0
        )

        # 3rd attempt past cooldown: refresh fires again, upstream now serves
        # new-kid, rotation_token validates successfully.
        decoded = validate_token(
            jwt=rotation_token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == 3  # noqa: PLR2004


# ============================================================================
# Cooldown is per-URI: an attacker hammering OP-A cannot suppress legitimate
# rotation refreshes for OP-B.
# ============================================================================


class TestCooldownIsolationAcrossIssuers:
    @respx.mock
    def test_per_issuer_cooldown_does_not_cross_contaminate(self):
        other_disco_url = "https://other.example/.well-known/openid-configuration"
        other_jwks_url = "https://other.example/jwks"
        other_disco_response = {
            "issuer": "https://other.example",
            "authorization_endpoint": "https://other.example/authorize",
            "token_endpoint": "https://other.example/token",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "jwks_uri": other_jwks_url,
        }

        attacker_key_dict, _ = generate_rsa_keypair()
        attacker_key_dict["kid"] = "attacker-side-kid"
        defender_key_dict, defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(other_disco_url).mock(
            return_value=httpx.Response(200, json=other_disco_response)
        )
        attacker_jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [attacker_key_dict]})
        )
        defender_jwks_route = respx.get(other_jwks_url).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config_attacker = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )
        config_defender = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://other.example"
        )

        defender_token = sign_jwt(
            defender_pem,
            {"sub": "legit", "iss": "https://other.example"},
            headers={"kid": "defender-kid"},
        )

        cache = ValidationCache(config=HIGH_COOLDOWN_CONFIG)
        with HTTPClient(config=NO_RETRY_DELAY_CONFIG) as client:
            # Saturate the attacker-side cooldown.
            for i in range(ATTACKER_REQUEST_COUNT):
                with pytest.raises(TokenValidationException):
                    validate_token(
                        jwt=_sign_unknown_kid_token(f"junk-{i}"),
                        token_validation_config=config_attacker,
                        disco_doc_address=DISCO_URL,
                        http_client=client,
                        cache=cache,
                    )

            # Defender-side issuer must NOT be in cooldown — legitimate token
            # signed by the defender's key validates without interference.
            decoded = validate_token(
                jwt=defender_token,
                token_validation_config=config_defender,
                disco_doc_address=other_disco_url,
                http_client=client,
                cache=cache,
            )
            cooldown_state = dict(cache.kid_miss_last_attempt)
        assert decoded["sub"] == "legit"

        # Attacker JWKS saw exactly 1 prime + 1 refresh; defender JWKS saw 1
        # prime (legitimate kid hit cache immediately).
        assert attacker_jwks_route.call_count == EXPECTED_FETCH_COUNT
        assert defender_jwks_route.call_count == 1
        # Cooldown state confirms isolation.
        assert JWKS_URL in cooldown_state
        assert other_jwks_url not in cooldown_state


# ============================================================================
# Config sanity: ``Config.jwks_kid_miss_cooldown`` is the only knob (the
# library reads no environment since #753). Pins the contract for operators
# who want to tune.
# ============================================================================

CUSTOM_COOLDOWN = 1.0
# Older than CUSTOM_COOLDOWN but younger than the 5s default, so the outcome
# shows which of the two governed the gate.
STAMP_AGE_BETWEEN_COOLDOWNS = 2.0


class TestCooldownFromConfig:
    def test_default_cooldown(self):
        assert Config().jwks_kid_miss_cooldown == (
            DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS
        )

    def test_environment_is_ignored(self, monkeypatch):
        """The old ``KID_MISS_REFRESH_COOLDOWN`` env var has no effect."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "0")
        assert ValidationCache().config.jwks_kid_miss_cooldown == (
            DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS
        )

    @respx.mock
    def test_cache_config_cooldown_governs_refresh(self):
        """A stamp older than the cache's custom cooldown (but inside the
        default window) no longer suppresses the kid-miss refresh. The
        client's own cooldown setting is ignored: the cache's applies."""
        assert CUSTOM_COOLDOWN < STAMP_AGE_BETWEEN_COOLDOWNS
        assert STAMP_AGE_BETWEEN_COOLDOWNS < DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS
        defender_key_dict, _ = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )
        cache = ValidationCache(config=Config(jwks_kid_miss_cooldown=CUSTOM_COOLDOWN))
        # A client-side cooldown long enough to suppress the refresh, were it
        # read; only transport settings on the client take effect.
        client_config = Config(
            jwks_kid_miss_cooldown=MAX_KID_MISS_COOLDOWN_SECONDS,
            http_retry_base_delay=0,
        )

        with HTTPClient(config=client_config) as client:
            with pytest.raises(TokenValidationException):
                validate_token(
                    jwt=_sign_unknown_kid_token("unknown-1"),
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                    http_client=client,
                    cache=cache,
                )
            assert jwks_route.call_count == EXPECTED_FETCH_COUNT
            cache.kid_miss_last_attempt[JWKS_URL] = (
                time.monotonic() - STAMP_AGE_BETWEEN_COOLDOWNS
            )
            with pytest.raises(TokenValidationException):
                validate_token(
                    jwt=_sign_unknown_kid_token("unknown-2"),
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                    http_client=client,
                    cache=cache,
                )

        # The second kid miss refreshed again: the custom cooldown elapsed.
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT + 1


# ============================================================================
# Cooldown sidecar must shrink alongside the cache. Without coordinated
# eviction, the kid_miss_last_attempt dict grows unboundedly in deployments
# with caller-influenced jwks_uri values (multi-tenant gateways) even though
# the JWKS cache itself is bounded — sibling unbounded-growth bug.
# ============================================================================


CACHE_CAPACITY = 3


def _jwks_response(kid: str, cache_control: str = "max-age=3600") -> JwksResponse:
    key_dict, _ = generate_rsa_keypair()
    jwk = JsonWebKey(
        kty=key_dict["kty"],
        kid=kid,
        alg=key_dict["alg"],
        use=key_dict["use"],
        n=key_dict["n"],
        e=key_dict["e"],
    )
    return JwksResponse(is_successful=True, keys=[jwk], cache_control=cache_control)


class TestCooldownEvictedWithCache:
    def test_apply_outcome_reports_evicted_uris(self):
        """``apply_jwks_cache_outcome`` returns the URIs that left the cache
        so the caller can drop their cooldown stamps — otherwise the
        cooldown dict outgrows the cache."""
        config = Config(cache_max_entries=CACHE_CAPACITY)
        cache: dict[str, JwksCacheEntry] = {}
        oldest_url = "https://op-oldest.example/jwks"
        surviving_urls = ["https://op-a.example/jwks", "https://op-b.example/jwks"]
        overflow_url = "https://overflow.example/jwks"

        for url in [oldest_url, *surviving_urls]:
            gone = apply_jwks_cache_outcome(
                cache, url, _jwks_response(f"kid-{url}"), time.monotonic(), config
            )
            assert gone == []

        gone = apply_jwks_cache_outcome(
            cache, overflow_url, _jwks_response("overflow"), time.monotonic(), config
        )

        assert gone == [oldest_url]
        assert list(cache) == [*surviving_urls, overflow_url]

    @respx.mock
    def test_cache_eviction_drops_cooldown_alongside_cache(self):
        """End to end on the sync path: when the cache's JWKS cache
        evicts a URI, the same URI's cooldown stamp goes with it."""
        oldest_url = "https://op-oldest.example/jwks"
        surviving_urls = ["https://op-a.example/jwks", "https://op-b.example/jwks"]
        urls = [oldest_url, *surviving_urls]
        overflow_url = "https://overflow.example/jwks"
        key_dict, _ = generate_rsa_keypair()
        for url in [*urls, overflow_url]:
            respx.get(url).mock(
                return_value=httpx.Response(
                    200,
                    json={"keys": [key_dict]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            )

        cache = ValidationCache(config=Config(cache_max_entries=len(urls)))
        with HTTPClient(config=NO_RETRY_DELAY_CONFIG) as client:
            for url in urls:
                sync_get_cached_jwks(url, http_client=client, cache=cache)
                cache.kid_miss_last_attempt[url] = time.monotonic()
            assert set(cache.kid_miss_last_attempt) == set(urls)

            sync_get_cached_jwks(overflow_url, http_client=client, cache=cache)

            assert oldest_url not in cache.jwks
            assert oldest_url not in cache.kid_miss_last_attempt
            # Surviving entries preserved on both sides.
            assert list(cache.jwks) == [*surviving_urls, overflow_url]
            assert set(cache.kid_miss_last_attempt) == set(surviving_urls)

    def test_uncacheable_response_replaces_entry_and_preserves_cooldown(self):
        """``Cache-Control: no-cache`` on JWKS is ignored (see #396); the
        rotated keys replace the cached entry and no URI is reported gone,
        so the cooldown stamp is preserved (kid-miss suppression continues
        to apply to the URI).
        """
        url = "https://op.example/jwks"
        config = Config()
        cache: dict[str, JwksCacheEntry] = {}

        apply_jwks_cache_outcome(
            cache, url, _jwks_response("primed"), time.monotonic(), config
        )
        assert url in cache

        # An uncacheable response with non-empty keys replaces the entry
        # with the rotated key and reports nothing gone.
        gone = apply_jwks_cache_outcome(
            cache,
            url,
            _jwks_response("rotated", cache_control="no-cache"),
            time.monotonic(),
            config,
        )
        assert gone == []
        assert {k.kid for k in (cache[url].response.keys or [])} == {"rotated"}


# Async cooldown state covered for symmetry — most of the integration
# coverage is via the sync end-to-end test above.
class TestAsyncCooldownStateMirrorsSync:
    @pytest.mark.asyncio
    @respx.mock
    async def test_async_cooldown_dict_populated_on_refresh(self):
        defender_key_dict, _ = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        with pytest.raises(TokenValidationException):
            await async_validate_token(
                jwt=_sign_unknown_kid_token("unknown"),
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        assert JWKS_URL in _async_caches().kid_miss_last_attempt


# ============================================================================
# Transient network errors during refresh must NOT wedge the cooldown.
# Otherwise a single dropped packet stretches a rotation outage from
# milliseconds to one cooldown window for every kid-miss caller.
# ============================================================================


class TestCooldownNotWedgedByTransientError:
    @respx.mock
    def test_sync_refresh_exception_does_not_stamp_cooldown(self):
        """The cooldown timestamp must be set on the success path, not on
        attempted-but-failed refreshes. A single network blip otherwise
        wedges rotation discovery for the entire cooldown window."""
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # Prime cache with old-kid via a successful first fetch, then have
        # the JWKS endpoint raise a connect error on subsequent calls.
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(200, json={"keys": [old_key_dict]})
            raise httpx.ConnectError("simulated upstream connect failure")

        respx.get(JWKS_URL).mock(side_effect=handler)

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        # Trigger a kid-miss; refresh fails mid-flight. get_jwks wraps the
        # httpx error into a failed JwksResponse, and validate_jwks_response
        # raises TokenValidationException from the unsuccessful response.
        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=_sign_unknown_kid_token("new-kid"),
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        # Cooldown must NOT be stamped — the refresh didn't actually
        # complete, so charging the budget would suppress recovery once
        # upstream returns.
        assert JWKS_URL not in _sync_caches().kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_refresh_exception_does_not_stamp_cooldown(self):
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(200, json={"keys": [old_key_dict]})
            raise httpx.ConnectError("simulated upstream connect failure")

        respx.get(JWKS_URL).mock(side_effect=handler)

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        with pytest.raises(TokenValidationException):
            await async_validate_token(
                jwt=_sign_unknown_kid_token("new-kid"),
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        assert JWKS_URL not in _async_caches().kid_miss_last_attempt


# ============================================================================
# A successful rotation must drop the cooldown stamp so a back-to-back
# second rotation within the cooldown window isn't suppressed. Without this,
# rapid double-rotations (incident-response key rolls) wedge for one window.
# ============================================================================


class TestCooldownClearedOnSuccessfulRotation:
    @respx.mock
    def test_sync_successful_kid_miss_refresh_clears_cooldown(self):
        """When a kid-miss refresh produces the requested kid, the cooldown
        stamp must be popped — proving a real rotation was absorbed and the
        next rotation isn't artificially suppressed."""
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(JWKS_URL).mock(
            side_effect=[
                # Prime
                httpx.Response(200, json={"keys": [old_key_dict]}),
                # Refresh after kid-miss returns rotated keys
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        rotation_token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )

        decoded = validate_token(
            jwt=rotation_token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"
        # Critical: cooldown must NOT be set, since the refresh produced
        # the missing kid. Otherwise a back-to-back second rotation within
        # the window would be suppressed.
        assert JWKS_URL not in _sync_caches().kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_successful_kid_miss_refresh_clears_cooldown(self):
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        rotation_token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )

        decoded = await async_validate_token(
            jwt=rotation_token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"
        assert JWKS_URL not in _async_caches().kid_miss_last_attempt


# ============================================================================
# The signature-failure retry path must share the kid-miss cooldown budget.
# An attacker forging tokens signed with a wrong key against a *cached* kid
# would otherwise drive 1:1 upstream JWKS fetches per request — the same DoS
# amplifier the kid-miss cooldown was built to close.
# ============================================================================


SIG_RETRY_ATTACKER_COUNT = 25


class TestSignatureFailureRetryGatedByCooldown:
    @respx.mock
    def test_sync_signature_failure_retry_capped_by_cooldown(self):
        """Tokens with a cached kid but a bad signature trigger the
        signature-failure retry path. Cooldown must bound upstream fetches."""
        defender_key_dict, _defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        # Forge tokens that advertise the cached kid but are signed with
        # attacker-controlled keys. Validator finds the cached key (kid
        # matches), attempts decode, signature fails, retry path fires.
        attacker_tokens = [
            _sign_unknown_kid_token("defender-kid")
            for _ in range(SIG_RETRY_ATTACKER_COUNT)
        ]

        rejections = 0
        for token in attacker_tokens:
            try:
                validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )
            except SignatureVerificationException:
                rejections += 1

        assert rejections == SIG_RETRY_ATTACKER_COUNT
        # 1 prime + 1 refresh (first retry); subsequent retries suppressed
        # by cooldown. Without C-1, this would be SIG_RETRY_ATTACKER_COUNT + 1.
        assert jwks_route.call_count == 2  # noqa: PLR2004
        # Cooldown was stamped by the signature-failure retry path.
        assert JWKS_URL in _sync_caches().kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_signature_failure_retry_capped_by_cooldown(self):
        defender_key_dict, _defender_pem = generate_rsa_keypair()
        defender_key_dict["kid"] = "defender-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [defender_key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        attacker_tokens = [
            _sign_unknown_kid_token("defender-kid")
            for _ in range(SIG_RETRY_ATTACKER_COUNT)
        ]

        async def _try(token: str) -> bool:
            try:
                await async_validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )
                return False
            except SignatureVerificationException:
                return True

        # Run sequentially — concurrent runs would all coalesce on the
        # per-URI fetch_lock and the test wouldn't exercise the
        # cooldown-gated suppression path.
        results = [await _try(t) for t in attacker_tokens]
        assert all(results)
        assert jwks_route.call_count == 2  # noqa: PLR2004
        assert JWKS_URL in _async_caches().kid_miss_last_attempt

    @respx.mock
    def test_sync_legit_rotation_via_signature_retry_clears_cooldown(self):
        """Signature-failure retry + decode succeeds with refreshed keys
        → real rotation absorbed → cooldown must clear (M-2 analogue for
        the signature-failure path)."""
        # Defender's old key cached; rotation produces new key with the
        # same kid (kid reuse across rotation is legal per RFC 7517 §4.5
        # but rare in practice — the more common case is new kid). For
        # this test the simpler same-kid rotation is sufficient.
        cached_kd, _old_pem = generate_rsa_keypair()
        cached_kd["kid"] = "defender-kid"
        rotated_kd, rotated_pem = generate_rsa_keypair()
        rotated_kd["kid"] = "defender-kid"  # same kid, new key material

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_kd]}),  # prime
                httpx.Response(200, json={"keys": [rotated_kd]}),  # rotated
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        # Token signed with the rotated key, advertises the same kid.
        # Validator picks cached key, signature fails, retry refreshes,
        # finds rotated key with same kid, decode succeeds.
        token = sign_jwt(
            rotated_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "defender-kid"},
        )

        decoded = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"
        # Real rotation absorbed; cooldown must be clear.
        assert JWKS_URL not in _sync_caches().kid_miss_last_attempt


# ============================================================================
# #403: a kid-miss refresh that returns 200 with empty keys (transient
# upstream blip) must NOT stamp the cooldown. Pre-fix behavior:
#   1. apply_jwks_cache_outcome retains the populated cache entry.
#   2. _refresh_jwks returned the empty response to the caller.
#   3. The caller saw kid_found=False, stamped the cooldown.
#   4. Subsequent kid-miss requests for the same URI were suppressed for
#      one cooldown window, even though working cached keys were available.
#
# Post-fix:
#   - _refresh_jwks surfaces the retained cache entry (from_retained_cache=True).
#   - Caller skips the cooldown stamp because the empty upstream response
#     is not attacker-amplifiable (returning empty regardless of attacker
#     input).
#   - validate_jwks_response succeeds (it sees the retained keys).
#   - find_key_by_kid raises "no matching kid" — accurate, informative.
# ============================================================================


class TestEmptyRefreshDoesNotStampCooldown:
    @respx.mock
    def test_sync_empty_refresh_keeps_cooldown_clear(self):
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                # Prime: working keys.
                return httpx.Response(200, json={"keys": [old_key_dict]})
            # Refresh: 200 with empty keys (transient blip).
            return httpx.Response(200, json={"keys": []})

        respx.get(JWKS_URL).mock(side_effect=handler)

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        with pytest.raises(TokenValidationException):
            validate_token(
                jwt=_sign_unknown_kid_token("new-kid"),
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        # The cache MUST still hold the primed working keys (apply_jwks_cache_outcome
        # retains the entry on an empty-successful response).
        assert JWKS_URL in _sync_caches().jwks
        cached_kids = {k.kid for k in _sync_caches().jwks[JWKS_URL].response.keys or []}
        assert cached_kids == {"old-kid"}

        # And the cooldown stamp must NOT be set — the empty refresh is
        # treated as a no-op (not an attacker-amplifiable event), so
        # subsequent kid-miss requests in the cooldown window are not wedged.
        assert JWKS_URL not in _sync_caches().kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_empty_refresh_keeps_cooldown_clear(self):
        old_key_dict, _ = generate_rsa_keypair()
        old_key_dict["kid"] = "old-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(200, json={"keys": [old_key_dict]})
            return httpx.Response(200, json={"keys": []})

        respx.get(JWKS_URL).mock(side_effect=handler)

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        with pytest.raises(TokenValidationException):
            await async_validate_token(
                jwt=_sign_unknown_kid_token("new-kid"),
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        assert JWKS_URL in _async_caches().jwks
        cached_kids = {
            k.kid for k in _async_caches().jwks[JWKS_URL].response.keys or []
        }
        assert cached_kids == {"old-kid"}
        assert JWKS_URL not in _async_caches().kid_miss_last_attempt

    @respx.mock
    def test_sync_kid_present_in_retained_cache_decodes(self):
        """If the refresh returns empty but the cached keys happen to contain
        the requested kid (e.g. a different thread populated the cache between
        the kid-miss check and the refresh), validation should succeed using
        the retained cache.

        This case is rare in practice but the fix should still produce the
        right outcome — the test pins the contract.
        """
        # Use _refresh_jwks directly to exercise the surface, then assert
        # the returned response has the cached kid and from_retained_cache=True.
        cached_key_dict, _ = generate_rsa_keypair()
        cached_key_dict["kid"] = "cached-kid"

        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(200, json={"keys": [cached_key_dict]})
            return httpx.Response(200, json={"keys": []})

        respx.get(JWKS_URL).mock(side_effect=handler)

        # Manually seed the cache so the refresh path uses retained-cache
        # fallback. (Going through _get_cached_jwks first would set
        # cached_at = now, and _refresh_jwks's freshness guard would
        # short-circuit without re-fetching.)
        cached_jwk = JsonWebKey(
            kty=cached_key_dict["kty"],
            kid=cached_key_dict["kid"],
            n=cached_key_dict["n"],
            e=cached_key_dict["e"],
            alg=cached_key_dict.get("alg"),
            use=cached_key_dict.get("use", "sig"),
        )
        _sync_caches().jwks[JWKS_URL] = JwksCacheEntry(
            response=JwksResponse(is_successful=True, keys=[cached_jwk]),
            cached_at=time.monotonic() - 10.0,  # stale enough to trigger refresh
            ttl=0.001,
        )

        # Now trigger refresh — upstream returns empty. Pre-fill call_log so
        # the handler returns the empty-response branch on this first call.
        call_log.append(1)
        response, from_retained_cache = sync_refresh_jwks(JWKS_URL)

        # The retained cache had the kid; the caller gets the retained response.
        assert from_retained_cache is True
        assert response.is_successful is True
        kids = {k.kid for k in response.keys or []}
        assert kids == {"cached-kid"}


# ============================================================================
# A kid that names only a ``use: enc`` key names no signing key (RFC 7517
# §4.2), so it is a kid miss: one cooldown-gated forced refresh, then
# key-not-found. A relabelled key picked up by that refresh verifies.
# ============================================================================


class TestEncKeyKidIsKidMiss:
    @staticmethod
    def _keys_and_token(kid: str = "k1") -> tuple[dict, dict, str]:
        sig_key, pem = generate_rsa_keypair()
        sig_key.update(kid=kid, use="sig")
        enc_key = {**sig_key, "use": "enc"}
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": kid},
        )
        return enc_key, sig_key, token

    @staticmethod
    def _config() -> TokenValidationConfig:
        return TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

    @respx.mock
    def test_sync_enc_kid_refreshes_then_verifies_relabelled_key(self):
        enc_key, sig_key, token = self._keys_and_token()
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [enc_key]}),
                httpx.Response(200, json={"keys": [sig_key]}),
            ]
        )

        decoded = validate_token(
            jwt=token,
            token_validation_config=self._config(),
            disco_doc_address=DISCO_URL,
        )

        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT
        assert JWKS_URL not in _sync_caches().kid_miss_last_attempt

    @respx.mock
    def test_sync_enc_kid_is_key_not_found_after_one_refresh(self):
        enc_key, _, token = self._keys_and_token()
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [enc_key]})
        )

        cache = ValidationCache(config=HIGH_COOLDOWN_CONFIG)
        with HTTPClient(config=NO_RETRY_DELAY_CONFIG) as client:
            for _ in range(2):
                with pytest.raises(KeyNotFoundException):
                    validate_token(
                        jwt=token,
                        token_validation_config=self._config(),
                        disco_doc_address=DISCO_URL,
                        http_client=client,
                        cache=cache,
                    )
            stamped = JWKS_URL in cache.kid_miss_last_attempt

        assert jwks_route.call_count == EXPECTED_FETCH_COUNT
        assert stamped

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_enc_kid_refreshes_then_verifies_relabelled_key(self):
        enc_key, sig_key, token = self._keys_and_token()
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [enc_key]}),
                httpx.Response(200, json={"keys": [sig_key]}),
            ]
        )

        decoded = await async_validate_token(
            jwt=token,
            token_validation_config=self._config(),
            disco_doc_address=DISCO_URL,
        )

        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == EXPECTED_FETCH_COUNT
        assert JWKS_URL not in _async_caches().kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_enc_kid_is_key_not_found_after_one_refresh(self):
        enc_key, _, token = self._keys_and_token()
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [enc_key]})
        )

        cache = AsyncValidationCache(config=HIGH_COOLDOWN_CONFIG)
        async with AsyncHTTPClient(config=NO_RETRY_DELAY_CONFIG) as client:
            for _ in range(2):
                with pytest.raises(KeyNotFoundException):
                    await async_validate_token(
                        jwt=token,
                        token_validation_config=self._config(),
                        disco_doc_address=DISCO_URL,
                        http_client=client,
                        cache=cache,
                    )
            stamped = JWKS_URL in cache.kid_miss_last_attempt

        assert jwks_route.call_count == EXPECTED_FETCH_COUNT
        assert stamped
