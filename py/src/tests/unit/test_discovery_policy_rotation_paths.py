"""
Proves the injected ``DiscoveryPolicy`` threads through *every* cached-path
sub-operation of ``validate_token`` — not just the initial discovery/JWKS
fetch, but the key-rotation refresh, the signature-failure retry, and the
injected-``http_client`` (DI) path.

Why this file exists
--------------------
``test_discovery_policy_injection.py`` proves the headline property (an injected
policy reaches the cached path and partitions the cache). ``test_require_https_
wiring.py`` proves the legacy ``require_https`` bool threads through. But both
exercise only the *happy* cached path — a single discovery + single JWKS fetch.
Neither drives the **refresh / retry / rotation** sub-paths, so a regression
that made ``_refresh_jwks`` / ``_retry_with_refreshed_jwks`` /
``_discover_and_resolve_key`` fall back to a *default* policy on those branches
would pass every existing test while silently re-imposing strict HTTPS (or any
other default knob) on a caller who opted out.

The lever
---------
A **non-loopback ``http://`` issuer**. The strict default policy rejects a
plaintext-HTTP endpoint on a non-loopback host (``validate_url_scheme`` raises
*before* the network call, inside ``get_jwks`` / ``get_discovery_document``
pre-flight); an injected ``DiscoveryPolicy(require_https=False)`` admits it. By
routing each refresh/retry fetch over such a URL and asserting the call
*succeeds and actually re-fetches*, we pin that the injected policy — not a
default — governs that specific fetch:

* real code  → refresh fetch admitted → ``jwks_route.call_count == 2`` → success
* a mutant that swaps in a default policy → refresh fetch pre-flight-rejected →
  the second fetch never fires (``call_count == 1``) → ``TokenValidationException``

Every config below sets ``discovery_policy=DiscoveryPolicy(require_https=False)``
while leaving the top-level ``require_https`` at its default ``True``, so these
tests *also* pin the precedence rule end-to-end: the injected policy overrides
the legacy bool on the rotation/retry paths, not only at the top of
``validate_token``.
"""

import httpx
import pytest
import respx

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    _kid_miss_last_attempt as async_kid_miss_last_attempt,
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
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import build_resolved_config
from py_identity_model.exceptions import (
    SignatureVerificationException,
    TokenValidationException,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    _kid_miss_last_attempt as sync_kid_miss_last_attempt,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache as sync_clear_discovery_cache,
)
from py_identity_model.sync.token_validation import (
    clear_jwks_cache as sync_clear_jwks_cache,
)
from py_identity_model.sync.token_validation import (
    validate_token as sync_validate_token,
)

from .token_validation_helpers import generate_rsa_keypair, sign_jwt


# ── Non-loopback HTTP endpoint: the default policy rejects it, an injected
#    ``require_https=False`` policy admits it. Loopback is unusable here because
#    the default ``allow_http_on_loopback=True`` would admit it regardless of
#    the injected policy, making the policy unobservable. ────────────────────
HTTP_ISSUER = "http://external.example.com"
HTTP_DISCO_URL = f"{HTTP_ISSUER}/.well-known/openid-configuration"
HTTP_JWKS_URL = f"{HTTP_ISSUER}/jwks"

HTTP_DISCO_DOC = {
    "issuer": HTTP_ISSUER,
    "authorization_endpoint": f"{HTTP_ISSUER}/authorize",
    "token_endpoint": f"{HTTP_ISSUER}/token",
    "jwks_uri": HTTP_JWKS_URL,
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

# Injected policy that relaxes ONLY the HTTPS requirement. Every other knob
# keeps its strict default, so the same-authority endpoint check still runs.
LAX_POLICY = DiscoveryPolicy(require_https=False)

SUBJECT = "user1"
OLD_KID = "old-kid"
NEW_KID = "new-kid"
SHARED_KID = "shared-kid"

# 1 prime fetch + 1 forced refresh in a single validate_token call. Named so the
# assertion reads as intent, not a bare literal.
PRIME_PLUS_REFRESH = 2


def _keypair_with_kid(kid: str) -> tuple[dict, bytes]:
    """A fresh RSA keypair whose JWK advertises ``kid``. Returns (jwk, pem)."""
    key_dict, pem = generate_rsa_keypair()
    key_dict["kid"] = kid
    return key_dict, pem


def _token(pem: bytes, kid: str) -> str:
    return sign_jwt(
        pem,
        {"sub": SUBJECT, "iss": HTTP_ISSUER},
        headers={"kid": kid},
    )


def _lax_config() -> TokenValidationConfig:
    """Config that injects the lax policy but leaves ``require_https=True``,
    so a pass proves the *policy* (not the bool) governs the refresh/retry
    fetches."""
    return TokenValidationConfig(
        perform_disco=True,
        audience=None,
        issuer=HTTP_ISSUER,
        discovery_policy=LAX_POLICY,
        # require_https intentionally left at its default True.
    )


@pytest.fixture(autouse=True)
async def _clear_caches():
    """Isolate cache + cooldown state (clear_jwks_cache also clears the
    kid-miss cooldown dict)."""
    sync_clear_discovery_cache()
    sync_clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    sync_clear_discovery_cache()
    sync_clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


# ============================================================================
# Kid-miss key-rotation refresh (``_discover_and_resolve_key`` cached branch →
# ``_get_cached_jwks`` prime → ``_refresh_jwks``). The token's kid is absent
# from the primed JWKS, forcing a refresh that must be admitted by the injected
# policy.
# ============================================================================


class TestInjectedPolicyGovernsKidMissRefresh:
    @respx.mock
    def test_sync_rotation_refresh_admitted_by_injected_policy(self):
        old_key, _ = _keypair_with_kid(OLD_KID)
        new_key, new_pem = _keypair_with_kid(NEW_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key]}),  # prime
                httpx.Response(200, json={"keys": [new_key]}),  # rotation refresh
            ]
        )

        decoded = sync_validate_token(
            jwt=_token(new_pem, NEW_KID),
            token_validation_config=_lax_config(),
            disco_doc_address=HTTP_DISCO_URL,
        )

        assert decoded["sub"] == SUBJECT
        # The refresh fetch actually fired over HTTP — proving the *refresh*
        # used the injected policy, not a default (which would pre-flight
        # reject the http URL and never issue the second request).
        assert jwks_route.call_count == PRIME_PLUS_REFRESH
        # Successful rotation clears the kid-miss cooldown stamp.
        assert HTTP_JWKS_URL not in sync_kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_rotation_refresh_admitted_by_injected_policy(self):
        old_key, _ = _keypair_with_kid(OLD_KID)
        new_key, new_pem = _keypair_with_kid(NEW_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key]}),
                httpx.Response(200, json={"keys": [new_key]}),
            ]
        )

        decoded = await async_validate_token(
            jwt=_token(new_pem, NEW_KID),
            token_validation_config=_lax_config(),
            disco_doc_address=HTTP_DISCO_URL,
        )

        assert decoded["sub"] == SUBJECT
        assert jwks_route.call_count == PRIME_PLUS_REFRESH
        assert HTTP_JWKS_URL not in async_kid_miss_last_attempt

    @respx.mock
    def test_sync_default_policy_rejects_http_flow_control(self):
        """Control: without the injected policy the same http flow is rejected
        at the very first fetch — proving the acceptance above is caused by the
        injected policy, not by the endpoint being permissible by default."""
        old_key, _ = _keypair_with_kid(OLD_KID)
        new_key, new_pem = _keypair_with_kid(NEW_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        respx.get(HTTP_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [old_key, new_key]})
        )

        strict = TokenValidationConfig(
            perform_disco=True, audience=None, issuer=HTTP_ISSUER
        )
        with pytest.raises(TokenValidationException, match="HTTPS is required"):
            sync_validate_token(
                jwt=_token(new_pem, NEW_KID),
                token_validation_config=strict,
                disco_doc_address=HTTP_DISCO_URL,
            )


# ============================================================================
# Signature-failure retry (``_retry_with_refreshed_jwks``). The token's kid IS
# cached, but the cached key material is stale; the initial decode fails on the
# signature, forcing a refresh + retry that must be admitted by the injected
# policy. Same-kid rotation is legal per RFC 7517 §4.5.
# ============================================================================


class TestInjectedPolicyGovernsSignatureRetry:
    @respx.mock
    def test_sync_signature_retry_refresh_admitted_by_injected_policy(self):
        cached_key, _cached_pem = _keypair_with_kid(SHARED_KID)
        rotated_key, rotated_pem = _keypair_with_kid(SHARED_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_key]}),  # prime (stale)
                httpx.Response(200, json={"keys": [rotated_key]}),  # retry refresh
            ]
        )

        # Signed with the ROTATED key but advertising the cached kid: the
        # validator finds the cached key, the signature check fails, and the
        # retry path refreshes to the rotated key.
        decoded = sync_validate_token(
            jwt=_token(rotated_pem, SHARED_KID),
            token_validation_config=_lax_config(),
            disco_doc_address=HTTP_DISCO_URL,
        )

        assert decoded["sub"] == SUBJECT
        assert jwks_route.call_count == PRIME_PLUS_REFRESH
        # Retry succeeded → real rotation absorbed → cooldown stamp cleared.
        assert HTTP_JWKS_URL not in sync_kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_signature_retry_refresh_admitted_by_injected_policy(self):
        cached_key, _cached_pem = _keypair_with_kid(SHARED_KID)
        rotated_key, rotated_pem = _keypair_with_kid(SHARED_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_key]}),
                httpx.Response(200, json={"keys": [rotated_key]}),
            ]
        )

        decoded = await async_validate_token(
            jwt=_token(rotated_pem, SHARED_KID),
            token_validation_config=_lax_config(),
            disco_doc_address=HTTP_DISCO_URL,
        )

        assert decoded["sub"] == SUBJECT
        assert jwks_route.call_count == PRIME_PLUS_REFRESH
        assert HTTP_JWKS_URL not in async_kid_miss_last_attempt


# ============================================================================
# Signature-failure retry that still fails after the refresh: the refresh IS
# admitted by the injected policy (so it fires and delivers a usable response),
# but the delivered key still cannot verify the attacker-forged token. This
# pins the *stamp* branch (opposite of the clear-on-success branch above) while
# proving the retry refresh used the injected policy.
# ============================================================================


class TestInjectedPolicyRetryStampsCooldownOnPersistentFailure:
    @respx.mock
    def test_sync_persistent_signature_failure_stamps_cooldown(self):
        cached_key, _cached_pem = _keypair_with_kid(SHARED_KID)
        refreshed_key, _refreshed_pem = _keypair_with_kid(SHARED_KID)
        _forged_key, forged_pem = _keypair_with_kid(SHARED_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_key]}),  # prime
                httpx.Response(200, json={"keys": [refreshed_key]}),  # refresh
            ]
        )

        # Token is signed by a key the upstream never serves; the refresh
        # delivers a real (but wrong) key, so decode still fails.
        with pytest.raises(SignatureVerificationException):
            sync_validate_token(
                jwt=_token(forged_pem, SHARED_KID),
                token_validation_config=_lax_config(),
                disco_doc_address=HTTP_DISCO_URL,
            )

        # The refresh was admitted (fired) but decode still failed → the
        # attacker-amplifiable path stamps the cooldown to suppress repeats.
        assert jwks_route.call_count == PRIME_PLUS_REFRESH
        assert HTTP_JWKS_URL in sync_kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_persistent_signature_failure_stamps_cooldown(self):
        cached_key, _cached_pem = _keypair_with_kid(SHARED_KID)
        refreshed_key, _refreshed_pem = _keypair_with_kid(SHARED_KID)
        _forged_key, forged_pem = _keypair_with_kid(SHARED_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_key]}),
                httpx.Response(200, json={"keys": [refreshed_key]}),
            ]
        )

        with pytest.raises(SignatureVerificationException):
            await async_validate_token(
                jwt=_token(forged_pem, SHARED_KID),
                token_validation_config=_lax_config(),
                disco_doc_address=HTTP_DISCO_URL,
            )

        assert jwks_route.call_count == PRIME_PLUS_REFRESH
        assert HTTP_JWKS_URL in async_kid_miss_last_attempt


# ============================================================================
# Injected-``http_client`` (DI) path. It bypasses the caches but must still
# apply the injected policy to both the discovery fetch and the JWKS fetch
# (``_discover_and_resolve_key`` DI branch), and to the retry refresh
# (``_retry_with_refreshed_jwks`` DI branch).
# ============================================================================


class TestInjectedPolicyGovernsInjectedClientPath:
    @respx.mock
    def test_sync_di_discovery_and_jwks_use_policy(self):
        key_dict, pem = _keypair_with_kid(NEW_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        respx.get(HTTP_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        with HTTPClient() as client:
            decoded = sync_validate_token(
                jwt=_token(pem, NEW_KID),
                token_validation_config=_lax_config(),
                disco_doc_address=HTTP_DISCO_URL,
                http_client=client,
            )
        assert decoded["sub"] == SUBJECT

    @respx.mock
    def test_sync_di_signature_retry_uses_policy(self):
        cached_key, _cached_pem = _keypair_with_kid(SHARED_KID)
        rotated_key, rotated_pem = _keypair_with_kid(SHARED_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_key]}),  # DI initial
                httpx.Response(200, json={"keys": [rotated_key]}),  # DI retry
            ]
        )

        with HTTPClient() as client:
            decoded = sync_validate_token(
                jwt=_token(rotated_pem, SHARED_KID),
                token_validation_config=_lax_config(),
                disco_doc_address=HTTP_DISCO_URL,
                http_client=client,
            )
        assert decoded["sub"] == SUBJECT
        assert jwks_route.call_count == PRIME_PLUS_REFRESH

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_di_discovery_and_jwks_use_policy(self):
        key_dict, pem = _keypair_with_kid(NEW_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        respx.get(HTTP_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        async with AsyncHTTPClient() as client:
            decoded = await async_validate_token(
                jwt=_token(pem, NEW_KID),
                token_validation_config=_lax_config(),
                disco_doc_address=HTTP_DISCO_URL,
                http_client=client,
            )
        assert decoded["sub"] == SUBJECT

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_di_signature_retry_uses_policy(self):
        cached_key, _cached_pem = _keypair_with_kid(SHARED_KID)
        rotated_key, rotated_pem = _keypair_with_kid(SHARED_KID)

        respx.get(HTTP_DISCO_URL).mock(
            return_value=httpx.Response(200, json=HTTP_DISCO_DOC)
        )
        jwks_route = respx.get(HTTP_JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [cached_key]}),
                httpx.Response(200, json={"keys": [rotated_key]}),
            ]
        )

        async with AsyncHTTPClient() as client:
            decoded = await async_validate_token(
                jwt=_token(rotated_pem, SHARED_KID),
                token_validation_config=_lax_config(),
                disco_doc_address=HTTP_DISCO_URL,
                http_client=client,
            )
        assert decoded["sub"] == SUBJECT
        assert jwks_route.call_count == PRIME_PLUS_REFRESH


# ============================================================================
# ``build_resolved_config`` must carry the injected policy onto the resolved
# config verbatim. The disco/retry paths re-derive their policy from the
# resolved config (``_retry_with_refreshed_jwks`` calls
# ``resolve_discovery_policy(config.discovery_policy, config.require_https)``),
# so dropping it here would silently re-impose the default on the retry.
# ============================================================================


class TestBuildResolvedConfigPreservesDiscoveryPolicy:
    def test_injected_policy_preserved_by_identity(self):
        policy = DiscoveryPolicy(
            validate_issuer=False,
            additional_endpoint_base_addresses=["https://cdn.example"],
        )
        original = TokenValidationConfig(
            perform_disco=True,
            audience="aud",
            discovery_policy=policy,
        )
        resolved = build_resolved_config(original, {"kty": "RSA"}, "RS256")
        # Same object, not a reconstructed default — a mutant that drops the
        # kwarg (→ None) or rebuilds a fresh policy fails this.
        assert resolved.discovery_policy is policy

    def test_none_policy_preserved_as_none(self):
        original = TokenValidationConfig(perform_disco=True, audience="aud")
        resolved = build_resolved_config(original, {"kty": "RSA"}, "RS256")
        assert resolved.discovery_policy is None
