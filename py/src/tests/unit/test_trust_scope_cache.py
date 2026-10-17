"""
Cached documents never cross transport trust scopes (#953).

The validation caches are shared by every client that uses them, and the
default cache by every client called without ``cache=``. A discovery document
or JWKS is only as trustworthy as the transport that fetched it, so each entry
is keyed by the fetching client's ``trust_scope``:

- A client built from a ``Config`` is scoped by ``Config.ca_bundle``; the
  default client and every ``HTTPClient(config=Config())`` share documents.
- A client wrapping a caller-supplied ``httpx`` client is scoped by that
  ``httpx`` client's identity, since its TLS, proxy and redirect settings
  cannot be read back.

The kid-miss cooldown is keyed by ``jwks_uri`` alone and stays shared by every
scope, so clients built per request are still rate-limited together (#945).
"""

from __future__ import annotations

from collections import OrderedDict
import gc

import certifi
import httpx
import pytest
import respx

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.aio.validation_cache import get_default_async_validation_cache
from py_identity_model.core.config import Config
from py_identity_model.core.jwks_cache import JwksCacheEntry, store_jwks_response
from py_identity_model.core.models import JwksResponse, TokenValidationConfig
from py_identity_model.core.parsers import jwks_from_dict
from py_identity_model.core.trust_scope import (
    TrustScope,
    owned_trust_scope,
    wrapped_trust_scope,
)
from py_identity_model.exceptions import (
    KeyNotFoundException,
    SignatureVerificationException,
)
from py_identity_model.sync.http_client import get_default_http_client
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)
from py_identity_model.sync.validation_cache import get_default_validation_cache

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import (
    DEFAULT_TRUST_SCOPE,
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    jwks_cache_key,
    sign_jwt,
)


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
OTHER_JWKS_URL = "https://other.example/jwks"
THIRD_JWKS_URL = "https://third.example/jwks"
KID = "test-kid"
UNKNOWN_KID = "unknown-kid"
CLAIMS = {"sub": "user1", "iss": ISSUER}
TWO_ENTRIES = 2


def _validation_config() -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)


def _key(kid: str = KID) -> tuple[dict, bytes]:
    key_dict, pem = generate_rsa_keypair()
    key_dict["kid"] = kid
    return key_dict, pem


def _jwks(key_dict: dict) -> httpx.Response:
    return httpx.Response(200, json={"keys": [key_dict]})


def _mock_disco() -> respx.Route:
    return respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )


@pytest.fixture(autouse=True)
def _empty_default_caches() -> None:
    clear_discovery_cache()
    clear_jwks_cache()
    async_cache = get_default_async_validation_cache()
    async_cache.disco.clear()
    async_cache.jwks.clear()
    async_cache.kid_miss_last_attempt.clear()


# ============================================================================
# Trust scopes
# ============================================================================


class TestTrustScope:
    def test_clients_built_from_config_are_scoped_by_ca_bundle(self):
        bundle = certifi.where()
        with (
            HTTPClient() as default_bundle,
            HTTPClient(config=Config(ca_bundle=bundle)) as pinned,
        ):
            assert default_bundle.trust_scope == DEFAULT_TRUST_SCOPE
            assert pinned.trust_scope == TrustScope(ca_bundle=bundle)
        assert get_default_http_client().trust_scope == DEFAULT_TRUST_SCOPE
        assert owned_trust_scope(Config(ca_bundle=bundle)) == TrustScope(
            ca_bundle=bundle
        )

    def test_wrappers_of_one_httpx_client_share_a_scope(self):
        with httpx.Client() as raw, httpx.Client() as other:
            first = HTTPClient(raw)
            assert HTTPClient(raw).trust_scope == first.trust_scope
            assert HTTPClient(other).trust_scope != first.trust_scope
            assert first.trust_scope != DEFAULT_TRUST_SCOPE

    def test_a_scope_is_never_reused_after_its_client_is_collected(self):
        seen = set()
        for _ in range(TWO_ENTRIES + 1):
            raw = httpx.Client()
            seen.add(wrapped_trust_scope(raw))
            raw.close()
            del raw
            gc.collect()
        assert len(seen) == TWO_ENTRIES + 1


# ============================================================================
# Cooldown pruning across scopes
# ============================================================================


class TestCooldownPruning:
    def test_cooldown_survives_while_any_scope_caches_the_uri(self):
        strict = DEFAULT_TRUST_SCOPE
        permissive = TrustScope(wrapped_client=-1)
        other = TrustScope(wrapped_client=-2)
        config = Config(cache_max_entries=TWO_ENTRIES)
        key_dict, _ = _key()
        response = JwksResponse(is_successful=True, keys=[jwks_from_dict(key_dict)])
        cache: OrderedDict[tuple[TrustScope, str], JwksCacheEntry] = OrderedDict()
        stamps = {JWKS_URL: 1.0}

        store_jwks_response(cache, stamps, (strict, JWKS_URL), response, config)
        store_jwks_response(cache, stamps, (permissive, JWKS_URL), response, config)
        # Evicts the strict entry; the permissive scope still caches the URI.
        store_jwks_response(cache, stamps, (other, OTHER_JWKS_URL), response, config)
        assert list(cache) == [(permissive, JWKS_URL), (other, OTHER_JWKS_URL)]
        assert stamps == {JWKS_URL: 1.0}

        # Evicts the last entry for the URI, so its cooldown goes too.
        store_jwks_response(cache, stamps, (other, THIRD_JWKS_URL), response, config)
        assert list(cache) == [(other, OTHER_JWKS_URL), (other, THIRD_JWKS_URL)]
        assert stamps == {}


# ============================================================================
# Sync
# ============================================================================

# Permissive client: one JWKS fetch. Strict client: its own fetch, then one
# signature-failure refresh before the cooldown is stamped.
JWKS_FETCHES_FORGED_THEN_STRICT = 3
# Client A: initial fetch plus one kid-miss refresh. Client B: its own fetch;
# the shared cooldown suppresses its refresh.
JWKS_FETCHES_TWO_SCOPES_ONE_COOLDOWN = 3


class TestSyncTrustScopes:
    @respx.mock
    def test_a_permissive_clients_jwks_is_never_served_to_a_strict_client(self):
        legit, _ = _key()
        planted, attacker_pem = _key()
        disco = _mock_disco()
        jwks = respx.get(JWKS_URL).mock(
            side_effect=[_jwks(planted), _jwks(legit), _jwks(legit)]
        )
        forged = sign_jwt(attacker_pem, CLAIMS, headers={"kid": KID})

        with httpx.Client(verify=False) as raw:
            claims = validate_token(
                forged, _validation_config(), DISCO_URL, http_client=HTTPClient(raw)
            )
        assert claims == CLAIMS

        with pytest.raises(SignatureVerificationException):
            validate_token(forged, _validation_config(), DISCO_URL)
        assert disco.call_count == TWO_ENTRIES
        assert jwks.call_count == JWKS_FETCHES_FORGED_THEN_STRICT

    @respx.mock
    def test_clients_in_one_scope_share_documents(self):
        key_dict, pem = _key()
        disco = _mock_disco()
        jwks = respx.get(JWKS_URL).mock(return_value=_jwks(key_dict))
        token = sign_jwt(pem, CLAIMS, headers={"kid": KID})

        for _ in range(TWO_ENTRIES):
            with HTTPClient(config=Config()) as per_request:
                validate_token(
                    token, _validation_config(), DISCO_URL, http_client=per_request
                )
        validate_token(token, _validation_config(), DISCO_URL)
        with httpx.Client() as raw:
            validate_token(
                token, _validation_config(), DISCO_URL, http_client=HTTPClient(raw)
            )
            validate_token(
                token, _validation_config(), DISCO_URL, http_client=HTTPClient(raw)
            )
            wrapped_scope = HTTPClient(raw).trust_scope

        assert disco.call_count == TWO_ENTRIES
        assert jwks.call_count == TWO_ENTRIES
        assert set(get_default_validation_cache().jwks) == {
            jwks_cache_key(JWKS_URL),
            jwks_cache_key(JWKS_URL, wrapped_scope),
        }

    @respx.mock
    def test_a_pinned_ca_bundle_gets_its_own_documents(self):
        key_dict, pem = _key()
        disco = _mock_disco()
        jwks = respx.get(JWKS_URL).mock(return_value=_jwks(key_dict))
        token = sign_jwt(pem, CLAIMS, headers={"kid": KID})

        validate_token(token, _validation_config(), DISCO_URL)
        with HTTPClient(config=Config(ca_bundle=certifi.where())) as pinned:
            validate_token(token, _validation_config(), DISCO_URL, http_client=pinned)

        assert disco.call_count == TWO_ENTRIES
        assert jwks.call_count == TWO_ENTRIES

    @respx.mock
    def test_per_request_wrapped_clients_share_the_cooldown(self):
        key_dict, pem = _key()
        _mock_disco()
        jwks = respx.get(JWKS_URL).mock(return_value=_jwks(key_dict))
        token = sign_jwt(pem, CLAIMS, headers={"kid": UNKNOWN_KID})

        for _ in range(TWO_ENTRIES):
            with httpx.Client() as raw, pytest.raises(KeyNotFoundException):
                validate_token(
                    token, _validation_config(), DISCO_URL, http_client=HTTPClient(raw)
                )

        assert jwks.call_count == JWKS_FETCHES_TWO_SCOPES_ONE_COOLDOWN
        assert set(get_default_validation_cache().kid_miss_last_attempt) == {JWKS_URL}


# ============================================================================
# Async
# ============================================================================


@pytest.mark.asyncio
class TestAsyncTrustScopes:
    @respx.mock
    async def test_a_permissive_clients_jwks_is_never_served_to_a_strict_client(
        self,
    ):
        legit, _ = _key()
        planted, attacker_pem = _key()
        disco = _mock_disco()
        jwks = respx.get(JWKS_URL).mock(
            side_effect=[_jwks(planted), _jwks(legit), _jwks(legit)]
        )
        forged = sign_jwt(attacker_pem, CLAIMS, headers={"kid": KID})

        async with httpx.AsyncClient(verify=False) as raw:
            claims = await async_validate_token(
                forged,
                _validation_config(),
                DISCO_URL,
                http_client=AsyncHTTPClient(raw),
            )
        assert claims == CLAIMS

        with pytest.raises(SignatureVerificationException):
            await async_validate_token(forged, _validation_config(), DISCO_URL)
        assert disco.call_count == TWO_ENTRIES
        assert jwks.call_count == JWKS_FETCHES_FORGED_THEN_STRICT

    @respx.mock
    async def test_clients_in_one_scope_share_documents(self):
        key_dict, pem = _key()
        disco = _mock_disco()
        jwks = respx.get(JWKS_URL).mock(return_value=_jwks(key_dict))
        token = sign_jwt(pem, CLAIMS, headers={"kid": KID})

        for _ in range(TWO_ENTRIES):
            async with AsyncHTTPClient(config=Config()) as per_request:
                await async_validate_token(
                    token, _validation_config(), DISCO_URL, http_client=per_request
                )
        await async_validate_token(token, _validation_config(), DISCO_URL)

        assert disco.call_count == 1
        assert jwks.call_count == 1

    @respx.mock
    async def test_per_request_wrapped_clients_share_the_cooldown(self):
        key_dict, pem = _key()
        _mock_disco()
        jwks = respx.get(JWKS_URL).mock(return_value=_jwks(key_dict))
        token = sign_jwt(pem, CLAIMS, headers={"kid": UNKNOWN_KID})

        for _ in range(TWO_ENTRIES):
            async with httpx.AsyncClient() as raw:
                with pytest.raises(KeyNotFoundException):
                    await async_validate_token(
                        token,
                        _validation_config(),
                        DISCO_URL,
                        http_client=AsyncHTTPClient(raw),
                    )

        assert jwks.call_count == JWKS_FETCHES_TWO_SCOPES_ONE_COOLDOWN
        assert set(get_default_async_validation_cache().kid_miss_last_attempt) == {
            JWKS_URL
        }
