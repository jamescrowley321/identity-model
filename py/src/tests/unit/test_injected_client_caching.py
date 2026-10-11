"""
An injected ``http_client`` gets the full cache stack, not a bypass (#753).

Before #753 passing ``http_client=`` to ``validate_token`` skipped the
discovery cache, the JWKS cache, the kid-miss cooldown and the
signature-failure cooldown, and a one-shot ``logger.warning`` flagged the
opt-out (#402). Each client now owns its caches and cooldown state, so an
injected client is cached and rate-limited exactly like the default client,
and there is nothing left to warn about.

Pinned contract (sync and async):
- Repeated validations through an injected client reuse its cached discovery
  document and JWKS, and leave the default client's caches untouched.
- An unknown ``kid`` forces at most one JWKS refresh per cooldown window on
  the injected client.
- A signature failure on a cached ``kid`` forces at most one JWKS refresh per
  cooldown window on the injected client (the same budget as the kid miss).
- No warning is logged for a successful validation through an injected
  client.

``test_injected_config.py`` covers what ``Config`` changes (cooldown 0,
``cache_max_entries``, cache clearing per client); this file pins the
default-config behavior of the injected client.
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from py_identity_model.aio.http_client import get_default_async_http_client
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.core.discovery_policy import resolve_discovery_policy
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    SignatureVerificationException,
    TokenValidationException,
)
from py_identity_model.sync.http_client import get_default_http_client
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import validate_token

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
KID = "test-kid"
UNKNOWN_KID = "unknown-kid"
REPEATED_CALLS = 5
# One initial JWKS fetch plus one forced refresh; the cooldown suppresses the
# refresh on every later call inside the window.
JWKS_FETCHES_WITH_ONE_REFRESH = 2


def _validation_config() -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)


def _disco_cache_key() -> tuple[str, tuple]:
    config = _validation_config()
    policy = resolve_discovery_policy(config.discovery_policy, config.require_https)
    return (DISCO_URL, policy.cache_key())


def _signed_token(pem: bytes, kid: str = KID) -> str:
    return sign_jwt(pem, {"sub": "user1", "iss": ISSUER}, headers={"kid": kid})


def _published_key() -> tuple[dict, bytes]:
    key_dict, pem = generate_rsa_keypair()
    key_dict["kid"] = KID
    return key_dict, pem


def _mock_disco_and_jwks(key_dict: dict) -> tuple[respx.Route, respx.Route]:
    disco = respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    jwks = respx.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )
    return disco, jwks


def _warnings(records: list[logging.LogRecord]) -> list[str]:
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


# ============================================================================
# Sync
# ============================================================================


class TestSyncInjectedClientCaching:
    @respx.mock
    def test_injected_client_owns_the_caches(self):
        key_dict, pem = _published_key()
        disco, jwks = _mock_disco_and_jwks(key_dict)
        cache_key = _disco_cache_key()

        with HTTPClient() as client:
            for _ in range(REPEATED_CALLS):
                validate_token(
                    _signed_token(pem),
                    _validation_config(),
                    DISCO_URL,
                    http_client=client,
                )
            assert list(client.caches.jwks) == [JWKS_URL]
            assert list(client.caches.disco) == [cache_key]

        assert disco.call_count == 1
        assert jwks.call_count == 1
        default_caches = get_default_http_client().caches
        assert JWKS_URL not in default_caches.jwks
        assert cache_key not in default_caches.disco

    @respx.mock
    def test_kid_miss_cooldown_applies_to_injected_client(self):
        key_dict, pem = _published_key()
        _, jwks = _mock_disco_and_jwks(key_dict)

        with HTTPClient() as client:
            for _ in range(REPEATED_CALLS):
                with pytest.raises(TokenValidationException):
                    validate_token(
                        _signed_token(pem, kid=UNKNOWN_KID),
                        _validation_config(),
                        DISCO_URL,
                        http_client=client,
                    )
            assert list(client.caches.kid_miss_last_attempt) == [JWKS_URL]

        assert jwks.call_count == JWKS_FETCHES_WITH_ONE_REFRESH
        assert JWKS_URL not in get_default_http_client().caches.kid_miss_last_attempt

    @respx.mock
    def test_signature_failure_cooldown_applies_to_injected_client(self):
        published_key, _ = _published_key()
        _, forger_pem = generate_rsa_keypair()
        _, jwks = _mock_disco_and_jwks(published_key)

        with HTTPClient() as client:
            for _ in range(REPEATED_CALLS):
                with pytest.raises(SignatureVerificationException):
                    validate_token(
                        _signed_token(forger_pem),
                        _validation_config(),
                        DISCO_URL,
                        http_client=client,
                    )
            assert list(client.caches.kid_miss_last_attempt) == [JWKS_URL]

        assert jwks.call_count == JWKS_FETCHES_WITH_ONE_REFRESH

    @respx.mock
    def test_no_warning_for_injected_client(self, caplog):
        key_dict, pem = _published_key()
        _mock_disco_and_jwks(key_dict)

        with (
            caplog.at_level(logging.WARNING, logger="py_identity_model"),
            HTTPClient() as client,
        ):
            for _ in range(REPEATED_CALLS):
                validate_token(
                    _signed_token(pem),
                    _validation_config(),
                    DISCO_URL,
                    http_client=client,
                )

        assert _warnings(caplog.records) == []


# ============================================================================
# Async mirror
# ============================================================================


class TestAsyncInjectedClientCaching:
    @pytest.mark.asyncio
    @respx.mock
    async def test_injected_client_owns_the_caches(self):
        key_dict, pem = _published_key()
        disco, jwks = _mock_disco_and_jwks(key_dict)
        cache_key = _disco_cache_key()

        async with AsyncHTTPClient() as client:
            for _ in range(REPEATED_CALLS):
                await async_validate_token(
                    _signed_token(pem),
                    _validation_config(),
                    DISCO_URL,
                    http_client=client,
                )
            assert list(client.caches.jwks) == [JWKS_URL]
            assert list(client.caches.disco) == [cache_key]

        assert disco.call_count == 1
        assert jwks.call_count == 1
        default_caches = get_default_async_http_client().caches
        assert JWKS_URL not in default_caches.jwks
        assert cache_key not in default_caches.disco

    @pytest.mark.asyncio
    @respx.mock
    async def test_kid_miss_cooldown_applies_to_injected_client(self):
        key_dict, pem = _published_key()
        _, jwks = _mock_disco_and_jwks(key_dict)

        async with AsyncHTTPClient() as client:
            for _ in range(REPEATED_CALLS):
                with pytest.raises(TokenValidationException):
                    await async_validate_token(
                        _signed_token(pem, kid=UNKNOWN_KID),
                        _validation_config(),
                        DISCO_URL,
                        http_client=client,
                    )
            assert list(client.caches.kid_miss_last_attempt) == [JWKS_URL]

        assert jwks.call_count == JWKS_FETCHES_WITH_ONE_REFRESH
        default_caches = get_default_async_http_client().caches
        assert JWKS_URL not in default_caches.kid_miss_last_attempt

    @pytest.mark.asyncio
    @respx.mock
    async def test_signature_failure_cooldown_applies_to_injected_client(self):
        published_key, _ = _published_key()
        _, forger_pem = generate_rsa_keypair()
        _, jwks = _mock_disco_and_jwks(published_key)

        async with AsyncHTTPClient() as client:
            for _ in range(REPEATED_CALLS):
                with pytest.raises(SignatureVerificationException):
                    await async_validate_token(
                        _signed_token(forger_pem),
                        _validation_config(),
                        DISCO_URL,
                        http_client=client,
                    )
            assert list(client.caches.kid_miss_last_attempt) == [JWKS_URL]

        assert jwks.call_count == JWKS_FETCHES_WITH_ONE_REFRESH

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_warning_for_injected_client(self, caplog):
        key_dict, pem = _published_key()
        _mock_disco_and_jwks(key_dict)

        with caplog.at_level(logging.WARNING, logger="py_identity_model"):
            async with AsyncHTTPClient() as client:
                for _ in range(REPEATED_CALLS):
                    await async_validate_token(
                        _signed_token(pem),
                        _validation_config(),
                        DISCO_URL,
                        http_client=client,
                    )

        assert _warnings(caplog.records) == []
