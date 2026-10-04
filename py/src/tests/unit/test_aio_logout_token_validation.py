"""Unit tests for asynchronous Back-Channel Logout token validation.

Async parity for ``py_identity_model.aio.validate_logout_token`` against the
same OpenID Connect Back-Channel Logout 1.0 §2.4 rules verified by the sync
suite (spec IDs LOGOUT-004, LOGOUT-005, LOGOUT-007, LOGOUT-010). The pure
claim rules (LOGOUT-006/009) are covered by the sync suite since the same
``core.logout_logic.validate_logout_token_claims`` function backs both wrappers.
"""

import time

import httpx
import pytest
import respx

from py_identity_model.aio.logout import validate_logout_token
from py_identity_model.aio.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.core.logout_logic import BACKCHANNEL_LOGOUT_EVENT
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    LogoutTokenValidationException,
    TokenExpiredException,
)

from ..constants import DISCO_URL
from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


_ISSUER = "https://example.com"
_AUDIENCE = "client-123"


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    return generate_rsa_keypair()


@pytest.fixture(autouse=True)
async def _clear_caches():
    """Clear all caches between tests (aio helpers are coroutines, #405)."""
    await clear_discovery_cache()
    await clear_jwks_cache()
    yield
    await clear_discovery_cache()
    await clear_jwks_cache()


def _valid_logout_claims(**overrides) -> dict:
    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": int(time.time()),
        "jti": "logout-jti-1",
        "sub": "user-1",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    claims.update(overrides)
    return claims


def _mock_disco_and_jwks(key_dict: dict) -> None:
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    respx.get("https://example.com/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )


def _config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=_AUDIENCE,
        issuer=_ISSUER,
    )


class TestAsyncValidateLogoutToken:
    """Async parity for Back-Channel Logout token validation."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_valid_signed_logout_token_accepted(self, rsa_keypair):
        # LOGOUT-004 (async parity).
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_logout_claims(), headers={"kid": key_dict["kid"]})

        claims = await validate_logout_token(
            token, _config(), disco_doc_address=DISCO_URL
        )

        assert claims["sub"] == "user-1"
        assert BACKCHANNEL_LOGOUT_EVENT in claims["events"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_expired_logout_token_rejected(self, rsa_keypair):
        # LOGOUT-007 (async parity).
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_logout_claims(exp=int(time.time()) - 3600),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(TokenExpiredException):
            await validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_token_with_nonce_rejected(self, rsa_keypair):
        # LOGOUT-010 (async parity): nonce rejected after signature check.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_logout_claims(nonce="nope"),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(LogoutTokenValidationException, match=r"nonce"):
            await validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_token_missing_events_rejected(self, rsa_keypair):
        # LOGOUT-005 (async parity).
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_logout_claims()
        del claims["events"]
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        with pytest.raises(LogoutTokenValidationException, match=r"events"):
            await validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)
