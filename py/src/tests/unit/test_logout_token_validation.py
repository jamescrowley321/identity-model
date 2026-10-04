"""Unit tests for synchronous Back-Channel Logout token validation.

Covers OpenID Connect Back-Channel Logout 1.0 §2.4 Logout Token validation
(spec IDs LOGOUT-004, LOGOUT-005, LOGOUT-006, LOGOUT-007, LOGOUT-009,
LOGOUT-010). Structural rules are tested directly against the pure claim
function; accept/expire cases run the full signature+discovery flow via respx.
"""

import time

import httpx
import pytest
import respx

from py_identity_model.core.logout_logic import (
    BACKCHANNEL_LOGOUT_EVENT,
    validate_logout_token_claims,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    LogoutTokenValidationException,
    TokenExpiredException,
)
from py_identity_model.sync.logout import validate_logout_token
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
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
def _clear_caches():
    """Clear all caches between tests."""
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _valid_logout_claims(**overrides) -> dict:
    """Build a well-formed Logout Token claim set (LOGOUT-004 shape)."""
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


class TestPureLogoutClaimValidation:
    """Structural Logout Token rules (pure claim function)."""

    def test_valid_logout_token_claims_accepted(self):
        # LOGOUT-004 (structural): a well-formed claim set validates cleanly.
        validate_logout_token_claims(_valid_logout_claims())

    def test_missing_events_rejected(self):
        # LOGOUT-005: missing ``events`` claim is rejected.
        claims = _valid_logout_claims()
        del claims["events"]
        with pytest.raises(LogoutTokenValidationException, match=r"events"):
            validate_logout_token_claims(claims)

    def test_wrong_events_member_rejected(self):
        # LOGOUT-006: ``events`` without the backchannel-logout member is rejected.
        claims = _valid_logout_claims(
            events={"http://schemas.openid.net/event/other": {}}
        )
        with pytest.raises(LogoutTokenValidationException, match=r"backchannel-logout"):
            validate_logout_token_claims(claims)

    def test_events_not_an_object_rejected(self):
        # LOGOUT-006 (edge): ``events`` present but not a JSON object.
        claims = _valid_logout_claims(events="backchannel-logout")
        with pytest.raises(LogoutTokenValidationException, match=r"JSON object"):
            validate_logout_token_claims(claims)

    def test_neither_sub_nor_sid_rejected(self):
        # LOGOUT-009: neither ``sub`` nor ``sid`` present is rejected.
        claims = _valid_logout_claims()
        del claims["sub"]
        with pytest.raises(LogoutTokenValidationException, match=r"sub.*sid"):
            validate_logout_token_claims(claims)

    def test_sid_only_accepted(self):
        # LOGOUT-009 (positive): ``sid`` alone satisfies the sub/sid rule.
        claims = _valid_logout_claims()
        del claims["sub"]
        claims["sid"] = "session-1"
        validate_logout_token_claims(claims)

    def test_nonce_present_rejected(self):
        # LOGOUT-010: a Logout Token containing ``nonce`` is rejected.
        claims = _valid_logout_claims(nonce="should-not-be-here")
        with pytest.raises(LogoutTokenValidationException, match=r"nonce"):
            validate_logout_token_claims(claims)

    def test_missing_jti_rejected(self):
        # §2.4 step 2: ``jti`` is required.
        claims = _valid_logout_claims()
        del claims["jti"]
        with pytest.raises(LogoutTokenValidationException, match=r"jti"):
            validate_logout_token_claims(claims)


class TestSyncValidateLogoutToken:
    """Full signature + discovery flow via ``validate_logout_token``."""

    @respx.mock
    def test_valid_signed_logout_token_accepted(self, rsa_keypair):
        # LOGOUT-004: a well-formed, signed Logout Token is accepted.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_logout_claims(), headers={"kid": key_dict["kid"]})

        claims = validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)

        assert claims["sub"] == "user-1"
        assert BACKCHANNEL_LOGOUT_EVENT in claims["events"]

    @respx.mock
    def test_expired_logout_token_rejected(self, rsa_keypair):
        # LOGOUT-007: a Logout Token with ``exp`` in the past is rejected.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_logout_claims(exp=int(time.time()) - 3600),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(TokenExpiredException):
            validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)

    @respx.mock
    def test_logout_token_without_exp_accepted(self, rsa_keypair):
        # §2.4: ``exp`` is not required; a valid token without it is accepted.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_logout_claims()
        assert "exp" not in claims
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        decoded = validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)
        assert decoded["jti"] == "logout-jti-1"

    @respx.mock
    def test_signed_token_with_nonce_rejected_after_signature_check(self, rsa_keypair):
        # LOGOUT-010: the wrapper applies the Logout rules even for a token
        # whose signature is otherwise valid.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_logout_claims(nonce="nope"),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(LogoutTokenValidationException, match=r"nonce"):
            validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)

    @respx.mock
    def test_signed_token_missing_events_rejected(self, rsa_keypair):
        # LOGOUT-005: missing ``events`` fails through the full flow.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_logout_claims()
        del claims["events"]
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        with pytest.raises(LogoutTokenValidationException, match=r"events"):
            validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)
