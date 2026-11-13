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

from py_identity_model.aio.logout import (
    validate_logout_token as aio_validate_logout_token,
)
from py_identity_model.core.logout_logic import (
    BACKCHANNEL_LOGOUT_EVENT,
    validate_logout_token_claims,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    LogoutTokenValidationException,
    TokenExpiredException,
    TokenValidationException,
)
from py_identity_model.sync.logout import validate_logout_token
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
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
        "exp": int(time.time()) + 120,
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
        validate_logout_token_claims(_valid_logout_claims(), client_id=_AUDIENCE)

    def test_missing_events_rejected(self):
        # LOGOUT-005: missing ``events`` claim is rejected.
        claims = _valid_logout_claims()
        del claims["events"]
        with pytest.raises(LogoutTokenValidationException, match=r"events"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_wrong_events_member_rejected(self):
        # LOGOUT-006: ``events`` without the backchannel-logout member is rejected.
        claims = _valid_logout_claims(
            events={"http://schemas.openid.net/event/other": {}}
        )
        with pytest.raises(LogoutTokenValidationException, match=r"backchannel-logout"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_events_not_an_object_rejected(self):
        # LOGOUT-006 (edge): ``events`` present but not a JSON object.
        claims = _valid_logout_claims(events="backchannel-logout")
        with pytest.raises(LogoutTokenValidationException, match=r"JSON object"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_neither_sub_nor_sid_rejected(self):
        # LOGOUT-009: neither ``sub`` nor ``sid`` present is rejected.
        claims = _valid_logout_claims()
        del claims["sub"]
        with pytest.raises(LogoutTokenValidationException, match=r"sub.*sid"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_sid_only_accepted(self):
        # LOGOUT-009 (positive): ``sid`` alone satisfies the sub/sid rule.
        claims = _valid_logout_claims()
        del claims["sub"]
        claims["sid"] = "session-1"
        validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_nonce_present_rejected(self):
        # LOGOUT-010: a Logout Token containing ``nonce`` is rejected.
        claims = _valid_logout_claims(nonce="should-not-be-here")
        with pytest.raises(LogoutTokenValidationException, match=r"nonce"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_missing_exp_rejected(self):
        # Back-Channel Logout 1.0 errata 1 §2.4: ``exp`` is REQUIRED.
        claims = _valid_logout_claims()
        del claims["exp"]
        with pytest.raises(LogoutTokenValidationException, match=r"'exp'"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)

    def test_missing_jti_rejected(self):
        # §2.4 step 2: ``jti`` is required.
        claims = _valid_logout_claims()
        del claims["jti"]
        with pytest.raises(LogoutTokenValidationException, match=r"jti"):
            validate_logout_token_claims(claims, client_id=_AUDIENCE)


class TestLogoutAudience:
    """§2.6 step 4: ``aud`` is validated as for ID Tokens (Core §3.1.3.7 step 3)."""

    def test_untrusted_extra_audience_rejected(self):
        claims = _valid_logout_claims(aud=[_AUDIENCE, "evil"])
        with pytest.raises(LogoutTokenValidationException) as exc_info:
            validate_logout_token_claims(claims, client_id=_AUDIENCE)
        assert (exc_info.value.message, exc_info.value.details) == (
            "Logout token contains audience(s) not trusted by the client",
            {"untrusted_audiences": ["evil"]},
        )

    def test_trusted_extra_audience_accepted(self):
        claims = _valid_logout_claims(aud=[_AUDIENCE, "partner"])
        validate_logout_token_claims(
            claims, client_id=_AUDIENCE, trusted_audiences=["partner"]
        )

    def test_without_client_id_every_audience_is_untrusted(self):
        with pytest.raises(LogoutTokenValidationException) as exc_info:
            validate_logout_token_claims(_valid_logout_claims(), client_id=None)
        assert exc_info.value.details == {"untrusted_audiences": [_AUDIENCE]}

    def test_empty_audience_rejected(self):
        with pytest.raises(LogoutTokenValidationException) as exc_info:
            validate_logout_token_claims(
                _valid_logout_claims(aud=""), client_id=_AUDIENCE
            )
        assert exc_info.value.message == "Logout token missing required 'aud' claim"

    def test_bare_string_trusted_audiences_is_config_error(self):
        with pytest.raises(ConfigurationException):
            validate_logout_token_claims(
                _valid_logout_claims(), client_id=_AUDIENCE, trusted_audiences="x"
            )

    @respx.mock
    def test_sync_wrapper_rejects_untrusted_audience(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_logout_claims(aud=[_AUDIENCE, "evil"]),
            headers={"kid": key_dict["kid"]},
        )
        with pytest.raises(LogoutTokenValidationException) as exc_info:
            validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)
        assert exc_info.value.details == {"untrusted_audiences": ["evil"]}

    @respx.mock
    def test_sync_wrapper_forwards_trusted_audiences(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_logout_claims(aud=[_AUDIENCE, "partner"]),
            headers={"kid": key_dict["kid"]},
        )
        claims = validate_logout_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            trusted_audiences=["partner"],
        )
        assert claims["aud"] == [_AUDIENCE, "partner"]

    async def test_async_wrapper_rejects_untrusted_audience(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, _valid_logout_claims(aud=[_AUDIENCE, "evil"]))
        config = TokenValidationConfig(
            perform_disco=False, key=key_dict, audience=_AUDIENCE, issuer=_ISSUER
        )
        with pytest.raises(LogoutTokenValidationException) as exc_info:
            await aio_validate_logout_token(token, config)
        assert exc_info.value.details == {"untrusted_audiences": ["evil"]}

    async def test_async_wrapper_forwards_trusted_audiences(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, _valid_logout_claims(aud=[_AUDIENCE, "partner"]))
        config = TokenValidationConfig(
            perform_disco=False, key=key_dict, audience=_AUDIENCE, issuer=_ISSUER
        )
        claims = await aio_validate_logout_token(
            token, config, trusted_audiences=["partner"]
        )
        assert claims["aud"] == [_AUDIENCE, "partner"]

    def test_sync_wrapper_rejects_empty_audience(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, _valid_logout_claims(aud=[""]))
        config = TokenValidationConfig(
            perform_disco=False, key=key_dict, audience=_AUDIENCE, issuer=_ISSUER
        )
        with pytest.raises(TokenValidationException) as exc_info:
            validate_logout_token(token, config)
        # The client_id is not among the audiences, so the base aud check fails.
        assert exc_info.value.message == "Invalid audience"

    async def test_async_wrapper_rejects_empty_audience(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, _valid_logout_claims(aud=[""]))
        config = TokenValidationConfig(
            perform_disco=False, key=key_dict, audience=_AUDIENCE, issuer=_ISSUER
        )
        with pytest.raises(TokenValidationException) as exc_info:
            await aio_validate_logout_token(token, config)
        assert exc_info.value.message == "Invalid audience"


class TestLogoutRequiresClientId:
    """§2.6 step 4: ``aud`` must contain the client_id, so one is required."""

    _MESSAGE = (
        "TokenValidationConfig.audience (the client_id) is required to "
        "validate a Logout Token"
    )

    @pytest.mark.parametrize("audience", [None, ""], ids=["none", "empty"])
    @respx.mock
    def test_sync_rejects_missing_client_id_before_io(self, audience):
        config = TokenValidationConfig(
            perform_disco=True, audience=audience, issuer=_ISSUER
        )
        with pytest.raises(ConfigurationException) as exc_info:
            validate_logout_token("not-a-jwt", config, disco_doc_address=DISCO_URL)
        assert exc_info.value.message == self._MESSAGE
        assert respx.calls.call_count == 0

    @respx.mock
    async def test_async_rejects_missing_client_id_before_io(self):
        config = TokenValidationConfig(perform_disco=True, issuer=_ISSUER)
        with pytest.raises(ConfigurationException) as exc_info:
            await aio_validate_logout_token(
                "not-a-jwt", config, disco_doc_address=DISCO_URL
            )
        assert exc_info.value.message == self._MESSAGE
        assert respx.calls.call_count == 0


class TestLogoutManualModeRequiresIssuer:
    """§2.6 step 4 applies Core §3.1.3.7 step 2: the issuer must be pinned."""

    @pytest.mark.parametrize("issuer", [None, "", []], ids=["none", "empty", "list"])
    def test_sync_rejects_missing_issuer(self, rsa_keypair, issuer):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, _valid_logout_claims(iss="https://evil.example"))
        config = TokenValidationConfig(
            perform_disco=False, key=key_dict, audience=_AUDIENCE, issuer=issuer
        )
        with pytest.raises(ConfigurationException) as exc_info:
            validate_logout_token(token, config)
        assert exc_info.value.message == (
            "TokenValidationConfig.issuer is required when perform_disco is "
            "False: the OP issuer must match the token's 'iss' claim"
        )

    async def test_async_rejects_missing_issuer(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, _valid_logout_claims())
        config = TokenValidationConfig(
            perform_disco=False, key=key_dict, audience=_AUDIENCE
        )
        with pytest.raises(ConfigurationException):
            await aio_validate_logout_token(token, config)


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
    def test_logout_token_without_exp_rejected(self, rsa_keypair):
        # Back-Channel Logout 1.0 errata 1 §2.4: ``exp`` is REQUIRED, so a
        # validly signed token without it is rejected.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_logout_claims()
        del claims["exp"]
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        with pytest.raises(LogoutTokenValidationException, match=r"'exp'"):
            validate_logout_token(token, _config(), disco_doc_address=DISCO_URL)

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
