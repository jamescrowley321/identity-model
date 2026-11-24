"""``validate_token`` rejects a JWT whose ``typ`` names another kind (RFC 9701 §8.1).

A signed introspection response or a Logout Token that the issuer signed for
the resource server's audience must not pass as an access token. ID Token and
Logout Token validation keep accepting their own ``typ``.
"""

import time

import httpx
import pytest
import respx

from py_identity_model import (
    AccessTokenTypeError,
    AccessTokenTypeErrorKind,
    TokenValidationException,
)
from py_identity_model.aio.logout import (
    validate_logout_token as aio_validate_logout_token,
)
from py_identity_model.aio.token_validation import (
    validate_token as aio_validate_token,
)
from py_identity_model.core.logout_logic import BACKCHANNEL_LOGOUT_EVENT
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import (
    reject_non_access_token_type,
)
from py_identity_model.sync.logout import validate_logout_token
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


_ISSUER = "https://example.com"
_AUDIENCE = "client-123"


@pytest.fixture(scope="module")
def rsa_keypair():
    return generate_rsa_keypair()


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _access_token_claims() -> dict:
    now = int(time.time())
    return {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
    }


def _introspection_response_claims() -> dict:
    # RFC 9701 §5: no exp and no top-level sub; the result is nested.
    return {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": int(time.time()),
        "token_introspection": {"active": True, "sub": "user-1"},
    }


def _logout_token_claims() -> dict:
    now = int(time.time())
    return {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": "user-1",
        "iat": now,
        "exp": now + 120,
        "jti": "logout-jti-1",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }


def _sign(rsa_keypair, claims: dict, typ: str | None) -> str:
    key_dict, pem = rsa_keypair
    # PyJWT drops a typ of None and otherwise defaults it to "JWT".
    headers = {"kid": key_dict["kid"], "typ": typ}
    return sign_jwt(pem, claims, headers=headers)


def _manual_config(rsa_keypair) -> TokenValidationConfig:
    key_dict, _ = rsa_keypair
    return TokenValidationConfig(
        perform_disco=False,
        key=key_dict,
        algorithms=["RS256"],
        audience=_AUDIENCE,
        issuer=_ISSUER,
    )


def _disco_config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=_AUDIENCE,
        issuer=_ISSUER,
    )


def _mock_disco_and_jwks(key_dict: dict) -> None:
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    respx.get("https://example.com/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )


def _error_fields(err: AccessTokenTypeError) -> dict:
    return {
        "kind": err.kind,
        "token_part": err.token_part,
        "details": err.details,
    }


def _expected_fields(kind: AccessTokenTypeErrorKind) -> dict:
    return {
        "kind": kind,
        "token_part": "header",
        "details": {"typ": kind.value},
    }


class TestRejectedAsAccessToken:
    def test_introspection_response_rejected(self, rsa_keypair):
        token = _sign(
            rsa_keypair, _introspection_response_claims(), "token-introspection+jwt"
        )
        with pytest.raises(AccessTokenTypeError) as exc_info:
            validate_token(token, _manual_config(rsa_keypair))
        assert _error_fields(exc_info.value) == _expected_fields(
            AccessTokenTypeErrorKind.TOKEN_INTROSPECTION
        )

    def test_logout_token_rejected(self, rsa_keypair):
        token = _sign(rsa_keypair, _logout_token_claims(), "logout+jwt")
        with pytest.raises(AccessTokenTypeError) as exc_info:
            validate_token(token, _manual_config(rsa_keypair))
        assert _error_fields(exc_info.value) == _expected_fields(
            AccessTokenTypeErrorKind.LOGOUT
        )

    async def test_async_introspection_response_rejected(self, rsa_keypair):
        token = _sign(
            rsa_keypair, _introspection_response_claims(), "token-introspection+jwt"
        )
        with pytest.raises(AccessTokenTypeError) as exc_info:
            await aio_validate_token(token, _manual_config(rsa_keypair))
        assert _error_fields(exc_info.value) == _expected_fields(
            AccessTokenTypeErrorKind.TOKEN_INTROSPECTION
        )

    async def test_async_logout_token_rejected(self, rsa_keypair):
        token = _sign(rsa_keypair, _logout_token_claims(), "logout+jwt")
        with pytest.raises(AccessTokenTypeError) as exc_info:
            await aio_validate_token(token, _manual_config(rsa_keypair))
        assert _error_fields(exc_info.value) == _expected_fields(
            AccessTokenTypeErrorKind.LOGOUT
        )

    @respx.mock
    def test_rejected_in_discovery_mode_before_any_request(self, rsa_keypair):
        key_dict, _ = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = _sign(rsa_keypair, _logout_token_claims(), "logout+jwt")
        with pytest.raises(AccessTokenTypeError) as exc_info:
            validate_token(token, _disco_config(), disco_doc_address=DISCO_URL)
        assert _error_fields(exc_info.value) == _expected_fields(
            AccessTokenTypeErrorKind.LOGOUT
        )
        assert respx.calls.call_count == 0

    @pytest.mark.parametrize("kind", list(AccessTokenTypeErrorKind), ids=str)
    @pytest.mark.parametrize(
        "spelling",
        ["bare", "media-type", "upper"],
    )
    def test_every_kind_and_spelling_rejected(self, rsa_keypair, kind, spelling):
        typ = {
            "bare": kind.value,
            "media-type": f"application/{kind.value}",
            "upper": f"APPLICATION/{kind.value.upper()}",
        }[spelling]
        token = _sign(rsa_keypair, _access_token_claims(), typ)
        with pytest.raises(AccessTokenTypeError) as exc_info:
            validate_token(token, _manual_config(rsa_keypair))
        assert _error_fields(exc_info.value) == _expected_fields(kind)

    def test_is_a_token_validation_exception(self):
        assert issubclass(AccessTokenTypeError, TokenValidationException)


class TestAcceptedAsAccessToken:
    @pytest.mark.parametrize(
        "typ", ["at+jwt", "application/at+jwt", "JWT", None, "unregistered+jwt"]
    )
    def test_access_token_typ_accepted(self, rsa_keypair, typ):
        claims = _access_token_claims()
        token = _sign(rsa_keypair, claims, typ)
        assert validate_token(token, _manual_config(rsa_keypair)) == claims

    async def test_async_at_jwt_accepted(self, rsa_keypair):
        claims = _access_token_claims()
        token = _sign(rsa_keypair, claims, "at+jwt")
        assert await aio_validate_token(token, _manual_config(rsa_keypair)) == claims

    def test_unreadable_header_left_to_decoding(self):
        assert reject_non_access_token_type("not-a-jwt") is None

    def test_non_string_typ_left_to_decoding(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem, _access_token_claims(), headers={"kid": key_dict["kid"], "typ": 1}
        )
        assert reject_non_access_token_type(token) is None


class TestLogoutTokenValidationUnaffected:
    @respx.mock
    def test_logout_token_with_logout_typ_accepted(self, rsa_keypair):
        key_dict, _ = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _logout_token_claims()
        token = _sign(rsa_keypair, claims, "logout+jwt")
        assert (
            validate_logout_token(token, _disco_config(), disco_doc_address=DISCO_URL)
            == claims
        )

    @respx.mock
    async def test_async_logout_token_with_logout_typ_accepted(self, rsa_keypair):
        key_dict, _ = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _logout_token_claims()
        token = _sign(rsa_keypair, claims, "logout+jwt")
        assert (
            await aio_validate_logout_token(
                token, _disco_config(), disco_doc_address=DISCO_URL
            )
            == claims
        )
