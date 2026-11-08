"""Signed JWT introspection responses (RFC 9701)."""

import json
import time

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt as pyjwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    IntrospectionErrorKind,
    JwksResponse,
    SignedIntrospectionOptions,
    TokenIntrospectionRequest,
    get_discovery_document,
    jwks_from_dict,
)
from py_identity_model.aio.introspection import introspect_token as aintrospect_token
from py_identity_model.sync.introspection import introspect_token


INTROSPECT_URL = "https://auth.example.com/introspect"
ISSUER = "https://auth.example.com"
CLIENT_ID = "rs-client"
MEDIA_TYPE = "application/token-introspection+jwt"
ACTIVE = {"active": True, "sub": "user-1", "scope": "read"}


@pytest.fixture(scope="module")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(ec_key, rsa_key) -> JwksResponse:
    ec_jwk = json.loads(ECAlgorithm.to_jwk(ec_key.public_key()))
    ec_jwk.update({"kid": "ec-1", "alg": "ES256"})
    rsa_jwk = json.loads(RSAAlgorithm.to_jwk(rsa_key.public_key()))
    rsa_jwk.update({"kid": "rsa-1"})
    return JwksResponse(
        is_successful=True, keys=[jwks_from_dict(ec_jwk), jwks_from_dict(rsa_jwk)]
    )


@pytest.fixture
def sign(ec_key):
    def _sign(
        *, key=None, alg="ES256", kid="ec-1", typ="token-introspection+jwt", **overrides
    ) -> str:
        payload = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": int(time.time()),
            "token_introspection": ACTIVE,
            **overrides,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        return pyjwt.encode(
            payload, key or ec_key, algorithm=alg, headers={"typ": typ, "kid": kid}
        )

    return _sign


def _request(jwks: JwksResponse, **options) -> TokenIntrospectionRequest:
    return TokenIntrospectionRequest(
        address=INTROSPECT_URL,
        token="the-token",
        client_id=CLIENT_ID,
        client_secret="secret",
        signed_response=SignedIntrospectionOptions(issuer=ISSUER, jwks=jwks, **options),
    )


def _respond(body: str, content_type: str = MEDIA_TYPE) -> respx.Route:
    return respx.post(INTROSPECT_URL).mock(
        return_value=httpx.Response(
            200, content=body.encode(), headers={"content-type": content_type}
        )
    )


def _outcome(response) -> tuple:
    if response.is_successful:
        return True, response.claims
    return False, response.error_kind


@pytest.mark.unit
class TestSignedIntrospection:
    @respx.mock
    def test_verified_response_returns_token_introspection(self, jwks, sign):
        route = _respond(sign())

        response = introspect_token(_request(jwks))

        assert (_outcome(response), route.calls.last.request.headers["accept"]) == (
            (True, ACTIVE),
            MEDIA_TYPE,
        )

    @respx.mock
    async def test_async_client_verifies(self, jwks, sign):
        _respond(sign())

        response = await aintrospect_token(_request(jwks))

        assert _outcome(response) == (True, ACTIVE)

    @respx.mock
    @pytest.mark.parametrize(
        "content_type", [MEDIA_TYPE, f"{MEDIA_TYPE}; charset=utf-8", MEDIA_TYPE.upper()]
    )
    def test_media_type_parameters_and_case_accepted(self, jwks, sign, content_type):
        _respond(sign(), content_type)

        assert _outcome(introspect_token(_request(jwks))) == (True, ACTIVE)

    @respx.mock
    def test_typ_with_application_prefix_accepted(self, jwks, sign):
        _respond(sign(typ=MEDIA_TYPE))

        assert _outcome(introspect_token(_request(jwks))) == (True, ACTIVE)

    @respx.mock
    def test_custom_algorithms_allow_rs256(self, jwks, sign, rsa_key):
        _respond(sign(key=rsa_key, alg="RS256", kid="rsa-1"))

        response = introspect_token(_request(jwks, algorithms=frozenset({"RS256"})))

        assert _outcome(response) == (True, ACTIVE)

    @respx.mock
    @pytest.mark.parametrize(
        ("overrides", "kind"),
        [
            (
                {"iss": "https://other.example.com"},
                IntrospectionErrorKind.CLAIM_VALIDATION,
            ),
            ({"aud": "other-client"}, IntrospectionErrorKind.CLAIM_VALIDATION),
            ({"aud": None}, IntrospectionErrorKind.CLAIM_VALIDATION),
            ({"iss": None}, IntrospectionErrorKind.CLAIM_VALIDATION),
            ({"iat": None}, IntrospectionErrorKind.CLAIM_VALIDATION),
            ({"iat": int(time.time()) + 3600}, IntrospectionErrorKind.CLAIM_VALIDATION),
            ({"iat": "yesterday"}, IntrospectionErrorKind.CLAIM_VALIDATION),
            ({"token_introspection": None}, IntrospectionErrorKind.MALFORMED),
            ({"token_introspection": "active"}, IntrospectionErrorKind.MALFORMED),
            ({"token_introspection": {"sub": "u"}}, IntrospectionErrorKind.MALFORMED),
            (
                {"token_introspection": {"active": "true"}},
                IntrospectionErrorKind.MALFORMED,
            ),
        ],
    )
    def test_bad_claims_refused(self, jwks, sign, overrides, kind):
        _respond(sign(**overrides))

        assert _outcome(introspect_token(_request(jwks))) == (False, kind)

    @respx.mock
    @pytest.mark.parametrize(
        ("header", "kind"),
        [
            ({"typ": "JWT"}, IntrospectionErrorKind.INVALID_TYPE),
            ({"typ": "at+jwt"}, IntrospectionErrorKind.INVALID_TYPE),
            ({"kid": "unknown"}, IntrospectionErrorKind.SIGNATURE),
        ],
    )
    def test_bad_header_refused(self, jwks, sign, header, kind):
        _respond(sign(**header))

        assert _outcome(introspect_token(_request(jwks))) == (False, kind)

    @respx.mock
    def test_fapi_set_refuses_rs256(self, jwks, sign, rsa_key):
        _respond(sign(key=rsa_key, alg="RS256", kid="rsa-1"))

        assert _outcome(introspect_token(_request(jwks))) == (
            False,
            IntrospectionErrorKind.UNSUPPORTED_ALGORITHM,
        )

    @respx.mock
    def test_unsigned_jwt_refused(self, jwks):
        token = pyjwt.encode(
            {"iss": ISSUER, "aud": CLIENT_ID, "iat": 1, "token_introspection": ACTIVE},
            "",
            algorithm="none",
            headers={"typ": "token-introspection+jwt"},
        )
        _respond(token)

        assert _outcome(introspect_token(_request(jwks))) == (
            False,
            IntrospectionErrorKind.UNSUPPORTED_ALGORITHM,
        )

    @respx.mock
    def test_signed_by_another_key_refused(self, jwks, sign):
        _respond(sign(key=ec.generate_private_key(ec.SECP256R1())))

        assert _outcome(introspect_token(_request(jwks))) == (
            False,
            IntrospectionErrorKind.SIGNATURE,
        )

    @respx.mock
    @pytest.mark.parametrize(
        ("body", "content_type"),
        [
            (json.dumps(ACTIVE), "application/json"),
            ("not-a-jwt", MEDIA_TYPE),
            ("", MEDIA_TYPE),
        ],
    )
    def test_not_a_signed_response_refused(self, jwks, body, content_type):
        _respond(body, content_type)

        assert _outcome(introspect_token(_request(jwks))) == (
            False,
            IntrospectionErrorKind.MALFORMED,
        )

    @respx.mock
    def test_http_error_keeps_status_error(self, jwks):
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(401, json={"error": "invalid_client"})
        )

        response = introspect_token(_request(jwks))

        assert (response.is_successful, response.error_kind) == (False, None)
        assert "status code: 401" in (response.error or "")

    @respx.mock
    def test_unsigned_mode_sends_no_accept_header(self):
        route = respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(200, json={"active": False})
        )

        introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL, token="t", client_id=CLIENT_ID
            )
        )

        assert route.calls.last.request.headers.get("accept") != MEDIA_TYPE


@pytest.mark.unit
class TestSignedIntrospectionOptions:
    @pytest.mark.parametrize(
        "algorithms",
        [
            frozenset(),
            frozenset({"none"}),
            frozenset({"HS256"}),
            frozenset({"ES256", "hs512"}),
        ],
    )
    def test_symmetric_or_empty_algorithms_rejected(self, jwks, algorithms):
        with pytest.raises(ValueError, match="asymmetric"):
            SignedIntrospectionOptions(issuer=ISSUER, jwks=jwks, algorithms=algorithms)

    def test_issuer_required(self, jwks):
        with pytest.raises(ValueError, match="issuer"):
            SignedIntrospectionOptions(issuer="", jwks=jwks)


DISCO_ADDRESS = "https://auth.example.com/.well-known/openid-configuration"
DISCO_JSON = {
    "issuer": ISSUER,
    "jwks_uri": f"{ISSUER}/jwks",
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["ES256"],
}


@pytest.mark.unit
class TestDiscoveryIntrospectionSigningAlgorithms:
    @respx.mock
    @pytest.mark.parametrize("value", [["ES256", "PS256"], None])
    def test_field_parsed(self, value):
        disco = dict(DISCO_JSON)
        if value is not None:
            disco["introspection_signing_alg_values_supported"] = value
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=disco))

        result = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_ADDRESS))

        assert result.introspection_signing_alg_values_supported == value
