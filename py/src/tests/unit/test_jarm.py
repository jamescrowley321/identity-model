"""Unit tests for JWT-Secured Authorization Response Mode (JARM, issue #218).

Covers the pure ``core/jarm.py`` helpers and the sync/async
``process_jarm_response`` orchestrators in both offline mode (caller supplies
issuer + jwks + algorithms) and discovery mode (respx-mocked discovery + JWKS
fetch).  Signatures are minted with a real EC key so signature verification,
tamper detection, and algorithm/issuer/audience/expiry validation are all
exercised end to end.
"""

import json
import time

from cryptography.hazmat.primitives.asymmetric import ec
import httpx
import jwt as pyjwt
from jwt import algorithms as jwt_algorithms
import pytest
import respx

from py_identity_model.aio.jarm import process_jarm_response as async_process_jarm
from py_identity_model.core.authorize_response import AuthorizeCallbackResponse
from py_identity_model.core.jarm import (
    advertised_jarm_algorithms,
    build_authorize_response_from_claims,
    extract_jarm_response_jwt,
    is_jarm_response,
    select_jarm_algorithm,
)
from py_identity_model.core.jwt_signing import DEFAULT_ALLOWED_ALGORITHMS
from py_identity_model.core.models import DiscoveryDocumentRequest, JwksResponse
from py_identity_model.core.parsers import jwks_from_dict
from py_identity_model.core.state_validation import (
    validate_authorize_callback_state,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    InvalidAudienceException,
    InvalidIssuerException,
    JarmValidationException,
    SignatureVerificationException,
    TokenExpiredException,
)
from py_identity_model.sync.discovery import get_discovery_document
from py_identity_model.sync.jarm import process_jarm_response


ISSUER = "https://as.example.com"
CLIENT_ID = "example-client"
KID = "jarm-sig-1"
CALLBACK = "https://app.example.com/callback"
DISCO_ADDRESS = "https://as.example.com/.well-known/openid-configuration"
JWKS_URI = "https://as.example.com/jwks"
STATE = "af0ifjsldkj"
CODE = "SplxlOBeZQQYbYS6WxSbIA"


def _make_key_and_jwks() -> tuple[ec.EllipticCurvePrivateKey, JwksResponse, dict]:
    """Generate an EC signing key plus the matching single-key JWKS + JWK dict."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(jwt_algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update(kid=KID, use="sig", alg="ES256")
    jwks = JwksResponse(is_successful=True, keys=[jwks_from_dict(public_jwk)])
    return private_key, jwks, public_jwk


def _base_claims(**overrides: object) -> dict:
    """Build a valid JARM claim set (iss/aud/exp are mandatory, JARM §4.1)."""
    claims: dict = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "exp": int(time.time()) + 300,
        "code": CODE,
        "state": STATE,
    }
    claims.update(overrides)
    return claims


def _sign(
    private_key: ec.EllipticCurvePrivateKey,
    claims: dict,
    *,
    algorithm: str = "ES256",
    key=None,
    kid: str | None = KID,
) -> str:
    """Mint a signed JARM response JWT (simulates the AS)."""
    headers = {"kid": kid} if kid is not None else None
    return pyjwt.encode(
        claims,
        key if key is not None else private_key,
        algorithm=algorithm,
        headers=headers,
    )


def _query_url(response_jwt: str) -> str:
    return f"{CALLBACK}?response={response_jwt}"


def _fragment_url(response_jwt: str) -> str:
    return f"{CALLBACK}#response={response_jwt}"


DISCO_JSON = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": JWKS_URI,
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["ES256"],
    "authorization_signing_alg_values_supported": ["ES256"],
    "response_modes_supported": ["query", "fragment", "query.jwt", "form_post.jwt"],
}


@pytest.fixture
def signing():
    """Fresh EC key + JWKS for each test."""
    return _make_key_and_jwks()


@pytest.mark.unit
class TestIsJarmResponse:
    def test_query_response(self, signing):
        private_key, _, _ = signing
        assert is_jarm_response(_query_url(_sign(private_key, _base_claims()))) is True

    def test_fragment_response(self, signing):
        private_key, _, _ = signing
        assert (
            is_jarm_response(_fragment_url(_sign(private_key, _base_claims()))) is True
        )

    def test_plain_callback_is_not_jarm(self):
        assert is_jarm_response(f"{CALLBACK}?code=abc&state=xyz") is False

    def test_empty_string(self):
        assert is_jarm_response("") is False

    def test_non_string(self):
        assert is_jarm_response(None) is False  # type: ignore[arg-type]

    def test_blank_response_param_is_not_jarm(self):
        assert is_jarm_response(f"{CALLBACK}?response=") is False

    def test_duplicate_response_param_still_detected(self, signing):
        # Parameter pollution is a (malformed) JARM response — detection reports
        # it so extraction can fail closed downstream.
        private_key, _, _ = signing
        good = _sign(private_key, _base_claims())
        forged = _sign(private_key, _base_claims(code="forged"))
        url = f"{CALLBACK}?response={good}&response={forged}"
        assert is_jarm_response(url) is True


@pytest.mark.unit
class TestExtractJarmResponseJwt:
    def test_from_query(self, signing):
        private_key, _, _ = signing
        jwt = _sign(private_key, _base_claims())
        assert extract_jarm_response_jwt(_query_url(jwt)) == jwt

    def test_from_fragment(self, signing):
        private_key, _, _ = signing
        jwt = _sign(private_key, _base_claims())
        assert extract_jarm_response_jwt(_fragment_url(jwt)) == jwt

    def test_fragment_takes_precedence_over_query(self, signing):
        private_key, _, _ = signing
        frag = _sign(private_key, _base_claims())
        query = _sign(private_key, _base_claims(code="other"))
        url = f"{CALLBACK}?response={query}#response={frag}"
        assert extract_jarm_response_jwt(url) == frag

    def test_missing_response_raises(self):
        with pytest.raises(JarmValidationException, match="no JARM 'response'"):
            extract_jarm_response_jwt(f"{CALLBACK}?code=abc")

    def test_empty_string_raises(self):
        with pytest.raises(JarmValidationException, match="non-empty string"):
            extract_jarm_response_jwt("")

    def test_duplicate_response_param_raises(self, signing):
        private_key, _, _ = signing
        good = _sign(private_key, _base_claims())
        forged = _sign(private_key, _base_claims(code="forged"))
        url = f"{CALLBACK}?response={good}&response={forged}"
        with pytest.raises(JarmValidationException, match="parameter pollution"):
            extract_jarm_response_jwt(url)


@pytest.mark.unit
class TestSelectJarmAlgorithm:
    def test_valid_asymmetric_alg(self):
        assert select_jarm_algorithm("ES256", ["ES256", "PS256"]) == "ES256"

    def test_none_alg_rejected(self):
        with pytest.raises(JarmValidationException, match="alg=none"):
            select_jarm_algorithm("none", ["ES256"])

    def test_none_alg_case_insensitive(self):
        with pytest.raises(JarmValidationException, match="unsigned"):
            select_jarm_algorithm("NONE", ["ES256"])

    def test_empty_alg_rejected(self):
        with pytest.raises(JarmValidationException, match="no 'alg'"):
            select_jarm_algorithm("", ["ES256"])

    def test_symmetric_alg_rejected(self):
        with pytest.raises(JarmValidationException, match="symmetric"):
            select_jarm_algorithm("HS256", ["HS256", "ES256"])

    def test_alg_not_in_allowlist_rejected(self):
        with pytest.raises(JarmValidationException, match="not in the allowed set"):
            select_jarm_algorithm("RS256", ["ES256", "PS256"])

    @pytest.mark.parametrize("alg", sorted(DEFAULT_ALLOWED_ALGORITHMS))
    def test_no_allowlist_means_verify_default(self, alg):
        assert select_jarm_algorithm(alg, None) == alg

    def test_no_allowlist_refuses_alg_outside_verify_default(self):
        with pytest.raises(JarmValidationException, match="not in the allowed set"):
            select_jarm_algorithm("ES256K", None)

    @pytest.mark.parametrize(
        ("advertised", "expected"),
        [
            (None, None),
            ([], []),
            (["ES256", "HS256", "ES256K", "PS256"], ["ES256", "PS256"]),
            (["HS256"], []),
        ],
    )
    def test_advertised_algorithms_filtered_to_verify_default(
        self, advertised, expected
    ):
        assert advertised_jarm_algorithms(advertised) == expected

    def test_empty_allowlist_rejected(self):
        with pytest.raises(JarmValidationException, match="No allowed JARM"):
            select_jarm_algorithm("ES256", [])


@pytest.mark.unit
class TestBuildAuthorizeResponseFromClaims:
    def test_success_maps_fields(self):
        result = build_authorize_response_from_claims(
            {"iss": ISSUER, "aud": CLIENT_ID, "code": CODE, "state": STATE},
            raw="raw.jwt.value",
        )
        assert isinstance(result, AuthorizeCallbackResponse)
        assert result.is_successful is True
        assert result.code == CODE
        assert result.state == STATE
        assert result.issuer == ISSUER
        assert result.raw == "raw.jwt.value"

    def test_error_claim_marks_unsuccessful(self):
        result = build_authorize_response_from_claims(
            {"error": "access_denied", "state": STATE}, raw="raw"
        )
        assert result.is_successful is False
        assert result.error == "access_denied"
        assert result.state == STATE

    def test_no_recognized_claims_raises(self):
        # ``iss`` maps to a recognized field, so use only protocol-irrelevant
        # claims to exercise the "no authorization-response parameter" guard.
        with pytest.raises(JarmValidationException, match="no recognized"):
            build_authorize_response_from_claims(
                {"exp": 123, "iat": 100, "jti": "abc"}, raw="raw"
            )


@pytest.mark.unit
class TestProcessJarmResponseOffline:
    """Sync process_jarm_response in offline mode (no network)."""

    def _process(self, signing, url, **kwargs):
        _, jwks, _ = signing
        return process_jarm_response(
            url,
            client_id=kwargs.pop("client_id", CLIENT_ID),
            issuer=kwargs.pop("issuer", ISSUER),
            jwks=jwks,
            algorithms=kwargs.pop("algorithms", ["ES256"]),
            **kwargs,
        )

    def test_happy_query_jwt(self, signing):
        private_key, _, _ = signing
        result = self._process(signing, _query_url(_sign(private_key, _base_claims())))
        assert result.is_successful is True
        assert result.code == CODE
        assert result.state == STATE
        assert result.issuer == ISSUER

    def test_without_algorithms_uses_verify_default(self, signing):
        private_key, _, _ = signing
        result = self._process(
            signing, _query_url(_sign(private_key, _base_claims())), algorithms=None
        )
        assert result.code == CODE

    def test_happy_fragment_jwt(self, signing):
        private_key, _, _ = signing
        result = self._process(
            signing, _fragment_url(_sign(private_key, _base_claims()))
        )
        assert result.code == CODE

    def test_form_post_jwt_raw_body(self, signing):
        private_key, _, _ = signing
        raw_jwt = _sign(private_key, _base_claims())
        result = self._process(signing, raw_jwt, is_jwt=True)
        assert result.code == CODE

    def test_error_response(self, signing):
        private_key, _, _ = signing
        error_jwt = _sign(
            private_key,
            {
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "exp": int(time.time()) + 300,
                "error": "access_denied",
                "state": STATE,
            },
        )
        result = self._process(signing, _query_url(error_jwt))
        assert result.is_successful is False
        assert result.error == "access_denied"
        assert result.state == STATE

    def test_state_binding_accepts_matching_state(self, signing):
        private_key, _, _ = signing
        result = self._process(signing, _query_url(_sign(private_key, _base_claims())))
        check = validate_authorize_callback_state(result, STATE)
        assert check.is_valid is True

    def test_state_binding_rejects_mismatched_state(self, signing):
        private_key, _, _ = signing
        result = self._process(signing, _query_url(_sign(private_key, _base_claims())))
        check = validate_authorize_callback_state(result, "different-state")
        assert check.is_valid is False

    # --- adversarial ---------------------------------------------------------

    def test_tampered_signature_rejected(self, signing):
        private_key, _, _ = signing
        other_key = ec.generate_private_key(ec.SECP256R1())
        tampered = _sign(private_key, _base_claims(), key=other_key)
        with pytest.raises(SignatureVerificationException):
            self._process(signing, _query_url(tampered))

    def test_issuer_mismatch_rejected(self, signing):
        private_key, _, _ = signing
        forged = _sign(private_key, _base_claims(iss="https://attacker.example.com"))
        with pytest.raises(InvalidIssuerException):
            self._process(signing, _query_url(forged))

    def test_audience_mismatch_rejected(self, signing):
        private_key, _, _ = signing
        wrong_aud = _sign(private_key, _base_claims(aud="other-client"))
        with pytest.raises(InvalidAudienceException):
            self._process(signing, _query_url(wrong_aud))

    def test_expired_rejected(self, signing):
        private_key, _, _ = signing
        expired = _sign(private_key, _base_claims(exp=int(time.time()) - 30))
        with pytest.raises(TokenExpiredException):
            self._process(signing, _query_url(expired))

    def test_missing_exp_claim_rejected(self, signing):
        private_key, _, _ = signing
        claims = _base_claims()
        del claims["exp"]
        no_exp = _sign(private_key, claims)
        with pytest.raises(JarmValidationException, match="mandatory claim"):
            self._process(signing, _query_url(no_exp))

    def test_alg_none_rejected(self, signing):
        none_jwt = pyjwt.encode(_base_claims(), key="", algorithm="none")
        with pytest.raises(JarmValidationException, match="alg=none"):
            self._process(signing, _query_url(none_jwt))

    def test_symmetric_alg_rejected(self, signing):
        hs_jwt = pyjwt.encode(
            _base_claims(),
            key="a" * 32,  # >=32 bytes to avoid PyJWT's insecure-key warning
            algorithm="HS256",
            headers={"kid": KID},
        )
        with pytest.raises(JarmValidationException, match="symmetric"):
            self._process(signing, _query_url(hs_jwt))

    def test_alg_not_in_allowlist_rejected(self, signing):
        private_key, _, _ = signing
        jwt = _sign(private_key, _base_claims())
        with pytest.raises(JarmValidationException, match="not in the allowed set"):
            self._process(signing, _query_url(jwt), algorithms=["PS256"])

    def test_missing_response_param_rejected(self, signing):
        with pytest.raises(JarmValidationException, match="no JARM 'response'"):
            self._process(signing, f"{CALLBACK}?code=abc")

    def test_non_jwt_response_raises_jarm_exception(self, signing):
        # A non-JWT ``?response=`` value must surface as the contracted
        # JarmValidationException, not a raw PyJWT DecodeError.
        with pytest.raises(JarmValidationException, match="not a well-formed JWT"):
            self._process(signing, _query_url("not-a-jwt"))

    def test_non_jwt_raw_body_raises_jarm_exception(self, signing):
        # Same guard on the form_post.jwt raw-body (is_jwt) path.
        with pytest.raises(JarmValidationException, match="not a well-formed JWT"):
            self._process(signing, "garbage", is_jwt=True)

    def test_duplicate_response_param_rejected(self, signing):
        private_key, _, _ = signing
        good = _sign(private_key, _base_claims())
        forged = _sign(private_key, _base_claims(code="forged"))
        url = f"{CALLBACK}?response={good}&response={forged}"
        with pytest.raises(JarmValidationException, match="parameter pollution"):
            self._process(signing, url)


@pytest.mark.unit
class TestProcessJarmResponseDiscoveryMode:
    """Sync discovery-mode: respx-mocked discovery + JWKS fetch."""

    def _mock_discovery(self, public_jwk, disco_overrides=None):
        disco = {**DISCO_JSON}
        if disco_overrides:
            disco.update(disco_overrides)
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=disco))
        respx.get(JWKS_URI).mock(
            return_value=httpx.Response(200, json={"keys": [public_jwk]})
        )

    @respx.mock
    def test_discovery_happy_path(self, signing):
        private_key, _, public_jwk = signing
        self._mock_discovery(public_jwk)
        result = process_jarm_response(
            _query_url(_sign(private_key, _base_claims())),
            client_id=CLIENT_ID,
            disco_doc_address=DISCO_ADDRESS,
        )
        assert result.is_successful is True
        assert result.code == CODE
        assert result.issuer == ISSUER

    @respx.mock
    def test_discovery_algs_enforced_from_metadata(self, signing):
        # AS advertises only PS256, but the response is ES256 -> rejected using
        # the discovery-sourced allowlist (no algorithms= override supplied).
        private_key, _, public_jwk = signing
        self._mock_discovery(
            public_jwk,
            disco_overrides={"authorization_signing_alg_values_supported": ["PS256"]},
        )
        with pytest.raises(JarmValidationException, match="not in the allowed set"):
            process_jarm_response(
                _query_url(_sign(private_key, _base_claims())),
                client_id=CLIENT_ID,
                disco_doc_address=DISCO_ADDRESS,
            )

    @respx.mock
    def test_discovery_issuer_mismatch_rejected(self, signing):
        # iss claim is a different AS -> mix-up defense (RFC 9207) fires using
        # the discovery-sourced issuer.
        private_key, _, public_jwk = signing
        self._mock_discovery(public_jwk)
        forged = _sign(private_key, _base_claims(iss="https://evil.example.com"))
        with pytest.raises(InvalidIssuerException):
            process_jarm_response(
                _query_url(forged),
                client_id=CLIENT_ID,
                disco_doc_address=DISCO_ADDRESS,
            )

    @respx.mock
    def test_discovery_without_advertised_algs_uses_verify_default(self, signing):
        private_key, _, public_jwk = signing
        disco = {
            k: v
            for k, v in DISCO_JSON.items()
            if k != "authorization_signing_alg_values_supported"
        }
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=disco))
        respx.get(JWKS_URI).mock(
            return_value=httpx.Response(200, json={"keys": [public_jwk]})
        )
        result = process_jarm_response(
            _query_url(_sign(private_key, _base_claims())),
            client_id=CLIENT_ID,
            disco_doc_address=DISCO_ADDRESS,
        )
        assert result.code == CODE

    @respx.mock
    def test_explicit_empty_algorithms_not_replaced_by_default(self, signing):
        private_key, _, public_jwk = signing
        disco = {
            k: v
            for k, v in DISCO_JSON.items()
            if k != "authorization_signing_alg_values_supported"
        }
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=disco))
        respx.get(JWKS_URI).mock(
            return_value=httpx.Response(200, json={"keys": [public_jwk]})
        )
        with pytest.raises(JarmValidationException, match="No allowed JARM"):
            process_jarm_response(
                _query_url(_sign(private_key, _base_claims())),
                client_id=CLIENT_ID,
                disco_doc_address=DISCO_ADDRESS,
                algorithms=[],
            )

    @respx.mock
    def test_non_string_advertised_algs_ignored(self, signing):
        private_key, _, public_jwk = signing
        self._mock_discovery(
            public_jwk,
            disco_overrides={
                "authorization_signing_alg_values_supported": [{"x": 1}, ["ES256"]]
            },
        )
        with pytest.raises(JarmValidationException, match="No allowed JARM"):
            process_jarm_response(
                _query_url(_sign(private_key, _base_claims())),
                client_id=CLIENT_ID,
                disco_doc_address=DISCO_ADDRESS,
            )

    def test_no_discovery_and_incomplete_offline_raises(self, signing):
        _, jwks, _ = signing
        with pytest.raises(
            ConfigurationException, match="disco_doc_address is required"
        ):
            process_jarm_response(
                _query_url("x.y.z"),
                client_id=CLIENT_ID,
                jwks=jwks,  # issuer missing -> not offline
            )


@pytest.mark.unit
class TestAsyncProcessJarmResponse:
    """Async mirror: offline + discovery-mode equivalence."""

    @pytest.mark.asyncio
    async def test_offline_happy_path(self, signing):
        private_key, jwks, _ = signing
        result = await async_process_jarm(
            _query_url(_sign(private_key, _base_claims())),
            client_id=CLIENT_ID,
            issuer=ISSUER,
            jwks=jwks,
            algorithms=["ES256"],
        )
        assert result.code == CODE
        assert result.issuer == ISSUER

    @pytest.mark.asyncio
    async def test_offline_without_algorithms_uses_verify_default(self, signing):
        private_key, jwks, _ = signing
        result = await async_process_jarm(
            _query_url(_sign(private_key, _base_claims())),
            client_id=CLIENT_ID,
            issuer=ISSUER,
            jwks=jwks,
        )
        assert result.code == CODE

    @pytest.mark.asyncio
    async def test_offline_tampered_signature_rejected(self, signing):
        private_key, jwks, _ = signing
        other_key = ec.generate_private_key(ec.SECP256R1())
        tampered = _sign(private_key, _base_claims(), key=other_key)
        with pytest.raises(SignatureVerificationException):
            await async_process_jarm(
                _query_url(tampered),
                client_id=CLIENT_ID,
                issuer=ISSUER,
                jwks=jwks,
                algorithms=["ES256"],
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_discovery_happy_path(self, signing):
        private_key, _, public_jwk = signing
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=DISCO_JSON))
        respx.get(JWKS_URI).mock(
            return_value=httpx.Response(200, json={"keys": [public_jwk]})
        )
        result = await async_process_jarm(
            _query_url(_sign(private_key, _base_claims())),
            client_id=CLIENT_ID,
            disco_doc_address=DISCO_ADDRESS,
        )
        assert result.code == CODE
        assert result.issuer == ISSUER


@pytest.mark.unit
class TestDiscoveryParsesJarmFields:
    """The three new RFC 8414 §2 JARM discovery metadata fields are parsed."""

    @respx.mock
    def test_jarm_metadata_fields_parsed(self):
        disco = {
            **DISCO_JSON,
            "authorization_signing_alg_values_supported": ["ES256", "PS256"],
            "authorization_encryption_alg_values_supported": ["RSA-OAEP"],
            "authorization_encryption_enc_values_supported": ["A256GCM"],
        }
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=disco))

        result = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_ADDRESS))

        assert result.authorization_signing_alg_values_supported == ["ES256", "PS256"]
        assert result.authorization_encryption_alg_values_supported == ["RSA-OAEP"]
        assert result.authorization_encryption_enc_values_supported == ["A256GCM"]

    @respx.mock
    def test_jarm_metadata_fields_absent_default_none(self):
        disco = dict(DISCO_JSON)
        disco.pop("authorization_signing_alg_values_supported", None)
        respx.get(DISCO_ADDRESS).mock(return_value=httpx.Response(200, json=disco))

        result = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_ADDRESS))

        assert result.authorization_signing_alg_values_supported is None
        assert result.authorization_encryption_alg_values_supported is None
        assert result.authorization_encryption_enc_values_supported is None
