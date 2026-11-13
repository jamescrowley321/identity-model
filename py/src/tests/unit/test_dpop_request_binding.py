"""Unit tests for DPoP request binding on PAR + auth-code token exchange.

Covers RFC 9449 threading through the public request path (#475):
- the ``DPoP`` proof header is attached when ``dpop_key`` is set,
- the token/PAR-endpoint proof carries **no** ``ath`` claim,
- the ``use_dpop_nonce`` challenge (RFC 9449 §8) is honored with a single retry,
- proofs and ``private_key_jwt`` coexist,
- sync and aio implementations behave identically (NFR-9 parity).

respx cannot perform a real DPoP handshake, but it can assert the exact wire
headers/body and drive the nonce-retry state machine.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    extract_dpop_nonce,
    generate_dpop_key,
)
from py_identity_model.aio.par import (
    push_authorization_request as push_authorization_request_async,
)
from py_identity_model.aio.token_client import (
    request_authorization_code_token as request_authorization_code_token_async,
)
from py_identity_model.core.dpop import remember_dpop_nonce
from py_identity_model.sync.par import push_authorization_request
from py_identity_model.sync.token_client import request_authorization_code_token


PAR_URL = "https://auth.example.com/par"
TOKEN_URL = "https://auth.example.com/token"
PAR_RESPONSE = {
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    "expires_in": 60,
}
TOKEN_RESPONSE = {
    "access_token": "at-123",
    "token_type": "DPoP",
    "expires_in": 3600,
}

# One original request + exactly one use_dpop_nonce retry (RFC 9449 §8).
EXPECTED_RETRY_CALLS = 2


def _ec_pem() -> bytes:
    """Fresh EC P-256 PEM for a ``private_key_jwt`` (ES256) assertion."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _dpop_header(request: httpx.Request) -> str:
    proof = request.headers.get("DPoP")
    assert proof is not None, "DPoP proof header missing"
    return proof


def _decode_proof(proof: str) -> dict:
    return pyjwt.decode(proof, options={"verify_signature": False})


# ---------------------------------------------------------------------------
# extract_dpop_nonce helper (RFC 9449 §8)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExtractDpopNonce:
    def test_returns_nonce_on_token_endpoint_challenge(self):
        resp = httpx.Response(
            400,
            json={"error": "use_dpop_nonce"},
            headers={"DPoP-Nonce": "srv-nonce-1"},
        )
        assert extract_dpop_nonce(resp) == "srv-nonce-1"

    def test_returns_nonce_on_resource_www_authenticate(self):
        resp = httpx.Response(
            401,
            headers={
                "DPoP-Nonce": "srv-nonce-2",
                "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
            },
        )
        assert extract_dpop_nonce(resp) == "srv-nonce-2"

    def test_none_when_no_nonce_header(self):
        resp = httpx.Response(400, json={"error": "use_dpop_nonce"})
        assert extract_dpop_nonce(resp) is None

    def test_success_nonce_is_remembered_not_retried(self):
        """RFC 9449 §8.2: a 200's nonce is for the next request, not a retry."""
        resp = httpx.Response(200, json={}, headers={"DPoP-Nonce": "n"})
        key = generate_dpop_key()
        assert extract_dpop_nonce(resp) is None
        remember_dpop_nonce(key, TOKEN_URL, resp)
        assert key.nonce_for(TOKEN_URL) == "n"

    def test_none_on_unrelated_error(self):
        resp = httpx.Response(
            400,
            json={"error": "invalid_request"},
            headers={"DPoP-Nonce": "n"},
        )
        assert extract_dpop_nonce(resp) is None

    def test_none_on_non_json_body_without_www_authenticate(self):
        resp = httpx.Response(
            400,
            content=b"<html>bad</html>",
            headers={"DPoP-Nonce": "n", "content-type": "text/html"},
        )
        assert extract_dpop_nonce(resp) is None


# ---------------------------------------------------------------------------
# Sync PAR
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSyncParDpop:
    @respx.mock
    def test_dpop_proof_attached_no_ath(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        key = generate_dpop_key("ES256")
        resp = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        proof = _dpop_header(route.calls[0].request)
        header = pyjwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert header["jwk"]["crv"] == "P-256"
        claims = _decode_proof(proof)
        assert claims["htm"] == "POST"
        assert claims["htu"] == PAR_URL
        # Token/PAR-endpoint proofs never carry ``ath`` (resource-only).
        assert "ath" not in claims

    @respx.mock
    def test_no_dpop_header_without_key(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
            )
        )
        assert route.calls[0].request.headers.get("DPoP") is None

    @respx.mock
    def test_use_dpop_nonce_retry_once_then_succeeds(self):
        route = respx.post(PAR_URL).mock(
            side_effect=[
                httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "srv-nonce-1"},
                ),
                httpx.Response(201, json=PAR_RESPONSE),
            ]
        )
        key = generate_dpop_key("ES256")
        resp = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        # First proof has no nonce; the retry embeds the server nonce.
        assert "nonce" not in _decode_proof(_dpop_header(route.calls[0].request))
        assert (
            _decode_proof(_dpop_header(route.calls[1].request))["nonce"]
            == "srv-nonce-1"
        )

    @respx.mock
    def test_use_dpop_nonce_retry_is_bounded_to_one(self):
        route = respx.post(PAR_URL).mock(
            side_effect=[
                httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "n1"},
                ),
                httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "n2"},
                ),
            ]
        )
        key = generate_dpop_key("ES256")
        resp = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                dpop_key=key,
            )
        )
        assert resp.is_successful is False
        assert route.call_count == EXPECTED_RETRY_CALLS

    @respx.mock
    def test_dpop_coexists_with_private_key_jwt(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        key = generate_dpop_key("ES256")
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                private_key_jwt=PrivateKeyJwt(private_key=_ec_pem(), algorithm="ES256"),
                dpop_key=key,
            )
        )
        request = route.calls[0].request
        assert request.headers.get("DPoP") is not None
        body = request.content.decode()
        assert "client_assertion=" in body
        assert request.headers.get("authorization") is None


# ---------------------------------------------------------------------------
# Sync auth-code token exchange
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSyncTokenDpop:
    @respx.mock
    def test_dpop_proof_attached_no_ath(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_RESPONSE)
        )
        key = generate_dpop_key("ES256")
        resp = request_authorization_code_token(
            AuthorizationCodeTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                code="auth-code",
                redirect_uri="https://app.com/cb",
                code_verifier="verifier",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        claims = _decode_proof(_dpop_header(route.calls[0].request))
        assert claims["htm"] == "POST"
        assert claims["htu"] == TOKEN_URL
        assert "ath" not in claims

    @respx.mock
    def test_use_dpop_nonce_retry_once_then_succeeds(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[
                httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "srv-nonce-9"},
                ),
                httpx.Response(200, json=TOKEN_RESPONSE),
            ]
        )
        key = generate_dpop_key("ES256")
        resp = request_authorization_code_token(
            AuthorizationCodeTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                code="auth-code",
                redirect_uri="https://app.com/cb",
                code_verifier="verifier",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        assert (
            _decode_proof(_dpop_header(route.calls[1].request))["nonce"]
            == "srv-nonce-9"
        )

    @respx.mock
    def test_no_dpop_header_without_key(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_RESPONSE)
        )
        request_authorization_code_token(
            AuthorizationCodeTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                code="auth-code",
                redirect_uri="https://app.com/cb",
                code_verifier="verifier",
            )
        )
        assert route.calls[0].request.headers.get("DPoP") is None


# ---------------------------------------------------------------------------
# Async parity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAsyncParDpop:
    @respx.mock
    async def test_dpop_proof_attached_no_ath(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        key = generate_dpop_key("ES256")
        resp = await push_authorization_request_async(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        claims = _decode_proof(_dpop_header(route.calls[0].request))
        assert claims["htm"] == "POST"
        assert claims["htu"] == PAR_URL
        assert "ath" not in claims

    @respx.mock
    async def test_use_dpop_nonce_retry_once_then_succeeds(self):
        route = respx.post(PAR_URL).mock(
            side_effect=[
                httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "srv-nonce-a"},
                ),
                httpx.Response(201, json=PAR_RESPONSE),
            ]
        )
        key = generate_dpop_key("ES256")
        resp = await push_authorization_request_async(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        assert (
            _decode_proof(_dpop_header(route.calls[1].request))["nonce"]
            == "srv-nonce-a"
        )


@pytest.mark.asyncio
class TestAsyncTokenDpop:
    @respx.mock
    async def test_dpop_proof_attached_no_ath(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_RESPONSE)
        )
        key = generate_dpop_key("ES256")
        resp = await request_authorization_code_token_async(
            AuthorizationCodeTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                code="auth-code",
                redirect_uri="https://app.com/cb",
                code_verifier="verifier",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        claims = _decode_proof(_dpop_header(route.calls[0].request))
        assert claims["htm"] == "POST"
        assert claims["htu"] == TOKEN_URL
        assert "ath" not in claims

    @respx.mock
    async def test_use_dpop_nonce_retry_once_then_succeeds(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[
                httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "srv-nonce-b"},
                ),
                httpx.Response(200, json=TOKEN_RESPONSE),
            ]
        )
        key = generate_dpop_key("ES256")
        resp = await request_authorization_code_token_async(
            AuthorizationCodeTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                code="auth-code",
                redirect_uri="https://app.com/cb",
                code_verifier="verifier",
                dpop_key=key,
            )
        )
        assert resp.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
