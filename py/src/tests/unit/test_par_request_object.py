"""PAR with a signed request object (RFC 9126 §3, FAPI 2.0 Message Signing §5.3.2)."""

from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model import PushedAuthorizationRequest
from py_identity_model.aio.par import (
    push_authorization_request as async_push_authorization_request,
)
from py_identity_model.core.dpop import generate_dpop_key
from py_identity_model.core.models import MtlsClientAuth, PrivateKeyJwt
from py_identity_model.core.par_logic import prepare_par_request_data
from py_identity_model.sync.par import push_authorization_request


PAR_URL = "https://auth.example.com/par"
PAR_RESPONSE = {
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    "expires_in": 60,
}
REQUEST_OBJECT = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhcHAxIn0.c2ln"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
KEY = generate_dpop_key("ES256")


def _signed(**overrides: Any) -> PushedAuthorizationRequest:
    fields: dict[str, Any] = {
        "address": PAR_URL,
        "client_id": "app1",
        "request": REQUEST_OBJECT,
        "private_key_jwt": PrivateKeyJwt(
            private_key=KEY.private_key_pem,
            algorithm="ES256",
            issuer="https://auth.example.com",
        ),
        **overrides,
    }
    return PushedAuthorizationRequest(**fields)


@pytest.mark.unit
class TestPrepareSignedPar:
    def test_private_key_jwt_form_carries_only_request_and_client_auth(self):
        form, headers, auth = prepare_par_request_data(_signed())
        assert set(form) == {
            "client_id",
            "request",
            "client_assertion_type",
            "client_assertion",
        }
        assert form["client_id"] == "app1"
        assert form["request"] == REQUEST_OBJECT
        assert form["client_assertion_type"] == JWT_BEARER
        assert headers == {"Content-Type": "application/x-www-form-urlencoded"}
        assert auth is None

    def test_mtls_form_carries_only_client_id_and_request(self):
        form, _, auth = prepare_par_request_data(
            _signed(
                private_key_jwt=None,
                mtls=MtlsClientAuth(
                    certificate="client.pem",
                    private_key="client.key",
                    auth_method="self_signed_tls_client_auth",
                ),
            )
        )
        assert form == {"client_id": "app1", "request": REQUEST_OBJECT}
        assert auth is None

    def test_client_secret_uses_basic_auth(self):
        form, _, auth = prepare_par_request_data(
            _signed(private_key_jwt=None, client_secret="secret")
        )
        assert form == {"client_id": "app1", "request": REQUEST_OBJECT}
        assert auth == ("app1", "secret")

    def test_dpop_proof_still_attached(self):
        _, headers, _ = prepare_par_request_data(_signed(dpop_key=KEY))
        assert set(headers) == {"Content-Type", "DPoP"}

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("redirect_uri", "https://app.com/cb"),
            ("scope", "openid accounts"),
            ("response_type", "code id_token"),
            ("state", "s"),
            ("nonce", "n"),
            ("code_challenge", "c"),
            ("code_challenge_method", "S256"),
            ("response_mode", "jwt"),
        ],
    )
    def test_plain_authorization_parameter_with_request_raises(self, field, value):
        with pytest.raises(
            ValueError,
            match=(
                rf"^{field} must be a claim of the request object, not a "
                r"separate parameter \(RFC 9126 §3\)$"
            ),
        ):
            prepare_par_request_data(_signed(**{field: value}))

    def test_missing_redirect_uri_without_request_raises(self):
        with pytest.raises(ValueError, match=r"^redirect_uri is required$"):
            prepare_par_request_data(
                PushedAuthorizationRequest(address=PAR_URL, client_id="app1")
            )


@pytest.mark.unit
class TestPushSignedPar:
    @respx.mock
    def test_sync_push(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = push_authorization_request(
            _signed(private_key_jwt=None, client_secret="secret")
        )
        assert response.is_successful is True
        assert parse_qs(route.calls.last.request.content.decode()) == {
            "client_id": ["app1"],
            "request": [REQUEST_OBJECT],
        }

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_push(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = await async_push_authorization_request(
            _signed(private_key_jwt=None, client_secret="secret")
        )
        assert response.is_successful is True
        assert parse_qs(route.calls.last.request.content.decode()) == {
            "client_id": ["app1"],
            "request": [REQUEST_OBJECT],
        }
