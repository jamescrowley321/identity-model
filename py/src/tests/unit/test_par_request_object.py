"""PAR with a signed request object (RFC 9126 §3, FAPI 2.0 Message Signing §5.3.2)."""

from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model import (
    ClientAuthMethod,
    PushedAuthorizationRequest,
    SignedPushedAuthorizationRequest,
)
from py_identity_model.aio.par import (
    push_authorization_request as async_push_authorization_request,
)
from py_identity_model.core.dpop import generate_dpop_key
from py_identity_model.core.models import MtlsClientAuth, PrivateKeyJwt
from py_identity_model.core.par_logic import prepare_par_request_data
from py_identity_model.exceptions import ConfigurationException
from py_identity_model.sync.par import push_authorization_request


PAR_URL = "https://auth.example.com/par"
PAR_RESPONSE = {
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    "expires_in": 60,
}
REQUEST_OBJECT = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhcHAxIn0.c2ln"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
KEY = generate_dpop_key("ES256")


def _signed(**overrides: Any) -> SignedPushedAuthorizationRequest:
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
    return SignedPushedAuthorizationRequest(**fields)


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
                    certificate_path="client.pem",
                    private_key_path="client.key",
                    auth_method=ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
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
        "field",
        [
            "redirect_uri",
            "scope",
            "response_type",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
            "response_mode",
        ],
    )
    def test_signed_request_has_no_plain_authorization_parameters(self, field):
        # RFC 9126 §3: they are claims of the request object, so the type
        # cannot carry them.
        with pytest.raises(TypeError, match=field):
            _signed(**{field: "x"})

    @pytest.mark.parametrize("request_object", ["", "   ", None, 42])
    def test_blank_request_object_refused(self, request_object):
        with pytest.raises(
            ConfigurationException,
            match=r"^SignedPushedAuthorizationRequest\.request must be a signed "
            r"request object \(RFC 9126 §3\)$",
        ):
            _signed(request=request_object)

    @pytest.mark.parametrize("request_object", ["", None])
    def test_request_blanked_after_construction_refused_at_send(self, request_object):
        request = _signed()
        # Frozen models block this; bypass it to cover the send-time guard.
        object.__setattr__(request, "request", request_object)
        with pytest.raises(ConfigurationException):
            prepare_par_request_data(request)

    def test_repr_hides_secret_and_request_object(self):
        text = repr(_signed(private_key_jwt=None, client_secret="s3cret-value"))
        assert "s3cret-value" not in text
        assert REQUEST_OBJECT not in text

    def test_plain_request_has_no_request_field(self):
        fields: dict[str, Any] = {
            "address": PAR_URL,
            "client_id": "app1",
            "redirect_uri": "https://app.com/cb",
            "request": REQUEST_OBJECT,
        }
        with pytest.raises(TypeError, match="request"):
            PushedAuthorizationRequest(**fields)

    def test_redirect_uri_is_a_required_field(self):
        with pytest.raises(TypeError, match=r"redirect_uri"):
            PushedAuthorizationRequest(address=PAR_URL, client_id="app1")  # type: ignore[call-arg]

    def test_empty_redirect_uri_raises_at_send(self):
        with pytest.raises(ValueError, match=r"^redirect_uri is required$"):
            prepare_par_request_data(
                PushedAuthorizationRequest(
                    address=PAR_URL, client_id="app1", redirect_uri=""
                )
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
