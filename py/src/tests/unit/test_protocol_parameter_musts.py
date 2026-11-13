"""Request-parameter MUSTs enforced before a request is built.

RFC 6749 §3.1.2 and RFC 8707 §2 (absolute ``redirect_uri`` / ``resource``
without a fragment), RFC 7592 §2.2 (client update body) and RFC 9700 §2.1.1
(public clients use PKCE).
"""

import pytest

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientAuthMethod,
    ClientUpdateRequest,
    ProtocolParameterError,
    ProtocolParameterErrorReason,
    PushedAuthorizationRequest,
    TokenExchangeRequest,
)
from py_identity_model.core.authorize_url import build_authorization_url
from py_identity_model.core.par_logic import prepare_par_request_data
from py_identity_model.core.registration_logic import prepare_update_request
from py_identity_model.core.token_client_logic import (
    prepare_auth_code_token_request_data,
)
from py_identity_model.core.token_exchange_logic import (
    prepare_token_exchange_request_data,
)
from py_identity_model.core.validators import validate_absolute_uri_without_fragment


AUTHORIZE_URL = "https://auth.example.com/authorize"
TOKEN_URL = "https://auth.example.com/token"
REDIRECT_URI = "https://app.example.com/cb"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

NOT_ABSOLUTE = ProtocolParameterErrorReason.NOT_ABSOLUTE_URI
HAS_FRAGMENT = ProtocolParameterErrorReason.URI_HAS_FRAGMENT

BAD_URIS = [
    pytest.param("cb", NOT_ABSOLUTE, id="bare_path"),
    pytest.param("/cb", NOT_ABSOLUTE, id="relative_path"),
    pytest.param("//app.example.com/cb", NOT_ABSOLUTE, id="network_path"),
    pytest.param("https://app.example.com/cb#frag", HAS_FRAGMENT, id="fragment"),
    pytest.param("https://app.example.com/cb#", HAS_FRAGMENT, id="empty_fragment"),
    pytest.param("cb#frag", NOT_ABSOLUTE, id="relative_with_fragment"),
]
GOOD_URIS = [
    "https://app.example.com/cb",
    "https://app.example.com/cb?tenant=a",
    "com.example.app:/oauth2redirect",
    "http://127.0.0.1:8080/cb",
]


def _reason(excinfo: pytest.ExceptionInfo[ProtocolParameterError]) -> tuple:
    return excinfo.value.reason, excinfo.value.parameter


@pytest.mark.unit
class TestAbsoluteUriWithoutFragment:
    @pytest.mark.parametrize(("value", "reason"), BAD_URIS)
    def test_rejected(self, value, reason):
        with pytest.raises(ProtocolParameterError) as excinfo:
            validate_absolute_uri_without_fragment(value, "redirect_uri")
        assert _reason(excinfo) == (reason, "redirect_uri")

    @pytest.mark.parametrize("value", GOOD_URIS)
    def test_accepted(self, value):
        validate_absolute_uri_without_fragment(value, "redirect_uri")

    @pytest.mark.parametrize(("value", "reason"), BAD_URIS)
    def test_authorize_url_redirect_uri(self, value, reason):
        with pytest.raises(ProtocolParameterError) as excinfo:
            build_authorization_url(AUTHORIZE_URL, "app1", value)
        assert _reason(excinfo) == (reason, "redirect_uri")

    @pytest.mark.parametrize(("value", "reason"), BAD_URIS)
    def test_authorize_url_resource(self, value, reason):
        with pytest.raises(ProtocolParameterError) as excinfo:
            build_authorization_url(AUTHORIZE_URL, "app1", REDIRECT_URI, resource=value)
        assert _reason(excinfo) == (reason, "resource")

    @pytest.mark.parametrize(("value", "reason"), BAD_URIS)
    def test_par_redirect_uri(self, value, reason):
        request = PushedAuthorizationRequest(
            address="https://auth.example.com/par", client_id="app1", redirect_uri=value
        )
        with pytest.raises(ProtocolParameterError) as excinfo:
            prepare_par_request_data(request)
        assert _reason(excinfo) == (reason, "redirect_uri")

    @pytest.mark.parametrize(("value", "reason"), BAD_URIS)
    def test_token_exchange_resource(self, value, reason):
        request = TokenExchangeRequest(
            address=TOKEN_URL,
            client_id="svc",
            subject_token="st",
            subject_token_type=ACCESS_TOKEN_TYPE,
            resource=value,
        )
        with pytest.raises(ProtocolParameterError) as excinfo:
            prepare_token_exchange_request_data(request)
        assert _reason(excinfo) == (reason, "resource")

    def test_token_exchange_resource_with_query_is_sent(self):
        resource = "https://api.example.com/v1?tenant=a"
        request = TokenExchangeRequest(
            address=TOKEN_URL,
            client_id="svc",
            subject_token="st",
            subject_token_type=ACCESS_TOKEN_TYPE,
            resource=resource,
        )
        params, _, _ = prepare_token_exchange_request_data(request)
        assert params["resource"] == resource


def _update(extra_metadata: dict | None) -> ClientUpdateRequest:
    return ClientUpdateRequest(
        address="https://auth.example.com/register/app1",
        registration_access_token="rat",
        client_id="app1",
        redirect_uris=[REDIRECT_URI],
        extra_metadata=extra_metadata,
    )


@pytest.mark.unit
class TestClientUpdateBody:
    def test_read_response_metadata_drops_server_issued_fields(self):
        read_metadata = {
            "client_id": "app1",
            "redirect_uris": [REDIRECT_URI],
            "client_name": "App",
            "registration_access_token": "rat",
            "registration_client_uri": "https://auth.example.com/register/app1",
            "client_secret_expires_at": 0,
            "client_id_issued_at": 1700000000,
        }
        body, _ = prepare_update_request(_update(read_metadata))
        assert body == {
            "client_id": "app1",
            "redirect_uris": [REDIRECT_URI],
            "client_name": "App",
        }

    def test_extra_metadata_cannot_change_client_id(self):
        with pytest.raises(ProtocolParameterError) as excinfo:
            prepare_update_request(_update({"client_id": "other"}))
        assert _reason(excinfo) == (
            ProtocolParameterErrorReason.CLIENT_ID_MISMATCH,
            "extra_metadata",
        )


def _auth_code(**kwargs) -> AuthorizationCodeTokenRequest:
    return AuthorizationCodeTokenRequest(
        address=TOKEN_URL,
        client_id="app1",
        code="code",
        redirect_uri=REDIRECT_URI,
        **kwargs,
    )


@pytest.mark.unit
class TestPublicClientRequiresPkce:
    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({}, id="no_credentials"),
            pytest.param(
                {"client_auth_method": ClientAuthMethod.NONE, "client_secret": "s"},
                id="explicit_none",
            ),
            pytest.param({"code_verifier": ""}, id="empty_verifier"),
            pytest.param({"client_secret": ""}, id="empty_secret"),
        ],
    )
    def test_public_client_without_verifier_rejected(self, kwargs):
        with pytest.raises(ProtocolParameterError) as excinfo:
            prepare_auth_code_token_request_data(_auth_code(**kwargs))
        assert _reason(excinfo) == (
            ProtocolParameterErrorReason.PKCE_REQUIRED,
            "code_verifier",
        )

    def test_public_client_with_verifier_sent(self):
        params, _, auth = prepare_auth_code_token_request_data(
            _auth_code(code_verifier="verifier")
        )
        assert params == {
            "grant_type": "authorization_code",
            "code": "code",
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "verifier",
            "client_id": "app1",
        }
        assert auth is None

    def test_confidential_client_without_verifier_allowed(self):
        params, _, auth = prepare_auth_code_token_request_data(
            _auth_code(client_secret="secret")
        )
        assert params == {
            "grant_type": "authorization_code",
            "code": "code",
            "redirect_uri": REDIRECT_URI,
        }
        assert auth == ("app1", "secret")
