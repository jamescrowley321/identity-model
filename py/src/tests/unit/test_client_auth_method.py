"""One ``ClientAuthMethod`` enum, chosen explicitly per request (#1056).

``client_auth_method=None`` keeps the implicit precedence
(``private_key_jwt`` > ``mtls`` > ``client_secret`` as Basic > public). An
explicit method needs its own credential and is the only one sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import httpx
import pytest
import respx

from py_identity_model import (
    ClientAuthMethod,
    oidc_constants,
    request_client_credentials_token,
)
from py_identity_model.core import config as config_module
from py_identity_model.core.client_auth import basic_auth_credentials
from py_identity_model.core.device_auth_logic import (
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
)
from py_identity_model.core.introspection_logic import (
    prepare_introspection_request_data,
)
from py_identity_model.core.models import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    DeviceAuthorizationRequest,
    DeviceTokenRequest,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    TokenExchangeRequest,
    TokenIntrospectionRequest,
    TokenRevocationRequest,
)
from py_identity_model.core.par_logic import prepare_par_request_data
from py_identity_model.core.revocation_logic import prepare_revocation_request_data
from py_identity_model.core.token_client_logic import (
    prepare_auth_code_token_request_data,
    prepare_refresh_token_request_data,
    prepare_token_request_data,
)
from py_identity_model.core.token_exchange_logic import (
    prepare_token_exchange_request_data,
)
from py_identity_model.exceptions import (
    ClientAuthMethodError,
    ClientAuthMethodErrorReason,
    ConfigurationException,
)


if TYPE_CHECKING:
    from collections.abc import Callable


CLIENT_ID = "cid"
SECRET = "s3cret"
ADDRESS = "https://as.example.com/endpoint"


@dataclass(frozen=True)
class Endpoint:
    """One confidential-client request type and its prepare function."""

    name: str
    build: Callable[..., Any]
    prepare: Callable[[Any], tuple[dict, dict, tuple[str, str] | None]]


ENDPOINTS = [
    Endpoint(
        "client_credentials",
        lambda **kw: ClientCredentialsTokenRequest(
            address=ADDRESS, client_id=CLIENT_ID, **kw
        ),
        prepare_token_request_data,
    ),
    Endpoint(
        "authorization_code",
        lambda **kw: AuthorizationCodeTokenRequest(
            address=ADDRESS,
            client_id=CLIENT_ID,
            code="code",
            redirect_uri="https://rp.example.com/cb",
            **kw,
        ),
        prepare_auth_code_token_request_data,
    ),
    Endpoint(
        "refresh",
        lambda **kw: RefreshTokenRequest(
            address=ADDRESS, client_id=CLIENT_ID, refresh_token="rt", **kw
        ),
        prepare_refresh_token_request_data,
    ),
    Endpoint(
        "introspection",
        lambda **kw: TokenIntrospectionRequest(
            address=ADDRESS, token="tok", client_id=CLIENT_ID, **kw
        ),
        prepare_introspection_request_data,
    ),
    Endpoint(
        "revocation",
        lambda **kw: TokenRevocationRequest(
            address=ADDRESS, token="tok", client_id=CLIENT_ID, **kw
        ),
        prepare_revocation_request_data,
    ),
    Endpoint(
        "token_exchange",
        lambda **kw: TokenExchangeRequest(
            address=ADDRESS,
            client_id=CLIENT_ID,
            subject_token="st",
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            **kw,
        ),
        prepare_token_exchange_request_data,
    ),
    Endpoint(
        "par",
        lambda **kw: PushedAuthorizationRequest(
            address=ADDRESS,
            client_id=CLIENT_ID,
            redirect_uri="https://rp.example.com/cb",
            **kw,
        ),
        prepare_par_request_data,
    ),
    Endpoint(
        "device_authorization",
        lambda **kw: DeviceAuthorizationRequest(
            address=ADDRESS, client_id=CLIENT_ID, **kw
        ),
        prepare_device_auth_request_data,
    ),
    Endpoint(
        "device_token",
        lambda **kw: DeviceTokenRequest(
            address=ADDRESS, client_id=CLIENT_ID, device_code="dc", **kw
        ),
        prepare_device_token_request_data,
    ),
]

endpoints = pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.name)


def _ec_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _pkjwt() -> PrivateKeyJwt:
    return PrivateKeyJwt(
        private_key=_ec_pem(), algorithm="ES256", issuer="https://as.example.com"
    )


def _mtls(
    method: ClientAuthMethod = ClientAuthMethod.TLS_CLIENT_AUTH,
) -> MtlsClientAuth:
    return MtlsClientAuth(
        certificate_path="/c.pem", private_key_path="/k.pem", auth_method=method
    )


# --------------------------------------------------------------------------- #
# The enum                                                                     #
# --------------------------------------------------------------------------- #


def test_enum_covers_every_implemented_method():
    # RFC 7591 §2 token_endpoint_auth_method values the library implements.
    assert {m.value for m in ClientAuthMethod} == {
        "none",
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    }


def test_uses_client_secret_only_for_client_secret_methods():
    assert {m for m in ClientAuthMethod if m.uses_client_secret} == {
        ClientAuthMethod.CLIENT_SECRET_BASIC,
        ClientAuthMethod.CLIENT_SECRET_POST,
    }


def test_config_module_still_exports_the_enum():
    assert config_module.ClientAuthMethod is ClientAuthMethod


def test_endpoint_authentication_methods_is_gone():
    assert not hasattr(oidc_constants, "EndpointAuthenticationMethods")


# --------------------------------------------------------------------------- #
# Explicit methods on every request                                            #
# --------------------------------------------------------------------------- #


@endpoints
def test_client_secret_post_sends_secret_in_body(endpoint: Endpoint):
    request = endpoint.build(
        client_secret=SECRET, client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST
    )
    params, headers, auth = endpoint.prepare(request)
    assert auth is None
    assert "Authorization" not in headers
    assert (params["client_id"], params["client_secret"]) == (CLIENT_ID, SECRET)


@endpoints
def test_explicit_basic_matches_implicit_default(endpoint: Endpoint):
    implicit = endpoint.prepare(endpoint.build(client_secret=SECRET))
    explicit = endpoint.prepare(
        endpoint.build(
            client_secret=SECRET,
            client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        )
    )
    assert explicit == implicit
    assert explicit[2] == basic_auth_credentials(CLIENT_ID, SECRET)
    assert "client_secret" not in explicit[0]


@endpoints
def test_explicit_none_sends_no_secret(endpoint: Endpoint):
    params, _headers, auth = endpoint.prepare(
        endpoint.build(client_secret=SECRET, client_auth_method=ClientAuthMethod.NONE)
    )
    assert auth is None
    assert params["client_id"] == CLIENT_ID
    assert "client_secret" not in params


@endpoints
def test_explicit_method_overrides_other_credentials(endpoint: Endpoint):
    # A private_key_jwt config is present, but the caller asked for POST:
    # only the secret is sent.
    params, _headers, auth = endpoint.prepare(
        endpoint.build(
            client_secret=SECRET,
            private_key_jwt=_pkjwt(),
            client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST,
        )
    )
    assert auth is None
    assert params["client_secret"] == SECRET
    assert "client_assertion" not in params


@endpoints
def test_explicit_private_key_jwt_sends_assertion(endpoint: Endpoint):
    params, _headers, auth = endpoint.prepare(
        endpoint.build(
            client_secret=SECRET,
            private_key_jwt=_pkjwt(),
            client_auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
        )
    )
    assert auth is None
    assert "client_secret" not in params
    assert params["client_assertion_type"] == (
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )


@endpoints
@pytest.mark.parametrize(
    ("method", "missing"),
    [
        (ClientAuthMethod.CLIENT_SECRET_BASIC, "client_secret"),
        (ClientAuthMethod.CLIENT_SECRET_POST, "client_secret"),
        (ClientAuthMethod.PRIVATE_KEY_JWT, "private_key_jwt"),
        (ClientAuthMethod.TLS_CLIENT_AUTH, "mtls"),
        (ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH, "mtls"),
    ],
    ids=lambda v: v.value if isinstance(v, ClientAuthMethod) else v,
)
def test_explicit_method_without_its_credential_fails_closed(
    endpoint: Endpoint, method: ClientAuthMethod, missing: str
):
    with pytest.raises(ClientAuthMethodError) as excinfo:
        endpoint.prepare(endpoint.build(client_auth_method=method))
    err = excinfo.value
    assert (err.reason, err.method, err.credential) == (
        ClientAuthMethodErrorReason.MISSING_CREDENTIAL,
        method,
        missing,
    )
    assert isinstance(err, ConfigurationException)


@endpoints
def test_empty_secret_does_not_satisfy_client_secret_post(endpoint: Endpoint):
    with pytest.raises(ClientAuthMethodError):
        endpoint.prepare(
            endpoint.build(
                client_secret="", client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST
            )
        )


@endpoints
def test_explicit_tls_method_must_match_mtls_config(endpoint: Endpoint):
    with pytest.raises(ClientAuthMethodError) as excinfo:
        endpoint.prepare(
            endpoint.build(
                mtls=_mtls(ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH),
                client_auth_method=ClientAuthMethod.TLS_CLIENT_AUTH,
            )
        )
    assert excinfo.value.reason is ClientAuthMethodErrorReason.MTLS_METHOD_MISMATCH


@endpoints
def test_explicit_tls_method_sends_client_id_only(endpoint: Endpoint):
    params, _headers, auth = endpoint.prepare(
        endpoint.build(
            client_secret=SECRET,
            mtls=_mtls(),
            client_auth_method=ClientAuthMethod.TLS_CLIENT_AUTH,
        )
    )
    assert auth is None
    assert params["client_id"] == CLIENT_ID
    assert "client_secret" not in params


@respx.mock
def test_public_request_function_sends_nothing_when_credential_missing():
    # Request functions return error responses rather than raising; the
    # misconfiguration must still stop the request before it is sent.
    route = respx.post(ADDRESS).mock(return_value=httpx.Response(200, json={}))
    response = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            address=ADDRESS,
            client_id=CLIENT_ID,
            client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST,
        )
    )
    assert response.is_successful is False
    assert "client_secret" in (response.error or "")
    assert route.call_count == 0


# --------------------------------------------------------------------------- #
# MtlsClientAuth                                                               #
# --------------------------------------------------------------------------- #


def test_mtls_defaults_to_tls_client_auth():
    assert (
        MtlsClientAuth(certificate_path="/c.pem", private_key_path="/k.pem").auth_method
        is ClientAuthMethod.TLS_CLIENT_AUTH
    )


@pytest.mark.parametrize(
    "method",
    [m for m in ClientAuthMethod if not m.is_mtls],
    ids=lambda m: m.value,
)
def test_mtls_rejects_non_tls_methods(method: ClientAuthMethod):
    with pytest.raises(ClientAuthMethodError) as excinfo:
        _mtls(method)
    assert excinfo.value.reason is ClientAuthMethodErrorReason.NOT_AN_MTLS_METHOD
