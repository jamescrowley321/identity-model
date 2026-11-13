"""Fail-closed control test: per-request client authentication method.

``core.client_auth.apply_client_auth`` must refuse to send a request when an
explicit ``client_auth_method`` lacks its credential or contradicts the mTLS
config, and must send exactly the configured secret, never a substitute.
"""

from dataclasses import dataclass

import pytest

from py_identity_model.core.client_auth import apply_client_auth
from py_identity_model.core.client_auth_method import ClientAuthMethod
from py_identity_model.core.models import MtlsClientAuth, PrivateKeyJwt
from py_identity_model.exceptions import (
    ClientAuthMethodError,
    ClientAuthMethodErrorReason,
)


@dataclass
class _Request:
    address: str = "https://op.example/token"
    client_id: str = "client"
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None
    client_auth_method: ClientAuthMethod | None = None


def _mtls(method: ClientAuthMethod) -> MtlsClientAuth:
    return MtlsClientAuth(
        certificate="/c.pem", private_key="/k.pem", auth_method=method
    )


@pytest.mark.unit
class TestClientAuthMethodFailClosed:
    def test_mtls_method_mismatch_names_the_mtls_credential(self) -> None:
        request = _Request(
            mtls=_mtls(ClientAuthMethod.TLS_CLIENT_AUTH),
            client_auth_method=ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
        )
        params: dict[str, str] = {}
        with pytest.raises(ClientAuthMethodError) as exc:
            apply_client_auth(params, request, client_secret=None)
        assert (exc.value.reason, exc.value.method, exc.value.credential) == (
            ClientAuthMethodErrorReason.MTLS_METHOD_MISMATCH,
            ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
            "mtls",
        )
        assert params == {}

    @pytest.mark.parametrize(
        "method",
        [ClientAuthMethod.CLIENT_SECRET_BASIC, ClientAuthMethod.CLIENT_SECRET_POST],
    )
    def test_explicit_secret_method_with_empty_secret_fails_closed(
        self, method: ClientAuthMethod
    ) -> None:
        params: dict[str, str] = {}
        with pytest.raises(ClientAuthMethodError) as exc:
            apply_client_auth(
                params, _Request(client_auth_method=method), client_secret=""
            )
        assert exc.value.reason is ClientAuthMethodErrorReason.MISSING_CREDENTIAL
        assert params == {}

    def test_implicit_basic_sends_the_empty_secret_verbatim(self) -> None:
        params: dict[str, str] = {}
        assert apply_client_auth(params, _Request(), client_secret="") == (
            "client",
            "",
        )
        assert params == {}

    def test_post_sends_exactly_the_configured_secret(self) -> None:
        params: dict[str, str] = {}
        auth = apply_client_auth(
            params,
            _Request(client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST),
            client_secret="s3cret",
        )
        assert auth is None
        assert params == {"client_id": "client", "client_secret": "s3cret"}
