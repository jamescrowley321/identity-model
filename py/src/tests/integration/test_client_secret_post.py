"""Integration tests for ``client_secret_post`` client authentication (#1056).

Runs against the bundled node-oidc-provider fixture, which registers a
``test-client-secret-post`` client. node-oidc-provider accepts either secret
method for such a client, so this proves a live provider accepts the POST
form; the exact request bytes are pinned by the CC-003, INTR-003 and EXCH-001
spec vectors. Skipped against any other provider.
"""

from urllib.parse import urlparse

import pytest

from py_identity_model import (
    ClientAuthMethod,
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)
from py_identity_model.aio import (
    request_client_credentials_token as async_request_client_credentials_token,
)


# Client registered in the node-oidc-provider fixture (provider.js).
# Test-only credentials for a disposable local provider.
POST_CLIENT_ID = "test-client-secret-post"
POST_CLIENT_SECRET = "test-client-secret-post-secret"


def _require_node_oidc(raw_discovery: dict) -> None:
    """Skip unless the provider is the bundled node-oidc fixture.

    node-oidc serves discovery at the host root on localhost; Keycloak also
    runs locally but under ``/realms/<realm>`` and doesn't register this client.
    """
    parsed = urlparse(raw_discovery.get("issuer", ""))
    if parsed.hostname not in ("localhost", "127.0.0.1") or parsed.path not in (
        "",
        "/",
    ):
        pytest.skip("client_secret_post fixture client only registered in node-oidc")


def _request(
    method: ClientAuthMethod, token_endpoint: str
) -> ClientCredentialsTokenRequest:
    return ClientCredentialsTokenRequest(
        address=token_endpoint,
        client_id=POST_CLIENT_ID,
        client_secret=POST_CLIENT_SECRET,
        scope="api",
        client_auth_method=method,
    )


@pytest.mark.integration
class TestClientSecretPostLive:
    """A live provider accepts a client authenticated with client_secret_post."""

    def test_client_secret_post_accepted(self, raw_discovery, token_endpoint):
        _require_node_oidc(raw_discovery)
        response = request_client_credentials_token(
            _request(ClientAuthMethod.CLIENT_SECRET_POST, token_endpoint)
        )
        assert response.is_successful is True, response.error
        assert response.token is not None
        assert response.token.get("access_token")

    @pytest.mark.asyncio
    async def test_async_client_secret_post_accepted(
        self, raw_discovery, token_endpoint
    ):
        _require_node_oidc(raw_discovery)
        response = await async_request_client_credentials_token(
            _request(ClientAuthMethod.CLIENT_SECRET_POST, token_endpoint)
        )
        assert response.is_successful is True, response.error
