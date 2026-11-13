"""Unit tests for authorization code token exchange."""

import httpx
import pytest
import respx

from py_identity_model.aio.token_client import (
    request_authorization_code_token as request_authorization_code_token_async,
)
from py_identity_model.core.models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
)
from py_identity_model.sync.token_client import (
    request_authorization_code_token,
)


TOKEN_URL = "https://auth.example.com/token"
TOKEN_JSON = {
    "access_token": "access_tok",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "refresh_tok",
    "id_token": "id_tok",
}


@pytest.mark.unit
class TestAuthCodeTokenExchange:
    @respx.mock
    def test_success_with_pkce(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            code_verifier="verifier_string",
        )
        response = request_authorization_code_token(request)

        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "access_tok"
        assert response.token["refresh_token"] == "refresh_tok"

    @respx.mock
    def test_success_with_client_secret(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            client_secret="secret",
        )
        response = request_authorization_code_token(request)

        assert response.is_successful is True

    @respx.mock
    def test_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={"error": "invalid_grant"},
                content=b'{"error": "invalid_grant"}',
            )
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="expired_code",
            redirect_uri="https://app.com/cb",
        )
        response = request_authorization_code_token(request)

        assert response.is_successful is False

    def test_response_repr_success_no_crash(self):
        """repr() on successful response must not crash (T104 pattern)."""
        resp = AuthorizationCodeTokenResponse(is_successful=True, token={"a": 1})
        r = repr(resp)
        assert "AuthorizationCodeTokenResponse" in r

    def test_response_repr_failure_no_crash(self):
        """repr() on failed response must not crash."""
        resp = AuthorizationCodeTokenResponse(is_successful=False, error="bad")
        r = repr(resp)
        assert "AuthorizationCodeTokenResponse" in r

    def test_response_eq_no_crash(self):
        """== on response instances must not crash."""
        r1 = AuthorizationCodeTokenResponse(is_successful=True, token={"a": 1})
        r2 = AuthorizationCodeTokenResponse(is_successful=True, token={"a": 1})
        assert r1 == r2

    @respx.mock
    def test_confidential_client_no_client_id_in_body(self):
        """RFC 6749 §2.3.1: client_id must not be in body when using Basic auth."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            client_secret="secret",
        )
        request_authorization_code_token(request)

        sent_request = route.calls[0].request
        body = sent_request.content.decode()
        assert "client_id" not in body

    @respx.mock
    def test_public_client_includes_client_id_in_body(self):
        """Public clients (no secret) must include client_id in body."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            code_verifier="verifier",
        )
        request_authorization_code_token(request)

        sent_request = route.calls[0].request
        body = sent_request.content.decode()
        assert "client_id=app1" in body


@pytest.mark.unit
@pytest.mark.asyncio
class TestAsyncAuthCodeTokenExchange:
    @respx.mock
    async def test_success_with_pkce(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            code_verifier="verifier_string",
        )
        response = await request_authorization_code_token_async(request)

        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "access_tok"

    @respx.mock
    async def test_success_with_client_secret(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="auth_code_123",
            redirect_uri="https://app.com/cb",
            client_secret="secret",
        )
        response = await request_authorization_code_token_async(request)

        assert response.is_successful is True

    @respx.mock
    async def test_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={"error": "invalid_grant"},
                content=b'{"error": "invalid_grant"}',
            )
        )

        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="expired_code",
            redirect_uri="https://app.com/cb",
        )
        response = await request_authorization_code_token_async(request)

        assert response.is_successful is False


AC_SECRET_TOKEN = {
    "access_token": "AC_SECRET_AT",
    "refresh_token": "AC_SECRET_RT",
    "id_token": "AC_SECRET_IDT",
}


@pytest.mark.unit
class TestAuthCodeTokenResponseReprRedaction:
    """#431: the ``token`` dict is a secret and must not leak via repr/str."""

    def test_repr_redacts_token_value(self):
        response = AuthorizationCodeTokenResponse(
            is_successful=True, token=AC_SECRET_TOKEN
        )

        rendered = repr(response)
        assert "AuthorizationCodeTokenResponse" in rendered
        assert "[REDACTED]" in rendered
        assert "AC_SECRET_AT" not in rendered
        assert "AC_SECRET_RT" not in rendered
        assert "AC_SECRET_IDT" not in rendered

    def test_str_redacts_token_value(self):
        response = AuthorizationCodeTokenResponse(
            is_successful=True, token=AC_SECRET_TOKEN
        )

        assert "AC_SECRET_RT" not in str(response)
        assert "[REDACTED]" in str(response)

    def test_repr_of_failed_response_does_not_crash_or_leak(self):
        response = AuthorizationCodeTokenResponse(
            is_successful=False, error="invalid_grant", token=None
        )

        rendered = repr(response)
        assert "invalid_grant" in rendered
        assert "[REDACTED]" not in rendered
        assert "token=None" in rendered

    def test_equality_still_behaves(self):
        a = AuthorizationCodeTokenResponse(is_successful=True, token=AC_SECRET_TOKEN)
        b = AuthorizationCodeTokenResponse(
            is_successful=True, token=dict(AC_SECRET_TOKEN)
        )
        c = AuthorizationCodeTokenResponse(
            is_successful=True, token={"access_token": "other"}
        )

        assert a == b
        assert a != c
        assert a != "not-a-response"
