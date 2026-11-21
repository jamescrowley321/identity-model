"""Unit tests for Pushed Authorization Requests (RFC 9126)."""

import httpx
import pytest
import respx

from py_identity_model import (
    BaseRequest,
    BaseResponse,
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
)
from py_identity_model.sync.par import push_authorization_request


PAR_URL = "https://auth.example.com/par"
PAR_RESPONSE = {
    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    "expires_in": 60,
}

# Expected PAR response values
EXPECTED_PAR_EXPIRES_IN = 60


@pytest.mark.unit
class TestPAR:
    @respx.mock
    def test_successful_par(self):
        respx.post(PAR_URL).mock(return_value=httpx.Response(201, json=PAR_RESPONSE))
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.request_uri == "urn:ietf:params:oauth:request_uri:abc123"
        assert response.expires_in == EXPECTED_PAR_EXPIRES_IN

    @respx.mock
    def test_par_with_pkce(self):
        respx.post(PAR_URL).mock(return_value=httpx.Response(201, json=PAR_RESPONSE))
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="challenge",
                code_challenge_method="S256",
            )
        )
        assert response.is_successful is True

    @respx.mock
    def test_par_pushes_response_mode_for_jarm(self):
        # JARM: response_mode must be pushed so the OP returns a signed
        # authorization response JWT (omitted from the body when unset).
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
                response_mode="jwt",
            )
        )
        assert "response_mode=jwt" in route.calls[0].request.content.decode()

    @respx.mock
    def test_par_omits_response_mode_when_unset(self):
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert "response_mode" not in route.calls[0].request.content.decode()

    @respx.mock
    def test_par_error(self):
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(400, content=b'{"error":"invalid_request"}')
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False

    def test_request_inherits_base(self):
        req = PushedAuthorizationRequest(
            address=PAR_URL, client_id="app", redirect_uri="https://app.com/cb"
        )
        assert isinstance(req, BaseRequest)

    def test_request_with_all_params(self):
        req = PushedAuthorizationRequest(
            address=PAR_URL,
            client_id="app",
            redirect_uri="https://app.com/cb",
            scope="openid profile",
            state="csrf",
            nonce="nonce",
            code_challenge="challenge",
            code_challenge_method="S256",
            client_secret="secret",
        )
        assert req.scope == "openid profile"
        assert req.code_challenge_method == "S256"

    @respx.mock
    def test_confidential_client_uses_basic_auth_and_body(self):
        """M1: confidential clients use Basic Auth AND include client_id in body (RFC 9126 §2)."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        request = route.calls[0].request
        assert request.headers.get("authorization") is not None
        assert request.headers["authorization"].startswith("Basic ")
        assert "client_id=app1" in request.content.decode()

    @respx.mock
    def test_public_client_sends_client_id_in_body(self):
        """M1: public clients send client_id in POST body, no Basic Auth."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="public_app",
                redirect_uri="https://app.com/cb",
            )
        )
        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=public_app" in body
        assert request.headers.get("authorization") is None

    @respx.mock
    def test_missing_request_uri_returns_error(self):
        """M2: Missing request_uri in successful response fails per RFC 9126 §2.2."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json={"expires_in": 60})
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "request_uri" in response.error

    @pytest.mark.parametrize(
        "request_uri", ["", "   ", 123, ["urn:x"], {"uri": "urn:x"}]
    )
    @respx.mock
    def test_blank_or_non_string_request_uri_returns_error(self, request_uri):
        """RFC 9126 §2.2: request_uri is a string; anything else is not a success."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201, json={"request_uri": request_uri, "expires_in": 60}
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error == (
            "PAR response missing required fields per RFC 9126 Section 2.2: request_uri"
        )

    @respx.mock
    def test_missing_expires_in_returns_error(self):
        """M2: Missing expires_in in successful response fails per RFC 9126 §2.2."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201,
                json={
                    "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
                },
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_pkce_requires_both_challenge_and_method(self):
        """S4: code_challenge and code_challenge_method must be paired.

        ValueError is caught by error handler — returns error response.
        """
        respx.post(PAR_URL).mock(return_value=httpx.Response(201, json=PAR_RESPONSE))
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="challenge",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "code_challenge" in response.error

    @respx.mock
    def test_network_error(self):
        respx.post(PAR_URL).mock(side_effect=httpx.ConnectError("Connection refused"))
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    def test_response_inherits_base(self):
        resp = PushedAuthorizationResponse(
            is_successful=True, request_uri="urn:...", expires_in=60
        )
        assert isinstance(resp, BaseResponse)

    @respx.mock
    def test_content_type_header(self):
        """RFC 9126: PAR uses form-urlencoded content type."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        request = route.calls[0].request
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"

    @respx.mock
    def test_empty_client_secret_treated_as_public(self):
        """client_secret='' is treated as absent (public client)."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="",
            )
        )
        request = route.calls[0].request
        assert request.headers.get("authorization") is None
        assert "client_id=app1" in request.content.decode()

    @respx.mock
    def test_empty_state_not_sent(self):
        """state='' is not sent as form param."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                state="",
            )
        )
        body = route.calls[0].request.content.decode()
        assert "state=" not in body

    @respx.mock
    def test_empty_nonce_not_sent(self):
        """nonce='' is not sent as form param."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                nonce="",
            )
        )
        body = route.calls[0].request.content.decode()
        assert "nonce=" not in body

    @respx.mock
    def test_pkce_empty_string_treated_as_absent(self):
        """Empty code_challenge/code_challenge_method treated as absent."""
        route = respx.post(PAR_URL).mock(
            return_value=httpx.Response(201, json=PAR_RESPONSE)
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="",
                code_challenge_method="",
            )
        )
        assert response.is_successful is True
        body = route.calls[0].request.content.decode()
        assert "code_challenge" not in body

    @respx.mock
    def test_expires_in_string_returns_error(self):
        """expires_in must be a positive integer per RFC 9126 §2.2."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201,
                json={
                    "request_uri": "urn:ietf:params:oauth:request_uri:abc",
                    "expires_in": "60",
                },
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_expires_in_zero_returns_error(self):
        """expires_in=0 is invalid (zero-second expiry)."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201,
                json={
                    "request_uri": "urn:ietf:params:oauth:request_uri:abc",
                    "expires_in": 0,
                },
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_expires_in_negative_returns_error(self):
        """expires_in=-1 is invalid."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201,
                json={
                    "request_uri": "urn:ietf:params:oauth:request_uri:abc",
                    "expires_in": -1,
                },
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_non_json_success_response(self):
        """2xx with non-JSON body returns error instead of crashing."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(
                201,
                content=b"<html>OK</html>",
                headers={"content-type": "text/html"},
            )
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_error_response_uses_text_not_bytes(self):
        """Error messages use response.text, not response.content (bytes)."""
        respx.post(PAR_URL).mock(
            return_value=httpx.Response(400, content=b'{"error":"invalid_request"}')
        )
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                client_secret="secret",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "b'" not in response.error


@pytest.mark.unit
class TestPARResponseReprRedaction:
    """#431: the ``request_uri`` capability is a secret and must not leak via repr/str."""

    SECRET_URI = "urn:ietf:params:oauth:request_uri:SUPER_SECRET_HANDLE"

    def test_repr_redacts_request_uri(self):
        response = PushedAuthorizationResponse(
            is_successful=True, request_uri=self.SECRET_URI, expires_in=60
        )

        rendered = repr(response)
        assert "PushedAuthorizationResponse" in rendered
        assert "[REDACTED]" in rendered
        assert "SUPER_SECRET_HANDLE" not in rendered
        # expires_in is not sensitive and must remain visible.
        assert "expires_in=60" in rendered

    def test_str_redacts_request_uri(self):
        response = PushedAuthorizationResponse(
            is_successful=True, request_uri=self.SECRET_URI, expires_in=60
        )

        assert "SUPER_SECRET_HANDLE" not in str(response)
        assert "[REDACTED]" in str(response)

    def test_repr_of_failed_response_does_not_crash_or_leak(self):
        response = PushedAuthorizationResponse(
            is_successful=False, error="invalid_request", request_uri=None
        )

        rendered = repr(response)
        assert "invalid_request" in rendered
        assert "[REDACTED]" not in rendered
        assert "request_uri=None" in rendered

    def test_equality_still_behaves(self):
        a = PushedAuthorizationResponse(
            is_successful=True, request_uri=self.SECRET_URI, expires_in=60
        )
        b = PushedAuthorizationResponse(
            is_successful=True, request_uri=self.SECRET_URI, expires_in=60
        )
        c = PushedAuthorizationResponse(
            is_successful=True, request_uri=self.SECRET_URI, expires_in=90
        )

        assert a == b
        assert a != c
        assert a != "not-a-response"
