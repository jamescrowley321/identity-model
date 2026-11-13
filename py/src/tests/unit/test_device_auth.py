"""Unit tests for Device Authorization Grant (RFC 8628)."""

import httpx
import pytest
import respx

from py_identity_model import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
    FailedResponseAccessError,
)
from py_identity_model.aio.device_auth import (
    poll_device_token as poll_device_token_async,
)
from py_identity_model.core.device_auth_logic import (
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
)
from py_identity_model.sync.device_auth import (
    poll_device_token,
    request_device_authorization,
)


DEVICE_AUTH_URL = "https://auth.example.com/device/authorize"
TOKEN_URL = "https://auth.example.com/token"

# Expected values from device authorization responses
EXPECTED_EXPIRES_IN = 1800
EXPECTED_INTERVAL = 5
EXPECTED_TOKEN_EXPIRES_IN = 3600
SLOW_DOWN_INTERVAL = 10

DEVICE_AUTH_RESPONSE = {
    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
    "user_code": "WDJB-MJHT",
    "verification_uri": "https://auth.example.com/device",
    "verification_uri_complete": "https://auth.example.com/device?user_code=WDJB-MJHT",
    "expires_in": 1800,
    "interval": 5,
}


@pytest.mark.unit
class TestRequestDeviceAuthorization:
    @respx.mock
    def test_successful_device_auth(self):
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=DEVICE_AUTH_RESPONSE)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
                client_secret="secret",
            )
        )
        assert response.is_successful is True
        assert response.device_code == DEVICE_AUTH_RESPONSE["device_code"]
        assert response.user_code == "WDJB-MJHT"
        assert response.verification_uri == "https://auth.example.com/device"
        assert response.verification_uri_complete is not None
        assert response.expires_in == EXPECTED_EXPIRES_IN
        assert response.interval == EXPECTED_INTERVAL

    @respx.mock
    def test_device_auth_without_client_secret(self):
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=DEVICE_AUTH_RESPONSE)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="public-app",
                scope="openid profile",
            )
        )
        assert response.is_successful is True
        assert response.user_code == "WDJB-MJHT"

    @respx.mock
    def test_device_auth_error(self):
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(400, content=b'{"error":"unauthorized_client"}')
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="bad-app",
            )
        )
        assert response.is_successful is False

    @respx.mock
    def test_missing_required_fields_returns_error(self):
        """S2: Missing REQUIRED fields per RFC 8628 §3.2 return error."""
        respx.post(DEVICE_AUTH_URL).mock(return_value=httpx.Response(200, json={}))
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "device_code" in response.error
        assert "user_code" in response.error
        assert "verification_uri" in response.error
        assert "expires_in" in response.error

    @respx.mock
    def test_missing_device_code_returns_error(self):
        """S2: Partial REQUIRED fields still fail."""
        partial = {**DEVICE_AUTH_RESPONSE}
        del partial["device_code"]
        respx.post(DEVICE_AUTH_URL).mock(return_value=httpx.Response(200, json=partial))
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "device_code" in response.error

    @respx.mock
    def test_expires_in_string_returns_error(self):
        """S3: expires_in must be a positive integer per RFC 8628 §3.2."""
        bad_response = {**DEVICE_AUTH_RESPONSE, "expires_in": "1800"}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=bad_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_expires_in_zero_returns_error(self):
        """S3: expires_in=0 is invalid."""
        bad_response = {**DEVICE_AUTH_RESPONSE, "expires_in": 0}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=bad_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "expires_in" in response.error

    @respx.mock
    def test_interval_float_coerced_to_int(self):
        """S3: float interval is coerced to int."""
        float_response = {**DEVICE_AUTH_RESPONSE, "interval": 5.5}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=float_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is True
        assert response.interval == EXPECTED_INTERVAL
        assert isinstance(response.interval, int)

    @respx.mock
    def test_interval_string_becomes_none(self):
        """S3: non-numeric interval is treated as absent."""
        bad_response = {**DEVICE_AUTH_RESPONSE, "interval": "five"}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=bad_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is True
        assert response.interval is None

    @respx.mock
    def test_non_json_success_returns_error(self):
        """M1: Non-JSON body on 200 returns error instead of crashing."""
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, content=b"<html>Gateway Error</html>")
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_non_dict_json_success_returns_error(self):
        """Edge: Non-dict JSON on 200 returns error instead of AttributeError."""
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error

    @respx.mock
    def test_expires_in_float_coerced_to_int(self):
        """M2: float expires_in is coerced to int (JSON has no int/float distinction)."""
        float_response = {**DEVICE_AUTH_RESPONSE, "expires_in": 1800.0}
        respx.post(DEVICE_AUTH_URL).mock(
            return_value=httpx.Response(200, json=float_response)
        )
        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=DEVICE_AUTH_URL,
                client_id="app1",
            )
        )
        assert response.is_successful is True
        assert response.expires_in == EXPECTED_EXPIRES_IN
        assert isinstance(response.expires_in, int)


@pytest.mark.unit
class TestPollDeviceToken:
    @respx.mock
    def test_successful_token(self):
        token_data = {
            "access_token": "SlAV32hkKG",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token_data))
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "SlAV32hkKG"
        assert response.error_code is None

    @respx.mock
    def test_authorization_pending(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "authorization_pending",
                    "error_description": "The user has not yet completed authorization",
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "authorization_pending"

    @respx.mock
    def test_slow_down(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "slow_down",
                    "interval": 10,
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "slow_down"
        assert response.interval == SLOW_DOWN_INTERVAL

    @respx.mock
    def test_slow_down_float_interval(self):
        """S3: float interval in slow_down response is coerced to int."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "slow_down",
                    "interval": 10.5,
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "slow_down"
        assert response.interval == SLOW_DOWN_INTERVAL
        assert isinstance(response.interval, int)

    @respx.mock
    def test_expired_token(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "expired_token",
                    "error_description": "The device code has expired",
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "expired_token"

    @respx.mock
    def test_access_denied(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "access_denied",
                    "error_description": "The user denied the request",
                },
            )
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code == "access_denied"

    @respx.mock
    def test_non_json_error_response(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(500, content=b"Internal Server Error")
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code is None

    @respx.mock
    def test_non_json_token_success_returns_error(self):
        """M1: Non-JSON body on 200 token response returns error."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, content=b"<html>Error</html>")
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "invalid JSON" in response.error

    @respx.mock
    def test_non_dict_json_token_success_returns_error(self):
        """WARN3: Non-dict JSON on 200 token response returns error."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error

    @respx.mock
    def test_non_dict_json_error_response(self):
        """WARN4: Non-dict JSON on error response handled gracefully."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json=["error_array"])
        )
        response = poll_device_token(
            DeviceTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                device_code="device123",
            )
        )
        assert response.is_successful is False
        assert response.error_code is None


@pytest.mark.unit
class TestDeviceAuthModels:
    def test_device_auth_response_guarded_fields(self):
        resp = DeviceAuthorizationResponse(
            is_successful=False,
            error="unauthorized_client",
        )
        with pytest.raises(FailedResponseAccessError):
            _ = resp.device_code
        with pytest.raises(FailedResponseAccessError):
            _ = resp.user_code


@pytest.mark.unit
class TestPrepareDeviceAuthData:
    def test_public_client(self):
        req = DeviceAuthorizationRequest(
            address="https://auth.example.com/device/authorize",
            client_id="public-app",
            scope="openid",
        )
        data, headers, auth = prepare_device_auth_request_data(req)
        assert data["client_id"] == "public-app"
        assert data["scope"] == "openid"
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert auth is None

    def test_confidential_client(self):
        req = DeviceAuthorizationRequest(
            address="https://auth.example.com/device/authorize",
            client_id="conf-app",
            client_secret="secret",
        )
        _data, _headers, auth = prepare_device_auth_request_data(req)
        assert auth == ("conf-app", "secret")

    def test_device_token_data(self):
        req = DeviceTokenRequest(
            address="https://auth.example.com/token",
            client_id="app",
            device_code="dev_code_xyz",
        )
        data, _headers, auth = prepare_device_token_request_data(req)
        assert data["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
        assert data["device_code"] == "dev_code_xyz"
        assert data["client_id"] == "app"
        assert auth is None


DEVICE_SECRET_TOKEN = {
    "access_token": "DEVICE_SECRET_AT",
    "refresh_token": "DEVICE_SECRET_RT",
}


@pytest.mark.unit
class TestDeviceTokenResponseReprRedaction:
    """#431: the ``token`` dict is a secret and must not leak via repr/str."""

    def test_repr_redacts_token_value(self):
        response = DeviceTokenResponse(is_successful=True, token=DEVICE_SECRET_TOKEN)

        rendered = repr(response)
        assert "DeviceTokenResponse" in rendered
        assert "[REDACTED]" in rendered
        assert "DEVICE_SECRET_AT" not in rendered
        assert "DEVICE_SECRET_RT" not in rendered

    def test_str_redacts_token_value(self):
        response = DeviceTokenResponse(is_successful=True, token=DEVICE_SECRET_TOKEN)

        assert "DEVICE_SECRET_AT" not in str(response)
        assert "[REDACTED]" in str(response)

    def test_repr_of_pending_response_does_not_crash_or_leak(self):
        response = DeviceTokenResponse(
            is_successful=False, error_code="authorization_pending", token=None
        )

        rendered = repr(response)
        assert "authorization_pending" in rendered
        assert "[REDACTED]" not in rendered
        assert "token=None" in rendered

    def test_equality_still_behaves(self):
        a = DeviceTokenResponse(is_successful=True, token=DEVICE_SECRET_TOKEN)
        b = DeviceTokenResponse(is_successful=True, token=dict(DEVICE_SECRET_TOKEN))
        c = DeviceTokenResponse(is_successful=True, token={"access_token": "other"})

        assert a == b
        assert a != c
        assert a != "not-a-response"


@pytest.mark.unit
class TestDeviceAuthorizationResponseReprRedaction:
    """#431: repr must not crash and must redact the device_code polling credential."""

    def test_repr_success_no_crash_and_redacts_device_code(self):
        response = DeviceAuthorizationResponse(
            is_successful=True,
            device_code="DA_SECRET_DC",
            user_code="WDJB-MJHT",
            verification_uri="https://example.com/device",
        )

        rendered = repr(response)
        assert "DeviceAuthorizationResponse" in rendered
        assert "[REDACTED]" in rendered
        assert "DA_SECRET_DC" not in rendered
        # user-facing fields stay visible
        assert "WDJB-MJHT" in rendered
        assert "https://example.com/device" in rendered

    def test_str_redacts_device_code(self):
        response = DeviceAuthorizationResponse(
            is_successful=True, device_code="DA_SECRET_DC"
        )

        assert "DA_SECRET_DC" not in str(response)
        assert "[REDACTED]" in str(response)

    def test_repr_of_failed_response_does_not_crash_or_leak(self):
        response = DeviceAuthorizationResponse(
            is_successful=False, error="access_denied"
        )

        rendered = repr(response)
        assert "access_denied" in rendered
        assert "[REDACTED]" not in rendered
        assert "device_code=None" in rendered

    def test_equality_still_behaves(self):
        a = DeviceAuthorizationResponse(is_successful=True, device_code="DA_SECRET_DC")
        b = DeviceAuthorizationResponse(is_successful=True, device_code="DA_SECRET_DC")
        c = DeviceAuthorizationResponse(is_successful=True, device_code="other")

        assert a == b
        assert a != c
        assert a != "not-a-response"


POLL_NOT_RETRIED = [
    pytest.param(httpx.Response(503), id="503"),
    pytest.param(httpx.Response(429), id="429"),
    pytest.param(httpx.ReadTimeout("response lost"), id="read_timeout"),
]


@pytest.mark.unit
class TestPollIsSingleAttempt:
    """RFC 8628 §3.5: the caller's loop sets the polling rate, never a retry."""

    @pytest.mark.parametrize("first", POLL_NOT_RETRIED)
    @respx.mock
    def test_sync_poll_sends_one_request(self, first):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[first, httpx.Response(200, json={"access_token": "at"})]
        )
        response = poll_device_token(
            DeviceTokenRequest(address=TOKEN_URL, client_id="app1", device_code="d")
        )
        assert response.is_successful is False
        assert response.error_code is None
        assert route.call_count == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("first", POLL_NOT_RETRIED)
    @respx.mock
    async def test_async_poll_sends_one_request(self, first):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[first, httpx.Response(200, json={"access_token": "at"})]
        )
        response = await poll_device_token_async(
            DeviceTokenRequest(address=TOKEN_URL, client_id="app1", device_code="d")
        )
        assert response.is_successful is False
        assert response.error_code is None
        assert route.call_count == 1
