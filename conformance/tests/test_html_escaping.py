"""Tests for HTML escaping in the conformance harness error/success responses.

Regression coverage for #381: the harness rendered IdP-controlled error
messages and claim values straight into HTMLResponse bodies via f-strings,
yielding reflected XSS in any branch that interpolated upstream data.
Every interpolation must now flow through ``html.escape``.

These tests exercise the branches that surface IdP-controlled data and
are reachable in the normal callback flow:

- Discovery Failed (line ~363)
- ID Token Validation Failed (line ~534)
- UserInfo Validation Failed (line ~577)
- Success body — UserInfo claim rendering (line ~604)

The other HTMLResponse branches either return static content (no
interpolation) or are guarded behind earlier validation that prevents
IdP data from reaching them (e.g. the OP Error branch at line ~437 is
gated by ``validate_authorize_callback_state`` returning
``ERROR_RESPONSE`` for callbacks that carry ``error=``).
"""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import patch

import app as harness_app
from fastapi.testclient import TestClient

# Importing the real exception class so the harness's `except` clause matches.
from py_identity_model.exceptions import TokenValidationException


XSS_PAYLOAD = "<script>alert(1)</script>"
XSS_ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"
QUOTE_PAYLOAD = '" onmouseover="alert(1)'
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_BAD_GATEWAY = 502
EXPECTED_KEY_VALUE_ESCAPES = 2


def _make_session(state: str = "test-state", nonce: str = "match-nonce"):
    """Register a session in the harness so /callback can resolve it."""
    session = harness_app.AuthSession(
        issuer="https://op.example.com",
        state=state,
        nonce=nonce,
        client_id="test-client",
        redirect_uri="http://localhost:8888/callback",
    )
    harness_app.sessions[state] = session
    return session


def _clear_state() -> None:
    harness_app.sessions.clear()
    harness_app.test_results.clear()


class _Disco:
    """Minimal stand-in for a successful DiscoveryDocumentResponse."""

    is_successful = True
    error = None
    issuer = "https://op.example.com"
    token_endpoint = "https://op.example.com/token"
    userinfo_endpoint = "https://op.example.com/userinfo"
    authorization_endpoint = "https://op.example.com/auth"
    jwks_uri = "https://op.example.com/jwks"
    end_session_endpoint = "https://op.example.com/end-session"


class _DiscoEndpoint:
    url = "https://op.example.com"
    authority = "https://op.example.com"


class _TokenRespOk:
    is_successful = True
    token: ClassVar[dict[str, str]] = {
        "id_token": "fake.jwt.token",
        "access_token": "fake-access",
    }
    error = None


class TestDiscoveryFailedEscaping:
    """Discovery error message must be HTML-escaped (line ~363)."""

    def teardown_method(self) -> None:
        _clear_state()

    def test_discovery_failure_escapes_script_payload(self) -> None:
        _make_session(state="state-disco")

        class _FailedDisco:
            is_successful = False
            error = XSS_PAYLOAD

        with patch.object(
            harness_app, "get_discovery_document", return_value=_FailedDisco()
        ):
            client = TestClient(harness_app.app)
            response = client.get(
                "/callback", params={"state": "state-disco", "code": "abc"}
            )

        assert response.status_code == HTTP_BAD_GATEWAY
        body = response.text
        assert XSS_PAYLOAD not in body, "raw <script> reached the rendered body"
        assert XSS_ESCAPED in body
        assert "<h1>Discovery Failed</h1>" in body


class TestIdTokenValidationFailedEscaping:
    """TokenValidationException.message must be HTML-escaped (line ~534)."""

    def teardown_method(self) -> None:
        _clear_state()

    def test_id_token_validation_failure_escapes_script_payload(self) -> None:
        _make_session(state="state-idtok")

        with (
            patch.object(harness_app, "get_discovery_document", return_value=_Disco()),
            patch.object(
                harness_app, "parse_discovery_url", return_value=_DiscoEndpoint()
            ),
            patch.object(
                harness_app,
                "request_authorization_code_token",
                return_value=_TokenRespOk(),
            ),
            patch.object(
                harness_app,
                "validate_id_token",
                side_effect=TokenValidationException(XSS_PAYLOAD),
            ),
        ):
            client = TestClient(harness_app.app)
            response = client.get(
                "/callback", params={"state": "state-idtok", "code": "abc"}
            )

        assert response.status_code == HTTP_BAD_REQUEST
        body = response.text
        assert XSS_PAYLOAD not in body
        assert XSS_ESCAPED in body
        assert "<h1>ID Token Validation Failed</h1>" in body


class TestUserInfoValidationFailedEscaping:
    """UserInfo error string must be HTML-escaped (line ~577)."""

    def teardown_method(self) -> None:
        _clear_state()

    def test_userinfo_failure_escapes_script_payload(self) -> None:
        _make_session(state="state-ui-err", nonce="match-nonce")

        class _UserInfoFail:
            is_successful = False
            claims = None
            error = XSS_PAYLOAD

        with (
            patch.object(harness_app, "get_discovery_document", return_value=_Disco()),
            patch.object(
                harness_app, "parse_discovery_url", return_value=_DiscoEndpoint()
            ),
            patch.object(
                harness_app,
                "request_authorization_code_token",
                return_value=_TokenRespOk(),
            ),
            patch.object(
                harness_app,
                "validate_id_token",
                return_value={
                    "sub": "user-1",
                    "iss": _Disco.issuer,
                    "nonce": "match-nonce",
                },
            ),
            patch.object(harness_app, "get_userinfo", return_value=_UserInfoFail()),
        ):
            client = TestClient(harness_app.app)
            response = client.get(
                "/callback", params={"state": "state-ui-err", "code": "abc"}
            )

        assert response.status_code == HTTP_BAD_REQUEST
        body = response.text
        assert XSS_PAYLOAD not in body
        assert XSS_ESCAPED in body
        assert "<h1>UserInfo Validation Failed</h1>" in body


class TestSuccessBodyClaimEscaping:
    """UserInfo claims rendered into the success body must be HTML-escaped (line ~604).

    This is the most concerning branch from the issue: claim keys AND values
    are IdP-supplied. The payload is placed as both the key and the value
    so the assertion verifies escape on both halves of ``<p>{key}: {value}</p>``.
    """

    def teardown_method(self) -> None:
        _clear_state()

    def test_userinfo_claim_value_escapes_script_payload(self) -> None:
        _make_session(state="state-success", nonce="match-nonce")

        class _UserInfoResp:
            is_successful = True
            claims: ClassVar[dict[str, str]] = {XSS_PAYLOAD: XSS_PAYLOAD}
            error = None

        with (
            patch.object(harness_app, "get_discovery_document", return_value=_Disco()),
            patch.object(
                harness_app, "parse_discovery_url", return_value=_DiscoEndpoint()
            ),
            patch.object(
                harness_app,
                "request_authorization_code_token",
                return_value=_TokenRespOk(),
            ),
            patch.object(
                harness_app,
                "validate_id_token",
                return_value={
                    "sub": "user-1",
                    "iss": _Disco.issuer,
                    "nonce": "match-nonce",
                },
            ),
            patch.object(harness_app, "get_userinfo", return_value=_UserInfoResp()),
        ):
            client = TestClient(harness_app.app)
            response = client.get(
                "/callback", params={"state": "state-success", "code": "abc"}
            )

        assert response.status_code == HTTP_OK
        body = response.text
        assert XSS_PAYLOAD not in body, "raw <script> reached the success body"
        # Both key and value get rendered, so escaped form appears at least twice.
        assert body.count(XSS_ESCAPED) >= EXPECTED_KEY_VALUE_ESCAPES
        assert "<h1>Authentication Successful</h1>" in body

    def test_id_token_sub_claim_with_quote_payload_is_escaped(self) -> None:
        """The Subject line interpolates claims.get('sub') directly.

        A malicious IdP could return a `sub` containing attribute-breakout
        characters. html.escape with the default quote=True must encode
        double quotes as &quot; so attribute injection is blocked.
        """
        _make_session(state="state-sub-attr", nonce="match-nonce")

        with (
            patch.object(harness_app, "get_discovery_document", return_value=_Disco()),
            patch.object(
                harness_app, "parse_discovery_url", return_value=_DiscoEndpoint()
            ),
            patch.object(
                harness_app,
                "request_authorization_code_token",
                return_value=_TokenRespOk(),
            ),
            patch.object(
                harness_app,
                "validate_id_token",
                return_value={
                    "sub": QUOTE_PAYLOAD,
                    "iss": _Disco.issuer,
                    "nonce": "match-nonce",
                },
            ),
            patch.object(
                harness_app,
                "get_userinfo",
                return_value=type(
                    "_Empty", (), {"is_successful": True, "claims": {}, "error": None}
                )(),
            ),
        ):
            client = TestClient(harness_app.app)
            response = client.get(
                "/callback", params={"state": "state-sub-attr", "code": "abc"}
            )

        assert response.status_code == HTTP_OK
        body = response.text
        assert QUOTE_PAYLOAD not in body
        assert "&quot;" in body
