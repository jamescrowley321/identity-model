"""A success token response needs ``access_token`` and ``token_type`` (RFC 6749 §5.1)."""

import httpx
import pytest

from py_identity_model import TokenErrorKind
from py_identity_model.core.response_processors import (
    parse_auth_code_token_response,
    parse_refresh_token_response,
    parse_token_response,
    token_response_error,
)


TOKEN_URL = "https://auth.example.com/token"
VALID = {"access_token": "at-1", "token_type": "Bearer", "expires_in": 300}
MISSING_FIELDS = "Token response is missing required fields per RFC 6749 Section 5.1"

PARSERS = [
    pytest.param(parse_token_response, id="client_credentials"),
    pytest.param(parse_auth_code_token_response, id="auth_code"),
    pytest.param(parse_refresh_token_response, id="refresh"),
]

INVALID_BODIES = [
    pytest.param({}, f"{MISSING_FIELDS}: access_token, token_type", id="empty"),
    pytest.param(
        {"access_token": "at-1"}, f"{MISSING_FIELDS}: token_type", id="no_type"
    ),
    pytest.param(
        {"token_type": "Bearer"}, f"{MISSING_FIELDS}: access_token", id="no_token"
    ),
    pytest.param(
        {"access_token": "", "token_type": "Bearer"},
        f"{MISSING_FIELDS}: access_token",
        id="empty_token",
    ),
    pytest.param(
        {"access_token": "at-1", "token_type": 1},
        f"{MISSING_FIELDS}: token_type",
        id="non_string_type",
    ),
    pytest.param([1, 2], "Token response is not a JSON object: list", id="array"),
]


def _response(body: object) -> httpx.Response:
    return httpx.Response(200, json=body, request=httpx.Request("POST", TOKEN_URL))


@pytest.mark.unit
class TestTokenResponseError:
    @pytest.mark.parametrize(("body", "expected"), INVALID_BODIES)
    def test_invalid_body(self, body, expected):
        assert token_response_error(body) == expected

    def test_valid_body(self):
        assert token_response_error(VALID) is None


@pytest.mark.unit
class TestParsersRequireFields:
    @pytest.mark.parametrize("parse", PARSERS)
    @pytest.mark.parametrize(("body", "expected"), INVALID_BODIES)
    def test_invalid_success_body_fails(self, parse, body, expected):
        response = parse(_response(body))
        assert response.is_successful is False
        assert response.error == expected
        assert response.error_kind is TokenErrorKind.INVALID_TOKEN_RESPONSE

    @pytest.mark.parametrize("parse", PARSERS)
    def test_valid_success_body(self, parse):
        response = parse(_response(VALID))
        assert response.is_successful is True
        assert response.error_kind is None
        assert response.token == VALID

    @pytest.mark.parametrize("parse", PARSERS)
    def test_unknown_token_type_is_passed_through(self, parse):
        """The type is checked for presence; the caller decides if it knows it."""
        body = {**VALID, "token_type": "N_A"}
        response = parse(_response(body))
        assert response.is_successful is True
        assert response.token == body


@pytest.mark.unit
class TestRejectedTokenKept:
    """A rotated refresh token in an invalid response is not lost."""

    @pytest.mark.parametrize(
        "parse",
        [
            pytest.param(parse_auth_code_token_response, id="auth_code"),
            pytest.param(parse_refresh_token_response, id="refresh"),
        ],
    )
    def test_object_body_kept_on_rejected_token(self, parse):
        body = {"access_token": "at-1", "refresh_token": "rt-2"}
        response = parse(_response(body))
        assert response.is_successful is False
        assert response.error_kind is TokenErrorKind.INVALID_TOKEN_RESPONSE
        assert response.rejected_token == body

    def test_non_object_body_not_kept(self):
        response = parse_refresh_token_response(_response([1, 2]))
        assert response.rejected_token is None
