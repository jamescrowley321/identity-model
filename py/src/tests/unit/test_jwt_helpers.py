"""
Unit tests for JWT helper functions.

These tests verify JWT decoding, validation, and exception handling.
"""

from jwt.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)
import pytest

import py_identity_model.core.jwt_helpers
from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.exceptions import (
    InvalidAudienceException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenValidationException,
)


# Never used to verify (_decode_jwt is patched), but sized at 2048 bits so it
# clears the key-strength floor checked before decoding.
PLACEHOLDER_RSA_KEY = {"kty": "RSA", "n": "w" + "A" * 341, "e": "AQAB"}


class TestDecodeAndValidateJWT:
    """Test JWT decoding and validation with exception handling."""

    def test_decode_jwt_invalid_audience(self, monkeypatch):
        """Test that InvalidAudienceError is converted to InvalidAudienceException."""

        def mock_decode(*_args, **_kwargs):
            raise InvalidAudienceError("Invalid audience")

        # Mock the internal _decode_jwt_cached function
        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt",
            mock_decode,
        )

        with pytest.raises(InvalidAudienceException, match="Invalid audience"):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key=PLACEHOLDER_RSA_KEY,
                algorithms=["RS256"],
                audience="expected-audience",
                issuer="expected-issuer",
                options=None,
            )

    def test_decode_jwt_invalid_issuer(self, monkeypatch):
        """Test that InvalidIssuerError is converted to InvalidIssuerException."""

        def mock_decode(*_args, **_kwargs):
            raise InvalidIssuerError("Invalid issuer")

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt",
            mock_decode,
        )

        with pytest.raises(InvalidIssuerException, match="Invalid issuer"):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key=PLACEHOLDER_RSA_KEY,
                algorithms=["RS256"],
                audience="expected-audience",
                issuer="expected-issuer",
                options=None,
            )

    def test_decode_jwt_invalid_signature(self, monkeypatch):
        """Test that InvalidSignatureError is converted to SignatureVerificationException."""

        def mock_decode(*_args, **_kwargs):
            raise InvalidSignatureError("Invalid signature")

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt",
            mock_decode,
        )

        with pytest.raises(SignatureVerificationException, match="Invalid signature"):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key=PLACEHOLDER_RSA_KEY,
                algorithms=["RS256"],
                audience=None,
                issuer=None,
                options=None,
            )

    def test_decode_jwt_invalid_token(self, monkeypatch):
        """Test that InvalidTokenError is converted to TokenValidationException."""

        def mock_decode(*_args, **_kwargs):
            raise InvalidTokenError("Invalid token format")

        monkeypatch.setattr(
            py_identity_model.core.jwt_helpers,
            "_decode_jwt",
            mock_decode,
        )

        with pytest.raises(
            TokenValidationException,
            match="Invalid token: Invalid token format",
        ):
            decode_and_validate_jwt(
                jwt="fake.jwt.token",
                key=PLACEHOLDER_RSA_KEY,
                algorithms=["RS256"],
                audience=None,
                issuer=None,
                options=None,
            )
