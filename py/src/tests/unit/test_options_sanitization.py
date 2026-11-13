"""Tests for options sanitization — prevents disabling security checks."""

import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt
import pytest

from py_identity_model.core.jwt_helpers import (
    _sanitize_options,
    decode_and_validate_jwt,
)
from py_identity_model.exceptions import ConfigurationException


@pytest.fixture
def rsa_key_pair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    def _int_to_base64url(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    key_dict = {
        "kty": "RSA",
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
        "kid": "test-key-1",
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem, key_dict


def _make_token(private_key, sub: str = "test-user") -> str:
    """Create a signed JWT."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "aud": "test-aud",
        "iss": "test-iss",
        "iat": now,
        "exp": now + 3600,
    }
    return pyjwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": "test-key-1"}
    )


class TestSanitizeOptions:
    """Unit tests for _sanitize_options."""

    def test_none_options_returns_none(self):
        assert _sanitize_options(None, None, None) is None

    def test_empty_options_returns_empty(self):
        assert _sanitize_options({}, None, None) == {}

    def test_safe_options_pass_through(self):
        options = {"require": ["sub", "exp"], "strict_aud": True}
        assert _sanitize_options(options, None, None) == options

    @pytest.mark.parametrize(
        "blocked_key",
        ["verify_signature", "verify_exp", "verify_nbf", "verify_iat"],
    )
    def test_blocked_option_false_raises(self, blocked_key):
        with pytest.raises(ConfigurationException, match=blocked_key):
            _sanitize_options({blocked_key: False}, None, None)

    @pytest.mark.parametrize(
        "blocked_key",
        ["verify_signature", "verify_exp", "verify_nbf", "verify_iat"],
    )
    def test_blocked_option_true_allowed(self, blocked_key):
        """Setting enforced options to True is redundant but safe."""
        result = _sanitize_options({blocked_key: True}, None, None)
        assert result is not None
        assert result[blocked_key] is True

    def test_mixed_safe_and_blocked_raises(self):
        with pytest.raises(ConfigurationException, match="verify_signature"):
            _sanitize_options(
                {"require": ["sub"], "verify_signature": False}, None, None
            )

    @pytest.mark.parametrize(
        ("option", "audience", "issuer", "expected_message"),
        [
            (
                "verify_aud",
                "test-aud",
                None,
                "Security option 'verify_aud' cannot be disabled "
                "while an audience is configured.",
            ),
            (
                "verify_iss",
                None,
                "test-iss",
                "Security option 'verify_iss' cannot be disabled "
                "while an issuer is configured.",
            ),
            (
                "verify_aud",
                "",
                None,
                "Security option 'verify_aud' cannot be disabled "
                "while an audience is configured.",
            ),
            (
                "verify_iss",
                None,
                ["test-iss", "other-iss"],
                "Security option 'verify_iss' cannot be disabled "
                "while an issuer is configured.",
            ),
        ],
    )
    def test_configured_check_cannot_be_disabled(
        self, option, audience, issuer, expected_message
    ):
        with pytest.raises(ConfigurationException) as exc_info:
            _sanitize_options({option: False}, audience, issuer)
        assert exc_info.value.message == expected_message

    @pytest.mark.parametrize("option", ["verify_aud", "verify_iss"])
    def test_unconfigured_check_may_be_disabled(self, option):
        """With nothing configured there is no pinned value to override."""
        assert _sanitize_options({option: False}, None, None) == {option: False}

    @pytest.mark.parametrize("required", [None, "exp", ["exp", 1]])
    def test_malformed_require_raises(self, required):
        with pytest.raises(ConfigurationException) as exc_info:
            _sanitize_options({"require": required}, None, None)
        assert (
            exc_info.value.message == "Option 'require' must be a list of claim names."
        )


class TestDecodeRejectsBlockedOptions:
    """Integration tests — blocked options are rejected through the full path."""

    def test_verify_signature_false_rejected(self, rsa_key_pair):
        """Passing verify_signature=False must raise, not silently skip verification."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        with pytest.raises(ConfigurationException, match="verify_signature"):
            decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                audience="test-aud",
                issuer="test-iss",
                options={"verify_signature": False},
            )

    def test_verify_exp_false_rejected(self, rsa_key_pair):
        """Passing verify_exp=False must raise."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        with pytest.raises(ConfigurationException, match="verify_exp"):
            decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                audience="test-aud",
                issuer="test-iss",
                options={"verify_exp": False},
            )

    @pytest.mark.parametrize(
        ("option", "configured", "claims", "expected_message"),
        [
            (
                "verify_aud",
                {"audience": "test-aud", "issuer": None},
                {"aud": "other-aud"},
                "Security option 'verify_aud' cannot be disabled "
                "while an audience is configured.",
            ),
            (
                "verify_iss",
                {"audience": None, "issuer": "test-iss"},
                {"iss": "https://evil.example"},
                "Security option 'verify_iss' cannot be disabled "
                "while an issuer is configured.",
            ),
        ],
    )
    def test_disabling_configured_check_rejected(
        self, rsa_key_pair, option, configured, claims, expected_message
    ):
        """A token that fails the configured check is never accepted."""
        pem, key_dict = rsa_key_pair
        now = int(time.time())
        payload = {
            "sub": "test-user",
            "aud": "test-aud",
            "iss": "test-iss",
            "iat": now,
            "exp": now + 3600,
            **claims,
        }
        token = pyjwt.encode(
            payload, pem, algorithm="RS256", headers={"kid": "test-key-1"}
        )

        with pytest.raises(ConfigurationException) as exc_info:
            decode_and_validate_jwt(
                jwt=token,
                key=key_dict,
                algorithms=["RS256"],
                options={option: False},
                **configured,
            )
        assert exc_info.value.message == expected_message

    def test_valid_options_still_work(self, rsa_key_pair):
        """Legitimate options like require still function."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        result = decode_and_validate_jwt(
            jwt=token,
            key=key_dict,
            algorithms=["RS256"],
            audience="test-aud",
            issuer="test-iss",
            options={"require": ["sub", "exp"]},
        )
        assert result["sub"] == "test-user"

    def test_no_options_works(self, rsa_key_pair):
        """Normal flow with no options continues to work."""
        pem, key_dict = rsa_key_pair
        token = _make_token(pem)

        result = decode_and_validate_jwt(
            jwt=token,
            key=key_dict,
            algorithms=["RS256"],
            audience="test-aud",
            issuer="test-iss",
            options=None,
        )
        assert result["sub"] == "test-user"
