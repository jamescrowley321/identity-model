"""Configuration guards at the entry of ``decode_and_validate_jwt``.

A configured audience cannot be switched off through ``options``, and an empty
issuer list is refused with its documented message. Both are checked before
the token is read, so a placeholder token is enough.
"""

from __future__ import annotations

import pytest

from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.exceptions import ConfigurationException


_TOKEN = "eyJhbGciOiJSUzI1NiJ9.e30.c2ln"
_KEY = {"kty": "RSA"}


def test_configured_audience_cannot_be_disabled_through_options():
    with pytest.raises(ConfigurationException) as exc_info:
        decode_and_validate_jwt(
            _TOKEN,
            _KEY,
            ["RS256"],
            audience="api",
            issuer=None,
            options={"verify_aud": False},
        )

    exc = exc_info.value
    assert type(exc) is ConfigurationException
    assert exc.message == (
        "Security option 'verify_aud' cannot be disabled"
        " while an audience is configured."
    )


def test_empty_issuer_list_is_refused_with_its_message():
    with pytest.raises(ConfigurationException) as exc_info:
        decode_and_validate_jwt(
            _TOKEN,
            _KEY,
            ["RS256"],
            audience=None,
            issuer=[],
            options=None,
        )

    exc = exc_info.value
    assert type(exc) is ConfigurationException
    assert exc.message == (
        "issuer must not be an empty list; omit or set to None to skip issuer"
        " validation"
    )
