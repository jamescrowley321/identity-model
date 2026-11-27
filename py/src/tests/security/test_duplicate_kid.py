"""Adversarial duplicate-``kid`` handling test (R.11 / SC6).

``find_key_by_kid`` (``core/parsers.py``) returns ``filtered_keys[0]`` — the
FIRST key whose ``kid`` matches — so a JWKS containing two keys that share a
``kid`` silently ignores every key after the first. If an OP publishes (or an
attacker injects) a decoy key ahead of the real signer under the same ``kid``,
a legitimately-signed token fails to validate because only the decoy is tried.
The R.11 control requires try-all-matching-keys semantics.

``test_token_signed_by_second_duplicate_kid_key_validates`` XFAILs until
try-all lands. ``test_token_signed_by_neither_key_is_rejected`` is a passing
control: a token signed by no advertised key must always be rejected (holds
before and after the fix).
"""

import httpx
import pytest
import respx

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ._security_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit

ISSUER = "https://example.com"
DISCO_URL = f"{ISSUER}/.well-known/openid-configuration"
DUP_KID = "dup-kid"

_DISCO_DOC = {
    "issuer": ISSUER,
    "jwks_uri": f"{ISSUER}/jwks",
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _mock_disco_and_jwks(keys: list[dict]) -> None:
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=_DISCO_DOC))
    respx.get(f"{ISSUER}/jwks").mock(
        return_value=httpx.Response(200, json={"keys": keys})
    )


@pytest.mark.xfail(
    strict=True,
    reason="R.11/SC6: find_key_by_kid returns first-match only; a token signed by "
    "the second key under a colliding kid is not tried",
)
@respx.mock
def test_token_signed_by_second_duplicate_kid_key_validates() -> None:
    decoy_key, _ = generate_rsa_keypair()
    real_key, real_pem = generate_rsa_keypair()
    decoy_key["kid"] = DUP_KID
    real_key["kid"] = DUP_KID

    token = sign_jwt(
        real_pem,
        {"sub": "user", "iss": ISSUER},
        headers={"kid": DUP_KID},
    )
    # Decoy first, real signer second — both under the same kid.
    _mock_disco_and_jwks([decoy_key, real_key])

    config = TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)
    decoded = validate_token(
        jwt=token,
        token_validation_config=config,
        issuer=ISSUER,
    )
    assert decoded["sub"] == "user"


@respx.mock
def test_token_signed_by_neither_key_is_rejected() -> None:
    decoy_key, _ = generate_rsa_keypair()
    other_key, _ = generate_rsa_keypair()
    decoy_key["kid"] = DUP_KID
    other_key["kid"] = DUP_KID

    # Signed by a THIRD key that is not published at all.
    _, foreign_pem = generate_rsa_keypair()
    token = sign_jwt(
        foreign_pem,
        {"sub": "user", "iss": ISSUER},
        headers={"kid": DUP_KID},
    )
    _mock_disco_and_jwks([decoy_key, other_key])

    config = TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)
    with pytest.raises(TokenValidationException):
        validate_token(
            jwt=token,
            token_validation_config=config,
            issuer=ISSUER,
        )
