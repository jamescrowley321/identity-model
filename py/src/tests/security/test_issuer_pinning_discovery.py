"""Adversarial issuer-allowlist test for discovery mode (F-04).

``token_validation_logic.decode_with_config`` passes ``issuer=disco issuer if
issuer is not None else config.issuer`` — so in discovery mode the discovery
document's issuer UNCONDITIONALLY wins and a configured ``issuer`` pin is
silently discarded (a single-string pin does not even log the warning a list
gets). A deployer who pins ``issuer="https://expected"`` as an allowlist gets
no enforcement: a discovery document advertising a *different* issuer (whose
tokens are signed for that other issuer) validates anyway.

This test pins one issuer but serves a discovery document + token for a
different issuer, and asserts validation is rejected. It XFAILs until the
configured ``issuer`` is enforced as an allowlist intersected against the
discovery issuer.
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

# The deployer pins THIS issuer as an allowlist.
EXPECTED_ISSUER = "https://expected-tenant.example.com"
# ...but discovery + token are for THIS (different, attacker/wrong-tenant) one.
WRONG_ISSUER = "https://wrong-tenant.example.com"
DISCO_URL = f"{WRONG_ISSUER}/.well-known/openid-configuration"


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


@pytest.mark.xfail(
    strict=True,
    reason="F-04: configured issuer allowlist is silently discarded in discovery "
    "mode; the discovery-document issuer overrides the pin",
)
@respx.mock
def test_configured_issuer_pin_rejects_mismatched_discovery_issuer() -> None:
    key_dict, pem = generate_rsa_keypair()
    token = sign_jwt(
        pem,
        {"sub": "user", "iss": WRONG_ISSUER},
        headers={"kid": key_dict["kid"]},
    )
    disco = {
        "issuer": WRONG_ISSUER,
        "jwks_uri": f"{WRONG_ISSUER}/jwks",
        "authorization_endpoint": f"{WRONG_ISSUER}/authorize",
        "token_endpoint": f"{WRONG_ISSUER}/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=disco))
    respx.get(f"{WRONG_ISSUER}/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )

    config = TokenValidationConfig(
        perform_disco=True,
        audience=None,
        issuer=EXPECTED_ISSUER,
    )
    with pytest.raises(TokenValidationException):
        validate_token(
            jwt=token,
            token_validation_config=config,
            issuer=WRONG_ISSUER,
        )
