"""Adversarial authorized-party (azp) test (F-10).

``AuthorizedParty = "azp"`` is defined in ``jwt_claim_types`` but referenced
nowhere in the validation path, and ``TokenValidationConfig`` has no
authorized-party field. PyJWT's non-strict audience check accepts any
intersection, so a multi-audience token ``aud=[A, B]`` with ``azp=A`` is
accepted by relying party B even though OIDC Core 1.0 §3.1.3.7 step 5 says
the client SHOULD verify that a present ``azp`` is its own client_id (and
§2 says a present ``azp`` MUST contain the client ID of the party the token
was issued to).

Relying party B (validating with ``audience=B``) must reject a token whose
``azp`` names a different client A. This XFAILs until an ``azp`` check is
enforced for multi-audience tokens.
"""

import pytest

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_validation import validate_token

from ._security_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit

CLIENT_A = "client-a"
CLIENT_B = "client-b"


@pytest.mark.xfail(
    strict=True,
    reason="F-10: no azp validation; a multi-aud token authorized for client A "
    "is accepted by client B",
)
def test_multi_aud_token_with_foreign_azp_is_rejected() -> None:
    key_dict, pem = generate_rsa_keypair()
    # Token minted for client A (azp=A) but listing B in its audiences.
    token = sign_jwt(
        pem,
        {"sub": "user", "aud": [CLIENT_A, CLIENT_B], "azp": CLIENT_A},
    )
    # Relying party B validates as itself.
    config = TokenValidationConfig(
        perform_disco=False,
        key=key_dict,
        algorithms=["RS256"],
        audience=CLIENT_B,
    )
    with pytest.raises(TokenValidationException):
        validate_token(jwt=token, token_validation_config=config)
