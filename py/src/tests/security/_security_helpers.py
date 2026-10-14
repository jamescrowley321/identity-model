"""Shared helpers for the adversarial security suite.

Re-exports the RSA keypair/signing helpers used across the unit suite and adds
attacker-shaped token builders (e.g. an ``alg=none`` token that PyJWT will not
mint via ``encode``).
"""

import base64
import json

from ..token_validation_helpers import generate_rsa_keypair, sign_jwt


__all__ = ["generate_rsa_keypair", "sign_jwt", "unsigned_none_alg_jwt"]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unsigned_none_alg_jwt(claims: dict) -> str:
    """Build an ``alg=none`` JWT with an empty signature.

    ``pyjwt.encode`` refuses to mint ``none`` tokens by default, so craft one
    directly: ``base64url(header).base64url(payload).`` with an empty third
    segment, exactly what an alg-confusion attacker sends.
    """
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    return f"{header}.{payload}."
