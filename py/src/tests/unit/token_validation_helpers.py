"""Shared test helpers for sync and async token validation tests."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt


# Expected call counts for JWKS fetch assertions
JWKS_FETCH_AFTER_EXPIRY = 2
JWKS_FETCH_WITH_RETRY = 2

# Shared discovery fixture; the issuer must match the discovery URL
ISSUER = "https://example.com"
DISCO_URL = f"{ISSUER}/.well-known/openid-configuration"

# Shared discovery responses
DISCO_RESPONSE_NO_JWKS = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

DISCO_RESPONSE_WITH_JWKS = {
    **DISCO_RESPONSE_NO_JWKS,
    "jwks_uri": "https://example.com/jwks",
}


def generate_rsa_keypair() -> tuple[dict, bytes]:
    """Generate an RSA key pair and return (jwk_dict, pem_bytes)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    def _int_to_base64url(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    key_dict = {
        "kty": "RSA",
        "kid": "test-key-1",
        "n": _int_to_base64url(pub_numbers.n, 256),
        "e": _int_to_base64url(pub_numbers.e, 3),
        "alg": "RS256",
        "use": "sig",
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return key_dict, pem


def sign_jwt(pem: bytes, claims: dict, headers: dict | None = None) -> str:
    """Sign a JWT with the given private key."""
    return pyjwt.encode(claims, pem, algorithm="RS256", headers=headers)
