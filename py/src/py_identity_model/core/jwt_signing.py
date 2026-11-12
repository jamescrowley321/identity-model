"""
JWS algorithm allowlists: one per purpose.

* **Verify** — :data:`DEFAULT_ALLOWED_ALGORITHMS`: what an inbound JWS (access
  token, ID token, DPoP proof, signed introspection response, JARM response)
  may be signed with when the caller passes ``algorithms=None``.
* **Sign** — :data:`SUPPORTED_SIGNING_ALGORITHMS`: what the library signs
  outbound JWTs with (``private_key_jwt`` client assertions, JAR request
  objects).
* **FAPI 2.0** — ``FAPI2_ALLOWED_SIGNING_ALGORITHMS`` in :mod:`.fapi`: applied
  only when a FAPI 2.0 profile or validator passes it explicitly.

The verify set is spelled out separately so adding a signing algorithm never
widens what the library accepts.
"""

from __future__ import annotations


# Asymmetric signing algorithms supported for signed JWTs. Symmetric (HS*)
# and ``none`` are intentionally excluded: request objects and client
# assertions must be verifiable by the authorization server using a public
# key.
SUPPORTED_SIGNING_ALGORITHMS = frozenset(
    {
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
    }
)

# Algorithms an inbound JWS may be signed with when the caller passes
# ``algorithms=None``, in every mode. Matches Go ``defaultAllowedAlgorithms``;
# Rust's default omits ES512, which it cannot verify yet. HMAC is excluded so a
# token can't be verified with a provider's public key used as a shared secret
# (RFC 8725 §2.1, §3.1), and ``none`` is never accepted.
DEFAULT_ALLOWED_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)


def validate_signing_algorithm(algorithm: str, *, context: str = "signing") -> None:
    """Validate that *algorithm* is a supported asymmetric signing algorithm.

    Args:
        algorithm: The JWS ``alg`` value to validate.
        context: Short label naming the caller for the error message
            (e.g. ``"JAR"`` or ``"client assertion"``).

    Raises:
        ValueError: If *algorithm* is not in
            :data:`SUPPORTED_SIGNING_ALGORITHMS`.
    """
    if algorithm not in SUPPORTED_SIGNING_ALGORITHMS:
        msg = (
            f"Unsupported {context} algorithm: {algorithm}. "
            f"Supported: {sorted(SUPPORTED_SIGNING_ALGORITHMS)}"
        )
        raise ValueError(msg)


__all__ = [
    "DEFAULT_ALLOWED_ALGORITHMS",
    "SUPPORTED_SIGNING_ALGORITHMS",
    "validate_signing_algorithm",
]
