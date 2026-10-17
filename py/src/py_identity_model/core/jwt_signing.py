"""
Shared JWT signing algorithm support and validation.

Centralises the set of asymmetric signing algorithms accepted across the
library — JAR request objects (RFC 9101) and ``private_key_jwt`` client
assertions (RFC 7523) — so the supported list and its validation are defined
in exactly one place.
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

# Algorithms a token may be signed with when ``TokenValidationConfig.algorithms``
# is unset: the asymmetric set above, matching the Go (``defaultAllowedAlgorithms``)
# and Rust (``DEFAULT_ALLOWED_ALGORITHMS``) defaults. HMAC is excluded so a token
# can't be verified with a provider's public key used as a shared secret
# (RFC 8725 §2.1, §3.1), and ``none`` is never accepted.
DEFAULT_ALLOWED_ALGORITHMS = SUPPORTED_SIGNING_ALGORITHMS


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
