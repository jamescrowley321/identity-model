"""ID Token profile logic — OpenID Connect Core 1.0 §3.1.3.7 / §3.3.2.11.

Pure, protocol-agnostic logic shared by the synchronous and asynchronous
surfaces. Contains no I/O.

The standard JWT validation — signature (via JWKS), ``iss``, ``aud``, ``iat``
and ``exp`` — is performed by the existing ``validate_token`` path;
``validate_id_token_claims`` enforces only the additional rules that make an
ID Token an ID Token:

* ``sub`` is REQUIRED (§2 / §3.1.3.7).
* ``azp`` authorized-party rules when the token carries multiple audiences
  (§3.1.3.7 steps 4-6).
* ``nonce`` binding, when the caller supplies the ``nonce`` it sent on the
  authorization request (§3.1.3.7 step 11).
* ``auth_time`` freshness against ``max_age`` (§3.1.3.7 step 12).
* ``at_hash`` / ``c_hash`` token/code binding for the hybrid and
  authorization-code flows (§3.3.2.11).

This module positively validates the ID-Token profile. It deliberately does
**not** reject "access-token-looking" claim sets — the relying-party-side
ID-token-vs-access-token discrimination (F-07) belongs in the middleware
layer, not here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

from ..exceptions import IdTokenValidationException


# Signing algorithms whose ``at_hash``/``c_hash`` digest is fixed regardless of
# the numeric suffix convention (EdDSA family). Every other supported alg is
# resolved from its trailing SHA-2 size (``*256``/``*384``/``*512``).
_EDDSA_ALGS = frozenset({"EdDSA", "Ed25519"})


def _hash_for_alg(alg: str | None):
    """Resolve the SHA-2 hash constructor implied by an ID Token ``alg``.

    Per OpenID Connect Core 1.0 §3.3.2.11 the ``at_hash``/``c_hash`` digest
    uses the hash algorithm of the ``alg`` Header Parameter of the ID Token —
    e.g. ``RS256``/``ES256``/``PS256``/``HS256`` → SHA-256, ``*384`` →
    SHA-384, ``*512`` → SHA-512. ``EdDSA``/``Ed25519`` use SHA-512.

    Raises:
        IdTokenValidationException: If ``alg`` is missing or is not one this
            profile can map to a hash. Fails **closed** — an unknown ``alg``
            for a hash check is an error, never a silently skipped check.
    """
    if not alg:
        raise IdTokenValidationException(
            "ID token header 'alg' is required to validate at_hash/c_hash",
            token_part="header",
        )
    normalized = alg.strip()
    if normalized in _EDDSA_ALGS:
        # Assumes Ed25519 (SHA-512). Ed448 also carries ``alg:"EdDSA"`` but
        # hashes with SHAKE256; it is intentionally unsupported here and fails
        # closed on the resulting at_hash/c_hash mismatch.
        return hashlib.sha512
    if normalized.endswith("256"):
        return hashlib.sha256
    if normalized.endswith("384"):
        return hashlib.sha384
    if normalized.endswith("512"):
        return hashlib.sha512
    raise IdTokenValidationException(
        f"Unsupported ID token 'alg' {alg!r} for at_hash/c_hash validation",
        token_part="header",
    )


def _left_half_hash(value: str, alg: str | None, field: str) -> str:
    """Compute the OIDC left-half hash of *value* under the ID Token *alg*.

    Hashes the ASCII octets of *value* with the SHA-2 variant implied by
    *alg*, takes the left-most half of the digest (``digest_len // 2`` bytes),
    and base64url-encodes it **without** padding — the exact construction of
    ``at_hash``/``c_hash`` in OpenID Connect Core 1.0 §3.3.2.11.

    *field* names the caller-supplied input (e.g. ``"access_token"``) purely
    for the error message when *value* is not ASCII.

    Raises:
        IdTokenValidationException: If *alg* cannot be mapped to a hash, or if
            *value* contains non-ASCII characters. Non-ASCII is re-raised as
            this exception (rather than the bare ``UnicodeEncodeError`` from
            :meth:`str.encode`) so it fails **closed** under the idiomatic
            ``except TokenValidationException`` handler.
    """
    hasher = _hash_for_alg(alg)
    try:
        octets = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IdTokenValidationException(
            f"ID token {field} must be ASCII to compute its at_hash/c_hash",
            token_part="payload",
        ) from exc
    digest = hasher(octets).digest()
    left_half = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(left_half).rstrip(b"=").decode("ascii")


def _hashes_equal(actual: str, expected: str, field: str) -> bool:
    """Constant-time compare two ASCII strings for the ID-Token bindings.

    Wraps :func:`hmac.compare_digest` (used to keep the ``nonce``/``at_hash``/
    ``c_hash`` comparisons timing-safe) so that a non-ASCII ``str`` operand —
    which makes ``compare_digest`` raise a bare ``TypeError`` — is re-raised as
    a fail-**closed** :class:`IdTokenValidationException` under the idiomatic
    ``except TokenValidationException`` handler. The timing-safe comparison is
    unchanged for the normal ASCII path.

    Raises:
        IdTokenValidationException: If either operand is a ``str`` carrying
            non-ASCII characters.
    """
    try:
        return hmac.compare_digest(actual, expected)
    except TypeError as exc:
        raise IdTokenValidationException(
            f"ID token {field} comparison requires ASCII values",
            token_part="payload",
        ) from exc


def validate_id_token_claims(  # noqa: PLR0913  # OIDC §3.1.3.7/§3.3.2.11 knobs
    claims: dict,
    header_alg: str | None,
    *,
    client_id: str | None = None,
    nonce: str | None = None,
    access_token: str | None = None,
    code: str | None = None,
    max_age: int | None = None,
    leeway: float = 0.0,
    now: float | None = None,
) -> None:
    """Validate the ID-Token-specific claim rules (OIDC Core §3.1.3.7 / §3.3.2.11).

    Assumes the JWT signature, ``iss``, ``aud``, ``iat`` and (when present)
    ``exp`` have ALREADY been verified by the standard token-validation path,
    and that the caller's ``client_id`` has already been enforced as an
    ``aud`` member there. This function enforces only the rules unique to ID
    Tokens; every violation raises :class:`IdTokenValidationException`.

    Args:
        claims: The decoded (and already signature/iss/aud/exp-validated) claim
            set.
        header_alg: The ``alg`` value from the ID Token's JOSE header, used to
            select the hash for ``at_hash``/``c_hash``.
        client_id: The relying party's ``client_id`` (i.e.
            ``TokenValidationConfig.audience``). When set, an ``azp`` present in
            the token MUST equal it (§3.1.3.7 step 6).
        nonce: When provided, the token's ``nonce`` MUST be present and equal
            this value (§3.1.3.7 step 11).
        access_token: When provided, the token's ``at_hash`` MUST be present
            and match the left-half hash of this access token (§3.3.2.11).
        code: When provided, the token's ``c_hash`` MUST be present and match
            the left-half hash of this authorization code (§3.3.2.11).
        max_age: When provided, ``auth_time`` MUST be present and satisfy
            ``now - auth_time <= max_age + leeway`` (§3.1.3.7 step 12).
        leeway: Clock-skew tolerance (seconds) applied to the ``max_age`` check.
        now: Current POSIX time (seconds), injected for deterministic tests.
            Defaults to :func:`time.time` when omitted.

    Raises:
        IdTokenValidationException: If any ID-Token profile rule is violated.
    """
    # §2 / §3.1.3.7 — ``sub`` is REQUIRED and must be non-empty.
    if not claims.get("sub"):
        raise IdTokenValidationException(
            "ID token missing required 'sub' claim",
            token_part="payload",
        )

    # §3.1.3.7 steps 4-6 — authorized-party (``azp``) rules.
    aud = claims.get("aud")
    azp = claims.get("azp")
    if isinstance(aud, (list, tuple)) and len(aud) > 1 and not azp:
        # Step 4: with multiple audiences an ``azp`` claim MUST be present.
        raise IdTokenValidationException(
            "ID token with multiple audiences must contain an 'azp' claim",
            token_part="payload",
        )
    if azp is not None and client_id is not None and azp != client_id:
        # Step 6: when present, ``azp`` MUST identify this client.
        raise IdTokenValidationException(
            "ID token 'azp' claim does not match the configured client_id",
            token_part="payload",
        )

    # §3.1.3.7 step 11 — ``nonce`` binding (only when the caller passed one).
    if nonce is not None:
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not _hashes_equal(
            token_nonce, nonce, "'nonce'"
        ):
            raise IdTokenValidationException(
                "ID token 'nonce' claim does not match the expected value",
                token_part="payload",
            )

    # §3.1.3.7 step 12 — ``auth_time`` freshness (only when ``max_age`` passed).
    if max_age is not None:
        auth_time = claims.get("auth_time")
        # ``bool`` is a subclass of ``int`` — exclude it explicitly.
        if isinstance(auth_time, bool) or not isinstance(auth_time, (int, float)):
            raise IdTokenValidationException(
                "ID token missing required numeric 'auth_time' claim for max_age check",
                token_part="payload",
            )
        current = time.time() if now is None else now
        if current - auth_time > max_age + leeway:
            raise IdTokenValidationException(
                "ID token 'auth_time' is older than the permitted max_age",
                token_part="payload",
            )

    # §3.3.2.11 — ``at_hash`` binding (only when an access token was passed).
    if access_token is not None:
        expected_at_hash = _left_half_hash(access_token, header_alg, "access_token")
        token_at_hash = claims.get("at_hash")
        if not isinstance(token_at_hash, str) or not _hashes_equal(
            token_at_hash, expected_at_hash, "'at_hash'"
        ):
            raise IdTokenValidationException(
                "ID token 'at_hash' claim does not match the access token",
                token_part="payload",
            )

    # §3.3.2.11 — ``c_hash`` binding (only when an authorization code was passed).
    if code is not None:
        expected_c_hash = _left_half_hash(code, header_alg, "code")
        token_c_hash = claims.get("c_hash")
        if not isinstance(token_c_hash, str) or not _hashes_equal(
            token_c_hash, expected_c_hash, "'c_hash'"
        ):
            raise IdTokenValidationException(
                "ID token 'c_hash' claim does not match the authorization code",
                token_part="payload",
            )


__all__ = ["validate_id_token_claims"]
