"""ID Token profile logic — OpenID Connect Core 1.0 §3.1.3.7 / §3.3.2.11.

Pure, protocol-agnostic logic shared by the synchronous and asynchronous
surfaces. Contains no I/O.

The standard JWT validation — signature (via JWKS), ``iss``, ``aud``, and the
``exp``/``iat``/``nbf`` values when present — is performed by the existing
``validate_token`` path; ``validate_id_token_claims`` enforces the additional
rules that make an ID Token an ID Token:

* ``exp`` and ``iat`` are REQUIRED (§2), so their absence is rejected.
* ``sub`` is REQUIRED (§2 / §3.1.3.7).
* Every ``aud`` value is the ``client_id`` or an audience the caller trusts
  (§3.1.3.7 step 3).
* ``azp`` authorized-party rules, only when the caller opts in with
  ``validate_azp`` (§3.1.3.7 steps 4-5; §2 says to ignore ``azp`` otherwise).
* ``nonce`` binding against the ``nonce`` the caller sent on the
  authorization request (§2, §3.1.3.7 step 11, §3.2.2.11 step 2). The caller
  always states it; ``None`` means none was sent, and a token carrying a
  ``nonce`` is then rejected. ``RefreshNonce(original)`` marks an ID Token
  from a refresh, whose ``nonce`` may be absent but, if present, must equal
  the original (§12.2).
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
import dataclasses
import hashlib
import hmac
import time
from typing import TYPE_CHECKING

from ..exceptions import (
    AzpRequiresClientIdError,
    ConfigurationException,
    IdTokenMissingClaimError,
    IdTokenRequiredClaim,
    IdTokenValidationException,
    UntrustedAudienceException,
)


if TYPE_CHECKING:
    from collections.abc import Iterable

    from .models import TokenValidationConfig


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


def find_untrusted_audiences(
    claims: dict, client_id: str | None, trusted_audiences: Iterable[str] | None
) -> list | None:
    """Return the ``aud`` values the client does not trust (§3.1.3.7 step 3).

    The trusted set is ``client_id`` plus ``trusted_audiences``. The list only
    adds trusted values; an empty or omitted list leaves ``client_id`` as the
    sole trusted audience, so nothing here can switch the check off. With no
    ``client_id`` and no list, every audience is untrusted (fail closed).

    Shared by ID Tokens and Logout Tokens (Back-Channel Logout 1.0 §2.6 step 4
    validates ``aud`` "in the same way" as for ID Tokens).

    Returns:
        ``None`` when ``aud`` is absent, ``null`` or holds only empty strings
        (the token names no audience); otherwise the untrusted values, empty
        when every audience is trusted.

    Raises:
        ConfigurationException: If ``trusted_audiences`` is a bare ``str`` or
            ``bytes``, which would otherwise iterate as single characters.
    """
    if isinstance(trusted_audiences, (str, bytes)):
        raise ConfigurationException(
            "trusted_audiences must be an iterable of audience strings, "
            "not a single string"
        )
    aud = claims.get("aud")
    if aud is None:
        audiences = []
    elif isinstance(aud, (list, tuple)):
        audiences = list(aud)
    else:
        audiences = [aud]
    if all(a == "" for a in audiences):
        return None
    trusted = set(trusted_audiences or ())
    if client_id:
        trusted.add(client_id)
    return [a for a in audiences if not isinstance(a, str) or a not in trusted]


def _reject_untrusted_audiences(
    claims: dict, client_id: str | None, trusted_audiences: Iterable[str] | None
) -> None:
    """Enforce §3.1.3.7 step 3 for an ID Token.

    ``aud`` is REQUIRED (§2): a token that names no audience is rejected first.

    Raises:
        IdTokenValidationException: If the token names no audience.
        UntrustedAudienceException: If an audience is not trusted.
        ConfigurationException: If ``trusted_audiences`` is a bare string.
    """
    untrusted = find_untrusted_audiences(claims, client_id, trusted_audiences)
    if untrusted is None:
        raise IdTokenValidationException(
            "ID token missing required 'aud' claim", token_part="payload"
        )
    if untrusted:
        raise UntrustedAudienceException(
            "ID token contains audience(s) not trusted by the client",
            untrusted_audiences=untrusted,
        )


def require_issuer_without_discovery(
    token_validation_config: TokenValidationConfig,
) -> None:
    """Reject a manual-mode config that pins no issuer.

    OIDC Core §3.1.3.7 step 2: the OP's Issuer Identifier MUST exactly match
    the ``iss`` claim. Back-Channel Logout 1.0 §2.6 step 4 applies the same
    rule to Logout Tokens. Discovery mode always pins the discovered issuer;
    with ``perform_disco=False`` the issuer must come from the config, or the
    check could not run.

    Raises:
        ConfigurationException: If ``perform_disco`` is ``False`` and
            ``issuer`` is ``None``, ``""`` or an empty list.
    """
    if not token_validation_config.perform_disco and not (
        token_validation_config.issuer
    ):
        raise ConfigurationException(
            "TokenValidationConfig.issuer is required when perform_disco is "
            "False: the OP issuer must match the token's 'iss' claim"
        )


def unset_empty_client_id(
    token_validation_config: TokenValidationConfig,
) -> TokenValidationConfig:
    """Return the config with an empty ``audience`` (``client_id``) unset.

    An empty ``client_id`` means none is configured, so ``audience=""`` is
    validated exactly like ``audience=None``.
    """
    if token_validation_config.audience == "":
        return dataclasses.replace(token_validation_config, audience=None)
    return token_validation_config


def check_azp_config(client_id: str | None, validate_azp: bool) -> None:
    """Reject ``validate_azp`` without a ``client_id`` (OIDC Core §3.1.3.7 step 5).

    Step 5 compares a present ``azp`` with the client's own ``client_id``. With
    none configured the comparison cannot run, and skipping it would leave the
    caller believing ``azp`` was checked. Depends on the caller's inputs only,
    so it runs before any claim (or, in the wrappers, any I/O) is touched.

    Raises:
        AzpRequiresClientIdError: If ``validate_azp`` is set and ``client_id``
            is ``None`` or empty.
    """
    if validate_azp and not client_id:
        raise AzpRequiresClientIdError


def _validate_azp(claims: dict, client_id: str) -> None:
    """Enforce the opt-in authorized-party (``azp``) rules.

    Neither rule is a MUST in OIDC Core 1.0 errata set 2, so the caller turns
    them on with ``validate_azp``. An empty-string ``azp`` counts as absent for
    the multiple-audience rule and is still compared against ``client_id``.
    """
    aud = claims.get("aud")
    azp = claims.get("azp")
    if isinstance(aud, (list, tuple)) and len(aud) > 1 and not azp:
        # Core 1.0 (2014) step 4 SHOULD: multiple audiences carry an ``azp``.
        raise IdTokenValidationException(
            "ID token with multiple audiences must contain an 'azp' claim",
            token_part="payload",
        )
    if azp is not None and azp != client_id:
        # Errata 2 step 5: a present ``azp`` identifies this client.
        raise IdTokenValidationException(
            "ID token 'azp' claim does not match the configured client_id",
            token_part="payload",
        )


# The value each §3.3.2.11 hash claim binds to: (input name, error wording).
_HASH_BINDINGS = {
    "at_hash": ("access_token", "the access token"),
    "c_hash": ("code", "the authorization code"),
}


def _validate_hash_binding(
    claims: dict,
    header_alg: str | None,
    claim: str,
    value: str,
    required: bool,
) -> None:
    """Check an ``at_hash``/``c_hash`` *claim* binds to *value* (§3.3.2.11).

    Presence is required only when *value* was issued in the same
    authorization response as the ID Token (*required*, §3.2.2.10 /
    §3.3.2.11); otherwise an absent claim is accepted. A present claim always
    has to match, whatever its type. Presence is checked before the hash is
    computed, so an absent, unrequired claim never consults ``alg``.
    """
    value_field, subject = _HASH_BINDINGS[claim]
    if claim not in claims:
        if required:
            raise IdTokenValidationException(
                f"ID token missing required '{claim}' claim for {subject} "
                "issued with it",
                token_part="payload",
            )
        return
    expected = _left_half_hash(value, header_alg, value_field)
    actual = claims[claim]
    if not isinstance(actual, str) or not _hashes_equal(actual, expected, f"'{claim}'"):
        raise IdTokenValidationException(
            f"ID token '{claim}' claim does not match {subject}",
            token_part="payload",
        )


@dataclasses.dataclass(frozen=True)
class RefreshNonce:
    """The expected ``nonce`` of an ID Token returned by a token refresh.

    OIDC Core §12.2: a refresh-issued ID Token SHOULD NOT have a ``nonce``
    claim, but if it is present its value MUST be the same as in the ID Token
    issued at the original authentication. Pass ``nonce=RefreshNonce(original)``
    to accept an absent ``nonce`` and require a present one to equal
    ``original``. Use ``nonce=None`` if the original authentication sent no
    nonce.

    Attributes:
        original: The ``nonce`` of the ID Token from the original
            authentication. Must be a non-empty string.

    Raises:
        ConfigurationException: If ``original`` is not a non-empty string.
    """

    original: str

    def __post_init__(self) -> None:
        if not isinstance(self.original, str) or not self.original:
            raise ConfigurationException(
                "RefreshNonce.original must be the non-empty nonce of the "
                "original ID Token"
            )


def _check_nonce(claims: dict, nonce: str | RefreshNonce | None) -> None:
    """Bind the token's ``nonce`` to the one sent (§2, §3.1.3.7 step 11, §12.2).

    ``None`` means no nonce was sent, so a token carrying one is rejected: §2
    requires a present ``nonce`` to equal the value sent. A sent nonce MUST be
    present in the token and equal it (compared in constant time). A
    :class:`RefreshNonce` allows an absent ``nonce``; a present one MUST equal
    the original (§12.2).
    """
    if nonce is None:
        if "nonce" in claims:
            raise IdTokenValidationException(
                "ID token carries a 'nonce' claim but no nonce was sent",
                token_part="payload",
            )
        return
    if isinstance(nonce, RefreshNonce):
        if "nonce" not in claims:
            return
        expected = nonce.original
    else:
        expected = nonce
    token_nonce = claims.get("nonce")
    if not isinstance(token_nonce, str) or not _hashes_equal(
        token_nonce, expected, "'nonce'"
    ):
        raise IdTokenValidationException(
            "ID token 'nonce' claim does not match the expected value",
            token_part="payload",
        )


def validate_id_token_claims(  # noqa: PLR0913  # OIDC §3.1.3.7/§3.3.2.11 knobs
    claims: dict,
    header_alg: str | None,
    *,
    client_id: str | None = None,
    trusted_audiences: Iterable[str] | None = None,
    validate_azp: bool = False,
    nonce: str | RefreshNonce | None,
    access_token: str | None = None,
    code: str | None = None,
    access_token_issued_with_id_token: bool = True,
    code_issued_with_id_token: bool = True,
    max_age: int | None = None,
    leeway: float = 0.0,
    now: float | None = None,
) -> None:
    """Validate the ID-Token-specific claim rules (OIDC Core §3.1.3.7 / §3.3.2.11).

    Assumes the JWT signature, ``iss``, ``aud`` and (when present) ``exp``,
    ``iat`` and ``nbf`` values have ALREADY been verified by the standard
    token-validation path, and that the caller's ``client_id`` has already been
    enforced as an ``aud`` member there. This function enforces the rules unique
    to ID Tokens, including the presence of ``exp`` and ``iat`` (§2); every
    violation raises :class:`IdTokenValidationException`.

    Args:
        claims: The decoded (and already signature/iss/aud/exp-validated) claim
            set.
        header_alg: The ``alg`` value from the ID Token's JOSE header, used to
            select the hash for ``at_hash``/``c_hash``.
        client_id: The relying party's ``client_id`` (i.e.
            ``TokenValidationConfig.audience``). It is the one audience trusted
            without being listed in ``trusted_audiences``, and the value a
            present ``azp`` must equal when ``validate_azp`` is set. ``None``
            and ``""`` both mean no ``client_id`` is configured.
        trusted_audiences: Additional audiences the client trusts besides
            ``client_id``. Every ``aud`` value MUST be ``client_id`` or one of
            these (§3.1.3.7 step 3). Omitted or empty means ``client_id`` is
            the only trusted audience; the list cannot disable the check.
        validate_azp: Opt in to the authorized-party rules. When ``True``, a
            token with multiple audiences must carry an ``azp`` and a present
            ``azp`` must equal ``client_id``. OIDC Core 1.0 errata set 2
            §3.1.3.7 step 5 makes the ``client_id`` comparison a MAY/SHOULD,
            and the multiple-audience rule is the Core 1.0 (2014) step-4
            SHOULD that errata set 2 removed. Requires ``client_id``. Defaults
            to ``False``: ``azp`` is ignored, as §2 advises relying parties
            that use no extensions.
        nonce: Required. The ``nonce`` sent on the authorization request:
            the token's ``nonce`` MUST be present and equal it (§3.1.3.7 step
            11). ``None`` when none was sent: a token carrying a ``nonce`` is
            rejected, since §2 requires a present ``nonce`` to equal the value
            sent. :class:`RefreshNonce` for an ID Token from a refresh: an
            absent ``nonce`` is accepted and a present one MUST equal the
            original (§12.2).
        access_token: When provided, the token's ``at_hash`` MUST match the
            left-half hash of this access token (§3.3.2.11). It MUST also be
            present unless ``access_token_issued_with_id_token`` is ``False``.
        code: When provided, the token's ``c_hash`` MUST match the left-half
            hash of this authorization code (§3.3.2.11). It MUST also be
            present unless ``code_issued_with_id_token`` is ``False``.
        access_token_issued_with_id_token: Whether ``access_token`` came back
            in the same authorization response as the ID Token
            (``response_type`` ``id_token token`` or ``code id_token token``),
            which makes ``at_hash`` REQUIRED (§3.2.2.10, §3.3.2.11). Defaults
            to ``True``. Pass ``False`` for a token-endpoint ID Token, which
            may omit ``at_hash`` (§3.1.3.6); a present one must still match.
            No effect without ``access_token``.
        code_issued_with_id_token: Whether ``code`` came back in the same
            authorization response as the ID Token (``response_type``
            ``code id_token`` or ``code id_token token``), which makes
            ``c_hash`` REQUIRED (§3.3.2.11). Defaults to ``True``. Pass
            ``False`` when it did not; a present ``c_hash`` must still match.
            No effect without ``code``.
        max_age: When provided, ``auth_time`` MUST be present and satisfy
            ``now - auth_time <= max_age + leeway`` (§3.1.3.7 step 12).
        leeway: Clock-skew tolerance (seconds) applied to the ``max_age`` check.
        now: Current POSIX time (seconds), injected for deterministic tests.
            Defaults to :func:`time.time` when omitted.

    Raises:
        AzpRequiresClientIdError: If ``validate_azp`` is set without a
            ``client_id``. Raised before any claim is read.
        ConfigurationException: If ``trusted_audiences`` is a bare ``str`` or
            ``bytes`` instead of an iterable of audiences.
        UntrustedAudienceException: If ``aud`` carries a value that is neither
            ``client_id`` nor in ``trusted_audiences`` (§3.1.3.7 step 3).
        IdTokenMissingClaimError: If ``exp`` or ``iat`` is absent (§2).
        IdTokenValidationException: If ``aud`` is absent, ``null`` or holds
            only empty strings (§2), or any other ID-Token profile rule is
            violated.
    """
    # §3.1.3.7 step 5 needs a client_id to compare ``azp`` with.
    check_azp_config(client_id, validate_azp)

    # §2 — ``exp`` and ``iat`` are REQUIRED. Standard JWT validation checks
    # their values only when present.
    for required in IdTokenRequiredClaim:
        if claims.get(required.value) is None:
            raise IdTokenMissingClaimError(required)

    # §2 / §3.1.3.7 — ``sub`` is REQUIRED and must be non-empty.
    if not claims.get("sub"):
        raise IdTokenValidationException(
            "ID token missing required 'sub' claim",
            token_part="payload",
        )

    # §3.1.3.7 step 3 — reject audiences the client does not trust.
    _reject_untrusted_audiences(claims, client_id, trusted_audiences)

    # §3.1.3.7 steps 4-5 — authorized-party (``azp``) rules, opt-in only.
    if validate_azp and client_id:
        _validate_azp(claims, client_id)

    _check_nonce(claims, nonce)

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
        _validate_hash_binding(
            claims,
            header_alg,
            "at_hash",
            access_token,
            required=access_token_issued_with_id_token,
        )

    # §3.3.2.11 — ``c_hash`` binding (only when an authorization code was passed).
    if code is not None:
        _validate_hash_binding(
            claims,
            header_alg,
            "c_hash",
            code,
            required=code_issued_with_id_token,
        )


__all__ = [
    "RefreshNonce",
    "check_azp_config",
    "find_untrusted_audiences",
    "require_issuer_without_discovery",
    "validate_id_token_claims",
]
