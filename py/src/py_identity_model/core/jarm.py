"""
JWT-Secured Authorization Response Mode (JARM) — protocol-agnostic logic.

JARM returns the OAuth 2.0 / OpenID Connect authorization response as a signed
(optionally encrypted) JWT carried in a single ``response`` parameter, instead
of individual query/fragment parameters.  The relying party extracts the JWT,
verifies its signature against the authorization server's JWKS, validates the
mandatory ``iss``/``aud``/``exp`` claims, and then reads ``code``/``state``/…
from the JWT claims.

Binding the response into a signed JWT lets the RP detect tampering and — via
the ``iss`` claim — defends against mix-up attacks (RFC 9207) at the
authorization-response stage rather than only at the token endpoint.

**Scope:** this module implements *signed* JARM (JWS, JARM §4.1).  Encrypted
JARM (JWE, JARM §4.2) is not yet supported; an encrypted ``response`` value is
rejected by the shared JWT decoder rather than silently accepted.

Reference: "Financial-grade API: JWT Secured Authorization Response Mode for
OAuth 2.0 (JARM)".
"""

from typing import Any
from urllib.parse import parse_qs, urlparse

from jwt import PyJWTError

from ..exceptions import JarmValidationException
from ..oidc_constants import AuthorizeResponse as AuthorizeResponseParams
from .authorize_response import (
    _PARAM_TO_FIELD,
    AuthorizeCallbackResponse,
    _map_params_to_fields,
)
from .jwt_helpers import decode_and_validate_jwt
from .jwt_signing import DEFAULT_ALLOWED_ALGORITHMS
from .parsers import extract_jwt_header_fields


# The single authorization-response parameter that carries the JARM JWT.
JARM_RESPONSE_PARAM = "response"

# Recognized authorization-response claim names, derived from the shared
# parameter→field mapping so ``values`` stays in lockstep with the parser.
_PARAM_TO_FIELD_KEYS = frozenset(_PARAM_TO_FIELD.keys())

# Claims that JARM §4.1 mandates in the response JWT.  ``exp`` in particular is
# checked explicitly here: PyJWT verifies ``exp`` when present but does not
# require its presence, so an omitted ``exp`` would otherwise pass.
_JARM_REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "aud", "exp")

_ERROR_CLAIM = AuthorizeResponseParams.ERROR.value


def _extract_response_param(params_str: str) -> str | None:
    """Return the sole ``response`` value from a query/fragment string, or None.

    Rejects duplicate ``response`` parameters: parameter pollution such as
    ``?response=<good>&response=<forged>`` is a security-sensitive ambiguity and
    is refused rather than resolved by position.

    Raises:
        JarmValidationException: If more than one ``response`` parameter is present.
    """
    parsed = parse_qs(params_str, keep_blank_values=True)
    values = parsed.get(JARM_RESPONSE_PARAM)
    if not values:
        return None
    if len(values) > 1:
        raise JarmValidationException(
            "callback carries multiple 'response' parameters; refusing to resolve "
            "JARM parameter pollution by position"
        )
    return values[0]


def is_jarm_response(redirect_uri: str) -> bool:
    """Return ``True`` when *redirect_uri* carries a JARM ``response`` parameter.

    Checks the URL fragment first, then the query string (mirroring the
    fragment-takes-precedence rule of the plain authorization-response parser).

    Args:
        redirect_uri: The callback URL received from the authorization server.

    Returns:
        ``True`` if a non-empty ``response`` parameter is present.
    """
    if not isinstance(redirect_uri, str) or not redirect_uri.strip():
        return False

    parsed = urlparse(redirect_uri)
    for params_str in (parsed.fragment, parsed.query):
        if not params_str:
            continue
        try:
            if _extract_response_param(params_str):
                return True
        except JarmValidationException:
            # Duplicate 'response' params: still a (malformed) JARM response —
            # detection reports it so extraction can fail closed downstream.
            return True
    return False


def extract_jarm_response_jwt(redirect_uri: str) -> str:
    """Extract the JARM response JWT from a callback URL.

    The ``response`` value is read from the URL fragment when present,
    otherwise from the query string — matching where the authorization
    server places JARM parameters for ``fragment.jwt`` vs ``query.jwt``.

    Args:
        redirect_uri: The callback URL received from the authorization server.

    Returns:
        The raw (compact-serialization) response JWT.

    Raises:
        JarmValidationException: If *redirect_uri* is not a usable string or
            carries no ``response`` parameter.
    """
    if not isinstance(redirect_uri, str) or not redirect_uri.strip():
        raise JarmValidationException("redirect_uri must be a non-empty string")

    parsed = urlparse(redirect_uri)
    # Fragment precedence, matching parse_authorize_callback_response.
    for params_str in (parsed.fragment, parsed.query):
        if params_str:
            response_jwt = _extract_response_param(params_str)
            if response_jwt:
                return response_jwt

    raise JarmValidationException("redirect_uri contains no JARM 'response' parameter")


def advertised_jarm_algorithms(advertised: list[str] | None) -> list[str] | None:
    """Return the AS-advertised JARM algorithms that are in the verify default.

    ``None`` (not advertised) stays ``None``, which
    :func:`select_jarm_algorithm` reads as ``DEFAULT_ALLOWED_ALGORITHMS``.
    """
    if advertised is None:
        return None
    return [
        alg
        for alg in advertised
        if isinstance(alg, str) and alg in DEFAULT_ALLOWED_ALGORITHMS
    ]


def select_jarm_algorithm(
    header_alg: str | None,
    allowed_algs: list[str] | None,
) -> str:
    """Select and validate the JARM signing algorithm (default-deny).

    A forged or downgraded signature is the primary JARM threat, so the
    algorithm from the JWT header is accepted only if it clears every check:

    1. It is a non-empty string.
    2. It is not ``none`` (an unsigned response is never acceptable).
    3. It is not a symmetric MAC (``HS*``) — JARM signatures are asymmetric so
       the RP verifies with the AS public key it already trusts; accepting an
       ``HS*`` alg would let an attacker sign with a shared/guessable secret.
    4. It appears in *allowed_algs*, or in ``DEFAULT_ALLOWED_ALGORITHMS``
       when *allowed_algs* is ``None``.

    Args:
        header_alg: The ``alg`` value from the response JWT header.
        allowed_algs: Allowed algorithms: the caller's list, or those the
            authorization server advertises in
            ``authorization_signing_alg_values_supported``. ``None`` means
            ``DEFAULT_ALLOWED_ALGORITHMS``; an empty list allows nothing.

    Returns:
        The validated algorithm to use for signature verification.

    Raises:
        JarmValidationException: If any check fails.
    """
    if not header_alg or not isinstance(header_alg, str):
        raise JarmValidationException("JARM response JWT header has no 'alg' value")

    alg = header_alg.strip()

    if alg.lower() == "none":
        raise JarmValidationException(
            "JARM response JWT uses 'alg=none'; an unsigned response is not permitted"
        )

    if alg.upper().startswith("HS"):
        raise JarmValidationException(
            f"JARM response JWT uses symmetric algorithm '{alg}'; only asymmetric "
            "signatures are permitted"
        )

    if allowed_algs is None:
        allowed_algs = sorted(DEFAULT_ALLOWED_ALGORITHMS)

    if not allowed_algs:
        raise JarmValidationException("No allowed JARM signing algorithms configured")

    if alg not in allowed_algs:
        raise JarmValidationException(
            f"JARM response JWT algorithm '{alg}' is not in the allowed set "
            f"{sorted(allowed_algs)}"
        )

    return alg


def extract_jarm_header(response_jwt: str) -> tuple[str | None, str | None]:
    """Return ``(kid, alg)`` from the unverified JARM response JWT header.

    Raises:
        JarmValidationException: If *response_jwt* is not a well-formed JWT.  The
            ``response`` value arrives from an untrusted redirect, so a non-JWT
            payload must surface as the contracted JARM error rather than a raw
            PyJWT ``DecodeError``.
    """
    try:
        return extract_jwt_header_fields(response_jwt)
    except PyJWTError as exc:
        raise JarmValidationException(
            "JARM 'response' value is not a well-formed JWT"
        ) from exc


def decode_jarm_claims(  # noqa: PLR0913  # JARM §4.1 validation requires these params
    response_jwt: str,
    key: dict,
    algorithms: list[str],
    issuer: str | None,
    audience: str | None,
    leeway: float = 0,
) -> dict:
    """Verify and decode a JARM response JWT into its claims.

    Wraps :func:`decode_and_validate_jwt`, which verifies the signature and the
    ``iss``/``aud``/``exp`` claims (raising the appropriate
    ``TokenValidationException`` subclass on mismatch), then additionally
    enforces that JARM's mandatory ``iss``/``aud``/``exp`` claims are *present*
    (JARM §4.1) — the underlying decoder verifies them when present but does
    not require ``exp``.

    Args:
        response_jwt: The raw response JWT.
        key: The verification key as a JWK dict.
        algorithms: The single validated algorithm to allow (default-deny).
        issuer: The expected issuer (the AS ``issuer`` — JARM's mix-up
            defense binds ``iss`` inside the JWT).
        audience: The expected audience (the RP ``client_id``).
        leeway: Clock-skew tolerance in seconds for ``exp``.

    Returns:
        The decoded JWT claims.

    Raises:
        JarmValidationException: If a mandatory JARM claim is absent.
        TokenValidationException: (subclasses) on signature/iss/aud/exp failure.
    """
    claims = decode_and_validate_jwt(
        response_jwt,
        key,
        algorithms,
        audience=audience,
        issuer=issuer,
        options=None,
        leeway=leeway,
    )

    missing = [claim for claim in _JARM_REQUIRED_CLAIMS if claim not in claims]
    if missing:
        raise JarmValidationException(
            f"JARM response JWT is missing mandatory claim(s): {', '.join(missing)}"
        )

    return claims


def build_authorize_response_from_claims(
    claims: dict[str, Any],
    raw: str,
) -> AuthorizeCallbackResponse:
    """Build an ``AuthorizeCallbackResponse`` from verified JARM claims.

    Reuses the shared parameter→field mapping so the resulting object is
    indistinguishable from one produced by the plain query/fragment parser,
    letting callers feed it into the existing
    ``validate_authorize_callback_state`` / ``validate_authorize_callback_issuer``
    helpers.

    Args:
        claims: The verified JARM response claims.
        raw: The raw response JWT (stored as ``raw`` for traceability).

    Returns:
        A parsed ``AuthorizeCallbackResponse``.  ``is_successful`` is ``False``
        when the claims carry an ``error``.

    Raises:
        JarmValidationException: If the claims carry no recognized
            authorization-response parameter.
    """
    field_values = _map_params_to_fields(claims)
    if not field_values:
        raise JarmValidationException(
            "JARM response JWT contains no recognized authorization-response claims"
        )

    # ``values`` mirrors the plain parser's string-valued view of the response.
    values: dict[str, str] = {
        param: str(claims[param])
        for param in _PARAM_TO_FIELD_KEYS
        if param in claims and claims[param] is not None
    }

    # ``_ERROR_CLAIM`` is a raw *parameter* name, so test it against ``values``
    # (keyed by parameter name) rather than ``field_values`` (keyed by dataclass
    # field name) — the two only coincide because ``error`` maps 1:1.
    has_error = _ERROR_CLAIM in values

    return AuthorizeCallbackResponse(
        is_successful=not has_error,
        raw=raw,
        values=values,
        **field_values,
    )


__all__ = [
    "JARM_RESPONSE_PARAM",
    "advertised_jarm_algorithms",
    "build_authorize_response_from_claims",
    "decode_jarm_claims",
    "extract_jarm_header",
    "extract_jarm_response_jwt",
    "is_jarm_response",
    "select_jarm_algorithm",
]
