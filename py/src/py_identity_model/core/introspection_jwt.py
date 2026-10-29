"""
JWT responses for token introspection (RFC 9701).

When the client asks for ``application/token-introspection+jwt``, the
authorization server answers with a JWT whose ``token_introspection`` claim is
the RFC 7662 response. The client verifies it before reading it (RFC 9701 §5):
the media type, ``typ``, an allowed asymmetric ``alg``, the signature against
the authorization server's keys, ``iss``, ``aud`` (the client's ``client_id``)
and ``iat``.
"""

import httpx
from jwt import (
    ImmatureSignatureError,
    InvalidIssuedAtError,
    MissingRequiredClaimError,
    PyJWTError,
    get_unverified_header,
)

from ..exceptions import (
    InvalidAudienceException,
    InvalidIssuerException,
    TokenExpiredException,
    TokenValidationException,
)
from ..jwt_claim_types import JwtTypes
from .fapi import FAPI2_ALLOWED_SIGNING_ALGORITHMS
from .jwt_helpers import decode_and_validate_jwt
from .models import (
    IntrospectionErrorKind,
    SignedIntrospectionOptions,
    TokenIntrospectionResponse,
)
from .parsers import find_key_by_kid


INTROSPECTION_JWT_MEDIA_TYPE = f"application/{JwtTypes.IntrospectionJwtResponse.value}"

# RFC 9701 §5: the JWT carries these claims alongside token_introspection.
_REQUIRED_CLAIMS = ("iss", "aud", "iat")
_TOKEN_INTROSPECTION_CLAIM = "token_introspection"

_CLAIM_ERRORS = (
    InvalidAudienceException,
    InvalidIssuerException,
    TokenExpiredException,
)
# PyJWT claim failures that the shared decoder wraps in TokenValidationException.
_WRAPPED_CLAIM_ERRORS = (
    MissingRequiredClaimError,
    InvalidIssuedAtError,
    ImmatureSignatureError,
)


class _Refused(Exception):
    def __init__(self, kind: IntrospectionErrorKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


def _typ_matches(typ: object) -> bool:
    # RFC 7515 §4.1.9: the "application/" prefix may be omitted.
    return isinstance(typ, str) and typ.lower() in (
        JwtTypes.IntrospectionJwtResponse.value,
        INTROSPECTION_JWT_MEDIA_TYPE,
    )


def _signed_token(response: httpx.Response) -> tuple[str, dict]:
    """The response JWT and its unverified header."""
    media_type = response.headers.get("content-type", "").split(";")[0].strip()
    if media_type.lower() != INTROSPECTION_JWT_MEDIA_TYPE:
        raise _Refused(
            IntrospectionErrorKind.MALFORMED,
            f"content type is {media_type or 'missing'}, not "
            f"{INTROSPECTION_JWT_MEDIA_TYPE}",
        )
    token = response.text.strip()
    try:
        return token, get_unverified_header(token)
    except PyJWTError as exc:
        raise _Refused(IntrospectionErrorKind.MALFORMED, "body is not a JWT") from exc


def _algorithm(header: dict, options: SignedIntrospectionOptions) -> str:
    if not _typ_matches(header.get("typ")):
        raise _Refused(IntrospectionErrorKind.INVALID_TYPE, "wrong typ header")
    alg = header.get("alg")
    allowed = (
        FAPI2_ALLOWED_SIGNING_ALGORITHMS
        if options.algorithms is None
        else options.algorithms
    )
    if not isinstance(alg, str) or alg not in allowed:
        raise _Refused(
            IntrospectionErrorKind.UNSUPPORTED_ALGORITHM, f"alg {alg!r} not allowed"
        )
    return alg


def _verified_claims(
    token: str, header: dict, client_id: str, options: SignedIntrospectionOptions
) -> dict:
    alg = _algorithm(header, options)
    try:
        key, _ = find_key_by_kid(header.get("kid"), options.jwks.keys or [], alg)
        claims = decode_and_validate_jwt(
            token,
            key,
            [alg],
            audience=client_id,
            issuer=options.issuer,
            options=None,
        )
    except _CLAIM_ERRORS as exc:
        raise _Refused(IntrospectionErrorKind.CLAIM_VALIDATION, str(exc)) from exc
    except TokenValidationException as exc:
        kind = (
            IntrospectionErrorKind.CLAIM_VALIDATION
            if isinstance(exc.__cause__, _WRAPPED_CLAIM_ERRORS)
            else IntrospectionErrorKind.SIGNATURE
        )
        raise _Refused(kind, str(exc)) from exc
    missing = [claim for claim in _REQUIRED_CLAIMS if claim not in claims]
    if missing:
        raise _Refused(
            IntrospectionErrorKind.CLAIM_VALIDATION, f"missing {', '.join(missing)}"
        )
    return claims


def verify_signed_introspection_response(
    response: httpx.Response,
    client_id: str,
    options: SignedIntrospectionOptions,
) -> TokenIntrospectionResponse:
    """Verify a successful (2xx) JWT introspection response.

    Args:
        response: The introspection endpoint's 2xx response.
        client_id: The introspecting client, the JWT's expected ``aud``.
        options: Expected issuer, keys and algorithms.

    Returns:
        A successful response whose ``claims`` are the verified
        ``token_introspection`` object, or a failed one whose ``error_kind``
        says why it was refused.
    """
    try:
        token, header = _signed_token(response)
        claims = _verified_claims(token, header, client_id, options)
        introspection = claims.get(_TOKEN_INTROSPECTION_CLAIM)
        if not isinstance(introspection, dict) or not isinstance(
            introspection.get("active"), bool
        ):
            raise _Refused(
                IntrospectionErrorKind.MALFORMED,
                "token_introspection is not an object with a boolean active",
            )
    except _Refused as refused:
        return TokenIntrospectionResponse(
            is_successful=False,
            error=f"Signed introspection response refused: {refused} (RFC 9701 §5)",
            error_kind=refused.kind,
        )
    return TokenIntrospectionResponse(is_successful=True, claims=introspection)


__all__ = ["INTROSPECTION_JWT_MEDIA_TYPE", "verify_signed_introspection_response"]
