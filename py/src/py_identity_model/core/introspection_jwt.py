"""
JWT responses for token introspection (RFC 9701).

When the client asks for ``application/token-introspection+jwt``, the
authorization server answers with a JWT whose ``token_introspection`` claim is
the RFC 7662 response. The client verifies it before reading it (RFC 9701 §5):
the media type, ``typ``, an allowed asymmetric ``alg``, the signature against
the authorization server's keys, ``iss``, ``aud`` (the client's ``client_id``)
and ``iat``.
"""

from collections.abc import Collection

import httpx
from jwt import (
    ImmatureSignatureError,
    InvalidIssuedAtError,
    MissingRequiredClaimError,
    PyJWTError,
    get_unverified_header,
)

from ..exceptions import (
    AmbiguousKeyException,
    ConfigurationException,
    InvalidAudienceException,
    InvalidIssuerException,
    KeyAlgorithmMismatchException,
    KeyNotFoundException,
    TokenExpiredException,
    TokenValidationException,
)
from ..jwt_claim_types import JwtTypes
from .jwt_helpers import decode_and_validate_jwt
from .jwt_signing import DEFAULT_ALLOWED_ALGORITHMS, advertised_verify_algorithms
from .models import (
    IntrospectionErrorKind,
    JsonWebKey,
    SignedIntrospectionOptions,
    TokenIntrospectionRequest,
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


class SignedIntrospectionRefused(Exception):
    """A signed introspection response failed a check (RFC 9701 §5)."""

    def __init__(self, kind: IntrospectionErrorKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


# Key-lookup failures: no key for the JWT, more than one, or one that can't
# verify its alg. Anything else (discovery or JWKS fetch failing) is not a
# refusal of the response.
KEY_LOOKUP_ERRORS = (
    KeyNotFoundException,
    AmbiguousKeyException,
    KeyAlgorithmMismatchException,
)


def _typ_matches(typ: object) -> bool:
    # RFC 7515 §4.1.9: the "application/" prefix may be omitted.
    return isinstance(typ, str) and typ.lower() in (
        JwtTypes.IntrospectionJwtResponse.value,
        INTROSPECTION_JWT_MEDIA_TYPE,
    )


def read_signed_introspection(response: httpx.Response) -> tuple[str, dict]:
    """The response JWT and its unverified header.

    Raises:
        SignedIntrospectionRefused: The response is not a JWT introspection
            response.
    """
    media_type = response.headers.get("content-type", "").split(";")[0].strip()
    if media_type.lower() != INTROSPECTION_JWT_MEDIA_TYPE:
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.MALFORMED,
            f"content type is {media_type or 'missing'}, not "
            f"{INTROSPECTION_JWT_MEDIA_TYPE}",
        )
    token = response.text.strip()
    try:
        return token, get_unverified_header(token)
    except PyJWTError as exc:
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.MALFORMED, "body is not a JWT"
        ) from exc


def allowed_introspection_algorithms(
    options: SignedIntrospectionOptions, advertised: object = None
) -> Collection[str]:
    """The algorithms a response may be signed with.

    *advertised* is the discovery document's
    ``introspection_signing_alg_values_supported``; manual mode passes nothing.
    """
    if options.algorithms is not None:
        return options.algorithms
    from_discovery = advertised_verify_algorithms(advertised)
    return DEFAULT_ALLOWED_ALGORITHMS if from_discovery is None else from_discovery


def check_signed_introspection_header(header: dict, allowed: Collection[str]) -> str:
    """Check ``typ`` and ``alg`` and return the ``alg``.

    Raises:
        SignedIntrospectionRefused: Wrong ``typ`` or an ``alg`` not in *allowed*.
    """
    if not _typ_matches(header.get("typ")):
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.INVALID_TYPE, "wrong typ header"
        )
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed:
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.UNSUPPORTED_ALGORITHM, f"alg {alg!r} not allowed"
        )
    return alg


def verified_introspection_response(
    token: str,
    key: dict | JsonWebKey,
    alg: str,
    request: TokenIntrospectionRequest,
    issuer: str | None,
) -> TokenIntrospectionResponse:
    """Verify the response JWT with *key* and return its introspection result.

    The JWT must be issued by *issuer* to ``request.client_id``, within
    ``request.signed_response.leeway``.

    Raises:
        SignedIntrospectionRefused: The signature, a claim or the
            ``token_introspection`` object is wrong.
    """
    if not issuer:
        # Without an expected issuer the iss check would be skipped.
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.CLAIM_VALIDATION, "no expected issuer"
        )
    options = request.signed_response
    try:
        claims = decode_and_validate_jwt(
            token,
            key,
            [alg],
            audience=request.client_id,
            issuer=issuer,
            options=None,
            leeway=None if options is None else options.leeway,
        )
    except _CLAIM_ERRORS as exc:
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.CLAIM_VALIDATION, str(exc)
        ) from exc
    except TokenValidationException as exc:
        kind = (
            IntrospectionErrorKind.CLAIM_VALIDATION
            if isinstance(exc.__cause__, _WRAPPED_CLAIM_ERRORS)
            else IntrospectionErrorKind.SIGNATURE
        )
        raise SignedIntrospectionRefused(kind, str(exc)) from exc
    missing = [claim for claim in _REQUIRED_CLAIMS if claim not in claims]
    if missing:
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.CLAIM_VALIDATION, f"missing {', '.join(missing)}"
        )
    introspection = claims.pop(_TOKEN_INTROSPECTION_CLAIM, None)
    if not isinstance(introspection, dict) or not isinstance(
        introspection.get("active"), bool
    ):
        raise SignedIntrospectionRefused(
            IntrospectionErrorKind.MALFORMED,
            "token_introspection is not an object with a boolean active",
        )
    return TokenIntrospectionResponse(
        is_successful=True, claims=introspection, jwt_claims=claims
    )


def refused_introspection_response(
    refused: SignedIntrospectionRefused,
) -> TokenIntrospectionResponse:
    """The failed response for a refused signed introspection response."""
    return TokenIntrospectionResponse(
        is_successful=False,
        error=f"Signed introspection response refused: {refused} (RFC 9701 §5)",
        error_kind=refused.kind,
    )


def verify_signed_introspection_response(
    response: httpx.Response,
    request: TokenIntrospectionRequest,
) -> TokenIntrospectionResponse:
    """Verify a successful (2xx) JWT introspection response with the fixed
    keys of manual-mode ``request.signed_response`` (``issuer`` and ``jwks``).

    Discovery mode (``discovery_address``) is handled by ``introspect_token``,
    which fetches the keys.

    Args:
        response: The introspection endpoint's 2xx response.
        request: The introspection request. ``client_id`` is the JWT's
            expected ``aud``; ``signed_response`` holds the expected issuer,
            keys and algorithms.

    Returns:
        A successful response whose ``claims`` are the verified
        ``token_introspection`` object, or a failed one whose ``error_kind``
        says why it was refused.
    """
    options = request.signed_response
    if options is None or options.issuer is None or options.jwks is None:
        raise ConfigurationException(
            "verify_signed_introspection_response needs signed_response "
            "with issuer and jwks"
        )
    try:
        token, header = read_signed_introspection(response)
        alg = check_signed_introspection_header(
            header, allowed_introspection_algorithms(options)
        )
        try:
            key, _ = find_key_by_kid(header.get("kid"), options.jwks.keys or [], alg)
        except KEY_LOOKUP_ERRORS as exc:
            raise SignedIntrospectionRefused(
                IntrospectionErrorKind.SIGNATURE, str(exc)
            ) from exc
        return verified_introspection_response(token, key, alg, request, options.issuer)
    except SignedIntrospectionRefused as refused:
        return refused_introspection_response(refused)


__all__ = [
    "INTROSPECTION_JWT_MEDIA_TYPE",
    "KEY_LOOKUP_ERRORS",
    "SignedIntrospectionRefused",
    "allowed_introspection_algorithms",
    "check_signed_introspection_header",
    "read_signed_introspection",
    "refused_introspection_response",
    "verified_introspection_response",
    "verify_signed_introspection_response",
]
