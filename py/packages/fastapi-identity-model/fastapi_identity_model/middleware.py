"""
FastAPI middleware for OAuth2/OIDC token validation.

This module provides middleware components for validating Bearer tokens
in FastAPI applications using py-identity-model.

Scope: this middleware validates **HTTP** requests only. It extends Starlette's
``BaseHTTPMiddleware``, which forwards every non-HTTP ASGI scope (WebSocket,
lifespan) straight to the app without calling ``dispatch`` — so WebSocket
handshakes are **not** authenticated here (issue #598). Guard WebSocket routes
with :func:`fastapi_identity_model.build_ws_authenticator` instead.
"""

from collections.abc import Callable
import logging

from fastapi import Request, status  # type: ignore[attr-defined]
from jwt import InvalidTokenError
from starlette.middleware.base import (
    BaseHTTPMiddleware,  # type: ignore[attr-defined]
)
from starlette.responses import (  # type: ignore[attr-defined]
    JSONResponse,
    Response,
)

from py_identity_model import (
    NetworkException,
    PyIdentityModelException,
    TokenValidationConfig,
    to_principal,
)
from py_identity_model.aio import validate_token


logger = logging.getLogger("fastapi_identity_model")

# Expected number of parts in "Bearer <token>" authorization header
_BEARER_HEADER_PART_COUNT = 2

# Claims that only ever appear in an ID token (OIDC Core 1.0 §2, §3.1.3.6).
# Their presence means an ID token was presented where an access token is
# expected — reject it to prevent token-substitution at the resource server.
_ID_TOKEN_ONLY_CLAIMS = ("nonce", "at_hash", "c_hash")

# Positive access-token marker claims for the opt-in ID-token-substitution
# defence (F-07). The negative ``_ID_TOKEN_ONLY_CLAIMS`` check misses a
# code-flow ID token that carries NONE of nonce/at_hash/c_hash (all optional in
# the auth-code flow) — such a token has ``aud == client_id`` and passes
# validation, so it authenticates as a bearer access token. Requiring a
# *positive* access-token signal closes that gap. ``scope`` is the discriminator
# that holds across the surveyed OPs (Descope, Keycloak, node-oidc): access
# tokens carry it, ID tokens never do (``scope`` is not an OIDC ID-token claim).
# ``scp`` is included so tokens that carry scopes under the Azure AD convention
# still count as access tokens. This is OPT-IN because some access tokens (e.g.
# a client_credentials token minted with no scopes) legitimately carry neither.
_DEFAULT_ACCESS_TOKEN_MARKER_CLAIMS = ("scope", "scp")

# F-18 (CWE-209): every token-validation failure returns this single generic 401
# body so the response cannot be used as an oracle to distinguish the rejection
# cause (invalid signature vs wrong audience vs expired). The specific cause is
# logged server-side for operators, never returned to the caller.
_GENERIC_401_DETAIL = "Invalid or unauthorized token"

# Stable message prefixes the core library uses for discovery/JWKS *fetch*
# failures (py_identity_model.core.error_handlers). The core wraps a failed
# fetch in an unsuccessful response, so validate_token surfaces it as a
# TokenValidationException — NOT a NetworkException — which would otherwise be
# reported as a 401 "invalid token" for what is really a transient provider
# outage. We match these prefixes to map such failures to 503 instead, so
# callers back off and 5xx monitoring fires. This is a pragmatic bridge: the
# clean fix is in py-identity-model (raise a NetworkException subtype from
# validate_disco_response / validate_jwks_response), after which the
# `except NetworkException` branch below handles it directly.
_UPSTREAM_FETCH_FAILURE_PREFIXES = (
    "Network error during discovery",
    "Network error during JWKS",
)


def _is_upstream_fetch_failure(exc: Exception) -> bool:
    """Whether a library exception is a transient upstream fetch failure."""
    message = str(exc)
    return any(message.startswith(p) for p in _UPSTREAM_FETCH_FAILURE_PREFIXES)


def evaluate_token_type(
    claims: dict,
    *,
    require_access_token_marker: bool,
    access_token_marker_claims: tuple[str, ...],
) -> str | None:
    """Reason string if *claims* are the wrong token type for a resource server
    (an ID token presented as an access token), else ``None``.

    Pure and transport-agnostic so the HTTP middleware and the WebSocket
    authenticator (:func:`fastapi_identity_model.build_ws_authenticator`) apply
    a byte-for-byte identical check — the F-07 defence must not diverge between
    the two entry points. See :meth:`TokenValidationMiddleware._wrong_token_type_error`
    for the semantics of the two complementary checks.
    """
    if any(c in claims for c in _ID_TOKEN_ONLY_CLAIMS):
        return "ID token cannot be used as an access token"
    if require_access_token_marker and not any(
        c in claims for c in access_token_marker_claims
    ):
        return (
            "Access token required; presented token lacks an access-token marker claim"
        )
    return None


class TokenValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating Bearer tokens on incoming requests.

    This middleware automatically validates JWT tokens from the Authorization header
    and attaches the validated claims to the request state.

    Args:
        app: The FastAPI application
        discovery_url: The OpenID Connect discovery document URL
        audience: Expected audience claim in the token. Required — a ``None``
            audience does not enforce ``aud`` for tokens that omit the claim,
            which on a shared multi-tenant issuer accepts tokens minted for
            other clients.
        excluded_paths: Paths that skip token validation. Matching is **exact**
            by default: ``/health`` excludes only ``/health``, never
            ``/health/db-dump`` (issue #600 — exact-match fails closed so a
            nested route under an excluded prefix is not silently exposed). To
            exclude a whole subtree, append ``/*`` to the entry: ``/docs/*``
            excludes ``/docs`` and every path beneath it. Pass ``[]`` to
            exclude nothing. When omitted, defaults to ``/docs``,
            ``/docs/oauth2-redirect`` (the Swagger OAuth2 redirect),
            ``/openapi.json``, ``/health``.
        custom_claims_validator: Optional custom function to validate additional claims
        require_access_token_marker: Opt-in ID-token-substitution defence
            (F-07), default ``False`` (behaviour unchanged). When ``True``, a
            validated token is additionally required to carry at least one
            *positive* access-token marker claim (``access_token_marker_claims``)
            or it is rejected 401 — stopping a code-flow ID token (which carries
            none of nonce/at_hash/c_hash and whose ``aud`` matches the client_id)
            from being replayed as a bearer access token. Leave ``False`` if any
            of your access tokens legitimately omit those claims (e.g. a
            client_credentials token minted with no scopes).
        access_token_marker_claims: Claims that mark a token as an access token
            for ``require_access_token_marker``. Defaults to ``("scope", "scp")``
            — ``scope`` is the cross-OP discriminator (access tokens carry it, ID
            tokens never do); ``scp`` covers the Azure AD convention. Override for
            an OP whose access tokens signal type differently. Ignored when
            ``require_access_token_marker`` is ``False``.
    """

    def __init__(  # noqa: PLR0913  # opt-in F-07 marker config adds two optional params
        self,
        app,
        discovery_url: str,
        audience: str | None = None,
        excluded_paths: list[str] | None = None,
        custom_claims_validator: Callable | None = None,
        require_access_token_marker: bool = False,
        access_token_marker_claims: tuple[
            str, ...
        ] = _DEFAULT_ACCESS_TOKEN_MARKER_CLAIMS,
    ):
        super().__init__(app)
        if not audience:
            raise ValueError(
                "TokenValidationMiddleware requires a non-empty 'audience'; a "
                "None/empty audience skips aud enforcement for aud-less tokens."
            )
        # An empty marker set with the check enabled would reject every token
        # (no claim can ever satisfy ``any(...)``); fail loudly at construction
        # rather than silently 401ing all traffic.
        if require_access_token_marker and not access_token_marker_claims:
            raise ValueError(
                "require_access_token_marker=True needs a non-empty "
                "access_token_marker_claims; an empty set rejects every token."
            )
        self.discovery_url = discovery_url
        self.audience = audience
        self.require_access_token_marker = require_access_token_marker
        self.access_token_marker_claims = access_token_marker_claims
        # ``is not None`` (not truthiness) so an explicit [] means "exclude
        # nothing" instead of silently re-enabling the defaults.
        self.excluded_paths = (
            excluded_paths
            if excluded_paths is not None
            else ["/docs", "/docs/oauth2-redirect", "/openapi.json", "/health"]
        )
        self.custom_claims_validator = custom_claims_validator

    def _is_excluded(self, path: str) -> bool:
        """Whether *path* is excluded from token validation.

        Matching is **exact** by default: an entry ``/health`` excludes only
        ``/health``, never ``/health/db-dump``. To exclude a whole subtree,
        append ``/*`` to the entry — ``/docs/*`` excludes ``/docs`` and every
        path beneath it. Exact-by-default fails closed: adding a nested route
        under an excluded prefix does not silently expose it (issue #600).

        A bare ``/*`` (root subtree) is ignored rather than excluding every
        path — disabling auth wholesale must be an explicit choice (don't add
        the middleware), never a one-character typo.

        Caution: subtree (``/*``) matching runs on the raw ASGI request path,
        not a normalized one. If you place a ``..``-resolving handler (e.g. a
        ``StaticFiles`` mount) under an excluded ``/*`` prefix, a request whose
        path *string* starts with that prefix but resolves elsewhere is treated
        as excluded. Keep ``/*`` exclusions off subtrees that normalize paths;
        the default (exact match) is immune.
        """
        for entry in self.excluded_paths:
            if entry.endswith("/*"):
                prefix = entry[:-2].rstrip("/")
                if prefix and (path == prefix or path.startswith(prefix + "/")):
                    return True
            elif path == entry:
                return True
        return False

    @staticmethod
    def _unauthorized(detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _extract_bearer_token(self, request: Request) -> str | JSONResponse:
        """Return the bearer token, or an error ``JSONResponse`` if absent/malformed."""
        authorization = request.headers.get("Authorization")
        if not authorization:
            return self._unauthorized("Missing Authorization header")
        parts = authorization.split()
        if len(parts) != _BEARER_HEADER_PART_COUNT or parts[0].lower() != "bearer":
            return self._unauthorized(
                "Invalid Authorization header format. Expected: Bearer <token>"
            )
        return parts[1]

    def _wrong_token_type_error(self, claims: dict) -> str | None:
        """A 401 detail if *claims* are the wrong token type for a resource
        server (an ID token presented as an access token), else ``None``.

        Two complementary checks:

        * Negative (always on): an ID-token-only claim
          (``nonce``/``at_hash``/``c_hash``) is present — those never appear on
          an access token. With ``audience`` defaulted to the client_id an ID
          token's ``aud`` matches, so the type must be discriminated on claims.
        * Positive (opt-in, ``require_access_token_marker``): a code-flow ID
          token carries none of the negative claims, so also require a positive
          access-token marker (``scope``/``scp`` by default). Off by default —
          behaviour unchanged unless explicitly enabled.
        """
        return evaluate_token_type(
            claims,
            require_access_token_marker=self.require_access_token_marker,
            access_token_marker_claims=self.access_token_marker_claims,
        )

    async def _authenticate(self, request: Request, token: str) -> JSONResponse | None:
        """Validate *token* and attach claims; return an error response or None."""
        try:
            claims = await validate_token(
                jwt=token,
                token_validation_config=TokenValidationConfig(
                    perform_disco=True,
                    audience=self.audience,
                    claims_validator=self.custom_claims_validator,
                ),
                disco_doc_address=self.discovery_url,
            )
            # Reject an ID token presented as an access token (token-type
            # confusion at the resource server).
            wrong_type = self._wrong_token_type_error(claims)
            if wrong_type is not None:
                return self._unauthorized(wrong_type)
            request.state.user = to_principal(claims)
            request.state.claims = claims
            request.state.token = token
            return None
        except PyIdentityModelException as e:
            # A provider outage is a transient server fault, not an auth
            # decision: surface 503 so callers retry instead of treating it as a
            # bad token. This covers both a real NetworkException (a
            # PyIdentityModelException subclass — the clean path if the core
            # raises one) and a discovery/JWKS fetch failure the core currently
            # surfaces as a TokenValidationException (_UPSTREAM_FETCH_FAILURE_
            # PREFIXES). Checked here rather than a separate `except
            # NetworkException` block so both share one 503 path.
            if isinstance(e, NetworkException) or _is_upstream_fetch_failure(e):
                logger.exception("Upstream fetch failure during token validation")
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "Authentication temporarily unavailable"},
                )
            # Uniform 401 body — do NOT echo the stage-specific cause
            # (signature/audience/expiry), which would form a CWE-209 oracle
            # (F-18). Log the real cause server-side for operators.
            logger.info("Token rejected during validation: %s", e)
            return self._unauthorized(_GENERIC_401_DETAIL)
        except InvalidTokenError as e:
            # A malformed/undecodable token (e.g. raw pyjwt DecodeError from
            # header parsing during key lookup) is a client error, not a 500 —
            # and returns the same generic body as any other rejection so the
            # response can't distinguish "malformed" from "invalid".
            logger.info("Malformed token rejected: %s", e)
            return self._unauthorized(_GENERIC_401_DETAIL)
        except Exception:
            # A genuinely unexpected (non-library) failure is a server fault,
            # not an auth decision. Surface a 500 without leaking internals.
            logger.exception("Unexpected error during token validation")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error during authentication"},
            )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and validate the token if required."""
        # CORS preflight carries no Authorization; excluded paths skip auth.
        if request.method == "OPTIONS" or self._is_excluded(request.url.path):
            return await call_next(request)

        token = self._extract_bearer_token(request)
        if isinstance(token, JSONResponse):
            return token

        auth_error = await self._authenticate(request, token)
        if auth_error is not None:
            return auth_error

        return await call_next(request)
