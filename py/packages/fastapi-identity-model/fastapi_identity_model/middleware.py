"""
FastAPI middleware for OAuth2/OIDC token validation.

This module provides middleware components for validating Bearer and DPoP
access tokens in FastAPI applications using py-identity-model.

Scope: this middleware validates **HTTP** requests only. It extends Starlette's
``BaseHTTPMiddleware``, which forwards every non-HTTP ASGI scope (WebSocket,
lifespan) straight to the app without calling ``dispatch`` — so WebSocket
handshakes are **not** authenticated here (issue #598). Guard WebSocket routes
with :func:`fastapi_identity_model.build_ws_authenticator` instead.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
import logging
from urllib.parse import urlsplit

from fastapi import Request, status  # type: ignore[attr-defined]
from jwt import InvalidTokenError
from starlette.datastructures import URL  # type: ignore[attr-defined]
from starlette.middleware.base import (
    BaseHTTPMiddleware,  # type: ignore[attr-defined]
)
from starlette.requests import HTTPConnection
from starlette.responses import (  # type: ignore[attr-defined]
    JSONResponse,
    Response,
)

from py_identity_model import (
    AuthorizationScheme,
    CertificateBindingError,
    DPoPErrorKind,
    DPoPReplayCacheError,
    DPoPValidationError,
    NetworkException,
    PyIdentityModelException,
    TokenBinding,
    TokenPresentation,
    TokenValidationConfig,
    to_principal,
)
from py_identity_model.aio import (
    AsyncHTTPClient,
    AsyncValidationCache,
    validate_token,
)

from .config import OIDCSettings
from .options import AuthOptions, resolve_auth_options


logger = logging.getLogger("fastapi_identity_model")

# Expected number of parts in "<scheme> <token>" authorization header
_AUTHORIZATION_HEADER_PART_COUNT = 2

# Authorization schemes accepted, keyed by their case-insensitive name
# (RFC 9110 §11.1): Bearer (RFC 6750 §2.1) and DPoP (RFC 9449 §7.1).
_SCHEMES = {scheme.value.lower(): scheme for scheme in AuthorizationScheme}

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


# RFC 6750 §3: a Bearer challenge MUST carry at least one auth-param; this
# realm is the one sent when nothing else would be.
DEFAULT_REALM = "api"


class BearerError(StrEnum):
    """The ``error`` auth-param of a challenge (RFC 6750 §3.1)."""

    INVALID_REQUEST = "invalid_request"
    """The ``Authorization`` header names a supported scheme but is malformed
    (sent with ``400``)."""
    INVALID_TOKEN = "invalid_token"
    """The access token is expired, revoked, malformed or otherwise invalid."""
    INSUFFICIENT_SCOPE = "insufficient_scope"
    """The token is valid but does not grant access to the resource (``403``)."""


@dataclass(frozen=True)
class AuthChallenge:
    """Builds the ``WWW-Authenticate`` header (RFC 6750 §3, RFC 9449 §7.1).

    The middleware stores the challenge for the current request on
    ``request.state.auth_challenge`` so the dependencies answer with the same
    scheme and parameters.
    """

    scheme: AuthorizationScheme = AuthorizationScheme.BEARER
    realm: str | None = None
    dpop_algs: tuple[str, ...] = ()

    def header(self, *, error: str | None = None, scope: str | None = None) -> str:
        """The header value, with *error* and *scope* auth-params when given.

        A ``DPoP`` challenge always carries ``algs``. A ``Bearer`` challenge
        that would have no auth-param carries ``realm`` (``DEFAULT_REALM``
        unless one is configured).
        """
        params = []
        if self.realm is not None:
            params.append(f'realm="{self.realm}"')
        if error is not None:
            params.append(f'error="{error}"')
        if scope is not None:
            params.append(f'scope="{scope}"')
        if self.scheme is AuthorizationScheme.DPOP:
            params.append(f'algs="{" ".join(self.dpop_algs)}"')
        if not params:
            params.append(f'realm="{DEFAULT_REALM}"')
        return f"{self.scheme.value} {', '.join(params)}"


def _is_upstream_fetch_failure(exc: Exception) -> bool:
    """Whether a library exception is a transient upstream fetch failure."""
    message = str(exc)
    return any(message.startswith(p) for p in _UPSTREAM_FETCH_FAILURE_PREFIXES)


def parse_authorization(header: str) -> tuple[AuthorizationScheme, str] | None:
    """The scheme and token of an ``Authorization`` header, or ``None`` when it
    is not ``Bearer <token>`` or ``DPoP <token>`` (case-insensitive scheme)."""
    parts = header.split()
    scheme = _SCHEMES.get(parts[0].lower()) if parts else None
    if len(parts) != _AUTHORIZATION_HEADER_PART_COUNT or scheme is None:
        return None
    return scheme, parts[1]


def request_uri(url: URL, scope: dict, expected_origin: str | None = None) -> str:
    """The request URI as the client sent it, for the DPoP ``htu`` check.

    Starlette builds ``url`` from the percent-decoded ASGI ``path``, so
    ``/files/a%20b`` reads as ``/files/a b`` and an encoded ``%3F`` or ``%23``
    turns into a query or fragment delimiter. The proof covers the path as
    sent (RFC 9449 §4.3), which is the ASGI ``raw_path``.

    With *expected_origin* (``scheme://host[:port]``) the scheme and authority
    are that origin rather than the request's ``Host`` header.
    """
    if expected_origin is not None:
        origin = urlsplit(expected_origin)
        url = url.replace(scheme=origin.scheme, netloc=origin.netloc)
    raw_path = scope.get("raw_path")
    if not raw_path:
        return str(url)
    return str(url.replace(path=raw_path.decode("latin-1")))


def presentation(
    connection: HTTPConnection,
    options: AuthOptions,
    *,
    scheme: AuthorizationScheme,
    method: str,
    url: URL | None = None,
) -> TokenPresentation:
    """The :class:`TokenPresentation` for *connection* under *options*.

    Shared by the HTTP middleware and the WebSocket authenticator. *url*
    overrides ``connection.url`` (the WebSocket handshake's ``http(s)`` form).
    """
    return TokenPresentation(
        scheme=scheme,
        method=method,
        url=request_uri(
            url if url is not None else connection.url,
            connection.scope,
            options.expected_origin,
        ),
        dpop_proof=connection.headers.get("DPoP"),
        client_certificate=(
            options.client_certificate(connection)
            if options.client_certificate
            else None
        ),
    )


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
        discovery_url: The OpenID Connect discovery document URL. Defaults to
            ``settings.discovery_url``; required without ``settings``.
        audience: Expected audience claim in the token. Defaults to
            ``settings.audience``. Required — a ``None``
            audience does not enforce ``aud`` for tokens that omit the claim,
            which on a shared multi-tenant issuer accepts tokens minted for
            other clients.
        excluded_paths: Paths that skip token validation. Matching is **exact**
            by default: ``/health`` excludes only ``/health``, never
            ``/health/db-dump`` (issue #600 — exact-match fails closed so a
            nested route under an excluded prefix is not silently exposed). To
            exclude a whole subtree, append ``/*`` to the entry: ``/docs/*``
            excludes ``/docs`` and every path beneath it. Pass ``[]`` to
            exclude nothing. When omitted, defaults to
            ``settings.excluded_paths``, or without ``settings`` to ``/docs``,
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
        http_client: Managed HTTP client for discovery and JWKS, built from
            your ``HTTPConfig`` (timeout, retries, TLS, JWKS size limits). ``None``
            uses the library default client.
        cache: The :class:`~py_identity_model.aio.AsyncValidationCache` that
            holds this middleware's discovery document, keys and kid-miss
            cooldown; its ``CacheConfig`` sets the cache TTLs, size and cooldown.
            ``None`` uses the library default cache.
        settings: :class:`~fastapi_identity_model.OIDCSettings` supplying
            ``discovery_url``, ``audience`` and ``excluded_paths`` when those
            are not passed, and the binding options (``required_binding``,
            ``client_certificate_header``, ``expected_origin``) when
            ``options`` is not passed.
        options: :class:`~fastapi_identity_model.AuthOptions` (binding, DPoP,
            client certificate, expected origin). Pass the same instance to
            :func:`~fastapi_identity_model.build_ws_authenticator`. Takes
            precedence over ``settings``, but must not drop a
            ``required_binding`` or ``expected_origin`` that ``settings`` sets.
            ``None`` uses ``AuthOptions.from_settings(settings)``, or the
            defaults without ``settings``. DPoP proofs are checked against
            ``request.url`` unless ``expected_origin`` is set; behind a proxy,
            run Starlette's proxy-headers handling so it is the URI the client
            addressed.
    """

    def __init__(
        self,
        app,
        discovery_url: str | None = None,
        audience: str | None = None,
        excluded_paths: list[str] | None = None,
        custom_claims_validator: Callable | None = None,
        require_access_token_marker: bool = False,
        access_token_marker_claims: tuple[
            str, ...
        ] = _DEFAULT_ACCESS_TOKEN_MARKER_CLAIMS,
        *,
        http_client: AsyncHTTPClient | None = None,
        cache: AsyncValidationCache | None = None,
        settings: OIDCSettings | None = None,
        options: AuthOptions | None = None,
    ):
        super().__init__(app)
        if settings is not None:
            discovery_url = discovery_url or settings.discovery_url
            audience = audience or settings.audience
            if excluded_paths is None:
                excluded_paths = list(settings.excluded_paths)
        if not discovery_url:
            raise ValueError(
                "TokenValidationMiddleware requires a discovery_url or settings."
            )
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
        self.http_client = http_client
        self.cache = cache
        self.options = resolve_auth_options(settings, options)
        # The scheme a client must use; RFC 9449 §7.1 challenges a DPoP-only
        # resource with ``DPoP``.
        self._challenge = AuthChallenge(
            scheme=(
                AuthorizationScheme.DPOP
                if self.options.required_binding is TokenBinding.DPOP
                else AuthorizationScheme.BEARER
            ),
            realm=self.options.realm,
            dpop_algs=tuple(self.options.dpop.accepted_algorithms),
        )

    def _challenge_for(self, scheme: AuthorizationScheme) -> AuthChallenge:
        """The challenge for a request that used *scheme*: ``DPoP`` when the
        request did or the resource requires it, else ``Bearer``."""
        if scheme is AuthorizationScheme.DPOP:
            return replace(self._challenge, scheme=scheme)
        return self._challenge

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

    def _unauthorized(
        self,
        detail: str,
        *,
        scheme: AuthorizationScheme = AuthorizationScheme.BEARER,
        error: str | None = None,
        status_code: int = status.HTTP_401_UNAUTHORIZED,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={"detail": detail},
            headers={
                "WWW-Authenticate": self._challenge_for(scheme).header(error=error)
            },
        )

    def _extract_token(
        self, request: Request
    ) -> tuple[AuthorizationScheme, str] | JSONResponse:
        """Return the scheme and access token, or an error ``JSONResponse``."""
        authorization = request.headers.get("Authorization")
        if not authorization:
            return self._unauthorized("Missing Authorization header")
        credentials = parse_authorization(authorization)
        if credentials is None:
            # RFC 6750 §3.1: a supported scheme with a malformed credential is
            # invalid_request (400); an unsupported scheme gets no error code.
            parts = authorization.split()
            scheme = _SCHEMES.get(parts[0].lower()) if parts else None
            if scheme is not None:
                return self._unauthorized(
                    "Invalid Authorization header format. Expected: Bearer "
                    "<token> or DPoP <token>",
                    scheme=scheme,
                    error=BearerError.INVALID_REQUEST,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            return self._unauthorized(
                "Invalid Authorization header format. Expected: Bearer <token> "
                "or DPoP <token>"
            )
        scheme, token = credentials
        # RFC 9449 §4.3 check 1: at most one DPoP header.
        if len(request.headers.getlist("DPoP")) > 1:
            return self._unauthorized(
                _GENERIC_401_DETAIL,
                scheme=AuthorizationScheme.DPOP,
                error=DPoPErrorKind.MALFORMED.oauth_error,
            )
        return scheme, token

    def _presentation(
        self, request: Request, scheme: AuthorizationScheme
    ) -> TokenPresentation:
        return presentation(request, self.options, scheme=scheme, method=request.method)

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

    async def _authenticate(
        self, request: Request, scheme: AuthorizationScheme, token: str
    ) -> JSONResponse | None:
        """Validate *token* and attach claims; return an error response or None."""
        try:
            claims = await validate_token(
                jwt=token,
                token_validation_config=TokenValidationConfig(
                    perform_disco=True,
                    audience=self.audience,
                    claims_validator=self.custom_claims_validator,
                    required_binding=self.options.required_binding,
                    dpop=self.options.dpop,
                ),
                disco_doc_address=self.discovery_url,
                http_client=self.http_client,
                cache=self.cache,
                presentation=self._presentation(request, scheme),
            )
            # Reject an ID token presented as an access token (token-type
            # confusion at the resource server).
            wrong_type = self._wrong_token_type_error(claims)
            if wrong_type is not None:
                return self._unauthorized(
                    wrong_type, scheme=scheme, error=BearerError.INVALID_TOKEN
                )
            request.state.user = to_principal(claims)
            request.state.claims = claims
            request.state.token = token
            return None
        except Exception as e:
            return self._rejection(e, scheme)

    def _rejection(self, e: Exception, scheme: AuthorizationScheme) -> JSONResponse:
        """The response for a token-validation failure *e* (called while it is
        being handled, so ``logger.exception`` records the traceback)."""
        if isinstance(e, DPoPValidationError):
            # RFC 9449 §7.1: challenge with the DPoP scheme and the error code
            # (invalid_token / invalid_dpop_proof). The body stays generic (F-18).
            logger.info("DPoP binding rejected: %s", e.kind.value)
            return self._unauthorized(
                _GENERIC_401_DETAIL,
                scheme=AuthorizationScheme.DPOP,
                error=e.kind.oauth_error,
            )
        if isinstance(e, CertificateBindingError):
            logger.info("Certificate binding rejected: %s", e.kind.value)
            return self._unauthorized(
                _GENERIC_401_DETAIL, scheme=scheme, error=BearerError.INVALID_TOKEN
            )
        # A replay cache that cannot be used is the server's fault, not a bad
        # token: it falls through to the 500 below.
        if isinstance(e, PyIdentityModelException) and not isinstance(
            e, DPoPReplayCacheError
        ):
            # A provider outage is a transient server fault, not an auth
            # decision: surface 503 so callers retry instead of treating it as a
            # bad token. This covers both a real NetworkException (a
            # PyIdentityModelException subclass — the clean path if the core
            # raises one) and a discovery/JWKS fetch failure the core currently
            # surfaces as a TokenValidationException (_UPSTREAM_FETCH_FAILURE_
            # PREFIXES).
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
            return self._unauthorized(
                _GENERIC_401_DETAIL, scheme=scheme, error=BearerError.INVALID_TOKEN
            )
        if isinstance(e, InvalidTokenError):
            # A malformed/undecodable token (e.g. raw pyjwt DecodeError from
            # header parsing during key lookup) is a client error, not a 500 —
            # and returns the same generic body as any other rejection so the
            # response can't distinguish "malformed" from "invalid".
            logger.info("Malformed token rejected: %s", e)
            return self._unauthorized(
                _GENERIC_401_DETAIL, scheme=scheme, error=BearerError.INVALID_TOKEN
            )
        # A genuinely unexpected (non-library) failure is a server fault,
        # not an auth decision. Surface a 500 without leaking internals.
        logger.exception("Unexpected error during token validation")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error during authentication"},
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and validate the token if required."""
        request.state.auth_challenge = self._challenge
        # CORS preflight carries no Authorization; excluded paths skip auth.
        if request.method == "OPTIONS" or self._is_excluded(request.url.path):
            return await call_next(request)

        credentials = self._extract_token(request)
        if isinstance(credentials, JSONResponse):
            return credentials
        request.state.auth_challenge = self._challenge_for(credentials[0])

        auth_error = await self._authenticate(request, *credentials)
        if auth_error is not None:
            return auth_error

        return await call_next(request)
