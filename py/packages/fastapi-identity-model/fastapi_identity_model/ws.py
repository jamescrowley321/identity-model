"""WebSocket authentication for FastAPI.

:class:`TokenValidationMiddleware` extends Starlette's ``BaseHTTPMiddleware``,
which forwards every non-HTTP ASGI scope to the app untouched — so WebSocket
handshakes bypass it entirely and a globally-installed middleware does **not**
authenticate WebSocket routes (issue #598). Browsers also cannot set an
``Authorization`` header on the WebSocket handshake, so bearer-in-header auth is
not transparently available for WebSockets the way it is for HTTP.

:func:`build_ws_authenticator` returns a FastAPI dependency that authenticates a
WebSocket by validating a Bearer token taken from (in order) the
``Authorization`` header (non-browser clients) or a query parameter (browsers).
It runs the **same** core ``validate_token`` path and the **same**
ID-token-substitution guard (:func:`fastapi_identity_model.middleware.evaluate_token_type`,
F-07) as the HTTP middleware, and closes the socket with a policy-violation code
on failure. The close *reason* is generic (mirroring the middleware's F-18
non-oracle 401); the specific cause is logged server-side.

    from fastapi import Depends, FastAPI, WebSocket
    from fastapi_identity_model import build_ws_authenticator

    app = FastAPI()
    ws_auth = build_ws_authenticator(
        discovery_url="https://op/.well-known/openid-configuration",
        audience="my-api",
    )

    @app.websocket("/ws")
    async def ws(websocket: WebSocket, claims: dict = Depends(ws_auth)):
        await websocket.accept()
        await websocket.send_json({"sub": claims.get("sub")})

The browser opens it as ``new WebSocket("wss://host/ws?access_token=<token>")``.
Prefer a short-lived token in the query string; query strings can land in logs.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import WebSocket, WebSocketException, status  # type: ignore[attr-defined]
from jwt import InvalidTokenError

from py_identity_model import (
    NetworkException,
    PyIdentityModelException,
    TokenValidationConfig,
    to_principal,
)
from py_identity_model.aio import validate_token

from .middleware import (
    _DEFAULT_ACCESS_TOKEN_MARKER_CLAIMS,
    _is_upstream_fetch_failure,
    evaluate_token_type,
)


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger("fastapi_identity_model")

# Expected number of parts in "Bearer <token>".
_BEARER_HEADER_PART_COUNT = 2

# WebSocket close codes (RFC 6455 §7.4.1). Auth rejection → policy violation;
# transient upstream (discovery/JWKS fetch) failure → try again later so the
# client backs off rather than treating it as a bad token; an unexpected fault
# → internal error.
_WS_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION
_WS_TRY_AGAIN_LATER = status.WS_1013_TRY_AGAIN_LATER
_WS_INTERNAL_ERROR = status.WS_1011_INTERNAL_ERROR

# Generic, non-oracle close reason for every auth rejection cause (signature /
# audience / expiry / wrong-type), mirroring the middleware's F-18 401 body so
# the close frame cannot distinguish rejection causes. WebSocket close reasons
# must be <= 123 UTF-8 bytes (RFC 6455 §5.5.1); this is well under.
_GENERIC_REJECT_REASON = "Invalid or unauthorized token"


def _extract_ws_token(websocket: WebSocket, query_param: str) -> str | None:
    """Return the bearer token from the Authorization header or query param.

    Header wins when present (non-browser clients). A present-but-malformed
    Authorization header returns ``None`` rather than falling through to the
    query param, so a client cannot smuggle a second token past a broken header.
    """
    header = websocket.headers.get("Authorization")
    if header is not None:
        parts = header.split()
        if len(parts) == _BEARER_HEADER_PART_COUNT and parts[0].lower() == "bearer":
            return parts[1]
        return None
    token = websocket.query_params.get(query_param)
    return token or None


def build_ws_authenticator(  # noqa: PLR0913  # mirrors the middleware's opt-in F-07 marker config + a WS token-source knob
    discovery_url: str,
    audience: str,
    *,
    query_param: str = "access_token",
    custom_claims_validator: Callable | None = None,
    require_access_token_marker: bool = False,
    access_token_marker_claims: tuple[str, ...] = _DEFAULT_ACCESS_TOKEN_MARKER_CLAIMS,
) -> Callable:
    """Build a FastAPI WebSocket dependency that validates a Bearer token.

    Mirrors :class:`TokenValidationMiddleware` for WebSocket routes, which the
    HTTP middleware cannot reach (issue #598).

    Args:
        discovery_url: The OpenID Connect discovery document URL.
        audience: Expected ``aud`` claim. Required — a ``None`` audience does
            not enforce ``aud`` for tokens that omit it, which on a shared
            multi-tenant issuer accepts tokens minted for other clients.
        query_param: Query-string parameter carrying the token when no
            ``Authorization`` header is present (browsers). Default
            ``access_token``.
        custom_claims_validator: Optional injectable claims validator, threaded
            into ``TokenValidationConfig`` exactly as the HTTP middleware does.
        require_access_token_marker: Opt-in ID-token-substitution defence (F-07),
            default ``False``. See :class:`TokenValidationMiddleware`.
        access_token_marker_claims: Positive access-token marker claims for
            ``require_access_token_marker``. Defaults to ``("scope", "scp")``.

    Returns:
        An async dependency ``(websocket) -> dict`` returning the validated
        claims. On failure it raises :class:`fastapi.WebSocketException`, which
        FastAPI turns into a handshake close with the given code — the socket is
        never accepted. The validated claims/principal/token are also attached
        to ``websocket.state`` (``.claims`` / ``.user`` / ``.token``).
    """
    if not audience:
        raise ValueError(
            "build_ws_authenticator requires a non-empty 'audience'; a "
            "None/empty audience skips aud enforcement for aud-less tokens."
        )
    if require_access_token_marker and not access_token_marker_claims:
        raise ValueError(
            "require_access_token_marker=True needs a non-empty "
            "access_token_marker_claims; an empty set rejects every token."
        )

    async def authenticate_websocket(websocket: WebSocket) -> dict:
        token = _extract_ws_token(websocket, query_param)
        if not token:
            # Structural failure (no/!bearer token) — distinct from a validation
            # rejection, exactly as the HTTP middleware distinguishes "Missing
            # Authorization header" from the generic 401.
            raise WebSocketException(
                code=_WS_POLICY_VIOLATION,
                reason="Missing or malformed bearer token",
            )
        try:
            claims = await validate_token(
                jwt=token,
                token_validation_config=TokenValidationConfig(
                    perform_disco=True,
                    audience=audience,
                    claims_validator=custom_claims_validator,
                ),
                disco_doc_address=discovery_url,
            )
        except PyIdentityModelException as e:
            if isinstance(e, NetworkException) or _is_upstream_fetch_failure(e):
                logger.exception("Upstream fetch failure during WS token validation")
                raise WebSocketException(
                    code=_WS_TRY_AGAIN_LATER,
                    reason="Authentication temporarily unavailable",
                ) from e
            logger.info("WS token rejected during validation: %s", e)
            raise WebSocketException(
                code=_WS_POLICY_VIOLATION, reason=_GENERIC_REJECT_REASON
            ) from e
        except InvalidTokenError as e:
            logger.info("Malformed WS token rejected: %s", e)
            raise WebSocketException(
                code=_WS_POLICY_VIOLATION, reason=_GENERIC_REJECT_REASON
            ) from e
        except WebSocketException:
            raise
        except Exception as e:
            logger.exception("Unexpected error during WS token validation")
            raise WebSocketException(
                code=_WS_INTERNAL_ERROR,
                reason="Internal error during authentication",
            ) from e

        wrong_type = evaluate_token_type(
            claims,
            require_access_token_marker=require_access_token_marker,
            access_token_marker_claims=access_token_marker_claims,
        )
        if wrong_type is not None:
            # Log the specific reason; return the generic one to the client.
            logger.info("WS token rejected (wrong type): %s", wrong_type)
            raise WebSocketException(
                code=_WS_POLICY_VIOLATION, reason=_GENERIC_REJECT_REASON
            )

        websocket.state.user = to_principal(claims)
        websocket.state.claims = claims
        websocket.state.token = token
        return claims

    return authenticate_websocket
