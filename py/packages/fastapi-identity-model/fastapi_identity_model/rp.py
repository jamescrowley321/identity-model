"""Relying-Party (OIDC login) router for FastAPI.

``build_oidc_router`` returns a mountable :class:`fastapi.APIRouter` implementing
the authorization-code + PKCE login flow against any OpenID Connect provider,
using the async ``py_identity_model.aio`` API for all protocol work:

    from fastapi import FastAPI
    from starlette.middleware.sessions import SessionMiddleware
    from fastapi_identity_model import OIDCSettings, build_oidc_router

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="...")   # required
    app.include_router(build_oidc_router(settings), prefix="/auth")

Routes: ``GET /login`` → provider, ``GET/POST /callback`` (exchange + validate
+ nonce + UserInfo; the POST route accepts the OAuth 2.0 ``form_post`` response
mode), ``POST /logout``. The transient PKCE/state/nonce are kept
under a separate ``<session_key>.flow`` entry and popped on callback (single
use); the resulting identity is written to ``session[session_key]`` only after
a verified ID token, so reading ``session[session_key]`` never observes an
in-flight login. Logout is POST-only so a cross-site GET cannot force it.

Security note: browsers only send the session cookie on the cross-site POST a
``form_post`` provider issues if it was set with ``same_site="none"`` (which
requires ``https_only=True``); with the default ``lax`` the POST callback
arrives without the flow cookie and fails with "No active login flow".
``SessionMiddleware`` signs but does **not** encrypt the cookie.
Identity claims stored there are tamper-proof but readable by the client. Raw
tokens are stored only when ``store_tokens=True`` — enable that only with an
encrypted or server-side session store. Logout clears the local session only;
it does not call the provider's ``end_session_endpoint``.
"""

from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode

from fastapi import APIRouter, HTTPException, Request, status
from starlette.responses import RedirectResponse

from py_identity_model import PyIdentityModelException
from py_identity_model.aio import (
    AuthorizationCodeTokenRequest,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    TokenValidationConfig,
    UserInfoRequest,
    build_authorization_url,
    generate_pkce_pair,
    get_discovery_document,
    get_userinfo,
    parse_authorize_callback_response,
    request_authorization_code_token,
    validate_authorize_callback_state,
    validate_token,
)


if TYPE_CHECKING:
    from .config import OIDCSettings


logger = logging.getLogger("fastapi_identity_model")

_STATE_TOKEN_BYTES = 32

# Paths registered by build_oidc_router, relative to the router's mount prefix.
# /callback is shared by the GET and POST (form_post) handlers.
_OIDC_ROUTER_PATHS = ("/login", "/callback", "/logout")


def oidc_public_paths(prefix: str = "") -> list[str]:
    """Return the paths ``build_oidc_router`` registers, for the RS middleware.

    A globally-installed :class:`TokenValidationMiddleware` would otherwise
    demand a Bearer token on ``/login`` and ``/callback`` — routes that by
    definition have no token yet — making login impossible (issue #599). Feed
    these into the middleware's ``excluded_paths`` so the login flow is
    reachable::

        router_prefix = "/auth"
        app.include_router(build_oidc_router(settings), prefix=router_prefix)
        app.add_middleware(
            TokenValidationMiddleware,
            discovery_url=settings.discovery_url,
            audience=settings.audience,
            excluded_paths=[
                *settings.excluded_paths,
                *oidc_public_paths(router_prefix),
            ],
        )

    Args:
        prefix: The same ``prefix`` passed to ``include_router`` (``""`` when
            the router is mounted at the app root). A trailing slash is
            normalized away.

    Returns:
        Absolute, exact paths (no ``/*`` subtree wildcard) — the login,
        callback, and logout endpoints.
    """
    base = prefix.rstrip("/")
    # Normalize a missing leading slash: request paths are always absolute, so a
    # relative ``base`` ("auth" instead of "/auth") would produce entries that
    # can never match and silently fail to exclude the login routes. FastAPI's
    # include_router already requires a leading-slash prefix; this just makes the
    # helper robust if called directly.
    if base and not base.startswith("/"):
        base = f"/{base}"
    return [f"{base}{route}" for route in _OIDC_ROUTER_PATHS]


def _flow_key(session_key: str) -> str:
    """Session key holding transient login-flow state (state/nonce/verifier).

    Kept separate from *session_key* (which holds the final identity) so a
    consumer reading ``session[session_key]`` never observes an in-flight
    login as an authenticated identity, and never sees the ``code_verifier``.
    """
    return f"{session_key}.flow"


def _require_session(request: Request) -> None:
    """Fail with a clear error when ``SessionMiddleware`` is not installed."""
    if "session" not in request.scope:
        raise RuntimeError(
            "SessionMiddleware is required by the OIDC router but is not "
            "installed. Add: app.add_middleware(SessionMiddleware, secret_key=...)"
        )


_WELL_KNOWN_SUFFIX = "/.well-known/openid-configuration"


def _expected_issuer(discovery_url: str) -> str:
    """Issuer implied by the discovery URL (OIDC Discovery 1.0 §4.1)."""
    base = discovery_url.rstrip("/")
    if base.endswith(_WELL_KNOWN_SUFFIX):
        base = base[: -len(_WELL_KNOWN_SUFFIX)]
    return base.rstrip("/")


async def _discover(settings: OIDCSettings) -> DiscoveryDocumentResponse:
    disco = await get_discovery_document(
        DiscoveryDocumentRequest(address=settings.discovery_url),
    )
    if not disco.is_successful:
        # Log the provider's specific error for operators; return a generic
        # detail so the callback endpoint cannot be probed for upstream
        # internals (mirrors the resource-server middleware's F-18 posture).
        logger.warning("OIDC discovery failed: %s", disco.error)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Identity provider discovery failed",
        )
    # OIDC Discovery 1.0 §4.3: the document's issuer MUST match the URL the
    # document was retrieved from (issuer mix-up defense). The library only
    # validates the issuer's *format*; the equality check is the RP's job.
    # Trailing slashes are normalized — issuer "https://op/" serves its
    # document at "https://op/.well-known/openid-configuration".
    expected = _expected_issuer(settings.discovery_url)
    if (disco.issuer or "").rstrip("/") != expected:
        logger.warning(
            "Discovery document issuer mismatch: expected %r, got %r",
            expected,
            disco.issuer,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Identity provider configuration error",
        )
    return disco


def _require_endpoint(value: str | None, name: str) -> str:
    if not value:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Provider discovery is missing '{name}'",
        )
    return value


async def _login(
    request: Request, settings: OIDCSettings, session_key: str
) -> RedirectResponse:
    _require_session(request)
    disco = await _discover(settings)
    authorization_endpoint = _require_endpoint(
        disco.authorization_endpoint, "authorization_endpoint"
    )
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(_STATE_TOKEN_BYTES)
    nonce = secrets.token_urlsafe(_STATE_TOKEN_BYTES)
    request.session[_flow_key(session_key)] = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
    }
    url = build_authorization_url(
        authorization_endpoint=authorization_endpoint,
        client_id=settings.client_id,
        redirect_uri=settings.redirect_uri,
        scope=settings.scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


async def _exchange_code(
    settings: OIDCSettings,
    disco: DiscoveryDocumentResponse,
    code: str,
    code_verifier: str,
) -> dict:
    """Exchange the authorization code and return the token dict."""
    token_endpoint = _require_endpoint(disco.token_endpoint, "token_endpoint")
    tok = await request_authorization_code_token(
        AuthorizationCodeTokenRequest(
            address=token_endpoint,
            client_id=settings.client_id,
            code=code,
            redirect_uri=settings.redirect_uri,
            code_verifier=code_verifier,
            client_secret=settings.client_secret or None,
        ),
    )
    if not tok.is_successful or not tok.token:
        logger.warning("Token exchange failed: %s", tok.error)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code exchange failed",
        )
    return tok.token


async def _validate_id_token(
    settings: OIDCSettings,
    disco: DiscoveryDocumentResponse,
    id_token: str,
    expected_nonce: str,
) -> dict:
    """Validate the ID token (signature/iss/aud/exp/required claims) and bind the nonce."""
    # Guard the issuer explicitly: a discovery doc missing ``issuer`` would
    # otherwise pass ``issuer=None`` and silently disable issuer verification.
    issuer = _require_endpoint(disco.issuer, "issuer")
    try:
        claims = await validate_token(
            jwt=id_token,
            token_validation_config=TokenValidationConfig(
                perform_disco=True,
                audience=settings.client_id,
                issuer=issuer,
                options={"verify_exp": True, "require": ["sub", "iat", "exp"]},
            ),
            disco_doc_address=settings.discovery_url,
        )
    except PyIdentityModelException as exc:
        logger.info("ID token validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ID token validation failed",
        ) from exc

    # Nonce binding is the RP's responsibility — the library does not check it.
    if claims.get("nonce") != expected_nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce mismatch",
        )
    return claims


async def _fetch_userinfo(
    disco: DiscoveryDocumentResponse,
    access_token: str | None,
    expected_sub: str | None,
) -> dict:
    """Fetch UserInfo, enforcing the OIDC Core 5.3.2 ``sub`` match as a hard gate.

    An unavailable UserInfo endpoint (no endpoint, or a transient fetch
    failure) is tolerated — identity is anchored on the validated ID token.
    But a *successful* fetch whose ``sub`` disagrees with the ID token is a
    token-substitution signal and must abort the login, not be swallowed.
    """
    userinfo_endpoint = disco.userinfo_endpoint
    if not access_token or not userinfo_endpoint:
        return {}
    # Fetch without expected_sub so is_successful reflects only the fetch;
    # the sub comparison is enforced here so a mismatch fails the login.
    ui = await get_userinfo(
        UserInfoRequest(address=userinfo_endpoint, token=access_token),
    )
    if not ui.is_successful:
        logger.warning("UserInfo fetch failed, continuing on ID token: %s", ui.error)
        return {}
    claims = ui.claims or {}
    if expected_sub is not None and claims.get("sub") != expected_sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UserInfo subject does not match ID token subject",
        )
    return claims


async def _callback(  # noqa: PLR0913  # request-scoped args + the router's build-time options
    request: Request,
    settings: OIDCSettings,
    session_key: str,
    callback_url: str,
    *,
    store_tokens: bool,
    fetch_userinfo: bool,
) -> RedirectResponse:
    _require_session(request)
    # Pop the flow state so it is single-use: a failed or replayed callback
    # cannot reuse the same state/verifier for another attempt.
    flow = request.session.pop(_flow_key(session_key), None)
    if not flow or not {"state", "nonce", "code_verifier"} <= flow.keys():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active login flow in session",
        )

    try:
        cb = parse_authorize_callback_response(callback_url)
    except PyIdentityModelException as exc:
        logger.info("Malformed authorization callback: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed authorization response",
        ) from exc
    if not cb.is_successful:
        # ``cb.error`` is the provider's OAuth 2.0 ``error`` param, but it can
        # carry an attacker-influenced ``error_description``; log it, return a
        # generic detail rather than reflecting it to the browser.
        logger.info("Authorization error from provider: %s", cb.error)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization request failed",
        )
    if not validate_authorize_callback_state(cb, flow["state"]).is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State mismatch (possible CSRF)",
        )
    if cb.code is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization response missing code",
        )

    disco = await _discover(settings)
    token = await _exchange_code(settings, disco, cb.code, flow["code_verifier"])
    id_token = token.get("id_token")
    access_token = token.get("access_token")

    # An OIDC login flow (openid scope, nonce sent) requires a verified ID
    # token. Refuse to establish a session on a token response that omits it
    # rather than degrading to an unauthenticated "logged-in" session.
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provider did not return an ID token",
        )
    claims = await _validate_id_token(settings, disco, id_token, flow["nonce"])

    userinfo: dict = {}
    if fetch_userinfo:
        userinfo = await _fetch_userinfo(disco, access_token, claims.get("sub"))

    session_data: dict = {
        "sub": claims.get("sub"),
        "claims": claims,
        "userinfo": userinfo,
    }
    if store_tokens:
        session_data["tokens"] = {
            "access_token": access_token,
            "refresh_token": token.get("refresh_token"),
            "id_token": id_token,
        }
    request.session[session_key] = session_data

    return RedirectResponse(
        settings.post_login_redirect,
        status_code=status.HTTP_302_FOUND,
    )


def build_oidc_router(
    settings: OIDCSettings,
    *,
    session_key: str = "oidc",
    store_tokens: bool = False,
    fetch_userinfo: bool = True,
) -> APIRouter:
    """Build an OIDC relying-party router.

    Args:
        settings: Provider/client configuration.
        session_key: Key under which flow + identity state is kept in the session.
        store_tokens: When True, also persist the access/refresh/id tokens in the
            session (requires an encrypted or server-side session store).
        fetch_userinfo: When False, skip the UserInfo request after ID-token
            validation and anchor identity on the ID token claims alone —
            for providers without a usable UserInfo endpoint, or to avoid
            the extra round-trip per login.

    Returns:
        An ``APIRouter`` with ``/login``, ``/callback`` and ``/logout`` routes.
    """
    if not settings.redirect_uri:
        raise ValueError(
            "build_oidc_router requires settings.redirect_uri (the provider "
            "callback URL); it is only optional for resource-server-only setups."
        )
    router = APIRouter()

    @router.get("/login")
    async def login(request: Request) -> RedirectResponse:
        return await _login(request, settings, session_key)

    @router.get("/callback")
    async def callback(request: Request) -> RedirectResponse:
        return await _callback(
            request,
            settings,
            session_key,
            str(request.url),
            store_tokens=store_tokens,
            fetch_userinfo=fetch_userinfo,
        )

    @router.post("/callback")
    async def callback_form_post(request: Request) -> RedirectResponse:
        # form_post response mode: the provider delivers the authorization
        # response as an application/x-www-form-urlencoded POST body instead
        # of query parameters. Rebuild a callback URL carrying the fields as
        # a query string so GET and POST share the exact same validation path
        # (parse → state → code → exchange). Parsed with stdlib parse_qsl —
        # form_post is urlencoded by definition, so this avoids taking a
        # python-multipart dependency for starlette's request.form().
        body = (await request.body()).decode("utf-8", errors="replace")
        params = urlencode(parse_qsl(body, keep_blank_values=True))
        callback_url = str(request.url.replace(query=params))
        return await _callback(
            request,
            settings,
            session_key,
            callback_url,
            store_tokens=store_tokens,
            fetch_userinfo=fetch_userinfo,
        )

    @router.post("/logout")
    async def logout(request: Request) -> RedirectResponse:
        # POST-only: a state-changing session mutation must not be triggerable
        # by a cross-site GET (e.g. an <img> tag) under a Lax cookie.
        _require_session(request)
        request.session.pop(session_key, None)
        request.session.pop(_flow_key(session_key), None)
        return RedirectResponse(
            settings.post_logout_redirect,
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return router
