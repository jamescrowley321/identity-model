"""OIDC RP conformance harness for the fastapi-identity-model package.

Exposes the same runner-facing contract as ``app.py`` (``GET /authorize``,
``GET/POST /callback``, ``GET /discover``, ``POST /clear-cache``, ``/health``,
per-test log routing) so ``run_tests.py`` drives it unchanged — but instead of
re-implementing the login orchestration with the core library, it delegates
every flow to the REAL ``fastapi_identity_model.build_oidc_router``.

This is a regression stage, not a second certification (#242): the core
library is the certification target; this harness proves the package's RP
router survives the same OIDF RP suite (invalid iss/aud/sig, nonce,
missing-sub, kid, key rotation, form_post) the library passes.

How it works — the OIDF suite varies the issuer per test module, while the
router binds one ``OIDCSettings.discovery_url`` at build time. So the harness
builds a fresh FastAPI app (SessionMiddleware + router) per ``/authorize``,
drives its ``/login`` in-process over ``httpx.ASGITransport``, and keeps the
``(client, cookie jar)`` pair keyed by the flow's ``state`` — the same
state-keyed recovery ``app.py`` uses for its sessions. When the OP calls back
(query or form_post) the harness recovers the pair by ``state`` and replays
the callback into that per-test router, flow cookie and all. The router's own
verdict (302 = login established, 4xx/5xx = rejected) is the test outcome.

The router always uses PKCE, so the runner's ``use_pkce`` hint is accepted
but not acted on (a safe superset of what the suite requires). The
``skip_userinfo`` hint maps to the router's ``fetch_userinfo`` option — the
discovery-jwks-uri-keys module is FINISHED once the token is issued, and a
trailing UserInfo request would be an illegal test state change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import html
import logging
import os
import secrets
from urllib.parse import parse_qs, parse_qsl, urlparse

# Shared per-test log plumbing from the library harness: the ContextVar-based
# active-test pointer and the handler that routes records to per-test files.
# Importing ``app`` also installs its handler on the ``py_identity_model``
# logger (and raises it to DEBUG), so only the package loggers need wiring here.
from app import _PerTestLogRouter, _set_active_test, merge_unattributed_rejection
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx
from starlette.middleware.sessions import SessionMiddleware

from fastapi_identity_model import OIDCSettings, build_oidc_router
from py_identity_model import parse_discovery_url
from py_identity_model.aio.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.exceptions import ConfigurationException


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("conformance-rp-fastapi")


def _install_rp_log_router() -> None:
    router = _PerTestLogRouter()
    router.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    for name in ("conformance-rp-fastapi", "fastapi_identity_model"):
        logging.getLogger(name).addHandler(router)
    # Capture the package's own decision detail in the per-test logs.
    logging.getLogger("fastapi_identity_model").setLevel(logging.DEBUG)


_install_rp_log_router()

app = FastAPI(title="fastapi-identity-model Conformance RP")

RP_BASE_URL = os.environ.get("RP_BASE_URL", "http://localhost:8889")

# Scopes the library harness requests by default; kept identical so the
# scope-userinfo-claims test sees the same claim surface from the router.
DEFAULT_SCOPE = "openid profile email address phone"

HTTP_FOUND = 302

# ---------------------------------------------------------------------------
# Per-flow state — (per-test router app, ASGI client with its cookie jar)
# keyed by the ``state`` parameter, mirroring app.py's session recovery
# ---------------------------------------------------------------------------


@dataclass
class FlowSession:
    """Tracks one login flow between /authorize and /callback."""

    client: httpx.AsyncClient  # bound to the per-test app; holds the flow cookie
    issuer: str
    test_id: str = ""
    test_name: str = ""
    profile: str = ""
    result: dict = field(default_factory=dict)


# state -> FlowSession
flows: dict[str, FlowSession] = {}

# test_id -> result dict (for /results/{test_id} debugging parity with app.py)
test_results: dict[str, dict] = {}


def _store_test_result(flow: FlowSession) -> None:
    if flow.test_id:
        flow.result.setdefault("test_id", flow.test_id)
        test_results[flow.test_id] = flow.result


# Reason classes for the router's fixed HTTPException details, so the runner can
# check a negative module was refused for the right reason (same classes as
# app.py records).
_ROUTER_REASONS = {
    "Identity provider discovery failed": "discovery_failed",
    "Identity provider configuration error": "issuer_mismatch",
    "Authorization code exchange failed": "token_exchange",
    "ID token validation failed": "id_token_validation",
    "Nonce mismatch": "nonce_mismatch",
    "UserInfo response has no subject": "userinfo_validation",
    "UserInfo subject does not match ID token subject": "userinfo_validation",
    "State mismatch (possible CSRF)": "state_validation",
    "Authorization request failed": "op_error",
    "Authorization response missing code": "missing_code",
    "Provider did not return an ID token": "missing_id_token",
}

# The router answers an unhandled exception with a bare 500; that is a crash,
# never a decision, so it gets a class no manifest lists as a rejection reason.
ROUTER_CRASH_REASON = "router_crashed"

# test_id of the most recent /authorize, for rejections that carry no flow
# (a callback whose state matches no parked flow).
_last_test_id = ""


def _router_rejection(resp: httpx.Response) -> str:
    """``<reason class>: <detail>`` for a router response that refused a flow."""
    detail = _error_detail(resp)
    if resp.status_code == httpx.codes.INTERNAL_SERVER_ERROR:
        return f"{ROUTER_CRASH_REASON}: {detail}"
    return f"{_ROUTER_REASONS.get(detail, 'router_rejected')}: {detail}"


def _record_unattributed(test_id: str, error: str) -> None:
    """Record a rejection that carries no flow (see app.merge_unattributed_rejection)."""
    if not test_id:
        return
    record = merge_unattributed_rejection(
        test_results.get(test_id), test_id, error, after_login=False
    )
    if record is not None:
        test_results[test_id] = record


def _record_error(test_id: str, error: str) -> None:
    if test_id:
        test_results[test_id] = {
            "test_id": test_id,
            "status": "error",
            "error": error,
        }


# ---------------------------------------------------------------------------
# Per-test router construction
# ---------------------------------------------------------------------------


def _build_test_app(settings: OIDCSettings, *, fetch_userinfo: bool = True) -> FastAPI:
    """A minimal app hosting the real OIDC router for one test's issuer."""
    test_app = FastAPI()
    test_app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(32))
    test_app.include_router(
        build_oidc_router(settings, store_tokens=True, fetch_userinfo=fetch_userinfo)
    )

    @test_app.get("/session")
    async def session_view(request: Request) -> JSONResponse:
        """Expose the router-established identity so the harness can report it."""
        return JSONResponse(content=request.session.get("oidc") or {})

    return test_app


def _build_test_client(test_app: FastAPI) -> httpx.AsyncClient:
    # base_url matches the public RP base so the router sees the same URLs the
    # OP redirects to. Generous timeout: one replayed /callback wraps the whole
    # token exchange + JWKS refresh/retry sequence.
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url=RP_BASE_URL,
        timeout=httpx.Timeout(120.0),
    )


def _error_detail(resp: httpx.Response) -> str:
    """Best-effort extraction of a FastAPI error detail from a router response."""
    try:
        payload = resp.json()
    except ValueError:
        return resp.text
    if isinstance(payload, dict):
        return str(payload.get("detail", payload))
    return str(payload)


# ---------------------------------------------------------------------------
# Endpoints (same contract as app.py)
# ---------------------------------------------------------------------------


@app.get("/")
@app.get("/health")
def health() -> dict:
    """Health check."""
    return {"status": "ok", "service": "conformance-rp-fastapi"}


@app.post("/clear-cache")
async def clear_cache() -> dict:
    """Clear library caches (and stale flows) between conformance tests.

    The suite reconfigures the OP's JWKS between test modules; the router
    validates through the ``py_identity_model.aio`` global caches, so those
    are what must be cleared.
    """
    _set_active_test(None, None)
    for state in list(flows):
        stale = flows.pop(state)
        await stale.client.aclose()
    await clear_discovery_cache()
    await clear_jwks_cache()
    logger.info("Cleared discovery and JWKS caches")
    return {"status": "ok", "cleared": ["discovery", "jwks"]}


@app.get("/discover", response_model=None)
async def discover(
    issuer: str = Query(..., description="Issuer URL for this test"),
    test_id: str = Query("", description="Test module ID for result tracking"),
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
) -> JSONResponse:
    """Drive the router's /login far enough to fetch + validate discovery.

    The router performs discovery (with the library's issuer validation) as
    the first step of ``/login``; a 302 back means the document was fetched
    and its issuer matched, a 5xx means the router refused it. No redirect is
    ever followed, so no authorization request reaches the OP — which is what
    the discovery-only and issuer-mismatch tests observe.
    """
    _set_active_test(profile, test_name)
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        logger.error("REJECTED: invalid issuer URL: %s", exc)
        _record_error(test_id, f"invalid_issuer: {exc}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
        )

    settings = OIDCSettings(
        discovery_url=disco_endpoint.url,
        client_id="conformance-rp",
        redirect_uri=f"{RP_BASE_URL}/callback",
    )
    client = _build_test_client(_build_test_app(settings))
    try:
        resp = await client.get("/login")
    finally:
        await client.aclose()

    if resp.status_code != HTTP_FOUND:
        detail = _error_detail(resp)
        logger.error("REJECTED: router refused discovery: %s", detail)
        _record_error(test_id, _router_rejection(resp))
        return JSONResponse(
            status_code=502,
            content={"error": "discovery_failed", "detail": detail},
        )

    if test_id:
        test_results[test_id] = {
            "test_id": test_id,
            "status": "success",
            "issuer": issuer,
        }
    logger.info(
        "ACCEPTED: discovery document fetched and validated for issuer '%s'",
        issuer,
    )
    return JSONResponse(content={"status": "ok", "issuer": issuer})


@app.get("/authorize", response_model=None)
async def authorize(
    issuer: str = Query(..., description="Issuer URL for this test"),
    client_id: str = Query(..., description="Client ID registered with the suite"),
    client_secret: str = Query("", description="Client secret"),
    test_id: str = Query("", description="Test module ID for result tracking"),
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
    use_pkce: str = Query("false", description="Ignored: the router always uses PKCE"),
    skip_userinfo: str = Query(
        "false", description="Maps to the router's fetch_userinfo option"
    ),
    scope: str = Query(DEFAULT_SCOPE, description="Requested scopes"),
) -> RedirectResponse | JSONResponse:
    """Build a per-test router and start its login flow.

    The router owns discovery, issuer validation, state/nonce/PKCE and the
    authorization URL; the harness only relays its 302 to the runner and
    parks the flow client for the callback.
    """
    _set_active_test(profile, test_name)
    # A new flow starts with no recorded outcome (see app.py /authorize).
    test_results.pop(test_id, None)
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        logger.error("REJECTED: invalid issuer URL: %s", exc)
        _record_error(test_id, f"invalid_issuer: {exc}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
        )

    settings = OIDCSettings(
        discovery_url=disco_endpoint.url,
        client_id=client_id,
        client_secret=client_secret or None,
        redirect_uri=f"{RP_BASE_URL}/callback",
        scope=scope,
    )
    client = _build_test_client(
        _build_test_app(settings, fetch_userinfo=skip_userinfo.lower() != "true")
    )

    resp = await client.get("/login")
    if resp.status_code != HTTP_FOUND:
        detail = _error_detail(resp)
        logger.error(
            "REJECTED: router /login failed (%d): %s", resp.status_code, detail
        )
        _record_error(test_id, _router_rejection(resp))
        await client.aclose()
        return JSONResponse(
            status_code=502,
            content={"error": "login_failed", "detail": detail},
        )

    location = resp.headers.get("location", "")
    state_values = parse_qs(urlparse(location).query).get("state", [])
    if not state_values:
        logger.error("Router authorization URL missing state: %s", location)
        _record_error(test_id, "missing_state_in_authorization_url")
        await client.aclose()
        return JSONResponse(
            status_code=502,
            content={"error": "missing_state", "detail": "No state in auth URL"},
        )

    flow = FlowSession(
        client=client,
        issuer=issuer,
        test_id=test_id,
        test_name=test_name,
        profile=profile,
    )
    if test_id:
        flow.result["test_id"] = test_id
    flows[state_values[0]] = flow
    global _last_test_id
    _last_test_id = test_id

    logger.info(
        "ACCEPTED: router validated discovery for issuer '%s'; redirecting to OP",
        issuer,
    )
    logger.info("Redirecting to OP: %s", location)
    return RedirectResponse(url=location, status_code=302)


async def _finish_callback(flow: FlowSession, resp: httpx.Response) -> HTMLResponse:
    """Turn the router's callback verdict into the harness response + result."""
    if resp.status_code != HTTP_FOUND:
        detail = _error_detail(resp)
        flow.result["status"] = "error"
        flow.result["error"] = _router_rejection(resp)
        _store_test_result(flow)
        logger.error(
            "REJECTED: router rejected callback (%d): %s", resp.status_code, detail
        )
        return HTMLResponse(
            content=f"<h1>Login Rejected</h1><p>{html.escape(detail)}</p>",
            status_code=resp.status_code,
        )

    # The 302 to post_login_redirect means the router established a session:
    # id_token validated (signature/iss/aud/exp/nonce) and UserInfo vetted.
    session_data = (await flow.client.get("/session")).json()
    claims = session_data.get("claims") or {}
    userinfo = session_data.get("userinfo") or {}
    tokens = session_data.get("tokens") or {}

    flow.result["status"] = "success"
    flow.result["id_token_claims"] = claims
    flow.result["userinfo_claims"] = userinfo
    flow.result["access_token"] = tokens.get("access_token")
    _store_test_result(flow)

    logger.info(
        "ACCEPTED: router completed login for issuer=%s, sub=%s",
        flow.issuer,
        session_data.get("sub"),
    )

    claim_lines = [
        f"<p>Subject: {html.escape(str(claims.get('sub', 'N/A')))}</p>",
        f"<p>Issuer: {html.escape(str(claims.get('iss', 'N/A')))}</p>",
    ]
    if userinfo:
        claim_lines.append("<h2>UserInfo Claims</h2>")
        for key, value in userinfo.items():
            claim_lines.append(
                f"<p>{html.escape(str(key))}: {html.escape(str(value))}</p>"
            )
    return HTMLResponse(
        content="<h1>Authentication Successful</h1>" + "\n".join(claim_lines),
        status_code=200,
    )


def _pop_flow(state: str | None) -> FlowSession | None:
    if not state:
        return None
    return flows.pop(state, None)


@app.get("/callback", response_model=None)
async def callback_get(request: Request) -> HTMLResponse:
    """Replay the OP's query-mode callback into the per-test router."""
    flow = _pop_flow(request.query_params.get("state"))
    if flow is None:
        logger.error(
            "REJECTED: unknown or missing state: %s", request.query_params.get("state")
        )
        _record_unattributed(_last_test_id, "state_validation: unknown state")
        return HTMLResponse(
            content="<h1>Error</h1><p>Unknown or missing state parameter</p>",
            status_code=400,
        )
    _set_active_test(flow.profile, flow.test_name)
    try:
        resp = await flow.client.get(f"/callback?{request.url.query}")
        return await _finish_callback(flow, resp)
    finally:
        await flow.client.aclose()


@app.post("/callback", response_model=None)
async def callback_post(request: Request) -> HTMLResponse:
    """Replay the OP's form_post callback into the router's POST /callback.

    The raw urlencoded body is forwarded verbatim so the router's own
    form_post handling — not a harness re-encoding — is what's under test.
    """
    body = await request.body()
    fields = dict(
        parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    )
    flow = _pop_flow(fields.get("state"))
    if flow is None:
        logger.error("REJECTED: unknown or missing state: %s", fields.get("state"))
        _record_unattributed(_last_test_id, "state_validation: unknown state")
        return HTMLResponse(
            content="<h1>Error</h1><p>Unknown or missing state parameter</p>",
            status_code=400,
        )
    _set_active_test(flow.profile, flow.test_name)
    try:
        resp = await flow.client.post(
            "/callback",
            content=body,
            headers={
                "content-type": request.headers.get(
                    "content-type", "application/x-www-form-urlencoded"
                )
            },
        )
        return await _finish_callback(flow, resp)
    finally:
        await flow.client.aclose()


@app.get("/results/{test_id}")
def get_result(test_id: str) -> JSONResponse:
    """Retrieve the result of a completed test flow."""
    if test_id in test_results:
        return JSONResponse(content=test_results[test_id])
    return JSONResponse(status_code=404, content={"error": "not_found"})
