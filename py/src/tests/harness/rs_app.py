"""Greenfield FastAPI resource server for the token-blaster harness (TH-1.2).

A minimal RS that mounts ``TokenValidationMiddleware`` and guards routes with
``require_scope``. All configuration comes from ``RS_*`` environment variables
so uvicorn ``--workers N`` forked workers each re-import this module and rebuild
an identical app (the workers are forked *after* import-string resolution, so
they cannot share a closure — only the env).

This is the ONLY harness module that imports FastAPI / fastapi-identity-model.
It is excluded from the root pyrefly lint env (see ``[tool.pyrefly]
project_excludes`` in ``pyproject.toml``) because that env installs only
py-identity-model and cannot resolve the fastapi stack; it is exercised via
``make test-harness-rs`` under ``uv run --all-packages``.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, WebSocket

from fastapi_identity_model import (
    Claims,
    CurrentUser,
    TokenValidationMiddleware,
    build_ws_authenticator,
    require_scope,
)
from fastapi_identity_model.config import _default_excluded_paths
from py_identity_model.core.cache_metrics import get_cache_counters


# The middleware's own default exclusion set, reused (not re-listed) so this
# harness cannot silently drift from the package if that default ever changes —
# we materialise it only so ``/metrics`` can be appended without dropping the
# health/docs excludes the middleware would otherwise apply on its own.
# Unauthenticated cache-counter readout for the load/soak harness (T311). Must be
# excluded from token validation so the driver can scrape it without a token.
_METRICS_PATH = "/metrics"


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _excluded_paths() -> list[str] | None:
    """Parse ``RS_EXCLUDED_PATHS`` (comma-separated) or return ``None`` so the
    middleware falls back to its own defaults (which include ``/health``).

    An unset OR empty ``RS_EXCLUDED_PATHS`` both fall back to the middleware
    defaults. An empty string (which is what ``boot_rs(excluded_paths=[])``
    serializes to) must NOT be read as an explicit "exclude nothing" list —
    that would drop the ``/health`` exclusion and break the readiness poll."""
    raw = os.environ.get("RS_EXCLUDED_PATHS")
    if not raw:
        return None
    return [p for p in raw.split(",") if p] or None


def create_app() -> FastAPI:
    """Build the resource-server app from ``RS_*`` env config.

    Required env: ``RS_DISCOVERY_URL``, ``RS_AUDIENCE``.
    Optional env: ``RS_REQUIRE_SCOPE`` (default ``api``),
    ``RS_REQUIRE_ACCESS_TOKEN_MARKER`` (bool, F-07 opt-in),
    ``RS_EXCLUDED_PATHS`` (comma-separated).
    """
    discovery_url = os.environ["RS_DISCOVERY_URL"]
    audience = os.environ["RS_AUDIENCE"]
    required_scope = os.environ.get("RS_REQUIRE_SCOPE", "api")

    # Materialise the exclusion set (defaults or the RS_EXCLUDED_PATHS override)
    # and always append ``/metrics`` — an unauthenticated readout the load driver
    # scrapes, which must never require a token regardless of the override.
    excluded = _excluded_paths() or _default_excluded_paths()
    if _METRICS_PATH not in excluded:
        excluded.append(_METRICS_PATH)

    app = FastAPI(title="token-harness-rs")
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=discovery_url,
        audience=audience,
        excluded_paths=excluded,
        require_access_token_marker=_truthy(
            os.environ.get("RS_REQUIRE_ACCESS_TOKEN_MARKER")
        ),
    )

    @app.get("/health")
    def health() -> dict:
        # Excluded from auth (middleware default) — the readiness probe target.
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics() -> dict:
        # Excluded from auth — per-process cache hit/miss/refresh counters
        # (T299). The load harness scrapes this at ``workers=1`` for an exact
        # cache-hit rate; across ``--workers N`` each worker keeps its own
        # counters, so aggregate the per-worker snapshots externally.
        return get_cache_counters().snapshot()

    @app.get("/protected", dependencies=[Depends(require_scope(required_scope))])
    def protected(claims: Claims) -> dict:
        # Reached only after the middleware validated the token AND the token
        # carries ``required_scope`` (else require_scope raises 403).
        return {
            "sub": claims.get("sub"),
            "scope": claims.get("scope") or claims.get("scp"),
        }

    @app.get("/whoami")
    def whoami(user: CurrentUser) -> dict:
        identity = user.identity
        return {"name": identity.name if identity is not None else None}

    @app.get("/health/deep")
    def health_deep(claims: Claims) -> dict:
        # A nested route UNDER the excluded "/health" prefix. With exact-match
        # exclusion (issue #600) "/health" no longer implies this subpath, so the
        # middleware validates it — reachable only WITH a valid token. Proves the
        # fail-closed default end-to-end: without a token the middleware 401s here
        # before routing; with one, the handler runs.
        return {"deep": True, "sub": claims.get("sub")}

    # WebSocket route (issue #598). The middleware never sees WebSocket scopes,
    # so this is guarded solely by the build_ws_authenticator dependency, which
    # runs the same core validate_token path + F-07 guard. A rejected token
    # closes the handshake before accept; a valid token reaches the body.
    ws_authenticator = build_ws_authenticator(
        discovery_url=discovery_url,
        audience=audience,
        require_access_token_marker=_truthy(
            os.environ.get("RS_REQUIRE_ACCESS_TOKEN_MARKER")
        ),
    )

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        # Invoke the authenticator explicitly rather than via ``Depends(...)``:
        # this module uses ``from __future__ import annotations`` (PEP 563), which
        # stringizes the ``Annotated[dict, Depends(ws_authenticator)]`` form so
        # FastAPI cannot resolve the closure-local ``ws_authenticator`` — the
        # marker is lost and every request 403s. Real apps (no closure-local dep)
        # use ``claims: dict = Depends(ws_auth)``; here the direct call is
        # equivalent and raises WebSocketException on rejection just the same.
        claims = await ws_authenticator(websocket)
        await websocket.accept()
        await websocket.send_json(
            {"sub": claims.get("sub"), "scope": claims.get("scope")}
        )
        await websocket.close()

    return app


# Module-level app so uvicorn can boot it by import string
# (``src.tests.harness.rs_app:app``) and forked workers re-import identically.
app = create_app()
