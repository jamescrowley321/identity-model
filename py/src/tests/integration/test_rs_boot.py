"""Real-HTTP DoD proof for TH-1.2 (#464 · epic #462).

Boots the greenfield resource server (``TokenValidationMiddleware +
require_scope``) under real uvicorn workers and drives it over httpx against a
live node-oidc issuer. This is the acceptance proof that the RS runs the
shipped middleware end-to-end — not an ASGI in-process shim.

Run via ``make test-harness-rs`` (Docker node-oidc + ``uv run --all-packages``
so ``fastapi_identity_model`` and ``uvicorn`` resolve). Under plain
``make test-integration-node-oidc`` the fastapi stack is absent, so the module
importorskips cleanly.
"""

import httpx
import jwt
import pytest

from ..harness.rs_server import boot_rs


pytest.importorskip("fastapi_identity_model")

pytestmark = pytest.mark.integration

# node-oidc issues JWT access tokens with aud=urn:test:api via
# resourceIndicators.defaultResource (infra/node-oidc-provider).
RS_AUDIENCE = "urn:test:api"
GENERIC_401_DETAIL = "Invalid or unauthorized token"


def _access_token(client_credentials_token) -> str:
    token = client_credentials_token.token.get("access_token", "")
    assert token, "CC fixture returned no access_token"
    return token


def _granted_scopes(access_token: str) -> list[str]:
    """Scopes actually present on the minted token (unverified decode)."""
    claims = jwt.decode(access_token, options={"verify_signature": False})
    raw = claims.get("scope") or claims.get("scp") or ""
    if isinstance(raw, str):
        return raw.split()
    return [s for s in raw if isinstance(s, str)]


@pytest.fixture(scope="module")
def rs_discovery_url(test_config, is_node_oidc_fixture) -> str:
    if not is_node_oidc_fixture:
        pytest.skip(
            "RS boot suite asserts node-oidc's urn:test:api audience / api "
            "scope; remote matrix providers mint different tokens"
        )
    return test_config["TEST_DISCO_ADDRESS"]


def test_valid_token_reaches_protected_route(
    rs_discovery_url, client_credentials_token
):
    """Valid CC token → 200, body echoes the validated claims."""
    access_token = _access_token(client_credentials_token)
    scopes = _granted_scopes(access_token)
    assert scopes, "minted token carried no scopes to guard on"

    with boot_rs(
        discovery_url=rs_discovery_url,
        audience=RS_AUDIENCE,
        require_scope=scopes[0],
    ) as base_url:
        response = httpx.get(
            f"{base_url}/protected",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )

    assert response.status_code == httpx.codes.OK
    body = response.json()
    assert body["sub"]
    assert scopes[0] in (body["scope"] or "")


def test_missing_authorization_is_uniform_401(rs_discovery_url):
    """No Authorization header → 401 with the middleware's own detail."""
    with boot_rs(discovery_url=rs_discovery_url, audience=RS_AUDIENCE) as base_url:
        response = httpx.get(f"{base_url}/protected", timeout=10.0)

    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json() == {"detail": "Missing Authorization header"}


def test_malformed_bearer_is_uniform_401(rs_discovery_url):
    """Garbage bearer → 401 with the generic (F-18) uniform body."""
    with boot_rs(discovery_url=rs_discovery_url, audience=RS_AUDIENCE) as base_url:
        response = httpx.get(
            f"{base_url}/protected",
            headers={"Authorization": "Bearer not-a-real-jwt"},
            timeout=10.0,
        )

    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json() == {"detail": GENERIC_401_DETAIL}


def test_missing_required_scope_is_403(rs_discovery_url, client_credentials_token):
    """Valid token but RS requires a scope the token lacks → 403 (require_scope)."""
    access_token = _access_token(client_credentials_token)
    absent_scope = "scope-the-token-does-not-carry"
    assert absent_scope not in _granted_scopes(access_token)

    with boot_rs(
        discovery_url=rs_discovery_url,
        audience=RS_AUDIENCE,
        require_scope=absent_scope,
    ) as base_url:
        response = httpx.get(
            f"{base_url}/protected",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )

    assert response.status_code == httpx.codes.FORBIDDEN
    assert absent_scope in response.json()["detail"]


def test_health_route_is_unauthenticated(rs_discovery_url):
    """Excluded /health answers 200 with no Authorization (readiness proof)."""
    with boot_rs(discovery_url=rs_discovery_url, audience=RS_AUDIENCE) as base_url:
        response = httpx.get(f"{base_url}/health", timeout=10.0)

    assert response.status_code == httpx.codes.OK
    assert response.json() == {"status": "ok"}


def test_boots_under_multiple_workers(rs_discovery_url, client_credentials_token):
    """uvicorn --workers 2 boots and serves a valid token → 200."""
    access_token = _access_token(client_credentials_token)
    scopes = _granted_scopes(access_token)
    assert scopes, "minted token carried no scopes to guard on"

    with boot_rs(
        discovery_url=rs_discovery_url,
        audience=RS_AUDIENCE,
        require_scope=scopes[0],
        workers=2,
    ) as base_url:
        response = httpx.get(
            f"{base_url}/protected",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )

    assert response.status_code == httpx.codes.OK
