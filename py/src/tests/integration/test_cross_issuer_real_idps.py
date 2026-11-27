"""Real cross-issuer proof against the bundled Docker IdPs (epic #462).

The mock-OP matrix proves cross-issuer rejection deterministically in one process
(``test_correctness_matrix.test_cross_issuer_...``). This proves the same property
with **real tokens from two real IdPs running side by side** — the bundled
node-oidc-provider (:9010) and Keycloak (:8080) Docker fixtures.

For each provider it mints a genuine client-credentials access token, then:

* the provider's OWN token reaches ``/protected`` on an RS trusting that provider
  (200) — proving the token is really valid, so a cross rejection is not just a
  malformed-token artefact; and
* every OTHER provider's token is rejected by that same RS (401) — the real
  cross-issuer / mix-up: a validly-signed token from issuer A must not be honoured
  by a resource server that trusts issuer B (A's key/kid is absent from B's JWKS
  and A's ``iss`` does not match B's discovery issuer).

Needs BOTH fixtures reachable; skips cleanly when either is down (so it no-ops in
a single-provider env). Run via ``make test-harness-cross-issuer`` or the
``integration-tests-cross-issuer`` CI job (which starts both fixtures).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
import jwt
import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    get_discovery_document,
    request_client_credentials_token,
)

from ..harness.rs_server import boot_rs
from .test_utils import issuer_from_discovery_address


pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

pytestmark = pytest.mark.integration

# py/src/tests/integration/test_*.py -> parents[4] is the true repo root, which
# holds the shared .env.* provider profiles (polyglot: py/go/rust all read them).
_REPO_ROOT = Path(__file__).resolve().parents[4]


@dataclass(frozen=True)
class ProviderConfig:
    """The client-credentials config for one bundled Docker IdP."""

    name: str
    env_file: str


# The two IdPs that run as Docker fixtures in this repo (remote providers —
# Descope/Ory — are not brought up here, so they are out of scope for a
# side-by-side cross-issuer run).
PROVIDERS = (
    ProviderConfig(name="node-oidc", env_file=".env.node-oidc"),
    ProviderConfig(name="keycloak", env_file=".env.keycloak"),
)


def _read_env(env_file: str) -> dict[str, str]:
    """Parse a committed ``.env.<provider>`` fixture file into a dict."""
    values: dict[str, str] = {}
    for raw in (_REPO_ROOT / env_file).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


def _mint_real_token(cfg: ProviderConfig) -> str:
    """Mint a genuine client-credentials access token from *cfg*'s live IdP.

    Skips (not fails) when the fixture is unreachable, so the module no-ops in a
    single-provider environment rather than reporting a spurious failure.
    """
    env = _read_env(cfg.env_file)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(
            issuer=issuer_from_discovery_address(env["TEST_DISCO_ADDRESS"])
        )
    )
    if not disco.is_successful or not disco.token_endpoint:
        pytest.skip(f"{cfg.name} discovery unreachable: {disco.error}")
    token_response = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            client_id=env["TEST_CLIENT_ID"],
            client_secret=env["TEST_CLIENT_SECRET"],
            address=disco.token_endpoint,
            scope=env.get("TEST_SCOPE") or "openid",
        )
    )
    if not token_response.is_successful or token_response.token is None:
        pytest.skip(f"{cfg.name} token mint failed: {token_response.error}")
    access_token = token_response.token.get("access_token", "")
    assert access_token, f"{cfg.name} returned no access_token"
    return access_token


def _audience_and_scope(token: str) -> tuple[str | None, str | None]:
    """Extract a usable RS audience + required scope from a real access token.

    The RS is configured from the token itself (not a hardcoded per-provider
    value) so a positive control accepts the token on its own merits. ``aud`` may
    be a list (pyjwt accepts the configured audience if it is a member), so the
    first entry is used; the first granted scope drives ``require_scope``.
    """
    claims = jwt.decode(token, options={"verify_signature": False})
    aud = claims.get("aud")
    if isinstance(aud, (list, tuple)):
        aud = aud[0] if aud else None
    raw_scope = claims.get("scope") or claims.get("scp") or ""
    scopes = raw_scope.split() if isinstance(raw_scope, str) else list(raw_scope)
    return aud, (scopes[0] if scopes else None)


def _get_protected(base_url: str, token: str) -> int:
    return httpx.get(
        f"{base_url}/protected",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    ).status_code


@pytest.fixture(scope="module")
def real_idp_tokens() -> dict[str, str]:
    """A real client-credentials access token from every bundled Docker IdP."""
    return {cfg.name: _mint_real_token(cfg) for cfg in PROVIDERS}


def test_real_cross_issuer_tokens_are_rejected(real_idp_tokens):
    """A real token from each Docker IdP is accepted only by its own issuer's RS.

    For every provider: boot an RS trusting that provider (audience + scope taken
    from the provider's own minted token), confirm the provider's token is
    accepted (200 — genuinely valid), then confirm every OTHER provider's real
    token is rejected (401 — the cross-issuer negative).
    """
    for owner, token in real_idp_tokens.items():
        env = _read_env(next(p.env_file for p in PROVIDERS if p.name == owner))
        audience, scope = _audience_and_scope(token)
        assert audience, f"{owner} token carried no audience to bind the RS to"

        boot_kwargs = {
            "issuer": issuer_from_discovery_address(env["TEST_DISCO_ADDRESS"]),
            "audience": audience,
        }
        if scope:
            boot_kwargs["require_scope"] = scope

        with boot_rs(**boot_kwargs) as rs_base:
            own = _get_protected(rs_base, token)
            assert own == httpx.codes.OK, (
                f"{owner}'s own real token was not accepted by its own RS "
                f"(got {own}) — cannot trust the cross-issuer negative"
            )
            for other, other_token in real_idp_tokens.items():
                if other == owner:
                    continue
                cross = _get_protected(rs_base, other_token)
                assert cross == httpx.codes.UNAUTHORIZED, (
                    f"RS trusting {owner!r} accepted {other!r}'s real token "
                    f"(got {cross}, want 401) — CROSS-ISSUER LEAK"
                )
