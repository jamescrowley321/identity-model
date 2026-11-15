"""Unit tests for TokenSource capability/credential gating (TH-1.1, #463).

The gating mirrors ``provider_matrix.detect_capabilities``: an unsupported
grant raises :class:`HarnessCapabilityError`, a supported grant with absent
credentials raises :class:`HarnessCredentialError`, and the ``MOCK`` provider
is always mintable (valid + forged).
"""

from __future__ import annotations

import base64
import json

import jwt
import pytest
import respx

from ..harness import (
    Grant,
    HarnessCapabilityError,
    HarnessCredentialError,
    Malform,
    MintSpec,
    Provider,
    ProviderConfig,
    TokenSource,
    prime_pool,
)
from ..harness.token_source import _peek_jwt_header


JWT_SEGMENT_COUNT = 2
DEDUPED_POOL_SIZE = 2


def test_mock_provider_is_always_mintable() -> None:
    source = TokenSource.with_mock()
    token = source.mint(Provider.MOCK, Grant.CLIENT_CREDENTIALS)
    assert token.provider is Provider.MOCK
    assert token.malform is Malform.VALID
    assert token.access_token.count(".") == JWT_SEGMENT_COUNT  # a real JWT
    assert token.expires_at is not None
    assert token.alg == "RS256"


def test_mock_provider_mints_every_forged_class() -> None:
    source = TokenSource.with_mock()
    for malform in Malform:
        token = source.mint(Provider.MOCK, malform=malform)
        assert token.malform is malform
        assert token.access_token  # non-empty


def test_forged_tokens_are_mock_only() -> None:
    node = ProviderConfig(
        provider=Provider.NODE_OIDC,
        capabilities={"client_credentials"},
        token_endpoint="https://issuer.example/token",
        client_id="cid",
        client_secret="secret",
    )
    source = TokenSource([node])
    with pytest.raises(HarnessCapabilityError, match="MOCK provider"):
        source.mint(Provider.NODE_OIDC, malform=Malform.ALG_NONE)


def test_capability_gating_rejects_unsupported_grant() -> None:
    # Advertises only client_credentials — auth_code must be capability-gated.
    node = ProviderConfig(
        provider=Provider.NODE_OIDC,
        capabilities={"client_credentials"},
        token_endpoint="https://issuer.example/token",
        client_id="cid",
        client_secret="secret",
    )
    source = TokenSource([node])
    with pytest.raises(HarnessCapabilityError, match="authorization_code"):
        source.mint(Provider.NODE_OIDC, Grant.AUTHORIZATION_CODE)


def test_credential_gating_when_secret_absent() -> None:
    # Capability present, credentials missing -> credential error (drives skip).
    ory = ProviderConfig(
        provider=Provider.ORY,
        capabilities={"client_credentials"},
        token_endpoint="https://issuer.example/token",
        client_id=None,
        client_secret=None,
    )
    source = TokenSource([ory])
    with pytest.raises(HarnessCredentialError):
        source.mint(Provider.ORY, Grant.CLIENT_CREDENTIALS)


@pytest.mark.parametrize("provider", [Provider.KEYCLOAK, Provider.ZITADEL])
def test_auth_code_requires_injected_minter(provider: Provider) -> None:
    config = ProviderConfig(
        provider=provider,
        capabilities={"authorization_code"},
    )
    source = TokenSource([config])
    with pytest.raises(HarnessCredentialError, match="auth-code minter"):
        source.mint(provider, Grant.AUTHORIZATION_CODE)


def test_unconfigured_provider_raises_capability_error() -> None:
    source = TokenSource.with_mock()
    with pytest.raises(HarnessCapabilityError, match="not configured"):
        source.mint(Provider.DESCOPE, Grant.CLIENT_CREDENTIALS)


def test_from_discovery_derives_capabilities() -> None:
    disco = {
        "issuer": "http://localhost:9000",
        "token_endpoint": "http://localhost:9000/token",
        "authorization_endpoint": "http://localhost:9000/auth",
        "grant_types_supported": ["client_credentials", "authorization_code"],
    }
    cfg = ProviderConfig.from_discovery(
        Provider.NODE_OIDC, disco, client_id="cid", client_secret="secret"
    )
    assert "client_credentials" in cfg.capabilities
    assert "authorization_code" in cfg.capabilities
    assert cfg.token_endpoint == "http://localhost:9000/token"


def test_auth_code_minter_is_invoked() -> None:
    calls: list[tuple[str | None, str | None]] = []

    def minter(tenant: str | None, scopes: str | None) -> dict:
        calls.append((tenant, scopes))
        return {"access_token": "opaque-token", "token_type": "Bearer"}

    cfg = ProviderConfig(
        provider=Provider.KEYCLOAK,
        capabilities={"authorization_code"},
        auth_code_minter=minter,
    )
    source = TokenSource([cfg])
    token = source.mint(
        Provider.KEYCLOAK, Grant.AUTHORIZATION_CODE, tenant="t1", scopes="openid"
    )
    assert token.access_token == "opaque-token"
    assert calls == [("t1", "openid")]


def test_descope_multitenant_requires_management_creds() -> None:
    # Plain CC creds present, but the multi-tenant (tenant=…) path needs the
    # access-key exchange config; absent -> credential error (drives skip).
    descope = ProviderConfig(
        provider=Provider.DESCOPE,
        capabilities={"client_credentials"},
        token_endpoint="https://api.descope.com/oauth2/v1/token",
        client_id="cid",
        client_secret="secret",
    )
    source = TokenSource([descope])
    with pytest.raises(HarnessCredentialError, match="multi-tenant"):
        source.mint(Provider.DESCOPE, Grant.CLIENT_CREDENTIALS, tenant="t1")


@respx.mock
def test_descope_multitenant_exchange_produces_dct_tenants() -> None:
    # AC-3: the multi-tenant path reuses access-key create -> exchange -> delete
    # and returns the session JWT carrying distinct dct/tenants claims.
    base = "https://api.descope.com"
    session_jwt = jwt.encode(
        {"sub": "u1", "dct": "t1", "tenants": {"t1": {"roles": ["admin"]}}},
        "x" * 32,
        algorithm="HS256",
    )
    create = respx.post(f"{base}/v1/mgmt/accesskey/create").respond(
        json={"key": {"id": "k1"}, "cleartext": "ck"}
    )
    exchange = respx.post(f"{base}/v1/auth/accesskey/exchange").respond(
        json={"sessionJwt": session_jwt}
    )
    delete = respx.post(f"{base}/v1/mgmt/accesskey/delete").respond(json={})

    cfg = ProviderConfig(
        provider=Provider.DESCOPE,
        capabilities={"client_credentials"},
        descope_project_id="P1",
        descope_management_key="MK",
        descope_base_url=base,
    )
    token = TokenSource([cfg]).mint(
        Provider.DESCOPE, Grant.CLIENT_CREDENTIALS, tenant="t1"
    )

    assert token.access_token == session_jwt
    assert token.tenant == "t1"
    # keyTenants array shaping (not top-level tenantId) is what yields dct/tenants.
    body = json.loads(create.calls.last.request.content)
    assert body["keyTenants"] == [{"tenantId": "t1", "roleNames": ["owner", "admin"]}]
    payload = json.loads(
        base64.urlsafe_b64decode(token.access_token.split(".")[1] + "==").decode()
    )
    assert payload["dct"] == "t1"
    assert "t1" in payload["tenants"]
    assert exchange.called
    assert delete.called  # temporary key cleaned up


def test_peek_jwt_header_guards_non_object_header() -> None:
    """A JWT whose header segment decodes to a non-object (e.g. ``5``) must not
    crash header inspection — return ``(None, None)`` like an opaque token."""
    non_object_header = base64.urlsafe_b64encode(b"5").rstrip(b"=").decode()
    token = f"{non_object_header}.{non_object_header}.sig"
    assert _peek_jwt_header(token) == (None, None)


def test_replay_pool_mints_once() -> None:
    source = TokenSource.with_mock()
    specs = [
        MintSpec(Provider.MOCK, Grant.CLIENT_CREDENTIALS),
        MintSpec(Provider.MOCK, Grant.CLIENT_CREDENTIALS),  # duplicate -> deduped
        MintSpec(Provider.MOCK, malform=Malform.EXPIRED),
    ]
    pool = prime_pool(source, specs)
    assert len(pool) == DEDUPED_POOL_SIZE
    valid = pool.get(MintSpec(Provider.MOCK, Grant.CLIENT_CREDENTIALS))
    assert valid.malform is Malform.VALID
