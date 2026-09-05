import pytest

from fastapi_identity_model import OIDCSettings


pytestmark = pytest.mark.unit


def test_audience_defaults_to_client_id():
    s = OIDCSettings(
        discovery_url="https://op/.well-known/openid-configuration",
        client_id="cid",
        redirect_uri="http://localhost/cb",
    )
    assert s.audience == "cid"
    assert s.scope == "openid profile email"
    assert s.excluded_paths == [
        "/docs",
        "/docs/oauth2-redirect",
        "/openapi.json",
        "/health",
    ]


def test_explicit_audience_preserved():
    s = OIDCSettings(
        discovery_url="d",
        client_id="cid",
        redirect_uri="r",
        audience="api://resource",
    )
    assert s.audience == "api://resource"


def test_from_env(monkeypatch):
    monkeypatch.setenv(
        "OIDC_DISCOVERY_URL", "https://op/.well-known/openid-configuration"
    )
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost/cb")
    monkeypatch.setenv("OIDC_SCOPE", "openid email")
    monkeypatch.setenv("OIDC_EXCLUDED_PATHS", "/a, /b ,/c")

    s = OIDCSettings.from_env()
    assert s.client_id == "cid"
    assert s.scope == "openid email"
    assert s.excluded_paths == ["/a", "/b", "/c"]
    assert s.audience == "cid"


def test_from_env_missing_required(monkeypatch):
    monkeypatch.delenv("OIDC_DISCOVERY_URL", raising=False)
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost/cb")
    with pytest.raises(ValueError, match="OIDC_DISCOVERY_URL"):
        OIDCSettings.from_env()


def test_from_env_default_excluded_paths(monkeypatch):
    monkeypatch.setenv("OIDC_DISCOVERY_URL", "d")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "r")
    monkeypatch.delenv("OIDC_EXCLUDED_PATHS", raising=False)
    s = OIDCSettings.from_env()
    assert s.excluded_paths == [
        "/docs",
        "/docs/oauth2-redirect",
        "/openapi.json",
        "/health",
    ]


def test_from_env_redirect_uri_optional_for_resource_server(monkeypatch):
    # A resource-server-only deployment (middleware, no login router) needs no
    # callback URL.
    monkeypatch.setenv("OIDC_DISCOVERY_URL", "d")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.delenv("OIDC_REDIRECT_URI", raising=False)
    s = OIDCSettings.from_env()
    assert s.redirect_uri == ""


@pytest.mark.parametrize(("discovery_url", "client_id"), [("", "cid"), ("d", "")])
def test_empty_required_fields_rejected(discovery_url, client_id):
    with pytest.raises(ValueError, match="non-empty"):
        OIDCSettings(discovery_url=discovery_url, client_id=client_id)
