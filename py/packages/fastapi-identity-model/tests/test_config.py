import pytest

from fastapi_identity_model import OIDCSettings, TokenManager
from py_identity_model import TokenBinding


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


@pytest.mark.parametrize(("discovery_url", "client_id"), [("", "cid"), ("d", "")])
def test_empty_required_fields_rejected(discovery_url, client_id):
    with pytest.raises(ValueError, match="non-empty"):
        OIDCSettings(discovery_url=discovery_url, client_id=client_id)


def test_required_binding_string_is_coerced_to_token_binding():
    s = OIDCSettings(discovery_url="d", client_id="cid", required_binding="dpop")
    assert s.required_binding is TokenBinding.DPOP


def test_unknown_required_binding_string_is_rejected():
    with pytest.raises(ValueError, match="'bearer' is not a valid TokenBinding"):
        OIDCSettings(discovery_url="d", client_id="cid", required_binding="bearer")


def test_client_secret_not_in_repr():
    s = OIDCSettings(
        discovery_url="https://op.example.com/.well-known/openid-configuration",
        client_id="cid",
        client_secret="s3cr3t",
    )
    assert "s3cr3t" not in repr(s)
    assert s.client_secret == "s3cr3t"


def test_token_manager_repr_omits_secrets():
    manager = TokenManager(
        discovery_url="https://op.example.com/.well-known/openid-configuration",
        client_id="cid",
        client_secret="s3cr3t",
    )
    manager.set_tokens(access_token="at-s3cr3t", refresh_token="rt-s3cr3t")
    assert "s3cr3t" not in repr(manager)
