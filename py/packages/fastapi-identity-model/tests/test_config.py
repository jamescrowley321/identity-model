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


@pytest.mark.parametrize(("discovery_url", "client_id"), [("", "cid"), ("d", "")])
def test_empty_required_fields_rejected(discovery_url, client_id):
    with pytest.raises(ValueError, match="non-empty"):
        OIDCSettings(discovery_url=discovery_url, client_id=client_id)
