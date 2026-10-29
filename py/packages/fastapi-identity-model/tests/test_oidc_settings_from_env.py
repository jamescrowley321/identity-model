"""``oidc_settings_from_env`` builds ``OIDCSettings`` from the environment.

The package never calls it. An app that wants environment configuration
imports it from ``fastapi_identity_model.config_helpers``; any other app
constructs ``OIDCSettings`` itself.
"""

import pytest

import fastapi_identity_model
from fastapi_identity_model import OIDCSettings
from fastapi_identity_model.config_helpers import oidc_settings_from_env
from py_identity_model import TokenBinding


pytestmark = pytest.mark.unit

_DEFAULT_EXCLUDED_PATHS = [
    "/docs",
    "/docs/oauth2-redirect",
    "/openapi.json",
    "/health",
]


@pytest.fixture
def clean_env(monkeypatch):
    for name in (
        "DISCOVERY_URL",
        "CLIENT_ID",
        "REDIRECT_URI",
        "CLIENT_SECRET",
        "SCOPE",
        "AUDIENCE",
        "POST_LOGIN_REDIRECT",
        "POST_LOGOUT_REDIRECT",
        "EXCLUDED_PATHS",
        "REQUIRED_BINDING",
    ):
        monkeypatch.delenv(f"OIDC_{name}", raising=False)
        monkeypatch.delenv(f"APP_{name}", raising=False)
    return monkeypatch


def test_every_setting_is_read(clean_env):
    clean_env.setenv(
        "OIDC_DISCOVERY_URL", "https://op/.well-known/openid-configuration"
    )
    clean_env.setenv("OIDC_CLIENT_ID", "cid")
    clean_env.setenv("OIDC_REDIRECT_URI", "http://localhost/cb")
    clean_env.setenv("OIDC_CLIENT_SECRET", "secret")
    clean_env.setenv("OIDC_SCOPE", "openid email")
    clean_env.setenv("OIDC_AUDIENCE", "api://resource")
    clean_env.setenv("OIDC_POST_LOGIN_REDIRECT", "/home")
    clean_env.setenv("OIDC_POST_LOGOUT_REDIRECT", "/bye")
    clean_env.setenv("OIDC_EXCLUDED_PATHS", "/a, /b ,/c")
    clean_env.setenv("OIDC_REQUIRED_BINDING", "dpop")

    assert oidc_settings_from_env() == OIDCSettings(
        discovery_url="https://op/.well-known/openid-configuration",
        client_id="cid",
        redirect_uri="http://localhost/cb",
        client_secret="secret",
        scope="openid email",
        audience="api://resource",
        post_login_redirect="/home",
        post_logout_redirect="/bye",
        excluded_paths=["/a", "/b", "/c"],
        required_binding=TokenBinding.DPOP,
    )


def test_unset_optional_settings_take_the_defaults(clean_env):
    clean_env.setenv("OIDC_DISCOVERY_URL", "d")
    clean_env.setenv("OIDC_CLIENT_ID", "cid")

    settings = oidc_settings_from_env()

    assert settings == OIDCSettings(discovery_url="d", client_id="cid")
    assert settings.redirect_uri == ""
    assert settings.audience == "cid"
    assert settings.excluded_paths == _DEFAULT_EXCLUDED_PATHS
    assert settings.required_binding is TokenBinding.NONE


def test_unknown_required_binding_is_rejected(clean_env):
    clean_env.setenv("OIDC_DISCOVERY_URL", "d")
    clean_env.setenv("OIDC_CLIENT_ID", "cid")
    clean_env.setenv("OIDC_REQUIRED_BINDING", "bearer")

    with pytest.raises(ValueError, match="'bearer' is not a valid TokenBinding"):
        oidc_settings_from_env()


@pytest.mark.parametrize("missing", ["DISCOVERY_URL", "CLIENT_ID"])
@pytest.mark.parametrize("value", [None, ""])
def test_missing_required_setting_names_the_variable(clean_env, missing, value):
    clean_env.setenv("OIDC_DISCOVERY_URL", "d")
    clean_env.setenv("OIDC_CLIENT_ID", "cid")
    if value is None:
        clean_env.delenv(f"OIDC_{missing}")
    else:
        clean_env.setenv(f"OIDC_{missing}", value)

    with pytest.raises(ValueError, match=f"OIDC_{missing}"):
        oidc_settings_from_env()


def test_prefix_applies_to_every_variable(clean_env):
    clean_env.setenv("OIDC_DISCOVERY_URL", "ignored")
    clean_env.setenv("OIDC_CLIENT_ID", "ignored")
    clean_env.setenv("APP_DISCOVERY_URL", "d")
    clean_env.setenv("APP_CLIENT_ID", "cid")
    clean_env.setenv("APP_SCOPE", "openid")

    assert oidc_settings_from_env("APP_") == OIDCSettings(
        discovery_url="d", client_id="cid", scope="openid"
    )


def test_settings_have_no_environment_constructor():
    assert hasattr(OIDCSettings, "from_env") is False


def test_helper_is_not_re_exported_at_the_top_level():
    assert "oidc_settings_from_env" not in fastapi_identity_model.__all__
    assert hasattr(fastapi_identity_model, "oidc_settings_from_env") is False
