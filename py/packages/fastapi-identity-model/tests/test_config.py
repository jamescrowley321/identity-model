import dataclasses
import inspect
from typing import Any

import pytest

from fastapi_identity_model import AuthOptions, OIDCSettings, TokenManager
from py_identity_model import TokenBinding


pytestmark = pytest.mark.unit


def test_audience_defaults_to_client_id():
    s = OIDCSettings(
        discovery_url="https://op/.well-known/openid-configuration",
        client_id="cid",
        redirect_uri="http://localhost/cb",
    )
    assert (s.audience, s.expected_audience) == (None, "cid")
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


def test_trusted_audiences_default_to_none_trusted():
    s = OIDCSettings(discovery_url="d", client_id="cid")
    assert (s.trusted_audiences, s.validate_azp) == ([], False)


def test_trusted_audiences_tuple_is_stored_as_list():
    audiences: Any = ("urn:a",)
    s = OIDCSettings(discovery_url="d", client_id="cid", trusted_audiences=audiences)
    assert s.trusted_audiences == ["urn:a"]


@pytest.mark.parametrize("audiences", ["urn:api", None, {"urn:api"}])
def test_trusted_audiences_must_be_a_list(audiences):
    with pytest.raises(ValueError, match="trusted_audiences must be a list of strings"):
        OIDCSettings(discovery_url="d", client_id="cid", trusted_audiences=audiences)


@pytest.mark.parametrize("entry", ["", 7, None])
def test_trusted_audiences_entries_must_be_non_empty_strings(entry):
    with pytest.raises(ValueError, match="trusted_audiences entries"):
        OIDCSettings(
            discovery_url="d", client_id="cid", trusted_audiences=["urn:a", entry]
        )


@pytest.mark.parametrize("value", ["false", 1, None])
def test_validate_azp_must_be_a_bool(value):
    with pytest.raises(ValueError, match="validate_azp must be a bool"):
        OIDCSettings(discovery_url="d", client_id="cid", validate_azp=value)


@pytest.mark.parametrize("cls", [OIDCSettings, AuthOptions], ids=lambda c: c.__name__)
def test_settings_types_are_frozen_and_keyword_only(cls):
    assert cls.__dataclass_params__.frozen is True
    positional = [
        name
        for name, param in inspect.signature(cls).parameters.items()
        if param.kind is not inspect.Parameter.KEYWORD_ONLY
    ]
    assert positional == []


def test_settings_replace_revalidates():
    s = OIDCSettings(
        discovery_url="https://op/.well-known/openid-configuration", client_id="cid"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.audience = "api"  # type: ignore[misc]
    with pytest.raises(
        ValueError, match=r"^OIDCSettings requires a non-empty client_id$"
    ):
        dataclasses.replace(s, client_id="")


def test_auth_options_replace_keeps_shared_replay_cache():
    opts = AuthOptions()
    assert (
        dataclasses.replace(opts, expected_origin="https://api.example.com").dpop
        is opts.dpop
    )


def test_replace_client_id_moves_the_default_audience():
    s = OIDCSettings(
        discovery_url="https://op/.well-known/openid-configuration", client_id="app-a"
    )
    assert dataclasses.replace(s, client_id="app-b").expected_audience == "app-b"


def test_explicit_audience_survives_replace():
    s = OIDCSettings(
        discovery_url="https://op/.well-known/openid-configuration",
        client_id="app-a",
        audience="api://resource",
    )
    assert dataclasses.replace(s, client_id="app-b").expected_audience == (
        "api://resource"
    )
