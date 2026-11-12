"""Request models never print credentials in ``repr`` or ``str`` (#1113).

Every ``BaseRequest`` subclass that carries a credential, plus the
client-auth key holders, is built with a distinct sentinel in each
credential field. The test fails if any sentinel shows up in ``repr`` or
``str``, so a new request model, or a new credential field on an existing
one, is covered without editing this file.
"""

from __future__ import annotations

import dataclasses

import pytest

from py_identity_model.core.models import (
    BaseRequest,
    MtlsClientAuth,
    PrivateKeyJwt,
    RequestObjectKey,
)


CREDENTIAL_FIELDS = frozenset(
    {
        "actor_token",
        "client_secret",
        "code",
        "code_verifier",
        "device_code",
        "initial_access_token",
        "password",
        "private_key",
        "refresh_token",
        "registration_access_token",
        "request",
        "subject_token",
        "token",
    }
)

ADDRESS = "https://op.example.com/endpoint"
REDIRECT_URIS = ["https://rp.example.com/callback"]


def _subclasses(cls: type) -> list[type]:
    found: list[type] = []
    for sub in cls.__subclasses__():
        found.append(sub)
        found.extend(_subclasses(sub))
    return found


MODELS = sorted(
    (
        cls
        for cls in {
            *_subclasses(BaseRequest),
            PrivateKeyJwt,
            RequestObjectKey,
            MtlsClientAuth,
        }
        if any(f.name in CREDENTIAL_FIELDS for f in dataclasses.fields(cls))
    ),
    key=lambda cls: cls.__name__,
)


def _sentinel(name: str) -> str:
    return f"SENTINEL-SECRET-{name}"


def _build(cls: type) -> tuple[object, dict[str, str]]:
    """Instantiate ``cls`` with a sentinel in every credential field."""
    kwargs: dict[str, object] = {}
    secrets: dict[str, str] = {}
    for f in dataclasses.fields(cls):
        if not f.init:
            continue
        if f.name in CREDENTIAL_FIELDS:
            secrets[f.name] = kwargs[f.name] = _sentinel(f.name)
        elif f.default is dataclasses.MISSING and (
            f.default_factory is dataclasses.MISSING
        ):
            kwargs[f.name] = REDIRECT_URIS if "list" in str(f.type) else ADDRESS
    return cls(**kwargs), secrets


@pytest.mark.parametrize("cls", MODELS, ids=lambda cls: cls.__name__)
def test_repr_and_str_never_contain_credentials(cls: type) -> None:
    instance, secrets = _build(cls)
    rendered = repr(instance) + str(instance)
    leaked = sorted(name for name, value in secrets.items() if value in rendered)
    assert leaked == []


def test_model_discovery_covers_every_request_model() -> None:
    names = {cls.__name__ for cls in MODELS}
    assert {
        "AuthorizationCodeTokenRequest",
        "ClientCredentialsTokenRequest",
        "PushedAuthorizationRequest",
        "TokenExchangeRequest",
        "UserInfoRequest",
    } <= names
