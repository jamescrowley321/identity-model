"""Fail-closed control tests: mTLS client credentials and discovery URL derivation.

``build_mtls_ssl_context`` must load exactly the configured certificate, key
and password, and verify the server against exactly the configured CA bundle.
``discovery_document_url`` must derive the OIDC Discovery 1.0 §4.1 URL from
the issuer unchanged apart from the terminating ``/``.
"""

from __future__ import annotations

import ssl
from typing import Any

import pytest

from py_identity_model.core.config import HTTPConfig
from py_identity_model.core.discovery_policy import discovery_document_url
from py_identity_model.core.models import MtlsClientAuth
import py_identity_model.core.mtls as mtls_module
from py_identity_model.exceptions import ConfigurationException


class _RecordingContext:
    def __init__(self, kwargs: dict[str, Any]) -> None:
        self.created_with = kwargs
        self.chains: list[tuple[Any, ...]] = []

    def load_cert_chain(self, *args: Any) -> None:
        self.chains.append(args)


@pytest.fixture
def recorded(monkeypatch, tmp_path) -> list[_RecordingContext]:
    # HTTPConfig checks that ca_bundle is a readable file.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ca.pem").write_text("placeholder CA bundle")
    contexts: list[_RecordingContext] = []

    def create_default_context(**kwargs: Any) -> _RecordingContext:
        ctx = _RecordingContext(kwargs)
        contexts.append(ctx)
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", create_default_context)
    return contexts


@pytest.mark.parametrize(
    ("password", "ca_bundle", "expected_create", "expected_chain"),
    [
        (None, None, {}, ("/certs/client.crt", "/certs/client.key")),
        (
            "s3cret",
            None,
            {},
            ("/certs/client.crt", "/certs/client.key", "s3cret"),
        ),
        (
            None,
            "ca.pem",
            {"cafile": "ca.pem"},
            ("/certs/client.crt", "/certs/client.key"),
        ),
        (
            "s3cret",
            "ca.pem",
            {"cafile": "ca.pem"},
            ("/certs/client.crt", "/certs/client.key", "s3cret"),
        ),
    ],
    ids=["no-password", "password", "ca-bundle", "password-and-ca-bundle"],
)
def test_mtls_context_loads_exactly_the_configured_credentials(
    recorded, password, ca_bundle, expected_create, expected_chain
):
    mtls = MtlsClientAuth(
        certificate_path="/certs/client.crt",
        private_key_path="/certs/client.key",
        password=password,
    )
    ctx = mtls_module.build_mtls_ssl_context(mtls, HTTPConfig(ca_bundle=ca_bundle))
    assert [(c.created_with, c.chains) for c in recorded] == [
        (expected_create, [expected_chain])
    ]
    assert ctx is recorded[0]


@pytest.mark.parametrize(
    ("issuer", "expected"),
    [
        ("https://op.example", "https://op.example/.well-known/openid-configuration"),
        (
            "https://op.example/",
            "https://op.example/.well-known/openid-configuration",
        ),
        (
            "https://op.example/tenantX",
            "https://op.example/tenantX/.well-known/openid-configuration",
        ),
        (
            "https://op.example/tenant ",
            "https://op.example/tenant /.well-known/openid-configuration",
        ),
        (
            "https://op.example/a/b/",
            "https://op.example/a/b/.well-known/openid-configuration",
        ),
    ],
)
def test_discovery_url_keeps_the_issuer_path(issuer, expected):
    assert discovery_document_url(issuer) == expected


@pytest.mark.parametrize(
    "issuer",
    [
        "",
        "op.example",
        "javascript://op.example",
        "https://",
        "https://op.example?x=1",
        "https://op.example#f",
        "https://op.example/.well-known/openid-configuration",
        "https://op.example/.well-known/openid-configuration/",
    ],
)
def test_discovery_url_refuses_non_issuers(issuer):
    with pytest.raises(ConfigurationException):
        discovery_document_url(issuer)
