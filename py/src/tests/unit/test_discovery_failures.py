"""Discovery failure metadata comes from the failing operation, never its prose."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryErrorKind,
    get_discovery_document,
)
from py_identity_model.aio.discovery import get_discovery_document as async_discover
from py_identity_model.core.discovery_policy import DiscoveryPolicy


ADDRESS = "https://server.example.com/.well-known/openid-configuration"
# Mutation tests copy this module under py/mutants/, changing its depth.
_VALID_FIXTURE = next(
    parent / "spec/test-fixtures/discovery/valid.json"
    for parent in Path(__file__).resolve().parents
    if (parent / "spec/test-fixtures/discovery/valid.json").is_file()
)
VALID = json.loads(_VALID_FIXTURE.read_text())


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("status", "body", "content_type", "kind", "fields"),
    [
        (
            404,
            "Invalid JSON response; HTTPS is required; jwks_uri; status code: 500",
            "text/plain",
            DiscoveryErrorKind.UNEXPECTED_STATUS,
            (),
        ),
        (
            500,
            "issuer mismatch",
            "application/json",
            DiscoveryErrorKind.UNEXPECTED_STATUS,
            (),
        ),
        (200, "not json", "application/json", DiscoveryErrorKind.INVALID_JSON, ()),
        (
            200,
            "Invalid JSON response",
            "text/plain",
            DiscoveryErrorKind.INVALID_DOCUMENT,
            (),
        ),
        (
            200,
            json.dumps({k: v for k, v in VALID.items() if k != "jwks_uri"}),
            "application/json",
            DiscoveryErrorKind.MISSING_FIELDS,
            ("jwks_uri",),
        ),
        (
            200,
            json.dumps(
                {
                    k: v
                    for k, v in VALID.items()
                    if k not in {"subject_types_supported", "response_types_supported"}
                }
            ),
            "application/json",
            DiscoveryErrorKind.MISSING_FIELDS,
            ("response_types_supported", "subject_types_supported"),
        ),
    ],
)
@respx.mock
async def test_discovery_reports_failure_metadata(  # noqa: PLR0913
    asynchronous, status, body, content_type, kind, fields
):
    respx.get(ADDRESS).mock(
        return_value=httpx.Response(
            status, text=body, headers={"content-type": content_type}
        )
    )
    request = DiscoveryDocumentRequest(address=ADDRESS)
    response = (
        await async_discover(request)
        if asynchronous
        else get_discovery_document(request)
    )
    assert not response.is_successful
    assert response.error_kind is kind
    assert response.status_code == (
        status if kind is DiscoveryErrorKind.UNEXPECTED_STATUS else None
    )
    assert response.missing_fields == fields
    assert response.error  # Legacy diagnostic prose is still available.


@pytest.mark.parametrize("asynchronous", [False, True])
@respx.mock
async def test_https_failure_is_distinct_from_other_configuration_failures(
    asynchronous,
):
    request = DiscoveryDocumentRequest(
        address="http://localhost/.well-known/openid-configuration",
        policy=DiscoveryPolicy(allow_http_on_loopback=False),
    )
    response = (
        await async_discover(request)
        if asynchronous
        else get_discovery_document(request)
    )
    assert not response.is_successful
    assert response.error_kind is DiscoveryErrorKind.HTTPS_REQUIRED
    assert response.status_code is None
    assert response.missing_fields == ()
    assert len(respx.calls) == 0


@respx.mock
def test_success_has_no_failure_metadata():
    respx.get(ADDRESS).mock(return_value=httpx.Response(200, json=VALID))
    response = get_discovery_document(DiscoveryDocumentRequest(address=ADDRESS))
    assert response.is_successful
    assert response.error_kind is None
    assert response.status_code is None
    assert response.missing_fields == ()


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("field", ["issuer", "token_endpoint"])
@respx.mock
async def test_metadata_https_failure_has_the_same_category(asynchronous, field):
    document = {**VALID, field: "http://server.example.com/insecure"}
    respx.get(ADDRESS).mock(return_value=httpx.Response(200, json=document))
    request = DiscoveryDocumentRequest(address=ADDRESS)
    response = (
        await async_discover(request)
        if asynchronous
        else get_discovery_document(request)
    )
    assert not response.is_successful
    assert response.error_kind is DiscoveryErrorKind.HTTPS_REQUIRED
