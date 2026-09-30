"""Discovery failure metadata comes from the failing operation, never its prose."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.aio.discovery import get_discovery_document as async_discover
from py_identity_model.core.discovery_policy import DiscoveryPolicy


ADDRESS = "https://server.example.com/.well-known/openid-configuration"
VALID = json.loads(
    (Path(__file__).parents[4] / "spec/test-fixtures/discovery/valid.json").read_text()
)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("status", "body", "content_type", "code", "fields"),
    [
        (
            404,
            "Invalid JSON response; HTTPS is required; jwks_uri; status code: 500",
            "text/plain",
            "http_status",
            (),
        ),
        (500, "issuer mismatch", "application/json", "http_status", ()),
        (200, "not json", "application/json", "parse", ()),
        (200, "Invalid JSON response", "text/plain", "validation", ()),
        (
            200,
            json.dumps({k: v for k, v in VALID.items() if k != "jwks_uri"}),
            "application/json",
            "missing_fields",
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
            "missing_fields",
            ("response_types_supported", "subject_types_supported"),
        ),
    ],
)
@respx.mock
async def test_discovery_reports_failure_metadata(  # noqa: PLR0913
    asynchronous, status, body, content_type, code, fields
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
    assert response.error_code == code
    assert response.status_code == (status if code == "http_status" else None)
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
    assert response.error_code == "https_required"
    assert response.status_code is None
    assert response.missing_fields == ()
    assert len(respx.calls) == 0


@respx.mock
def test_success_has_no_failure_metadata():
    respx.get(ADDRESS).mock(return_value=httpx.Response(200, json=VALID))
    response = get_discovery_document(DiscoveryDocumentRequest(address=ADDRESS))
    assert response.is_successful
    assert response.error_code is None
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
    assert response.error_code == "https_required"
