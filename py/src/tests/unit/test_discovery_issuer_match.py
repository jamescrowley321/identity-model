"""The discovery document's issuer must be the one its URL was built from.

OIDC Discovery 1.0 §4.3 and RFC 8414 §3.3; not configurable.
"""

import httpx
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryErrorKind,
    DiscoveryIssuerMismatchError,
    HTTPClient,
    get_discovery_document,
)
from py_identity_model.aio import AsyncHTTPClient
from py_identity_model.aio.discovery import get_discovery_document as async_discover
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.response_processors import (
    validate_and_parse_discovery_response,
)


WELL_KNOWN = "/.well-known/openid-configuration"


def _document(issuer: str) -> dict:
    authority = "/".join(issuer.split("/")[:3])
    return {
        "issuer": issuer,
        "jwks_uri": f"{authority}/jwks",
        "authorization_endpoint": f"{authority}/authorize",
        "token_endpoint": f"{authority}/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


async def _discover(asynchronous: bool, address: str):
    request = DiscoveryDocumentRequest(address=address, policy=DiscoveryPolicy())
    if asynchronous:
        return await async_discover(request)
    return get_discovery_document(request)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("requested", "returned"),
    [
        ("https://server.example.com", "https://server.example.com"),
        ("https://server.example.com", "https://server.example.com/"),
        ("https://server.example.com/", "https://server.example.com"),
        ("https://server.example.com/tenant", "https://server.example.com/tenant"),
        # Discovery §4.1 removes a path issuer's terminating "/" before
        # appending the well-known suffix.
        ("https://server.example.com/tenant", "https://server.example.com/tenant/"),
        # Compared as the caller wrote it, before httpx normalises the URL.
        ("https://server.example.com:443", "https://server.example.com:443"),
        ("https://SERVER.example.com", "https://SERVER.example.com"),
        # Descope serves both issuer forms, each from its own discovery URL.
        ("https://api.descope.com/P123", "https://api.descope.com/P123"),
        (
            "https://api.descope.com/v1/apps/P123",
            "https://api.descope.com/v1/apps/P123",
        ),
    ],
)
@respx.mock
async def test_matching_issuer_is_accepted(asynchronous, requested, returned):
    address = requested.rstrip("/") + WELL_KNOWN
    respx.get(address).mock(return_value=httpx.Response(200, json=_document(returned)))

    response = await _discover(asynchronous, address)

    assert response.is_successful, response.error
    assert response.issuer == returned


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("requested", "returned"),
    [
        ("https://server.example.com", "https://attacker.example.com"),
        ("https://server.example.com/tenant-a", "https://server.example.com/tenant-b"),
        ("https://server.example.com/tenant", "https://server.example.com"),
        ("https://server.example.com", "https://server.example.com/tenant"),
        ("https://server.example.com", "https://SERVER.example.com"),
        ("https://SERVER.example.com", "https://server.example.com"),
        ("https://server.example.com:443", "https://server.example.com"),
        ("https://server.example.com", "https://server.example.com:443"),
        # Descope: the two issuer forms are different issuers.
        ("https://api.descope.com/P123", "https://api.descope.com/v1/apps/P123"),
        ("https://api.descope.com/v1/apps/P123", "https://api.descope.com/P123"),
    ],
)
@respx.mock
async def test_mismatched_issuer_is_rejected(asynchronous, requested, returned):
    address = requested + WELL_KNOWN
    respx.get(address).mock(return_value=httpx.Response(200, json=_document(returned)))

    response = await _discover(asynchronous, address)

    assert not response.is_successful
    assert response.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH


@pytest.mark.parametrize("validate_issuer", [True, False])
def test_policy_cannot_disable_the_match(validate_issuer):
    response = httpx.Response(200, json=_document("https://attacker.example.com"))

    with pytest.raises(DiscoveryIssuerMismatchError) as excinfo:
        validate_and_parse_discovery_response(
            response,
            DiscoveryPolicy(validate_issuer=validate_issuer, validate_endpoints=False),
            requested_address="https://server.example.com" + WELL_KNOWN,
        )

    assert (excinfo.value.requested, excinfo.value.returned) == (
        "https://server.example.com",
        "https://attacker.example.com",
    )


def _redirect_to_attacker(request: httpx.Request) -> httpx.Response:
    if request.url.host == "server.example.com":
        return httpx.Response(302, headers={"Location": ATTACKER + WELL_KNOWN})
    return httpx.Response(200, json=_document(ATTACKER))


ATTACKER = "https://attacker.example.com"


@pytest.mark.parametrize("suffix", [WELL_KNOWN, WELL_KNOWN + "/"])
def test_well_known_suffix_is_stripped_with_or_without_trailing_slash(suffix):
    response = httpx.Response(200, json=_document("https://server.example.com"))

    result = validate_and_parse_discovery_response(
        response, requested_address="https://server.example.com" + suffix
    )

    assert result["issuer"] == "https://server.example.com"


def test_redirect_following_client_cannot_substitute_issuer():
    client = httpx.Client(
        transport=httpx.MockTransport(_redirect_to_attacker), follow_redirects=True
    )
    request = DiscoveryDocumentRequest(
        address="https://server.example.com" + WELL_KNOWN
    )

    response = get_discovery_document(request, http_client=HTTPClient(client))

    assert response.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH


async def test_redirect_following_async_client_cannot_substitute_issuer():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_redirect_to_attacker), follow_redirects=True
    )
    request = DiscoveryDocumentRequest(
        address="https://server.example.com" + WELL_KNOWN
    )

    response = await async_discover(request, http_client=AsyncHTTPClient(client))

    assert response.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH
