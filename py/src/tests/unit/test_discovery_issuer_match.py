"""The discovery document's issuer must be exactly the configured issuer.

OIDC Discovery 1.0 §4.3 and RFC 8414 §3.3, compared code point to code point
(§5); not configurable.
"""

import httpx
import pytest
import respx

from py_identity_model import (
    ConfigurationException,
    DiscoveryDocumentRequest,
    DiscoveryErrorKind,
    DiscoveryIssuerMismatchError,
    HTTPClient,
    ValidationCache,
    get_discovery_document,
)
from py_identity_model.aio import AsyncHTTPClient, AsyncValidationCache
from py_identity_model.aio.discovery import get_discovery_document as async_discover
from py_identity_model.aio.token_validation import (
    _get_disco_response as async_get_disco_response,
)
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.response_processors import (
    validate_and_parse_discovery_response,
)
from py_identity_model.sync.token_validation import _get_disco_response


WELL_KNOWN = "/.well-known/openid-configuration"
SERVER = "https://server.example.com"
ATTACKER = "https://attacker.example.com"
COGNITO_ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123"

pytestmark = pytest.mark.unit


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


async def _discover(asynchronous: bool, issuer: str):
    request = DiscoveryDocumentRequest(issuer=issuer, policy=DiscoveryPolicy())
    if asynchronous:
        return await async_discover(request)
    return get_discovery_document(request)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("issuer", "url"),
    [
        (SERVER, SERVER + WELL_KNOWN),
        # A terminating "/" is removed before appending (§4.1), but the
        # document must still say "https://server.example.com/".
        (SERVER + "/", SERVER + WELL_KNOWN),
        (SERVER + "/tenant", SERVER + "/tenant" + WELL_KNOWN),
        (SERVER + "/tenant/", SERVER + "/tenant" + WELL_KNOWN),
        # Compared as the caller wrote it, before httpx normalises the URL.
        (
            "https://server.example.com:443",
            "https://server.example.com:443" + WELL_KNOWN,
        ),
        ("https://SERVER.example.com", "https://SERVER.example.com" + WELL_KNOWN),
        # Descope serves both issuer forms, each from its own discovery URL.
        ("https://api.descope.com/P123", "https://api.descope.com/P123" + WELL_KNOWN),
        (
            "https://api.descope.com/v1/apps/P123",
            "https://api.descope.com/v1/apps/P123" + WELL_KNOWN,
        ),
        (
            COGNITO_ISSUER,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123"
            "/.well-known/openid-configuration",
        ),
    ],
)
@respx.mock
async def test_exact_issuer_is_accepted_from_the_derived_url(asynchronous, issuer, url):
    route = respx.get(url).mock(
        return_value=httpx.Response(200, json=_document(issuer))
    )

    response = await _discover(asynchronous, issuer)

    assert response.is_successful, response.error
    assert response.issuer == issuer
    assert route.call_count == 1


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("configured", "returned"),
    [
        # Trailing-slash-only differences, both directions.
        (SERVER, SERVER + "/"),
        (SERVER + "/", SERVER),
        (SERVER + "/tenant", SERVER + "/tenant/"),
        (SERVER + "/tenant/", SERVER + "/tenant"),
        (COGNITO_ISSUER, COGNITO_ISSUER + "/"),
        (SERVER, ATTACKER),
        (SERVER + "/tenant-a", SERVER + "/tenant-b"),
        (SERVER + "/tenant", SERVER),
        (SERVER, SERVER + "/tenant"),
        (SERVER, "https://SERVER.example.com"),
        ("https://SERVER.example.com", SERVER),
        ("https://server.example.com:443", SERVER),
        (SERVER, "https://server.example.com:443"),
        # Descope: the two issuer forms are different issuers.
        ("https://api.descope.com/P123", "https://api.descope.com/v1/apps/P123"),
        ("https://api.descope.com/v1/apps/P123", "https://api.descope.com/P123"),
    ],
)
@respx.mock
async def test_mismatched_issuer_is_rejected(asynchronous, configured, returned):
    url = configured.rstrip("/") + WELL_KNOWN
    respx.get(url).mock(return_value=httpx.Response(200, json=_document(returned)))

    response = await _discover(asynchronous, configured)

    assert not response.is_successful
    assert response.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH


@pytest.mark.parametrize(
    ("configured", "returned"),
    [(SERVER, SERVER + "/"), (SERVER + "/", SERVER)],
)
def test_trailing_slash_mismatch_reports_both_values(configured, returned):
    response = httpx.Response(200, json=_document(returned))

    with pytest.raises(DiscoveryIssuerMismatchError) as excinfo:
        validate_and_parse_discovery_response(
            response, DiscoveryPolicy(), requested_issuer=configured
        )

    assert (excinfo.value.requested, excinfo.value.returned) == (configured, returned)


@pytest.mark.parametrize("validate_issuer", [True, False])
def test_policy_cannot_disable_the_match(validate_issuer):
    response = httpx.Response(200, json=_document(ATTACKER))

    with pytest.raises(DiscoveryIssuerMismatchError) as excinfo:
        validate_and_parse_discovery_response(
            response,
            DiscoveryPolicy(validate_issuer=validate_issuer, validate_endpoints=False),
            requested_issuer=SERVER,
        )

    assert (excinfo.value.requested, excinfo.value.returned) == (SERVER, ATTACKER)


@pytest.mark.parametrize("issuer", [5, [SERVER]])
def test_non_string_issuer_is_a_mismatch(issuer):
    document = _document(SERVER) | {"issuer": issuer}
    response = httpx.Response(200, json=document)

    with pytest.raises(DiscoveryIssuerMismatchError):
        validate_and_parse_discovery_response(
            response,
            DiscoveryPolicy(validate_issuer=False, validate_endpoints=False),
            requested_issuer=SERVER,
        )


DISCOVERY_URLS_AS_ISSUER = [
    SERVER + WELL_KNOWN,
    SERVER + WELL_KNOWN + "/",
    SERVER + "/tenant" + WELL_KNOWN,
    SERVER + "/.well-known/oauth-authorization-server",
    SERVER + "/.well-known/oauth-authorization-server/tenant",
    COGNITO_ISSUER + WELL_KNOWN,
]


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("issuer", DISCOVERY_URLS_AS_ISSUER)
async def test_discovery_url_as_issuer_is_a_configuration_error(asynchronous, issuer):
    with respx.mock(assert_all_mocked=False) as router:
        response = await _discover(asynchronous, issuer)
        assert router.calls.call_count == 0

    assert not response.is_successful
    assert response.error_kind is DiscoveryErrorKind.INVALID_CONFIGURATION


def _never_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected request to {request.url}")


@pytest.mark.parametrize("issuer", DISCOVERY_URLS_AS_ISSUER)
def test_cached_discovery_rejects_a_discovery_url_before_any_request(issuer):
    client = HTTPClient(httpx.Client(transport=httpx.MockTransport(_never_called)))

    with pytest.raises(ConfigurationException):
        _get_disco_response(issuer, DiscoveryPolicy(), client, ValidationCache())


@pytest.mark.parametrize("issuer", DISCOVERY_URLS_AS_ISSUER)
async def test_async_cached_discovery_rejects_a_discovery_url_before_any_request(
    issuer,
):
    client = AsyncHTTPClient(
        httpx.AsyncClient(transport=httpx.MockTransport(_never_called))
    )

    with pytest.raises(ConfigurationException):
        await async_get_disco_response(
            issuer, DiscoveryPolicy(), client, AsyncValidationCache()
        )


def _redirect_to_attacker(request: httpx.Request) -> httpx.Response:
    if request.url.host == "server.example.com":
        return httpx.Response(302, headers={"Location": ATTACKER + WELL_KNOWN})
    return httpx.Response(200, json=_document(ATTACKER))


def test_redirect_following_client_cannot_substitute_issuer():
    client = httpx.Client(
        transport=httpx.MockTransport(_redirect_to_attacker), follow_redirects=True
    )
    request = DiscoveryDocumentRequest(issuer=SERVER)

    response = get_discovery_document(request, http_client=HTTPClient(client))

    assert response.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH


async def test_redirect_following_async_client_cannot_substitute_issuer():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_redirect_to_attacker), follow_redirects=True
    )
    request = DiscoveryDocumentRequest(issuer=SERVER)

    response = await async_discover(request, http_client=AsyncHTTPClient(client))

    assert response.error_kind is DiscoveryErrorKind.ISSUER_MISMATCH
