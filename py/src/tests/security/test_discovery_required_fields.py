"""Discovery §3 REQUIRED metadata is unconditional (DISC-008, D2).

OpenID Connect Discovery 1.0 §3 lists seven REQUIRED provider metadata fields.
Every one must be present and non-empty, each missing one must be reported in
the ``required_fields`` order of ``spec/vectors/discovery.json``, and no policy
switch may relax ``jwks_uri`` (the removed ``require_key_set``).
"""

import dataclasses
import json

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
from py_identity_model.core.response_processors import (
    validate_and_parse_discovery_response,
)
from py_identity_model.core.validators import validate_required_parameters
from py_identity_model.exceptions import (
    DiscoveryMissingFieldsError,
    DiscoveryParseError,
)


pytestmark = pytest.mark.unit

ISSUER = "https://server.example.com"
DISCO_URL = f"{ISSUER}/.well-known/openid-configuration"

REQUIRED_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
)

COMPLETE_DOCUMENT = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/auth",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": f"{ISSUER}/jwks",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

EMPTY_VALUES = {"null": None, "empty-string": "", "empty-array": []}
FALSY_VALUES = {"false": False, "zero": 0, "empty-object": {}}
NON_OBJECT_BODIES = {"array": [], "null": None, "string": "x", "number": 1}


def _without(*fields: str) -> dict:
    return {k: v for k, v in COMPLETE_DOCUMENT.items() if k not in fields}


def _missing(document: dict) -> DiscoveryMissingFieldsError:
    with pytest.raises(DiscoveryMissingFieldsError) as exc_info:
        validate_required_parameters(document)
    return exc_info.value


def test_complete_document_passes():
    validate_required_parameters(dict(COMPLETE_DOCUMENT))


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_each_absent_field_is_reported(field):
    error = _missing(_without(field))
    assert error.fields == (field,)
    assert str(error) == f"Missing required parameters: {field}"


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
@pytest.mark.parametrize("empty", EMPTY_VALUES.values(), ids=EMPTY_VALUES.keys())
def test_each_empty_field_is_reported(field, empty):
    assert _missing({**COMPLETE_DOCUMENT, field: empty}).fields == (field,)


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
@pytest.mark.parametrize("falsy", FALSY_VALUES.values(), ids=FALSY_VALUES.keys())
def test_each_falsy_field_is_reported(field, falsy):
    assert _missing({**COMPLETE_DOCUMENT, field: falsy}).fields == (field,)


@pytest.mark.parametrize(
    "body", NON_OBJECT_BODIES.values(), ids=NON_OBJECT_BODIES.keys()
)
def test_non_object_document_is_a_parse_error(body):
    with pytest.raises(DiscoveryParseError) as exc_info:
        validate_required_parameters(body)  # type: ignore[arg-type]
    assert str(exc_info.value) == "Discovery document must be a JSON object"


async def _discover(body: str, asynchronous: bool):
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(
            200, text=body, headers={"Content-Type": "application/json"}
        )
    )
    request = DiscoveryDocumentRequest(address=DISCO_URL)
    if asynchronous:
        return await async_discover(request)
    return get_discovery_document(request)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("falsy", FALSY_VALUES.values(), ids=FALSY_VALUES.keys())
@respx.mock
async def test_falsy_jwks_uri_is_missing_fields(asynchronous, falsy):
    body = json.dumps({**COMPLETE_DOCUMENT, "jwks_uri": falsy})
    response = await _discover(body, asynchronous)
    assert response.is_successful is False
    assert response.error_kind is DiscoveryErrorKind.MISSING_FIELDS
    assert response.missing_fields == ("jwks_uri",)


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "body", NON_OBJECT_BODIES.values(), ids=NON_OBJECT_BODIES.keys()
)
@respx.mock
async def test_non_object_body_is_invalid_json(asynchronous, body):
    response = await _discover(json.dumps(body), asynchronous)
    assert response.is_successful is False
    assert response.error_kind is DiscoveryErrorKind.INVALID_JSON
    assert response.missing_fields == ()


def test_every_missing_field_is_reported_in_spec_order():
    error = _missing({})
    assert error.fields == REQUIRED_FIELDS
    assert str(error) == "Missing required parameters: " + ", ".join(REQUIRED_FIELDS)


def test_empty_required_arrays_are_reported_together():
    """DISC-008 empty-required-arrays: the arrays are reported in spec order."""
    arrays = (
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    )
    document = {**COMPLETE_DOCUMENT, **{field: [] for field in arrays}}
    assert _missing(document).fields == arrays


def test_non_empty_values_of_any_type_are_present():
    """Presence is the only rule here; value checks run later."""
    validate_required_parameters({**COMPLETE_DOCUMENT, "subject_types_supported": [0]})
    validate_required_parameters({**COMPLETE_DOCUMENT, "issuer": 1})


@pytest.mark.parametrize(
    "policy",
    [
        None,
        DiscoveryPolicy(),
        DiscoveryPolicy(
            require_https=False,
            validate_issuer=False,
            validate_endpoints=False,
        ),
    ],
    ids=["no-policy", "default-policy", "relaxed-policy"],
)
def test_no_policy_relaxes_jwks_uri(policy):
    response = httpx.Response(
        200,
        json=_without("jwks_uri"),
        request=httpx.Request("GET", DISCO_URL),
    )
    with pytest.raises(DiscoveryMissingFieldsError) as exc_info:
        validate_and_parse_discovery_response(
            response, policy, requested_address=DISCO_URL
        )
    assert exc_info.value.fields == ("jwks_uri",)


def test_require_key_set_is_gone():
    """D2: there is no switch for the jwks_uri requirement."""
    names = {f.name for f in dataclasses.fields(DiscoveryPolicy)}
    assert "require_key_set" not in names
    with pytest.raises(TypeError, match="require_key_set"):
        DiscoveryPolicy(require_key_set=False)  # type: ignore[call-arg]


def test_fields_after_validate_endpoints_are_keyword_only():
    """Removing require_key_set must not shift a positional call silently.

    The old fifth positional argument was require_key_set. With the field
    gone, ``DiscoveryPolicy(True, True, True, True, False)`` would have bound
    False to additional_endpoint_base_addresses; it raises TypeError instead.
    """
    with pytest.raises(TypeError, match="positional"):
        DiscoveryPolicy(True, True, True, True, False)  # type: ignore[misc]
    keyword_only = {f.name for f in dataclasses.fields(DiscoveryPolicy) if f.kw_only}
    assert keyword_only == {
        "additional_endpoint_base_addresses",
        "authority",
        "allow_loopback_endpoints",
    }
    assert DiscoveryPolicy(True, True, True, True) == DiscoveryPolicy()
