"""Discovery §3 REQUIRED metadata is unconditional (DISC-008, D2).

OpenID Connect Discovery 1.0 §3 lists seven REQUIRED provider metadata fields.
Every one must be present and non-empty, each missing one must be reported in
the ``required_fields`` order of ``spec/vectors/discovery.json``, and no policy
switch may relax ``jwks_uri`` (the removed ``require_key_set``).
"""

import dataclasses

import httpx
import pytest

from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.response_processors import (
    validate_and_parse_discovery_response,
)
from py_identity_model.core.validators import validate_required_parameters
from py_identity_model.exceptions import DiscoveryMissingFieldsError


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
    validate_required_parameters({**COMPLETE_DOCUMENT, "issuer": 0})


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
        validate_and_parse_discovery_response(response, policy)
    assert exc_info.value.fields == ("jwks_uri",)


def test_require_key_set_is_gone():
    """D2: there is no switch for the jwks_uri requirement."""
    names = {f.name for f in dataclasses.fields(DiscoveryPolicy)}
    assert "require_key_set" not in names
    with pytest.raises(TypeError, match="require_key_set"):
        DiscoveryPolicy(require_key_set=False)  # type: ignore[call-arg]
