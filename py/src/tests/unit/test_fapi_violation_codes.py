"""Every FAPI 2.0 violation carries the typed code for the rule it breaks.

The other FAPI tests pin the messages; these pin the codes, one scenario per
code, each producing exactly one violation.
"""

from collections.abc import Callable

import pytest

from py_identity_model import ClientAuthMethod
from py_identity_model.core.dpop import generate_dpop_key
from py_identity_model.core.fapi import (
    FAPIProfileError,
    FAPIViolationCode,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)
from py_identity_model.core.models import DiscoveryDocumentResponse

from .test_fapi_profile import (
    DPOP_KEY,
    ED448_PEM,
    ISSUER,
    _discovery,
    _mtls,
    _par,
    _pkj,
    _profile,
    _profile_from,
    _request_object,
    _request_object_key,
    _signed_par,
    _signed_profile,
)


Codes = list[FAPIViolationCode]


def _request(**overrides) -> Codes:
    return validate_fapi_authorization_request(_par(**overrides)).codes


def _signed(request_object: str) -> Codes:
    return validate_fapi_authorization_request(_signed_par(request_object)).codes


def _server(**overrides) -> Codes:
    return validate_fapi_discovery(_discovery(**overrides)).codes


def _refused(build: Callable[[], object]) -> Codes:
    with pytest.raises(FAPIProfileError) as exc_info:
        build()
    return exc_info.value.codes


SCENARIOS: dict[FAPIViolationCode, Callable[[], Codes]] = {
    FAPIViolationCode.RESPONSE_TYPE_NOT_CODE: lambda: _request(response_type="token"),
    FAPIViolationCode.PKCE_CHALLENGE_MISSING: lambda: _request(code_challenge=""),
    FAPIViolationCode.PKCE_METHOD_NOT_S256: lambda: _request(
        code_challenge_method="plain"
    ),
    FAPIViolationCode.PKCE_VERIFIER_MISSING: lambda: _refused(
        lambda: _profile().authorization_code_token_request(
            code="code", code_verifier="", dpop_key=DPOP_KEY
        )
    ),
    FAPIViolationCode.NONCE_TOO_LONG: lambda: _request(nonce="n" * 65),
    FAPIViolationCode.NONCE_INVALID: lambda: _signed(_request_object({"nonce": 5})),
    FAPIViolationCode.REDIRECT_URI_INVALID: lambda: _request(
        redirect_uri="https:///cb"
    ),
    FAPIViolationCode.REDIRECT_URI_NOT_HTTPS: lambda: _request(
        redirect_uri="http://client.example.com/cb"
    ),
    FAPIViolationCode.CLIENT_ID_MISSING: lambda: _refused(
        lambda: _profile(client_id="")
    ),
    FAPIViolationCode.CLIENT_AUTH_MISSING: lambda: _request(private_key_jwt=None),
    FAPIViolationCode.CLIENT_AUTH_TYPE_INVALID: lambda: _refused(
        lambda: _profile(client_auth="client-secret")
    ),
    FAPIViolationCode.CLIENT_AUTH_METHOD_NOT_ALLOWED: lambda: _request(
        client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST
    ),
    FAPIViolationCode.ALGORITHM_NOT_ALLOWED: lambda: _request(
        dpop_key=generate_dpop_key("RS256")
    ),
    FAPIViolationCode.KEY_NOT_ALLOWED: lambda: _request(
        private_key_jwt=_pkj(private_key=ED448_PEM, algorithm="EdDSA")
    ),
    FAPIViolationCode.SENDER_CONSTRAINT_MISSING: lambda: _request(dpop_key=None),
    FAPIViolationCode.MTLS_WITH_DPOP: lambda: _refused(
        lambda: _profile(client_auth=_mtls()).pushed_authorization_request(
            state="state", code_challenge="challenge", dpop_key=DPOP_KEY
        )
    ),
    FAPIViolationCode.ASSERTION_AUDIENCE_NOT_ISSUER: lambda: (
        validate_fapi_client_config(
            issuer=ISSUER, private_key_jwt=_pkj(), dpop_key=DPOP_KEY
        ).codes
    ),
    FAPIViolationCode.REQUEST_OBJECT_LIFETIME_INVALID: lambda: _refused(
        lambda: _signed_profile(request_object_key=_request_object_key(lifetime=0))
    ),
    FAPIViolationCode.REQUEST_OBJECT_INVALID: lambda: _signed("not-a-jwt"),
    FAPIViolationCode.REQUEST_OBJECT_ENCRYPTED: lambda: _signed("a.b.c.d.e"),
    FAPIViolationCode.REQUEST_OBJECT_CLIENT_ID_MISMATCH: lambda: _signed(
        _request_object({"client_id": "other"}, drop=("iss",))
    ),
    FAPIViolationCode.REQUEST_OBJECT_ISSUER_MISMATCH: lambda: _signed(
        _request_object({"iss": "other"})
    ),
    FAPIViolationCode.REQUEST_URI_MISSING: lambda: _refused(
        lambda: _profile().authorization_url("")
    ),
    FAPIViolationCode.REFRESH_TOKEN_MISSING: lambda: _refused(
        lambda: _profile().refresh_token_request(refresh_token="", dpop_key=DPOP_KEY)
    ),
    FAPIViolationCode.ENDPOINT_MISSING: lambda: _refused(
        lambda: _profile_from(_discovery(authorization_endpoint=None))
    ),
    FAPIViolationCode.ENDPOINT_INVALID: lambda: _refused(
        lambda: _profile_from(_discovery(token_endpoint="http://auth.example.com/t"))
    ),
    FAPIViolationCode.DISCOVERY_FAILED: lambda: (
        validate_fapi_discovery(
            DiscoveryDocumentResponse(is_successful=False, error="unreachable")
        ).codes
    ),
    FAPIViolationCode.REQUIRED_METADATA_MISSING: lambda: _server(
        response_types_supported=None
    ),
    FAPIViolationCode.SERVER_GRANT_TYPE_UNSUPPORTED: lambda: _server(
        grant_types_supported=["client_credentials"]
    ),
    FAPIViolationCode.SERVER_RESPONSE_TYPE_UNSUPPORTED: lambda: _server(
        response_types_supported=["token"]
    ),
    FAPIViolationCode.SERVER_CLIENT_AUTH_UNSUPPORTED: lambda: _server(
        token_endpoint_auth_methods_supported=["client_secret_basic"]
    ),
    FAPIViolationCode.SERVER_AUTH_SIGNING_ALG_UNSUPPORTED: lambda: _server(
        token_endpoint_auth_signing_alg_values_supported=["RS256"]
    ),
    FAPIViolationCode.SERVER_ID_TOKEN_ALG_UNSUPPORTED: lambda: _server(
        id_token_signing_alg_values_supported=["RS256"]
    ),
    FAPIViolationCode.SERVER_PKCE_UNSUPPORTED: lambda: _server(
        code_challenge_methods_supported=["plain"]
    ),
    FAPIViolationCode.SERVER_PAR_UNSUPPORTED: lambda: _server(
        pushed_authorization_request_endpoint=None
    ),
    FAPIViolationCode.SERVER_ISS_PARAMETER_UNSUPPORTED: lambda: _server(
        authorization_response_iss_parameter_supported=False
    ),
    FAPIViolationCode.SERVER_SENDER_CONSTRAINT_UNSUPPORTED: lambda: _server(
        dpop_signing_alg_values_supported=None,
        tls_client_certificate_bound_access_tokens=False,
    ),
    FAPIViolationCode.SERVER_DPOP_ALG_UNSUPPORTED: lambda: _refused(
        lambda: _profile().pushed_authorization_request(
            state="state",
            code_challenge="challenge",
            dpop_key=generate_dpop_key("PS256"),
        )
    ),
    FAPIViolationCode.SERVER_REQUEST_OBJECT_ALG_UNSUPPORTED: lambda: _refused(
        lambda: _signed_profile(
            discovery={"request_object_signing_alg_values_supported": ["PS256"]}
        )
    ),
}


@pytest.mark.unit
def test_every_code_has_a_scenario():
    assert set(SCENARIOS) == set(FAPIViolationCode)


@pytest.mark.unit
@pytest.mark.parametrize("code", list(SCENARIOS), ids=lambda c: c.value)
def test_violation_code(code: FAPIViolationCode):
    assert SCENARIOS[code]() == [code]
