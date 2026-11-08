"""Unit tests for FAPI 2.0 Security Profile compliance validation."""

from typing import Any

import httpx
import pytest
import respx

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.core.fapi import (
    FAPIValidationResult,
    validate_fapi_discovery,
)
from py_identity_model.core.models import DiscoveryDocumentResponse

from ..constants import DISCO_URL, ISSUER


@pytest.mark.unit
class TestFAPIValidationResult:
    def test_empty_violations_is_compliant(self):
        result = FAPIValidationResult(violations=[])
        assert result.is_compliant is True

    def test_violations_is_not_compliant(self):
        result = FAPIValidationResult(violations=["problem"])
        assert result.is_compliant is False

    def test_default_is_compliant(self):
        result = FAPIValidationResult()
        assert result.is_compliant is True
        assert result.violations == []


# Discovery metadata a FAPI 2.0 authorization server advertises. Each test
# overrides one field so the violation it expects is the only one.
COMPLIANT_METADATA: dict[str, Any] = {
    "issuer": "https://auth.example.com",
    "grant_types_supported": ["authorization_code"],
    "response_types_supported": ["code"],
    "token_endpoint_auth_methods_supported": ["private_key_jwt"],
    "token_endpoint_auth_signing_alg_values_supported": ["PS256"],
    "id_token_signing_alg_values_supported": ["ES256", "PS256"],
    "code_challenge_methods_supported": ["S256"],
    "pushed_authorization_request_endpoint": "https://auth.example.com/par",
    "authorization_response_iss_parameter_supported": True,
    "dpop_signing_alg_values_supported": ["ES256"],
}

# Every value a compliant array could need, so a mixed array fails only
# because of its non-string entry.
COMPLIANT_VALUES = [
    "authorization_code",
    "code",
    "private_key_jwt",
    "PS256",
    "ES256",
    "EdDSA",
    "S256",
]

REQUIRED_RESPONSE_TYPES = (
    "response_types_supported not advertised; "
    "OpenID Connect Discovery 1.0 §3 marks it REQUIRED, with no default"
)
REQUIRED_ID_TOKEN_ALGS = (
    "id_token_signing_alg_values_supported not advertised; "
    "OpenID Connect Discovery 1.0 §3 marks it REQUIRED, with no default"
)
AUTH_METHODS_DEFAULT = (
    "token_endpoint_auth_methods_supported not advertised; "
    "RFC 8414 default is client_secret_basic, which FAPI 2.0 prohibits"
)
PKCE_ABSENT = (
    "code_challenge_methods_supported not advertised; RFC 8414 §2 reads that "
    "as no PKCE support, and FAPI 2.0 Security Profile §5.3.2.2 requires S256"
)
PAR_ABSENT = (
    "pushed_authorization_request_endpoint not advertised; FAPI 2.0 Security "
    "Profile §5.3.2.2 requires pushed authorization requests (RFC 9126)"
)
ISS_NOT_SUPPORTED = (
    "authorization_response_iss_parameter_supported is not true; FAPI 2.0 "
    "Security Profile §5.3.2.2 requires the iss authorization response "
    "parameter (RFC 9207 §3)"
)
NO_SENDER_CONSTRAINT = (
    "Neither dpop_signing_alg_values_supported with one of ES256, EdDSA, PS256 "
    "nor tls_client_certificate_bound_access_tokens: true is advertised; "
    "FAPI 2.0 Security Profile §5.3.2.1 requires sender-constrained access "
    "tokens (DPoP or MTLS)"
)
AUTH_SIGNING_ALGS_ABSENT = (
    "token_endpoint_auth_signing_alg_values_supported not advertised; "
    "private_key_jwt needs one of ES256, EdDSA, PS256 "
    "(FAPI 2.0 Security Profile §5.4.1)"
)
AUTH_SIGNING_ALGS_WEAK = (
    "Server does not support FAPI-compliant token endpoint auth signing "
    "algorithms (ES256, EdDSA, PS256)"
)


def _discovery(**overrides: Any) -> DiscoveryDocumentResponse:
    return DiscoveryDocumentResponse(
        is_successful=True, **{**COMPLIANT_METADATA, **overrides}
    )


@pytest.mark.unit
class TestValidateFAPIDiscovery:
    def test_compliant_discovery(self):
        result = validate_fapi_discovery(_discovery())
        assert result.is_compliant is True
        assert result.violations == []

    def test_missing_auth_code_grant(self):
        result = validate_fapi_discovery(
            _discovery(grant_types_supported=["client_credentials"])
        )
        assert result.violations == [
            "Server does not support authorization_code grant type"
        ]

    def test_weak_auth_methods(self):
        result = validate_fapi_discovery(
            _discovery(token_endpoint_auth_methods_supported=["client_secret_basic"])
        )
        assert result.violations == [
            "Server does not support FAPI-compliant client auth "
            "(private_key_jwt or tls_client_auth)"
        ]

    def test_weak_algorithms(self):
        result = validate_fapi_discovery(
            _discovery(id_token_signing_alg_values_supported=["RS256"])
        )
        assert result.violations == [
            "Server does not support FAPI-compliant signing algorithms "
            "(ES256, EdDSA, PS256)"
        ]

    def test_eddsa_is_a_fapi_algorithm(self):
        """FAPI 2.0 Security Profile §5.4.1: PS256, ES256 or EdDSA (Ed25519)."""
        result = validate_fapi_discovery(
            _discovery(
                id_token_signing_alg_values_supported=["EdDSA"],
                token_endpoint_auth_signing_alg_values_supported=["EdDSA"],
            )
        )
        assert result.violations == []

    def test_failed_discovery_returns_non_compliant(self):
        result = validate_fapi_discovery(DiscoveryDocumentResponse(is_successful=False))
        assert result.violations == ["Discovery document fetch failed"]

    def test_none_auth_methods_non_compliant(self):
        """RFC 8414 §2 default is client_secret_basic — FAPI-prohibited."""
        result = validate_fapi_discovery(
            _discovery(token_endpoint_auth_methods_supported=None)
        )
        assert result.violations == [AUTH_METHODS_DEFAULT]

    def test_none_signing_algs_non_compliant(self):
        """OIDC Discovery §3: REQUIRED, no RS256 (or any other) default."""
        result = validate_fapi_discovery(
            _discovery(id_token_signing_alg_values_supported=None)
        )
        assert result.violations == [REQUIRED_ID_TOKEN_ALGS]

    def test_none_fields_non_compliant(self):
        """All-None metadata: every FAPI requirement is reported."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
        )
        result = validate_fapi_discovery(disco)
        assert result.violations == [
            REQUIRED_RESPONSE_TYPES,
            AUTH_METHODS_DEFAULT,
            REQUIRED_ID_TOKEN_ALGS,
            PKCE_ABSENT,
            PAR_ABSENT,
            ISS_NOT_SUPPORTED,
            NO_SENDER_CONSTRAINT,
        ]

    def test_response_types_missing_code(self):
        result = validate_fapi_discovery(_discovery(response_types_supported=["token"]))
        assert result.violations == [
            "Server does not support 'code' response type "
            "(authorization code flow required)"
        ]

    def test_response_types_none_is_non_compliant(self):
        """OIDC Discovery §3: response_types_supported is REQUIRED, no default."""
        result = validate_fapi_discovery(_discovery(response_types_supported=None))
        assert result.violations == [REQUIRED_RESPONSE_TYPES]

    def test_grant_types_none_is_compliant(self):
        """OIDC Discovery §3 default is ["authorization_code", "implicit"]."""
        result = validate_fapi_discovery(_discovery(grant_types_supported=None))
        assert result.violations == []

    def test_pkce_methods_without_s256(self):
        result = validate_fapi_discovery(
            _discovery(code_challenge_methods_supported=["plain"])
        )
        assert result.violations == [
            "Server does not support S256 PKCE "
            "(FAPI 2.0 requires code_challenge_methods_supported to include S256)"
        ]

    def test_pkce_methods_with_s256(self):
        result = validate_fapi_discovery(
            _discovery(code_challenge_methods_supported=["S256", "plain"])
        )
        assert result.violations == []

    def test_pkce_methods_none_is_non_compliant(self):
        """RFC 8414 §2: omitted code_challenge_methods_supported means no PKCE."""
        result = validate_fapi_discovery(
            _discovery(code_challenge_methods_supported=None)
        )
        assert result.violations == [PKCE_ABSENT]

    def test_par_endpoint_none_is_non_compliant(self):
        result = validate_fapi_discovery(
            _discovery(pushed_authorization_request_endpoint=None)
        )
        assert result.violations == [PAR_ABSENT]

    @pytest.mark.parametrize("supported", [None, False], ids=["absent", "false"])
    def test_iss_parameter_not_supported_is_non_compliant(self, supported):
        result = validate_fapi_discovery(
            _discovery(authorization_response_iss_parameter_supported=supported)
        )
        assert result.violations == [ISS_NOT_SUPPORTED]

    @pytest.mark.parametrize(
        ("dpop_algs", "mtls_bound"),
        [
            (None, None),
            ([], None),
            (None, False),
            (["RS256", "HS256", "none"], None),
        ],
        ids=["both-absent", "empty-dpop-algs", "mtls-false", "no-fapi-dpop-alg"],
    )
    def test_no_sender_constraint_is_non_compliant(self, dpop_algs, mtls_bound):
        result = validate_fapi_discovery(
            _discovery(
                dpop_signing_alg_values_supported=dpop_algs,
                tls_client_certificate_bound_access_tokens=mtls_bound,
            )
        )
        assert result.violations == [NO_SENDER_CONSTRAINT]

    def test_mtls_bound_tokens_satisfy_sender_constraint(self):
        result = validate_fapi_discovery(
            _discovery(
                dpop_signing_alg_values_supported=None,
                tls_client_certificate_bound_access_tokens=True,
            )
        )
        assert result.violations == []

    def test_auth_signing_algs_none_with_private_key_jwt(self):
        result = validate_fapi_discovery(
            _discovery(token_endpoint_auth_signing_alg_values_supported=None)
        )
        assert result.violations == [AUTH_SIGNING_ALGS_ABSENT]

    def test_auth_signing_algs_without_fapi_algorithm(self):
        result = validate_fapi_discovery(
            _discovery(token_endpoint_auth_signing_alg_values_supported=["RS256"])
        )
        assert result.violations == [AUTH_SIGNING_ALGS_WEAK]

    def test_auth_signing_algs_ignored_without_private_key_jwt(self):
        """RFC 8414 §2: the field governs JWT client authentication only."""
        result = validate_fapi_discovery(
            _discovery(
                token_endpoint_auth_methods_supported=["tls_client_auth"],
                token_endpoint_auth_signing_alg_values_supported=None,
            )
        )
        assert result.violations == []

    @pytest.mark.parametrize(
        ("field", "violation"),
        [
            (
                "grant_types_supported",
                "Server does not support authorization_code grant type",
            ),
            (
                "response_types_supported",
                "Server does not support 'code' response type "
                "(authorization code flow required)",
            ),
            (
                "token_endpoint_auth_methods_supported",
                "Server does not support FAPI-compliant client auth "
                "(private_key_jwt or tls_client_auth)",
            ),
            (
                "token_endpoint_auth_signing_alg_values_supported",
                AUTH_SIGNING_ALGS_WEAK,
            ),
            (
                "id_token_signing_alg_values_supported",
                "Server does not support FAPI-compliant signing algorithms "
                "(ES256, EdDSA, PS256)",
            ),
            (
                "code_challenge_methods_supported",
                "Server does not support S256 PKCE "
                "(FAPI 2.0 requires code_challenge_methods_supported to include S256)",
            ),
            ("dpop_signing_alg_values_supported", NO_SENDER_CONSTRAINT),
        ],
    )
    @pytest.mark.parametrize(
        "malformed",
        [False, "PS256", [["PS256"]], [*COMPLIANT_VALUES, None]],
        ids=["bool", "string", "nested", "mixed"],
    )
    def test_malformed_list_metadata_is_a_violation(self, field, violation, malformed):
        """Server metadata is untrusted: a non-list or non-string value fails closed."""
        result = validate_fapi_discovery(_discovery(**{field: malformed}))
        assert result.violations == [violation]


@pytest.mark.unit
class TestValidateFAPIDiscoveryAuthMethods:
    @pytest.mark.parametrize(
        "auth_method", ["tls_client_auth", "self_signed_tls_client_auth"]
    )
    def test_discovery_with_mtls_client_auth(self, auth_method):
        result = validate_fapi_discovery(
            _discovery(token_endpoint_auth_methods_supported=[auth_method])
        )
        assert result.violations == []


@pytest.mark.unit
class TestValidateFAPIDiscoveryFromDocument:
    @respx.mock
    def test_fetched_fapi_document_is_compliant(self):
        """Every field the validator reads is parsed from the document."""
        metadata = {
            **COMPLIANT_METADATA,
            "issuer": ISSUER,
            "pushed_authorization_request_endpoint": f"{ISSUER}/par",
            "jwks_uri": f"{ISSUER}/jwks",
            "authorization_endpoint": f"{ISSUER}/auth",
            "token_endpoint": f"{ISSUER}/token",
            "subject_types_supported": ["public"],
        }
        respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=metadata))

        disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_URL))

        assert disco.dpop_signing_alg_values_supported == ["ES256"]
        assert validate_fapi_discovery(disco).violations == []
