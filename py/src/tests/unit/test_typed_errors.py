"""Typed errors: discovery/JWKS failures, configuration errors and argument checks.

Covers the 5.0 error contract: ``validate_token`` raises a typed exception per
discovery/JWKS failure kind (an outage is a ``NetworkException``; an invalid
document is a ``ValidationException``), request functions raise a
``ConfigurationException`` instead of returning it as a failed response, and
argument checks raise ``InvalidArgumentError``/``DPoPKeyError``.
"""

import httpx
import pytest
import respx

from py_identity_model import (
    ClientAuthMethod,
    ClientCredentialsTokenRequest,
    ConfigError,
    FAPIProfileError,
    MtlsClientAuth,
    PrivateKeyJwt,
    TokenValidationConfig,
)
from py_identity_model.core.config import ConfigIssue
from py_identity_model.core.device_auth_logic import (
    handle_device_auth_error,
    handle_device_token_error,
)
from py_identity_model.core.dpop import (
    DPoPKey,
    compute_ath,
    compute_jwk_thumbprint,
    create_dpop_proof,
)
from py_identity_model.core.dpop_verify import (
    DPoPProofRequest,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
)
from py_identity_model.core.error_handlers import (
    handle_auth_code_token_error,
    handle_client_delete_error,
    handle_discovery_error,
    handle_introspection_error,
    handle_jwks_error,
    handle_par_error,
    handle_refresh_token_error,
    handle_registration_error,
    handle_revocation_error,
    handle_token_error,
    handle_userinfo_error,
)
from py_identity_model.core.fapi import FAPIViolation, FAPIViolationCode
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
    JwksErrorKind,
    JwksResponse,
)
from py_identity_model.core.token_exchange_logic import handle_token_exchange_error
from py_identity_model.core.token_validation_logic import (
    discovery_failure,
    jwks_failure,
    validate_jwks_uri,
)
from py_identity_model.exceptions import (
    ClientAuthMethodError,
    ClientAuthMethodErrorReason,
    ConfigurationException,
    DiscoveryException,
    DiscoveryHTTPSRequiredError,
    DiscoveryIssuerMismatchError,
    DiscoveryMissingFieldsError,
    DiscoveryParseError,
    DiscoveryValidationError,
    DPoPKeyError,
    DPoPKeyErrorKind,
    InvalidArgumentError,
    InvalidArgumentKind,
    JwksException,
    JwksValidationError,
    NetworkException,
    ValidationException,
)
from py_identity_model.sync.token_client import request_client_credentials_token
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)


ISSUER = "https://issuer.example"
SERVICE_UNAVAILABLE = httpx.codes.SERVICE_UNAVAILABLE
BAD_GATEWAY = httpx.codes.BAD_GATEWAY
DISCO_ADDR = f"{ISSUER}/.well-known/openid-configuration"


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _failed_disco(
    kind: DiscoveryErrorKind | None, **fields
) -> DiscoveryDocumentResponse:
    return DiscoveryDocumentResponse(
        is_successful=False, error="boom", error_kind=kind, **fields
    )


class TestHierarchy:
    """Security failures never sit under NetworkException (M4)."""

    @pytest.mark.parametrize(
        "exc_type",
        [
            DiscoveryValidationError,
            DiscoveryParseError,
            DiscoveryMissingFieldsError,
            DiscoveryIssuerMismatchError,
            JwksValidationError,
        ],
    )
    def test_document_failures_are_validation_not_network(self, exc_type):
        assert issubclass(exc_type, ValidationException)
        assert not issubclass(exc_type, NetworkException)

    @pytest.mark.parametrize("exc_type", [DiscoveryException, JwksException])
    def test_fetch_failures_are_network(self, exc_type):
        assert issubclass(exc_type, NetworkException)
        assert not issubclass(exc_type, ValidationException)

    @pytest.mark.parametrize(
        "exc_type",
        [ConfigError, FAPIProfileError, InvalidArgumentError, DPoPKeyError],
    )
    def test_configuration_errors_are_library_typed(self, exc_type):
        assert issubclass(exc_type, ConfigurationException)
        assert not issubclass(exc_type, ValueError)

    def test_config_error_carries_issues(self):
        issue = ConfigIssue("http_timeout", "must be positive")
        error = ConfigError([issue])
        assert error.issues == (issue,)

    def test_fapi_profile_error_is_configuration_exception(self):
        violation = FAPIViolation(FAPIViolationCode.CLIENT_ID_MISSING, "a")
        error = FAPIProfileError([violation])
        assert isinstance(error, ConfigurationException)
        assert error.codes == [FAPIViolationCode.CLIENT_ID_MISSING]


class TestDiscoveryFailure:
    """A failed discovery response maps to one typed exception per kind (M3)."""

    @pytest.mark.parametrize(
        ("kind", "exc_type"),
        [
            (DiscoveryErrorKind.UNEXPECTED_STATUS, DiscoveryException),
            (DiscoveryErrorKind.NETWORK_ERROR, DiscoveryException),
            (DiscoveryErrorKind.UNEXPECTED_ERROR, DiscoveryException),
            (None, DiscoveryException),
            (DiscoveryErrorKind.INVALID_JSON, DiscoveryParseError),
            (DiscoveryErrorKind.INVALID_DOCUMENT, DiscoveryValidationError),
            (DiscoveryErrorKind.HTTPS_REQUIRED, DiscoveryHTTPSRequiredError),
            (DiscoveryErrorKind.INVALID_CONFIGURATION, ConfigurationException),
        ],
    )
    def test_kind_maps_to_type(self, kind, exc_type):
        exc = discovery_failure(_failed_disco(kind))
        assert (type(exc), str(exc)) == (exc_type, "boom")

    def test_unexpected_status_keeps_status_code(self):
        exc = discovery_failure(
            _failed_disco(
                DiscoveryErrorKind.UNEXPECTED_STATUS, status_code=SERVICE_UNAVAILABLE
            )
        )
        assert isinstance(exc, DiscoveryException)
        assert exc.status_code == SERVICE_UNAVAILABLE

    def test_missing_fields_keeps_fields(self):
        exc = discovery_failure(
            _failed_disco(
                DiscoveryErrorKind.MISSING_FIELDS, missing_fields=("issuer", "jwks_uri")
            )
        )
        assert isinstance(exc, DiscoveryMissingFieldsError)
        assert exc.fields == ("issuer", "jwks_uri")

    def test_issuer_mismatch_keeps_both_issuers(self):
        exc = discovery_failure(
            _failed_disco(
                DiscoveryErrorKind.ISSUER_MISMATCH,
                requested_issuer=ISSUER,
                returned_issuer="https://other.example",
            )
        )
        assert isinstance(exc, DiscoveryIssuerMismatchError)
        assert (exc.requested, exc.returned) == (ISSUER, "https://other.example")

    def test_missing_jwks_uri_is_missing_fields(self):
        response = DiscoveryDocumentResponse(is_successful=True, issuer=ISSUER)
        with pytest.raises(DiscoveryMissingFieldsError) as excinfo:
            validate_jwks_uri(response)
        assert excinfo.value.fields == ("jwks_uri",)


class TestJwksFailure:
    @pytest.mark.parametrize(
        ("kind", "exc_type"),
        [
            (JwksErrorKind.UNEXPECTED_STATUS, JwksException),
            (JwksErrorKind.NETWORK_ERROR, JwksException),
            (JwksErrorKind.UNEXPECTED_ERROR, JwksException),
            (None, JwksException),
            (JwksErrorKind.INVALID_JSON, JwksValidationError),
            (JwksErrorKind.INVALID_DOCUMENT, JwksValidationError),
            (JwksErrorKind.INVALID_CONFIGURATION, ConfigurationException),
        ],
    )
    def test_kind_maps_to_type(self, kind, exc_type):
        exc = jwks_failure(
            JwksResponse(is_successful=False, error="boom", error_kind=kind)
        )
        assert (type(exc), str(exc)) == (exc_type, "boom")

    def test_unexpected_status_keeps_status_code(self):
        exc = jwks_failure(
            JwksResponse(
                is_successful=False,
                error="boom",
                error_kind=JwksErrorKind.UNEXPECTED_STATUS,
                status_code=BAD_GATEWAY,
            )
        )
        assert isinstance(exc, JwksException)
        assert exc.status_code == BAD_GATEWAY


class TestHandlers:
    """Discovery/JWKS handlers classify by type, never by message text (S11)."""

    def test_issuer_mismatch_response_keeps_both_issuers(self):
        response = handle_discovery_error(
            DiscoveryIssuerMismatchError(ISSUER, "https://other.example")
        )
        assert (
            response.error_kind,
            response.requested_issuer,
            response.returned_issuer,
        ) == (DiscoveryErrorKind.ISSUER_MISMATCH, ISSUER, "https://other.example")

    def test_blocked_redirect_is_unexpected_status(self):
        exc = NetworkException("redirect blocked", status_code=302)
        disco = handle_discovery_error(exc)
        jwks = handle_jwks_error(exc)
        assert (disco.error_kind, disco.status_code) == (
            DiscoveryErrorKind.UNEXPECTED_STATUS,
            302,
        )
        assert (jwks.error_kind, jwks.status_code) == (
            JwksErrorKind.UNEXPECTED_STATUS,
            302,
        )

    @pytest.mark.parametrize(
        "handler",
        [
            handle_token_error,
            handle_auth_code_token_error,
            handle_refresh_token_error,
            handle_introspection_error,
            handle_revocation_error,
            handle_par_error,
            handle_registration_error,
            handle_client_delete_error,
            handle_userinfo_error,
            handle_device_auth_error,
            handle_device_token_error,
            handle_token_exchange_error,
        ],
    )
    def test_request_handlers_raise_configuration_errors(self, handler):
        error = ClientAuthMethodError(
            ClientAuthMethodErrorReason.MISSING_CREDENTIAL,
            ClientAuthMethod.PRIVATE_KEY_JWT,
            "private_key_jwt",
        )
        with pytest.raises(ClientAuthMethodError) as excinfo:
            handler(error)
        assert excinfo.value is error


class TestValidateTokenOverHttp:
    """End to end: validate_token surfaces the typed cause (M3)."""

    @respx.mock
    def test_discovery_outage_raises_network_exception(self):
        respx.get(DISCO_ADDR).mock(return_value=httpx.Response(SERVICE_UNAVAILABLE))
        config = TokenValidationConfig(perform_disco=True, audience=None)
        with pytest.raises(DiscoveryException) as excinfo:
            validate_token(
                jwt="a.b.c",
                token_validation_config=config,
                disco_doc_address=DISCO_ADDR,
            )
        assert excinfo.value.status_code == SERVICE_UNAVAILABLE

    @respx.mock
    def test_issuer_mismatch_raises_validation_error(self):
        document = {
            "issuer": "https://other.example",
            "authorization_endpoint": "https://other.example/authorize",
            "token_endpoint": "https://other.example/token",
            "jwks_uri": "https://other.example/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        respx.get(DISCO_ADDR).mock(return_value=httpx.Response(200, json=document))
        config = TokenValidationConfig(perform_disco=True, audience=None)
        with pytest.raises(DiscoveryIssuerMismatchError) as excinfo:
            validate_token(
                jwt="a.b.c",
                token_validation_config=config,
                disco_doc_address=DISCO_ADDR,
            )
        assert (excinfo.value.requested, excinfo.value.returned) == (
            ISSUER,
            "https://other.example",
        )

    @respx.mock
    @pytest.mark.parametrize(
        "member",
        [{"subject_types_supported": 5}, {"response_types_supported": [5]}],
        ids=["subject-types-not-a-list", "response-type-not-a-string"],
    )
    def test_wrongly_typed_document_is_a_validation_error(self, member):
        # A check crashing on a wrongly typed member means the document is
        # invalid, not that the provider is unavailable.
        document = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            **member,
        }
        respx.get(DISCO_ADDR).mock(return_value=httpx.Response(200, json=document))
        config = TokenValidationConfig(perform_disco=True, audience=None)
        with pytest.raises(DiscoveryValidationError) as excinfo:
            validate_token(
                jwt="a.b.c",
                token_validation_config=config,
                disco_doc_address=DISCO_ADDR,
            )
        assert type(excinfo.value) is DiscoveryValidationError


class TestRequestFunctionsRaise:
    """A misconfigured request raises instead of returning a failure (M13)."""

    @respx.mock
    def test_missing_private_key_jwt_raises(self):
        route = respx.post(f"{ISSUER}/token").mock(
            return_value=httpx.Response(200, json={})
        )
        with pytest.raises(ClientAuthMethodError) as excinfo:
            request_client_credentials_token(
                ClientCredentialsTokenRequest(
                    address=f"{ISSUER}/token",
                    client_id="client",
                    client_auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
                )
            )
        assert (excinfo.value.reason, excinfo.value.credential) == (
            ClientAuthMethodErrorReason.MISSING_CREDENTIAL,
            "private_key_jwt",
        )
        assert route.call_count == 0

    @respx.mock
    def test_non_string_assertion_audience_raises(self):
        route = respx.post(f"{ISSUER}/token").mock(
            return_value=httpx.Response(200, json={})
        )
        key = DPoPKey("ES256")
        with pytest.raises(InvalidArgumentError) as excinfo:
            request_client_credentials_token(
                ClientCredentialsTokenRequest(
                    address=f"{ISSUER}/token",
                    client_id="client",
                    private_key_jwt=PrivateKeyJwt(
                        private_key=key.private_key_pem,
                        algorithm="ES256",
                        audience=[ISSUER],  # type: ignore[arg-type]
                    ),
                )
            )
        assert (excinfo.value.argument, excinfo.value.kind) == (
            "audience",
            InvalidArgumentKind.INVALID_TYPE,
        )
        assert route.call_count == 0


class TestMtlsAuthMethod:
    """S23: a non-enum auth_method names the value passed."""

    def test_string_method_is_not_a_client_auth_method(self):
        with pytest.raises(ClientAuthMethodError) as excinfo:
            MtlsClientAuth(
                certificate="c.pem",
                private_key="k.pem",
                auth_method="tls_client_auth",  # type: ignore[arg-type]
            )
        assert (excinfo.value.reason, excinfo.value.method, str(excinfo.value)) == (
            ClientAuthMethodErrorReason.NOT_A_CLIENT_AUTH_METHOD,
            "tls_client_auth",
            "auth_method must be a ClientAuthMethod, got 'tls_client_auth' (str)",
        )

    def test_non_mtls_member_names_that_member(self):
        with pytest.raises(ClientAuthMethodError) as excinfo:
            MtlsClientAuth(
                certificate="c.pem",
                private_key="k.pem",
                auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
            )
        assert (excinfo.value.reason, excinfo.value.method) == (
            ClientAuthMethodErrorReason.NOT_AN_MTLS_METHOD,
            ClientAuthMethod.CLIENT_SECRET_BASIC,
        )


class TestArgumentErrors:
    """S10: argument checks raise typed errors with a kind."""

    @pytest.mark.parametrize(
        ("call", "argument", "kind"),
        [
            (lambda: compute_ath(""), "access_token", InvalidArgumentKind.MISSING),
            (
                lambda: compute_ath("tökén"),
                "access_token",
                InvalidArgumentKind.INVALID_VALUE,
            ),
            (
                lambda: create_dpop_proof(DPoPKey("ES256"), "", "https://rs.example"),
                "method",
                InvalidArgumentKind.MISSING,
            ),
            (
                lambda: create_dpop_proof(DPoPKey("ES256"), "GET", "/relative"),
                "uri",
                InvalidArgumentKind.INVALID_VALUE,
            ),
            (
                lambda: DPoPProofRequest(method="GET", url="/relative"),
                "url",
                InvalidArgumentKind.INVALID_VALUE,
            ),
            (
                lambda: InMemoryDPoPReplayCache(max_entries=0),
                "max_entries",
                InvalidArgumentKind.INVALID_VALUE,
            ),
            (
                lambda: DPoPVerificationOptions(
                    replay_cache=InMemoryDPoPReplayCache(), max_age=0
                ),
                "max_age",
                InvalidArgumentKind.INVALID_VALUE,
            ),
        ],
        ids=[
            "ath-empty",
            "ath-non-ascii",
            "proof-method",
            "proof-uri",
            "proof-request-url",
            "replay-cache-size",
            "verification-max-age",
        ],
    )
    def test_invalid_argument(self, call, argument, kind):
        with pytest.raises(InvalidArgumentError) as excinfo:
            call()
        assert (excinfo.value.argument, excinfo.value.kind) == (argument, kind)

    @pytest.mark.parametrize(
        ("call", "kind"),
        [
            (lambda: DPoPKey("HS256"), DPoPKeyErrorKind.UNSUPPORTED_ALGORITHM),
            (
                lambda: DPoPKey.from_jwk({"kty": "EC"}),
                DPoPKeyErrorKind.ALGORITHM_REQUIRED,
            ),
            (
                lambda: DPoPKey.from_jwk({"kty": "oct"}, "ES256"),
                DPoPKeyErrorKind.UNSUPPORTED_KEY_TYPE,
            ),
            (
                lambda: DPoPKey.from_pem(b"not a pem", "ES256"),
                DPoPKeyErrorKind.INVALID_KEY,
            ),
            (
                lambda: compute_jwk_thumbprint({"kty": "EC"}),
                DPoPKeyErrorKind.MISSING_THUMBPRINT_MEMBERS,
            ),
        ],
        ids=["algorithm", "no-alg", "kty", "pem", "thumbprint"],
    )
    def test_dpop_key_error(self, call, kind):
        with pytest.raises(DPoPKeyError) as excinfo:
            call()
        assert excinfo.value.kind is kind
