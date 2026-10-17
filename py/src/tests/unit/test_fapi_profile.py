"""Unit tests for the FAPI 2.0 client profile and the object-based validators."""

from dataclasses import FrozenInstanceError, replace
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from py_identity_model.core.authorize_response import (
    parse_authorize_callback_response,
)
from py_identity_model.core.dpop import generate_dpop_key
from py_identity_model.core.fapi import (
    FAPI2ClientProfile,
    FAPIProfileError,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
)
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
)
from py_identity_model.core.state_validation import AuthorizeCallbackValidationResult


ISSUER = "https://auth.example.com"
CLIENT_ID = "fapi-client"
REDIRECT_URI = "https://client.example.com/callback"
PAR_ENDPOINT = f"{ISSUER}/par"
TOKEN_ENDPOINT = f"{ISSUER}/token"
AUTHORIZATION_ENDPOINT = f"{ISSUER}/authorize"
MTLS_PAR_ENDPOINT = "https://mtls.auth.example.com/par"
MTLS_TOKEN_ENDPOINT = "https://mtls.auth.example.com/token"

DPOP_KEY = generate_dpop_key("ES256")
RS256_DPOP_KEY = generate_dpop_key("RS256")

AUD_NOT_ISSUER = (
    "private_key_jwt assertion aud would be {aud!r}, not the issuer "
    f"{ISSUER!r} (FAPI 2.0 Security Profile §5.3.3.1)"
)
NO_SENDER_CONSTRAINT = (
    "Sender-constrained tokens required: a DPoP key or mTLS "
    "(FAPI 2.0 Security Profile §5.3.3.1)"
)
MTLS_WITH_DPOP = (
    "An mTLS client's tokens are bound to its certificate; do not also pass a DPoP key"
)
HTTP_REDIRECT = (
    "redirect_uri must use HTTPS, got '{uri}'; http is allowed only for a native "
    "app's loopback redirect (FAPI 2.0 Security Profile §5.3.2.2, RFC 8252 §7.3)"
)


def _alg_violation(what: str, alg: str) -> str:
    return (
        f"{what} algorithm '{alg}' not allowed; use ES256, EdDSA, PS256 "
        "(FAPI 2.0 Security Profile §5.4.1)"
    )


def _pkj(**overrides: Any) -> PrivateKeyJwt:
    fields: dict[str, Any] = {
        "private_key": DPOP_KEY.private_key_pem,
        "algorithm": "ES256",
        **overrides,
    }
    return PrivateKeyJwt(**fields)


def _mtls(**overrides: Any) -> MtlsClientAuth:
    fields: dict[str, Any] = {
        "certificate": "client.pem",
        "private_key": "client.key",
        "auth_method": "self_signed_tls_client_auth",
        **overrides,
    }
    return MtlsClientAuth(**fields)


def _discovery(**overrides: Any) -> DiscoveryDocumentResponse:
    metadata: dict[str, Any] = {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZATION_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "pushed_authorization_request_endpoint": PAR_ENDPOINT,
        "mtls_endpoint_aliases": {
            "token_endpoint": MTLS_TOKEN_ENDPOINT,
            "pushed_authorization_request_endpoint": MTLS_PAR_ENDPOINT,
        },
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": [
            "private_key_jwt",
            "self_signed_tls_client_auth",
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "id_token_signing_alg_values_supported": ["ES256", "PS256"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        "dpop_signing_alg_values_supported": ["ES256"],
        "tls_client_certificate_bound_access_tokens": True,
    }
    return DiscoveryDocumentResponse(is_successful=True, **{**metadata, **overrides})


def _profile(**kwargs: Any) -> FAPI2ClientProfile:
    args: dict[str, Any] = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "client_auth": _pkj(),
        **kwargs,
    }
    return FAPI2ClientProfile(_discovery(), **args)


def _par(**overrides: Any) -> PushedAuthorizationRequest:
    fields: dict[str, Any] = {
        "address": PAR_ENDPOINT,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": "state",
        "nonce": "nonce",
        "code_challenge": "challenge",
        "code_challenge_method": "S256",
        "private_key_jwt": _pkj(issuer=ISSUER),
        "dpop_key": DPOP_KEY,
        **overrides,
    }
    return PushedAuthorizationRequest(**fields)


@pytest.mark.unit
class TestValidateFAPIAuthorizationRequest:
    def test_compliant_private_key_jwt_dpop_request(self):
        assert validate_fapi_authorization_request(_par()).violations == []

    def test_compliant_mtls_request(self):
        request = _par(private_key_jwt=None, dpop_key=None, mtls=_mtls())
        assert validate_fapi_authorization_request(request).violations == []

    def test_wrong_response_type(self):
        result = validate_fapi_authorization_request(_par(response_type="token"))
        assert result.violations == ["response_type must be 'code', got 'token'"]
        assert result.is_compliant is False

    @pytest.mark.parametrize("challenge", [None, "", "   "])
    def test_missing_code_challenge(self, challenge):
        result = validate_fapi_authorization_request(_par(code_challenge=challenge))
        assert result.violations == ["PKCE code_challenge is required"]

    def test_missing_code_challenge_method(self):
        result = validate_fapi_authorization_request(_par(code_challenge_method=None))
        assert result.violations == ["PKCE code_challenge_method is required"]

    def test_plain_pkce_rejected(self):
        result = validate_fapi_authorization_request(
            _par(code_challenge_method="plain")
        )
        assert result.violations == ["PKCE method must be 'S256', got 'plain'"]

    def test_nonce_of_64_characters_allowed(self):
        result = validate_fapi_authorization_request(_par(nonce="n" * 64))
        assert result.violations == []

    def test_nonce_over_64_characters_rejected(self):
        """FAPI 2.0 Security Profile §5.3.3.2: nonce of at most 64 characters."""
        result = validate_fapi_authorization_request(_par(nonce="n" * 65))
        assert result.violations == [
            "nonce is 65 characters; FAPI 2.0 Security Profile §5.3.3.2 limits it to 64"
        ]

    def test_no_nonce_allowed(self):
        assert validate_fapi_authorization_request(_par(nonce=None)).violations == []

    def test_http_redirect_uri_rejected(self):
        uri = "http://client.example.com/callback"
        result = validate_fapi_authorization_request(_par(redirect_uri=uri))
        assert result.violations == [HTTP_REDIRECT.format(uri=uri)]

    @pytest.mark.parametrize(
        "uri",
        [
            "http://127.0.0.1:8080/callback",
            "http://127.1.2.3/callback",
            "http://[::1]:8080/callback",
            "http://localhost:8888/callback",
        ],
    )
    def test_native_app_http_loopback_allowed(self, uri):
        result = validate_fapi_authorization_request(
            _par(redirect_uri=uri), native_app=True
        )
        assert result.violations == []

    @pytest.mark.parametrize(
        "uri",
        ["http://127.0.0.1:8080/callback", "http://localhost:8888/callback"],
    )
    def test_loopback_http_rejected_for_non_native_client(self, uri):
        result = validate_fapi_authorization_request(_par(redirect_uri=uri))
        assert result.violations == [HTTP_REDIRECT.format(uri=uri)]

    def test_native_app_non_loopback_http_rejected(self):
        uri = "http://client.example.com/callback"
        result = validate_fapi_authorization_request(
            _par(redirect_uri=uri), native_app=True
        )
        assert result.violations == [HTTP_REDIRECT.format(uri=uri)]

    def test_native_app_custom_scheme_rejected(self):
        uri = "com.example.app://callback"
        result = validate_fapi_authorization_request(
            _par(redirect_uri=uri), native_app=True
        )
        assert result.violations == [HTTP_REDIRECT.format(uri=uri)]

    def test_redirect_uri_scheme_case_insensitive(self):
        result = validate_fapi_authorization_request(
            _par(redirect_uri="HTTPS://client.example.com/callback")
        )
        assert result.violations == []

    def test_redirect_uri_without_host_rejected(self):
        result = validate_fapi_authorization_request(_par(redirect_uri="https:///cb"))
        assert result.violations == ["redirect_uri must have a host, got 'https:///cb'"]

    def test_client_secret_request_rejected(self):
        result = validate_fapi_authorization_request(
            _par(private_key_jwt=None, client_secret="secret")
        )
        assert result.violations == [
            "Client authentication is required: private_key_jwt or mTLS "
            "(FAPI 2.0 Security Profile §5.3.3.1)"
        ]

    def test_weak_private_key_jwt_algorithm_rejected(self):
        result = validate_fapi_authorization_request(
            _par(private_key_jwt=_pkj(issuer=ISSUER, algorithm="RS256"))
        )
        assert result.violations == [_alg_violation("private_key_jwt", "RS256")]

    def test_weak_dpop_algorithm_rejected(self):
        result = validate_fapi_authorization_request(_par(dpop_key=RS256_DPOP_KEY))
        assert result.violations == [_alg_violation("DPoP", "RS256")]

    def test_no_sender_constraint_rejected(self):
        result = validate_fapi_authorization_request(_par(dpop_key=None))
        assert result.violations == [NO_SENDER_CONSTRAINT]


@pytest.mark.unit
class TestValidateFAPIClientConfig:
    def test_private_key_jwt_with_dpop(self):
        result = validate_fapi_client_config(
            issuer=ISSUER, private_key_jwt=_pkj(issuer=ISSUER), dpop_key=DPOP_KEY
        )
        assert result.violations == []
        assert result.is_compliant is True

    @pytest.mark.parametrize(
        "auth_method", ["tls_client_auth", "self_signed_tls_client_auth"]
    )
    def test_mtls(self, auth_method):
        result = validate_fapi_client_config(
            issuer=ISSUER, mtls=_mtls(auth_method=auth_method)
        )
        assert result.violations == []

    def test_audience_equal_to_issuer_allowed(self):
        result = validate_fapi_client_config(
            issuer=ISSUER, private_key_jwt=_pkj(audience=ISSUER), dpop_key=DPOP_KEY
        )
        assert result.violations == []

    def test_endpoint_url_fallback_rejected(self):
        """Neither issuer nor audience: aud would fall back to the endpoint URL."""
        result = validate_fapi_client_config(
            issuer=ISSUER, private_key_jwt=_pkj(), dpop_key=DPOP_KEY
        )
        assert result.violations == [AUD_NOT_ISSUER.format(aud=None)]

    def test_audience_naming_an_endpoint_rejected(self):
        result = validate_fapi_client_config(
            issuer=ISSUER,
            private_key_jwt=_pkj(issuer=ISSUER, audience=TOKEN_ENDPOINT),
            dpop_key=DPOP_KEY,
        )
        assert result.violations == [AUD_NOT_ISSUER.format(aud=TOKEN_ENDPOINT)]

    def test_other_issuer_rejected(self):
        other = "https://other.example.com"
        result = validate_fapi_client_config(
            issuer=ISSUER, private_key_jwt=_pkj(issuer=other), dpop_key=DPOP_KEY
        )
        assert result.violations == [AUD_NOT_ISSUER.format(aud=other)]

    def test_no_client_auth(self):
        result = validate_fapi_client_config(issuer=ISSUER, dpop_key=DPOP_KEY)
        assert result.violations == [
            "Client authentication is required: private_key_jwt or mTLS "
            "(FAPI 2.0 Security Profile §5.3.3.1)"
        ]

    def test_client_secret_mtls_method_rejected(self):
        result = validate_fapi_client_config(
            issuer=ISSUER, mtls=_mtls(auth_method="client_secret_basic")
        )
        assert result.violations == [
            "mTLS auth method 'client_secret_basic' is not FAPI 2.0 compliant; use "
            "private_key_jwt, self_signed_tls_client_auth, tls_client_auth"
        ]

    def test_private_key_jwt_without_dpop_rejected(self):
        result = validate_fapi_client_config(
            issuer=ISSUER, private_key_jwt=_pkj(issuer=ISSUER)
        )
        assert result.violations == [NO_SENDER_CONSTRAINT]


@pytest.mark.unit
class TestFAPI2ClientProfileConstruction:
    def test_private_key_jwt_profile_takes_discovery_values(self):
        profile = _profile()
        assert profile.issuer == ISSUER
        assert profile.client_id == CLIENT_ID
        assert profile.redirect_uri == REDIRECT_URI
        assert profile.authorization_endpoint == AUTHORIZATION_ENDPOINT
        assert profile.pushed_authorization_request_endpoint == PAR_ENDPOINT
        assert profile.token_endpoint == TOKEN_ENDPOINT
        assert profile.private_key_jwt == _pkj(issuer=ISSUER)
        assert profile.mtls is None
        assert profile.scope == "openid"

    def test_mtls_profile_uses_endpoint_aliases(self):
        profile = _profile(client_auth=_mtls())
        assert profile.pushed_authorization_request_endpoint == MTLS_PAR_ENDPOINT
        assert profile.token_endpoint == MTLS_TOKEN_ENDPOINT
        assert profile.private_key_jwt is None
        assert profile.mtls == _mtls()

    def test_caller_private_key_jwt_is_not_mutated(self):
        pkj = _pkj()
        _profile(client_auth=pkj)
        assert pkj.issuer is None

    def test_private_key_jwt_with_matching_issuer_kept(self):
        assert _profile(client_auth=_pkj(issuer=ISSUER)).private_key_jwt == _pkj(
            issuer=ISSUER
        )

    def test_private_key_jwt_audience_naming_endpoint_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_auth=_pkj(audience=TOKEN_ENDPOINT))
        assert exc_info.value.violations == [AUD_NOT_ISSUER.format(aud=TOKEN_ENDPOINT)]

    def test_private_key_jwt_other_issuer_refused(self):
        other = "https://other.example.com"
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_auth=_pkj(issuer=other))
        assert exc_info.value.violations == [AUD_NOT_ISSUER.format(aud=other)]

    def test_weak_private_key_jwt_algorithm_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_auth=_pkj(algorithm="RS256"))
        assert exc_info.value.violations == [_alg_violation("private_key_jwt", "RS256")]

    def test_client_secret_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_auth="client-secret")
        assert exc_info.value.violations == [
            "client_auth must be PrivateKeyJwt or MtlsClientAuth "
            "(FAPI 2.0 Security Profile §5.3.3.1)"
        ]

    def test_http_redirect_uri_refused(self):
        uri = "http://client.example.com/callback"
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(redirect_uri=uri)
        assert exc_info.value.violations == [HTTP_REDIRECT.format(uri=uri)]

    def test_native_app_loopback_redirect_accepted(self):
        uri = "http://127.0.0.1:8080/callback"
        assert _profile(redirect_uri=uri, native_app=True).redirect_uri == uri

    def test_non_compliant_discovery_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            FAPI2ClientProfile(
                _discovery(pushed_authorization_request_endpoint=None),
                client_id=CLIENT_ID,
                redirect_uri=REDIRECT_URI,
                client_auth=_pkj(),
            )
        assert exc_info.value.violations == [
            "pushed_authorization_request_endpoint not advertised; FAPI 2.0 "
            "Security Profile §5.3.2.2 requires pushed authorization requests "
            "(RFC 9126)"
        ]

    def test_failed_discovery_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            FAPI2ClientProfile(
                DiscoveryDocumentResponse(is_successful=False),
                client_id=CLIENT_ID,
                redirect_uri=REDIRECT_URI,
                client_auth=_pkj(),
            )
        assert exc_info.value.violations == ["Discovery document fetch failed"]

    def test_missing_issuer_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            FAPI2ClientProfile(
                _discovery(issuer=None),
                client_id=CLIENT_ID,
                redirect_uri=REDIRECT_URI,
                client_auth=_mtls(),
            )
        assert exc_info.value.violations == ["issuer is required"]

    def test_missing_authorization_endpoint_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            FAPI2ClientProfile(
                _discovery(authorization_endpoint=None),
                client_id=CLIENT_ID,
                redirect_uri=REDIRECT_URI,
                client_auth=_mtls(),
            )
        assert exc_info.value.violations == ["authorization_endpoint is required"]

    def test_derived_fields_are_not_constructor_arguments(self):
        kwargs: dict[str, Any] = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "client_auth": _pkj(),
            "issuer": "https://other.example.com",
        }
        with pytest.raises(TypeError):
            FAPI2ClientProfile(_discovery(), **kwargs)

    def test_replace_reruns_every_check(self):
        uri = "http://client.example.com/callback"
        with pytest.raises(FAPIProfileError) as exc_info:
            replace(_profile(), discovery=_discovery(), redirect_uri=uri)
        assert exc_info.value.violations == [HTTP_REDIRECT.format(uri=uri)]

    def test_empty_client_id_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_id="")
        assert exc_info.value.violations == ["client_id is required"]

    def test_profile_is_immutable(self):
        profile = _profile()
        with pytest.raises(FrozenInstanceError):
            profile.native_app = True  # type: ignore[misc]

    def test_error_is_value_error_with_joined_message(self):
        error = FAPIProfileError(["a", "b"])
        assert isinstance(error, ValueError)
        assert str(error) == "a; b"

    def test_signing_algorithms(self):
        assert _profile().signing_algorithms == ["ES256", "EdDSA", "PS256"]


@pytest.mark.unit
class TestFAPI2ClientProfilePushedAuthorizationRequest:
    def test_private_key_jwt_request(self):
        request = _profile().pushed_authorization_request(
            state="state", code_challenge="challenge", nonce="nonce", dpop_key=DPOP_KEY
        )
        assert request == _par()

    def test_profile_scope_requested(self):
        request = _profile(scope="openid accounts").pushed_authorization_request(
            state="state", code_challenge="challenge", dpop_key=DPOP_KEY
        )
        assert request.scope == "openid accounts"

    def test_mtls_request(self):
        request = _profile(client_auth=_mtls()).pushed_authorization_request(
            state="state", code_challenge="challenge", nonce="nonce"
        )
        assert request == _par(
            address=MTLS_PAR_ENDPOINT, private_key_jwt=None, dpop_key=None, mtls=_mtls()
        )

    def test_jarm_profile_requests_jwt_response_mode(self):
        request = _profile(jarm=True).pushed_authorization_request(
            state="state", code_challenge="challenge", nonce="nonce", dpop_key=DPOP_KEY
        )
        assert request == _par(response_mode="jwt")

    def test_private_key_jwt_without_dpop_key_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().pushed_authorization_request(
                state="state", code_challenge="challenge"
            )
        assert exc_info.value.violations == [NO_SENDER_CONSTRAINT]

    def test_weak_dpop_key_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().pushed_authorization_request(
                state="state", code_challenge="challenge", dpop_key=RS256_DPOP_KEY
            )
        assert exc_info.value.violations == [_alg_violation("DPoP", "RS256")]

    def test_mtls_with_dpop_key_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_auth=_mtls()).pushed_authorization_request(
                state="state", code_challenge="challenge", dpop_key=DPOP_KEY
            )
        assert exc_info.value.violations == [MTLS_WITH_DPOP]

    def test_long_nonce_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().pushed_authorization_request(
                state="state",
                code_challenge="challenge",
                nonce="n" * 65,
                dpop_key=DPOP_KEY,
            )
        assert exc_info.value.violations == [
            "nonce is 65 characters; FAPI 2.0 Security Profile §5.3.3.2 limits it to 64"
        ]

    def test_empty_code_challenge_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().pushed_authorization_request(
                state="state", code_challenge="", dpop_key=DPOP_KEY
            )
        assert exc_info.value.violations == ["PKCE code_challenge is required"]


@pytest.mark.unit
class TestFAPI2ClientProfileAuthorizationUrl:
    def test_only_client_id_and_request_uri(self):
        url = _profile().authorization_url("urn:ietf:params:oauth:request_uri:abc")
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
            AUTHORIZATION_ENDPOINT
        )
        assert parse_qs(parsed.query) == {
            "client_id": [CLIENT_ID],
            "request_uri": ["urn:ietf:params:oauth:request_uri:abc"],
        }

    def test_endpoint_with_query_keeps_it(self):
        profile = FAPI2ClientProfile(
            _discovery(authorization_endpoint=f"{AUTHORIZATION_ENDPOINT}?tenant=a"),
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            client_auth=_pkj(),
        )
        assert parse_qs(urlparse(profile.authorization_url("urn:x")).query) == {
            "tenant": ["a"],
            "client_id": [CLIENT_ID],
            "request_uri": ["urn:x"],
        }

    def test_empty_request_uri_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().authorization_url("")
        assert exc_info.value.violations == ["request_uri is required"]


@pytest.mark.unit
class TestFAPI2ClientProfileCallbackIssuer:
    def test_matching_iss_valid(self):
        response = parse_authorize_callback_response(
            f"{REDIRECT_URI}?code=c&state=s&iss={ISSUER}"
        )
        assert _profile().validate_callback_issuer(response).is_valid is True

    def test_missing_iss_rejected_even_without_metadata_flag(self):
        """FAPI 2.0 Security Profile §5.3.3.2: iss is always required."""
        response = parse_authorize_callback_response(f"{REDIRECT_URI}?code=c&state=s")
        result = _profile().validate_callback_issuer(response)
        assert result.result == AuthorizeCallbackValidationResult.MISSING_ISSUER

    def test_wrong_iss_rejected(self):
        response = parse_authorize_callback_response(
            f"{REDIRECT_URI}?code=c&state=s&iss=https://evil.example.com"
        )
        result = _profile().validate_callback_issuer(response)
        assert result.result == AuthorizeCallbackValidationResult.ISSUER_MISMATCH


@pytest.mark.unit
class TestFAPI2ClientProfileTokenRequest:
    def test_private_key_jwt_request(self):
        request = _profile().authorization_code_token_request(
            code="code", code_verifier="verifier", dpop_key=DPOP_KEY
        )
        assert request.address == TOKEN_ENDPOINT
        assert request.client_id == CLIENT_ID
        assert request.code == "code"
        assert request.redirect_uri == REDIRECT_URI
        assert request.code_verifier == "verifier"
        assert request.private_key_jwt == _pkj(issuer=ISSUER)
        assert request.dpop_key is DPOP_KEY
        assert request.mtls is None
        assert request.client_secret is None

    def test_mtls_request(self):
        request = _profile(client_auth=_mtls()).authorization_code_token_request(
            code="code", code_verifier="verifier"
        )
        assert request.address == MTLS_TOKEN_ENDPOINT
        assert request.mtls == _mtls()
        assert request.private_key_jwt is None
        assert request.dpop_key is None

    def test_private_key_jwt_without_dpop_key_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().authorization_code_token_request(
                code="code", code_verifier="verifier"
            )
        assert exc_info.value.violations == [NO_SENDER_CONSTRAINT]

    def test_mtls_with_dpop_key_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile(client_auth=_mtls()).authorization_code_token_request(
                code="code", code_verifier="verifier", dpop_key=DPOP_KEY
            )
        assert exc_info.value.violations == [MTLS_WITH_DPOP]

    def test_missing_code_verifier_refused(self):
        with pytest.raises(FAPIProfileError) as exc_info:
            _profile().authorization_code_token_request(
                code="code", code_verifier="", dpop_key=DPOP_KEY
            )
        assert exc_info.value.violations == ["PKCE code_verifier is required"]
