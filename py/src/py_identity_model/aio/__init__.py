"""Asynchronous implementations of py-identity-model.

This module provides async/await versions of all client methods
for non-blocking I/O operations.

Example:
    ```python
    from py_identity_model import DiscoveryDocumentRequest
    from py_identity_model.aio import get_discovery_document


    async def main():
        request = DiscoveryDocumentRequest(
            address="https://example.com/.well-known/openid-configuration"
        )
        response = await get_discovery_document(request)
        if response.is_successful:
            print(f"Issuer: {response.issuer}")
    ```
"""

# Initialize SSL compatibility for backward compatibility with requests library
from .. import ssl_config  # noqa: F401
from ..core.authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from ..core.authorize_url import build_authorization_url
from ..core.claims_validation import (
    ClaimsValidationError,
    ClaimsValidator,
    combine_claims_validators,
    require_claim_value,
    require_claims,
    require_scopes,
)
from ..core.discovery_policy import (
    DiscoveryEndpoint,
    DiscoveryPolicy,
    parse_discovery_url,
)
from ..core.dpop import (
    DPoPKey,
    build_dpop_headers,
    compute_ath,
    create_dpop_proof,
    extract_dpop_nonce,
    generate_dpop_key,
)
from ..core.fapi import (
    FAPI2_ALLOWED_AUTH_METHODS,
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    FAPI2_REQUIRED_PKCE_METHOD,
    FAPI2_REQUIRED_RESPONSE_TYPE,
    FAPIValidationResult,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)
from ..core.jar import build_jar_authorization_url, create_request_object
from ..core.jarm import (
    extract_jarm_response_jwt,
    is_jarm_response,
)
from ..core.logout_logic import (
    build_end_session_url,
    validate_post_logout_state,
)
from ..core.models import (
    BaseRequest,
    BaseResponse,
    MtlsClientAuth,
    PrivateKeyJwt,
)
from ..core.mtls import (
    certificate_thumbprint_from_file,
    compute_certificate_thumbprint,
    resolve_mtls_endpoint,
    validate_certificate_binding,
)
from ..core.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)
from ..core.state_validation import (
    AuthorizeCallbackValidationResult,
    StateValidationResult,
    validate_authorize_callback_issuer,
    validate_authorize_callback_state,
)
from .device_auth import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
    poll_device_token,
    request_device_authorization,
)
from .discovery import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    get_discovery_document,
)
from .introspection import (
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    introspect_token,
)
from .jarm import process_jarm_response
from .jwks import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
    get_jwks,
    jwks_from_dict,
)
from .logout import validate_logout_token
from .managed_client import AsyncHTTPClient
from .par import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
    push_authorization_request,
)
from .registration import (
    ClientDeleteRequest,
    ClientDeleteResponse,
    ClientReadRequest,
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    ClientUpdateRequest,
    delete_client,
    read_client,
    register_client,
    update_client,
)
from .revocation import (
    TokenRevocationRequest,
    TokenRevocationResponse,
    revoke_token,
)
from .token_client import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    refresh_token,
    request_authorization_code_token,
    request_client_credentials_token,
)
from .token_exchange import (
    TokenExchangeRequest,
    TokenExchangeResponse,
    exchange_token,
)
from .token_validation import TokenValidationConfig, validate_token
from .userinfo import UserInfoRequest, UserInfoResponse, get_userinfo


__all__ = [
    # FAPI 2.0
    "FAPI2_ALLOWED_AUTH_METHODS",
    "FAPI2_ALLOWED_SIGNING_ALGORITHMS",
    "FAPI2_REQUIRED_PKCE_METHOD",
    "FAPI2_REQUIRED_RESPONSE_TYPE",
    # HTTP Client
    "AsyncHTTPClient",
    # Auth Code + PKCE
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    # Authorize Callback
    "AuthorizeCallbackResponse",
    "AuthorizeCallbackValidationResult",
    # Base Classes
    "BaseRequest",
    "BaseResponse",
    "ClaimsValidationError",
    "ClaimsValidator",
    # Token Client
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    # Dynamic Client Registration
    "ClientDeleteRequest",
    "ClientDeleteResponse",
    "ClientReadRequest",
    "ClientRegistrationRequest",
    "ClientRegistrationResponse",
    "ClientUpdateRequest",
    # DPoP
    "DPoPKey",
    # Device Authorization Grant
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    # Discovery
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    # Discovery Policy
    "DiscoveryEndpoint",
    "DiscoveryPolicy",
    "FAPIValidationResult",
    # JWKS
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    # mTLS (RFC 8705)
    "MtlsClientAuth",
    # PAR
    "PrivateKeyJwt",
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    # Refresh Token
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "StateValidationResult",
    # Token Exchange
    "TokenExchangeRequest",
    "TokenExchangeResponse",
    # Token Introspection
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    # Token Revocation
    "TokenRevocationRequest",
    "TokenRevocationResponse",
    # Token Validation
    "TokenValidationConfig",
    # UserInfo
    "UserInfoRequest",
    "UserInfoResponse",
    "build_authorization_url",
    "build_dpop_headers",
    "build_end_session_url",
    "build_jar_authorization_url",
    "certificate_thumbprint_from_file",
    "combine_claims_validators",
    "compute_ath",
    "compute_certificate_thumbprint",
    "create_dpop_proof",
    "create_request_object",
    "delete_client",
    "exchange_token",
    "extract_dpop_nonce",
    "extract_jarm_response_jwt",
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_dpop_key",
    "generate_pkce_pair",
    "get_discovery_document",
    "get_jwks",
    "get_userinfo",
    "introspect_token",
    "is_jarm_response",
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "parse_discovery_url",
    "poll_device_token",
    "process_jarm_response",
    "push_authorization_request",
    "read_client",
    "refresh_token",
    "register_client",
    "request_authorization_code_token",
    "request_client_credentials_token",
    "request_device_authorization",
    "require_claim_value",
    "require_claims",
    "require_scopes",
    "resolve_mtls_endpoint",
    "revoke_token",
    "update_client",
    "validate_authorize_callback_issuer",
    "validate_authorize_callback_state",
    "validate_certificate_binding",
    "validate_fapi_authorization_request",
    "validate_fapi_client_config",
    "validate_fapi_discovery",
    "validate_logout_token",
    "validate_post_logout_state",
    "validate_token",
]
