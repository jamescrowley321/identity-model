"""
Core module for py-identity-model.

This module contains shared business logic, models, validators, and utilities
that are used by both sync and async implementations.
"""

from .authorize_response import (
    AuthorizeCallbackResponse,
    parse_authorize_callback_response,
)
from .authorize_url import build_authorization_url
from .http_utils import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RETRY_BASE_DELAY,
    DEFAULT_RETRY_MAX_ATTEMPTS,
)
from .jwt_helpers import decode_and_validate_jwt
from .models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    BaseRequest,
    BaseResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
    TokenValidationConfig,
)
from .parsers import (
    get_public_key_from_jwk as get_public_key_from_jwk,
)
from .parsers import jwks_from_dict
from .pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)
from .state_validation import (
    AuthorizeCallbackValidationResult,
    StateValidationResult,
    validate_authorize_callback_issuer,
    validate_authorize_callback_state,
)
from .validators import (
    validate_https_url,
    validate_issuer,
    validate_parameter_values,
    validate_required_parameters,
    validate_token_config,
)


__all__ = [
    # From http_utils
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_RETRY_BASE_DELAY",
    "DEFAULT_RETRY_MAX_ATTEMPTS",
    # Auth Code + PKCE
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    # From authorize_response
    "AuthorizeCallbackResponse",
    # From state_validation
    "AuthorizeCallbackValidationResult",
    # From models (base classes)
    "BaseRequest",
    "BaseResponse",
    # From models
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "DiscoveryErrorKind",
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    "StateValidationResult",
    "TokenValidationConfig",
    "build_authorization_url",
    # From jwt_helpers
    "decode_and_validate_jwt",
    "generate_code_challenge",
    "generate_code_verifier",
    "generate_pkce_pair",
    # From parsers
    "jwks_from_dict",
    "parse_authorize_callback_response",
    "validate_authorize_callback_issuer",
    "validate_authorize_callback_state",
    # From validators
    "validate_https_url",
    "validate_issuer",
    "validate_parameter_values",
    "validate_required_parameters",
    "validate_token_config",
]
