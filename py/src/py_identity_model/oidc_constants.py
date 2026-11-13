from enum import Enum


class AuthorizeRequest(Enum):
    """OpenID Connect authorize request parameters."""

    SCOPE = "scope"
    RESPONSE_TYPE = "response_type"
    CLIENT_ID = "client_id"
    REDIRECT_URI = "redirect_uri"
    STATE = "state"
    RESPONSE_MODE = "response_mode"
    NONCE = "nonce"
    DISPLAY = "display"
    PROMPT = "prompt"
    MAX_AGE = "max_age"
    UI_LOCALES = "ui_locales"
    ID_TOKEN_HINT = "id_token_hint"
    LOGIN_HINT = "login_hint"
    ACR_VALUES = "acr_values"
    CODE_CHALLENGE = "code_challenge"
    CODE_CHALLENGE_METHOD = "code_challenge_method"
    REQUEST = "request"
    REQUEST_URI = "request_uri"
    RESOURCE = "resource"
    DPOP_KEY_THUMBPRINT = "dpop_jkt"


class AuthorizeErrors(Enum):
    """OpenID Connect authorize error codes."""

    # OAuth2 errors
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_SCOPE = "invalid_scope"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    UNMET_AUTHENTICATION_REQUIREMENTS = "unmet_authentication_requirements"
    # OIDC errors
    INTERACTION_REQUIRED = "interaction_required"
    LOGIN_REQUIRED = "login_required"
    ACCOUNT_SELECTION_REQUIRED = "account_selection_required"
    CONSENT_REQUIRED = "consent_required"
    INVALID_REQUEST_URI = "invalid_request_uri"
    INVALID_REQUEST_OBJECT = "invalid_request_object"
    REQUEST_NOT_SUPPORTED = "request_not_supported"
    REQUEST_URI_NOT_SUPPORTED = "request_uri_not_supported"
    REGISTRATION_NOT_SUPPORTED = "registration_not_supported"
    # resource indicator spec
    INVALID_TARGET = "invalid_target"


class AuthorizeResponse(Enum):
    """OpenID Connect authorize response parameters."""

    SCOPE = "scope"
    CODE = "code"
    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    TOKEN_TYPE = "token_type"
    REFRESH_TOKEN = "refresh_token"
    IDENTITY_TOKEN = "id_token"
    STATE = "state"
    SESSION_STATE = "session_state"
    ISSUER = "iss"
    ERROR = "error"
    ERROR_DESCRIPTION = "error_description"


class DeviceAuthorizationResponse(Enum):
    """OpenID Connect device authorization response parameters."""

    DEVICE_CODE = "device_code"
    USER_CODE = "user_code"
    VERIFICATION_URI = "verification_uri"
    VERIFICATION_URI_COMPLETE = "verification_uri_complete"
    EXPIRES_IN = "expires_in"
    INTERVAL = "interval"


class EndSessionRequest(Enum):
    """OpenID Connect end session request parameters."""

    ID_TOKEN_HINT = "id_token_hint"
    POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri"
    STATE = "state"
    SID = "sid"
    ISSUER = "iss"
    UI_LOCALES = "ui_locales"


class TokenRequest(Enum):
    """OpenID Connect token request parameters."""

    GRANT_TYPE = "grant_type"
    REDIRECT_URI = "redirect_uri"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    CLIENT_ASSERTION = "client_assertion"
    CLIENT_ASSERTION_TYPE = "client_assertion_type"
    ASSERTION = "assertion"
    CODE = "code"
    REFRESH_TOKEN = "refresh_token"
    SCOPE = "scope"
    USER_NAME = "username"
    PASSWORD = "password"
    CODE_VERIFIER = "code_verifier"
    TOKEN_TYPE = "token_type"
    ALGORITHM = "alg"
    KEY = "key"
    DEVICE_CODE = "device_code"
    # token exchange
    RESOURCE = "resource"
    AUDIENCE = "audience"
    REQUESTED_TOKEN_TYPE = "requested_token_type"
    SUBJECT_TOKEN = "subject_token"
    SUBJECT_TOKEN_TYPE = "subject_token_type"
    ACTOR_TOKEN = "actor_token"
    ACTOR_TOKEN_TYPE = "actor_token_type"
    # ciba
    AUTHENTICATION_REQUEST_ID = "auth_req_id"


class BackchannelAuthenticationRequest(Enum):
    """OpenID Connect backchannel authentication request parameters."""

    SCOPE = "scope"
    CLIENT_NOTIFICATION_TOKEN = "client_notification_token"
    ACR_VALUES = "acr_values"
    LOGIN_HINT_TOKEN = "login_hint_token"
    ID_TOKEN_HINT = "id_token_hint"
    LOGIN_HINT = "login_hint"
    BINDING_MESSAGE = "binding_message"
    USER_CODE = "user_code"
    REQUESTED_EXPIRY = "requested_expiry"
    REQUEST = "request"
    RESOURCE = "resource"
    DPOP_KEY_THUMBPRINT = "dpop_jkt"


class BackchannelAuthenticationRequestErrors(Enum):
    """OpenID Connect backchannel authentication request error codes."""

    INVALID_REQUEST_OBJECT = "invalid_request_object"
    INVALID_REQUEST = "invalid_request"
    INVALID_SCOPE = "invalid_scope"
    EXPIRED_LOGIN_HINT_TOKEN = "expired_login_hint_token"
    UNKNOWN_USER_ID = "unknown_user_id"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    MISSING_USER_CODE = "missing_user_code"
    INVALID_USER_CODE = "invalid_user_code"
    INVALID_BINDING_MESSAGE = "invalid_binding_message"
    INVALID_CLIENT = "invalid_client"
    ACCESS_DENIED = "access_denied"
    INVALID_TARGET = "invalid_target"


class TokenRequestTypes(Enum):
    """OpenID Connect token request types."""

    BEARER = "bearer"
    POP = "pop"


class TokenErrors(Enum):
    """OpenID Connect token error codes."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_SCOPE = "invalid_scope"
    AUTHORIZATION_PENDING = "authorization_pending"
    ACCESS_DENIED = "access_denied"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"
    INVALID_TARGET = "invalid_target"
    INVALID_DPOP_PROOF = "invalid_dpop_proof"
    USE_DPOP_NONCE = "use_dpop_nonce"


class TokenResponse(Enum):
    """OpenID Connect token response parameters."""

    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    TOKEN_TYPE = "token_type"
    REFRESH_TOKEN = "refresh_token"
    IDENTITY_TOKEN = "id_token"
    ERROR = "error"
    ERROR_DESCRIPTION = "error_description"
    BEARER_TOKEN_TYPE = "Bearer"
    DPOP_TOKEN_TYPE = "DPoP"
    ISSUED_TOKEN_TYPE = "issued_token_type"
    SCOPE = "scope"


class BackchannelAuthenticationResponse(Enum):
    """OpenID Connect backchannel authentication response parameters."""

    AUTHENTICATION_REQUEST_ID = "auth_req_id"
    EXPIRES_IN = "expires_in"
    INTERVAL = "interval"


class PushedAuthorizationRequestResponse(Enum):
    """OpenID Connect pushed authorization request response parameters."""

    EXPIRES_IN = "expires_in"
    REQUEST_URI = "request_uri"


class TokenIntrospectionRequest(Enum):
    """OpenID Connect token introspection request parameters."""

    TOKEN = "token"
    TOKEN_TYPE_HINT = "token_type_hint"


class RegistrationResponse(Enum):
    """OpenID Connect registration response parameters."""

    ERROR = "error"
    ERROR_DESCRIPTION = "error_description"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    REGISTRATION_ACCESS_TOKEN = "registration_access_token"
    REGISTRATION_CLIENT_URI = "registration_client_uri"
    CLIENT_ID_ISSUED_AT = "client_id_issued_at"
    CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at"
    SOFTWARE_STATEMENT = "software_statement"


class ClientMetadata(Enum):
    """OpenID Connect client metadata parameters."""

    REDIRECT_URIS = "redirect_uris"
    RESPONSE_TYPES = "response_types"
    GRANT_TYPES = "grant_types"
    APPLICATION_TYPE = "application_type"
    CONTACTS = "contacts"
    CLIENT_NAME = "client_name"
    LOGO_URI = "logo_uri"
    CLIENT_URI = "client_uri"
    POLICY_URI = "policy_uri"
    TOS_URI = "tos_uri"
    JWKS_URI = "jwks_uri"
    JWKS = "jwks"
    SECTOR_IDENTIFIER_URI = "sector_identifier_uri"
    SCOPE = "scope"
    POST_LOGOUT_REDIRECT_URIS = "post_logout_redirect_uris"
    FRONT_CHANNEL_LOGOUT_URI = "frontchannel_logout_uri"
    FRONT_CHANNEL_LOGOUT_SESSION_REQUIRED = "frontchannel_logout_session_required"
    BACKCHANNEL_LOGOUT_URI = "backchannel_logout_uri"
    BACKCHANNEL_LOGOUT_SESSION_REQUIRED = "backchannel_logout_session_required"
    SOFTWARE_ID = "software_id"
    SOFTWARE_STATEMENT = "software_statement"
    SOFTWARE_VERSION = "software_version"
    SUBJECT_TYPE = "subject_type"
    TOKEN_ENDPOINT_AUTHENTICATION_METHOD = "token_endpoint_auth_method"
    TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM = "token_endpoint_auth_signing_alg"
    DEFAULT_MAX_AGE = "default_max_age"
    REQUIRE_AUTHENTICATION_TIME = "require_auth_time"
    DEFAULT_ACR_VALUES = "default_acr_values"
    INITIATE_LOGIN_URI = "initiate_login_uri"
    REQUEST_URIS = "request_uris"
    IDENTITY_TOKEN_SIGNED_RESPONSE_ALGORITHM = "id_token_signed_response_alg"
    IDENTITY_TOKEN_ENCRYPTED_RESPONSE_ALGORITHM = "id_token_encrypted_response_alg"
    IDENTITY_TOKEN_ENCRYPTED_RESPONSE_ENCRYPTION = "id_token_encrypted_response_enc"
    USERINFO_SIGNED_RESPONSE_ALGORITHM = "userinfo_signed_response_alg"
    USER_INFO_ENCRYPTED_RESPONSE_ALGORITHM = "userinfo_encrypted_response_alg"
    USERINFO_ENCRYPTED_RESPONSE_ENCRYPTION = "userinfo_encrypted_response_enc"
    REQUEST_OBJECT_SIGNING_ALGORITHM = "request_object_signing_alg"
    REQUEST_OBJECT_ENCRYPTION_ALGORITHM = "request_object_encryption_alg"
    REQUEST_OBJECT_ENCRYPTION_ENCRYPTION = "request_object_encryption_enc"
    REQUIRE_SIGNED_REQUEST_OBJECT = "require_signed_request_object"
    ALWAYS_USE_DPOP_BOUND_ACCESS_TOKENS = "dpop_bound_access_tokens"
    INTROSPECTION_SIGNED_RESPONSE_ALGORITHM = "introspection_signed_response_alg"
    INTROSPECTION_ENCRYPTED_RESPONSE_ALGORITHM = "introspection_encrypted_response_alg"
    INTROSPECTION_ENCRYPTED_RESPONSE_ENCRYPTION = "introspection_encrypted_response_enc"


class TokenTypes(Enum):
    """OpenID Connect token types."""

    ACCESS_TOKEN = "access_token"
    IDENTITY_TOKEN = "id_token"
    REFRESH_TOKEN = "refresh_token"


class TokenTypeIdentifiers(Enum):
    """OpenID Connect token type identifiers."""

    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    IDENTITY_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
    SAML11 = "urn:ietf:params:oauth:token-type:saml1"
    SAML2 = "urn:ietf:params:oauth:token-type:saml2"
    JWT = "urn:ietf:params:oauth:token-type:jwt"


class AuthenticationSchemes(Enum):
    """OAuth 2.0 authentication schemes for Authorization header (RFC 6750, RFC 9449)."""

    BEARER = "Bearer"
    DPOP = "DPoP"
    POP = "PoP"


class TokenParameterNames(Enum):
    """Parameter names for passing tokens in different contexts (RFC 6750)."""

    # Bearer tokens
    ACCESS_TOKEN = "access_token"  # Form body and query string parameter
    # PoP tokens
    POP_ACCESS_TOKEN = "pop_access_token"  # Form body and query string parameter


class GrantTypes(Enum):
    """OpenID Connect grant types."""

    PASSWORD = "password"
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    IMPLICIT = "implicit"
    SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    CIBA = "urn:openid:params:grant-type:ciba"


class ClientAssertionTypes(Enum):
    """OpenID Connect client assertion types."""

    JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    SAML_BEARER = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"


class ResponseTypes(Enum):
    """OpenID Connect response types."""

    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"
    ID_TOKEN_TOKEN = "id_token token"
    CODE_ID_TOKEN = "code id_token"
    CODE_TOKEN = "code token"
    CODE_ID_TOKEN_TOKEN = "code id_token token"


class ResponseModes(Enum):
    """OpenID Connect response modes."""

    FORM_POST = "form_post"
    QUERY = "query"
    FRAGMENT = "fragment"
    # JWT-Secured Authorization Response Mode (JARM) — the authorization
    # response is returned as a JWT in the ``response`` parameter.
    QUERY_JWT = "query.jwt"
    FRAGMENT_JWT = "fragment.jwt"
    FORM_POST_JWT = "form_post.jwt"
    JWT = "jwt"


class DisplayModes(Enum):
    """OpenID Connect display modes."""

    PAGE = "page"
    POPUP = "popup"
    TOUCH = "touch"
    WAP = "wap"


class PromptModes(Enum):
    """OpenID Connect prompt modes."""

    NONE = "none"
    LOGIN = "login"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"
    CREATE = "create"


class CodeChallengeMethods(Enum):
    """OpenID Connect code challenge methods."""

    PLAIN = "plain"
    SHA256 = "S256"


class ProtectedResourceErrors(Enum):
    """OpenID Connect protected resource error codes."""

    INVALID_TOKEN = "invalid_token"
    EXPIRED_TOKEN = "expired_token"
    INVALID_REQUEST = "invalid_request"
    INSUFFICIENT_SCOPE = "insufficient_scope"


class AuthenticationMethods(Enum):
    """OpenID Connect authentication methods."""

    FACIAL_RECOGNITION = "face"
    FINGERPRINT_BIOMETRIC = "fpt"
    GEOLOCATION = "geo"
    PROOF_OF_POSSESSION_HARDWARE_SECURED_KEY = "hwk"
    IRIS_SCAN_BIOMETRIC = "iris"
    KNOWLEDGE_BASED_AUTHENTICATION = "kba"
    MULTIPLE_CHANNEL_AUTHENTICATION = "mca"
    MULTI_FACTOR_AUTHENTICATION = "mfa"
    ONE_TIME_PASSWORD = "otp"
    PERSONAL_IDENTIFICATION_OR_PATTERN = "pin"
    PROOF_OF_POSSESSION_KEY = "pop"
    PASSWORD = "pwd"
    RISK_BASED_AUTHENTICATION = "rba"
    RETINA_SCAN_BIOMETRIC = "retina"
    SMART_CARD = "sc"
    CONFIRMATION_BY_SMS = "sms"
    PROOF_OF_POSSESSION_SOFTWARE_SECURED_KEY = "swk"
    CONFIRMATION_BY_TELEPHONE = "tel"
    USER_PRESENCE_TEST = "user"
    VOICE_BIOMETRIC = "vbm"
    WINDOWS_INTEGRATED_AUTHENTICATION = "wia"


class SymmetricAlgorithms(Enum):
    """OpenID Connect symmetric algorithms."""

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"


class AsymmetricAlgorithms(Enum):
    """OpenID Connect asymmetric algorithms."""

    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"


class Algorithms(Enum):
    """OpenID Connect algorithms."""

    NONE = "none"
    # Nested classes are implemented as separate enums


class Discovery(Enum):
    """OpenID Connect discovery parameters."""

    ISSUER = "issuer"
    # endpoints
    AUTHORIZATION_ENDPOINT = "authorization_endpoint"
    DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization_endpoint"
    TOKEN_ENDPOINT = "token_endpoint"
    USER_INFO_ENDPOINT = "userinfo_endpoint"
    INTROSPECTION_ENDPOINT = "introspection_endpoint"
    REVOCATION_ENDPOINT = "revocation_endpoint"
    DISCOVERY_ENDPOINT = ".well-known/openid-configuration"
    JWKS_URI = "jwks_uri"
    END_SESSION_ENDPOINT = "end_session_endpoint"
    CHECK_SESSION_IFRAME = "check_session_iframe"
    REGISTRATION_ENDPOINT = "registration_endpoint"
    MTLS_ENDPOINT_ALIASES = "mtls_endpoint_aliases"
    PUSHED_AUTHORIZATION_REQUEST_ENDPOINT = "pushed_authorization_request_endpoint"
    # common capabilities
    FRONT_CHANNEL_LOGOUT_SUPPORTED = "frontchannel_logout_supported"
    FRONT_CHANNEL_LOGOUT_SESSION_SUPPORTED = "frontchannel_logout_session_supported"
    BACK_CHANNEL_LOGOUT_SUPPORTED = "backchannel_logout_supported"
    BACK_CHANNEL_LOGOUT_SESSION_SUPPORTED = "backchannel_logout_session_supported"
    GRANT_TYPES_SUPPORTED = "grant_types_supported"
    CODE_CHALLENGE_METHODS_SUPPORTED = "code_challenge_methods_supported"
    SCOPES_SUPPORTED = "scopes_supported"
    SUBJECT_TYPES_SUPPORTED = "subject_types_supported"
    RESPONSE_MODES_SUPPORTED = "response_modes_supported"
    RESPONSE_TYPES_SUPPORTED = "response_types_supported"
    CLAIMS_SUPPORTED = "claims_supported"
    TOKEN_ENDPOINT_AUTHENTICATION_METHODS_SUPPORTED = (
        "token_endpoint_auth_methods_supported"
    )
    # more capabilities
    CLAIMS_LOCALES_SUPPORTED = "claims_locales_supported"
    CLAIMS_PARAMETER_SUPPORTED = "claims_parameter_supported"
    CLAIM_TYPES_SUPPORTED = "claim_types_supported"
    DISPLAY_VALUES_SUPPORTED = "display_values_supported"
    ACR_VALUES_SUPPORTED = "acr_values_supported"
    ID_TOKEN_ENCRYPTION_ALGORITHMS_SUPPORTED = (
        "id_token_encryption_alg_values_supported"
    )
    ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED = (
        "id_token_encryption_enc_values_supported"
    )
    ID_TOKEN_SIGNING_ALGORITHMS_SUPPORTED = "id_token_signing_alg_values_supported"
    OP_POLICY_URI = "op_policy_uri"
    OP_TOS_URI = "op_tos_uri"
    REQUEST_OBJECT_ENCRYPTION_ALGORITHMS_SUPPORTED = (
        "request_object_encryption_alg_values_supported"
    )
    REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED = (
        "request_object_encryption_enc_values_supported"
    )
    REQUEST_OBJECT_SIGNING_ALGORITHMS_SUPPORTED = (
        "request_object_signing_alg_values_supported"
    )
    REQUEST_PARAMETER_SUPPORTED = "request_parameter_supported"
    REQUEST_URI_PARAMETER_SUPPORTED = "request_uri_parameter_supported"
    REQUIRE_REQUEST_URI_REGISTRATION = "require_request_uri_registration"
    SERVICE_DOCUMENTATION = "service_documentation"
    TOKEN_ENDPOINT_AUTH_SIGNING_ALGORITHMS_SUPPORTED = (
        "token_endpoint_auth_signing_alg_values_supported"
    )
    UI_LOCALES_SUPPORTED = "ui_locales_supported"
    USER_INFO_ENCRYPTION_ALGORITHMS_SUPPORTED = (
        "userinfo_encryption_alg_values_supported"
    )
    USER_INFO_ENCRYPTION_ENC_VALUES_SUPPORTED = (
        "userinfo_encryption_enc_values_supported"
    )
    USER_INFO_SIGNING_ALGORITHMS_SUPPORTED = "userinfo_signing_alg_values_supported"
    TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS = (
        "tls_client_certificate_bound_access_tokens"
    )
    AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED = (
        "authorization_response_iss_parameter_supported"
    )
    PROMPT_VALUES_SUPPORTED = "prompt_values_supported"
    INTROSPECTION_SIGNING_ALGORITHMS_SUPPORTED = (
        "introspection_signing_alg_values_supported"
    )
    INTROSPECTION_ENCRYPTION_ALGORITHMS_SUPPORTED = (
        "introspection_encryption_alg_values_supported"
    )
    INTROSPECTION_ENCRYPTION_ENC_VALUES_SUPPORTED = (
        "introspection_encryption_enc_values_supported"
    )
    # CIBA
    BACKCHANNEL_TOKEN_DELIVERY_MODES_SUPPORTED = (
        "backchannel_token_delivery_modes_supported"
    )
    BACKCHANNEL_AUTHENTICATION_ENDPOINT = "backchannel_authentication_endpoint"
    BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG_VALUES_SUPPORTED = (
        "backchannel_authentication_request_signing_alg_values_supported"
    )
    BACKCHANNEL_USER_CODE_PARAMETER_SUPPORTED = (
        "backchannel_user_code_parameter_supported"
    )
    # DPoP
    DPOP_SIGNING_ALGORITHMS_SUPPORTED = "dpop_signing_alg_values_supported"
    # PAR
    REQUIRE_PUSHED_AUTHORIZATION_REQUESTS = "require_pushed_authorization_requests"


class BackchannelTokenDeliveryModes(Enum):
    """OpenID Connect backchannel token delivery modes."""

    POLL = "poll"
    PING = "ping"
    PUSH = "push"


class Events(Enum):
    """OpenID Connect events."""

    BACK_CHANNEL_LOGOUT = "http://schemas.openid.net/event/backchannel-logout"


class BackChannelLogoutRequest(Enum):
    """OpenID Connect backchannel logout request parameters."""

    LOGOUT_TOKEN = "logout_token"


class StandardScopes(Enum):
    """OpenID Connect standard scopes."""

    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"
    ADDRESS = "address"
    PHONE = "phone"
    OFFLINE_ACCESS = "offline_access"


class HttpHeaders(Enum):
    """OpenID Connect HTTP headers."""

    DPOP = "DPoP"
    DPOP_NONCE = "DPoP-Nonce"
