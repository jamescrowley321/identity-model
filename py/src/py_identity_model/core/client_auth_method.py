"""The client authentication methods the library implements.

Kept free of imports from the rest of the package so request models, the
config module and the client-auth helpers can all depend on it without a cycle.
"""

from __future__ import annotations

from enum import Enum


class ClientAuthMethod(Enum):
    """How a client authenticates at a token-family endpoint.

    Values are the ``token_endpoint_auth_method`` names from RFC 7591 §2 and
    OpenID Connect Core 1.0 §9 (``client_secret_*``, ``private_key_jwt``,
    ``none``) and RFC 8705 §2 (``tls_client_auth``,
    ``self_signed_tls_client_auth``). ``client_secret_jwt`` is not implemented.
    """

    NONE = "none"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"
    PRIVATE_KEY_JWT = "private_key_jwt"
    TLS_CLIENT_AUTH = "tls_client_auth"
    SELF_SIGNED_TLS_CLIENT_AUTH = "self_signed_tls_client_auth"

    @property
    def uses_client_secret(self) -> bool:
        """Whether the method sends the shared ``client_secret``."""
        return self in _CLIENT_SECRET_METHODS

    @property
    def is_mtls(self) -> bool:
        """Whether the method authenticates with a TLS client certificate."""
        return self in _MTLS_METHODS


_CLIENT_SECRET_METHODS = frozenset(
    {ClientAuthMethod.CLIENT_SECRET_BASIC, ClientAuthMethod.CLIENT_SECRET_POST}
)
_MTLS_METHODS = frozenset(
    {ClientAuthMethod.TLS_CLIENT_AUTH, ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH}
)


__all__ = ["ClientAuthMethod"]
