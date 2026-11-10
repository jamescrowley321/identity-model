"""Client authentication for token-family requests.

RFC 6749 §2.3.1 (``client_secret_basic`` / ``client_secret_post``), RFC 7523
(``private_key_jwt``), RFC 8705 §2 (mTLS) and public clients (``none``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from urllib.parse import quote

from ..exceptions import ClientAuthMethodError, ClientAuthMethodErrorReason
from ..oidc_constants import TokenRequest
from .client_assertion import apply_private_key_jwt
from .client_auth_method import ClientAuthMethod
from .mtls import apply_mtls_client_auth


if TYPE_CHECKING:
    from .models import MtlsClientAuth, PrivateKeyJwt


def basic_auth_credentials(client_id: str, client_secret: str) -> tuple[str, str]:
    """Return ``(client_id, client_secret)`` encoded for HTTP Basic auth.

    RFC 6749 §2.3.1 requires the client identifier and secret to be encoded
    using ``application/x-www-form-urlencoded`` (Appendix B) *before* they are
    used as the HTTP Basic username and password. HTTP client libraries (httpx
    included) base64-encode the pair verbatim, so a client_id or secret that
    contains reserved characters (``%``, ``+``, ``/``, ``:``, space) would be
    mangled by an authorization server that form-urldecodes per spec — the
    exact failure dynamically-registered secrets trigger.

    Percent-encode both values with an empty ``safe`` set so every reserved
    character (including the ``:`` Basic-auth separator) is escaped; clean
    ASCII credentials pass through unchanged, so this is a no-op for the common
    case and only corrects credentials that would otherwise be misdecoded.
    """
    return quote(client_id, safe=""), quote(client_secret, safe="")


class ClientAuthenticatingRequest(Protocol):
    """The fields a confidential-client request carries for authentication."""

    address: str
    client_id: str
    private_key_jwt: PrivateKeyJwt | None
    mtls: MtlsClientAuth | None
    client_auth_method: ClientAuthMethod | None


def resolve_client_auth_method(
    request: ClientAuthenticatingRequest, *, client_secret: str | None
) -> ClientAuthMethod:
    """The method *request* authenticates with.

    An explicit ``client_auth_method`` wins. ``None`` picks by precedence:
    ``private_key_jwt``, then ``mtls`` (its own ``auth_method``), then
    ``client_secret`` as HTTP Basic, else public.
    """
    if request.client_auth_method is not None:
        return request.client_auth_method
    if request.private_key_jwt is not None:
        return ClientAuthMethod.PRIVATE_KEY_JWT
    if request.mtls is not None:
        return request.mtls.auth_method
    if client_secret is not None:
        return ClientAuthMethod.CLIENT_SECRET_BASIC
    return ClientAuthMethod.NONE


def _missing(method: ClientAuthMethod, credential: str) -> ClientAuthMethodError:
    return ClientAuthMethodError(
        ClientAuthMethodErrorReason.MISSING_CREDENTIAL, method, credential
    )


def apply_client_auth(
    params: dict[str, str],
    request: ClientAuthenticatingRequest,
    *,
    client_secret: str | None,
) -> tuple[str, str] | None:
    """Authenticate the client on a form-encoded request.

    Mutates *params* in place and returns HTTP Basic credentials, or ``None``
    when the method sends no ``Authorization`` header. Only the resolved
    method's credential is sent.

    Args:
        params: Request body parameters to mutate in place.
        request: The request being authenticated.
        client_secret: ``request.client_secret`` as the caller treats it
            (``None`` means "not provided").

    Raises:
        ClientAuthMethodError: An explicit method's credential is missing, or
            an explicit mTLS method differs from ``mtls.auth_method``. Raised
            before anything is sent.
    """
    method = resolve_client_auth_method(request, client_secret=client_secret)

    if method is ClientAuthMethod.PRIVATE_KEY_JWT:
        if request.private_key_jwt is None:
            raise _missing(method, "private_key_jwt")
        apply_private_key_jwt(
            params,
            request.private_key_jwt,
            client_id=request.client_id,
            default_audience=request.address,
        )
        return None

    if method.is_mtls:
        if request.mtls is None:
            raise _missing(method, "mtls")
        if request.mtls.auth_method is not method:
            raise ClientAuthMethodError(
                ClientAuthMethodErrorReason.MTLS_METHOD_MISMATCH, method, "mtls"
            )
        # RFC 8705 §2: the certificate is presented at the TLS layer and
        # client_id goes in the body; no Authorization header.
        apply_mtls_client_auth(params, client_id=request.client_id)
        return None

    if method.uses_client_secret:
        secret = client_secret or ""
        if not secret and request.client_auth_method is not None:
            raise _missing(method, "client_secret")
        if method is ClientAuthMethod.CLIENT_SECRET_BASIC:
            return basic_auth_credentials(request.client_id, secret)
        params[TokenRequest.CLIENT_ID.value] = request.client_id
        params[TokenRequest.CLIENT_SECRET.value] = secret
        return None

    params[TokenRequest.CLIENT_ID.value] = request.client_id
    return None


__all__ = [
    "ClientAuthenticatingRequest",
    "apply_client_auth",
    "basic_auth_credentials",
    "resolve_client_auth_method",
]
