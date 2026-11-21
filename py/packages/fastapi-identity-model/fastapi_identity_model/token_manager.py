"""Access-token lifecycle management for FastAPI applications.

``TokenManager`` keeps an access/refresh token pair and transparently refreshes
the access token (via the library's native async refresh grant) shortly before
it expires. It is a thin convenience layer over
:func:`py_identity_model.aio.refresh_token` — all protocol work lives in the
core library.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from enum import Enum
import re

from py_identity_model import AuthorizationScheme, PyIdentityModelException
from py_identity_model.aio import (
    AsyncHTTPClient,
    DiscoveryDocumentRequest,
    RefreshTokenRequest,
    RefreshTokenResponse,
    TokenErrorKind,
    get_discovery_document,
    refresh_token,
)


class TokenManagerErrorKind(Enum):
    """Why :class:`TokenManager` could not return an access token."""

    NO_REFRESH_TOKEN = "no_refresh_token"
    """The access token expired and no refresh token is held; log in again."""
    DISCOVERY_FAILED = "discovery_failed"
    """The discovery document could not be fetched or has no token endpoint."""
    REFRESH_FAILED = "refresh_failed"
    """The refresh grant failed (``details["error"]`` holds the cause)."""
    MISSING_ACCESS_TOKEN = "missing_access_token"
    """The refresh response is a success with no ``access_token``."""
    UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"
    """The ``token_type`` is not ``Bearer`` or ``DPoP`` (RFC 6749 §7.1)."""


_ERROR_MESSAGES = {
    TokenManagerErrorKind.NO_REFRESH_TOKEN: (
        "Token expired and no refresh token available"
    ),
    TokenManagerErrorKind.DISCOVERY_FAILED: ("Discovery failed while refreshing token"),
    TokenManagerErrorKind.REFRESH_FAILED: "Token refresh failed",
    TokenManagerErrorKind.MISSING_ACCESS_TOKEN: (
        "Token refresh succeeded but no access token returned"
    ),
    TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE: (
        "Access token type is not Bearer or DPoP (RFC 6749 §7.1)"
    ),
}


class TokenManagerError(PyIdentityModelException):
    """Raised when :class:`TokenManager` cannot return an access token.

    ``kind`` says why; the message is fixed per kind and ``details`` carries
    the underlying error, if any.
    """

    def __init__(self, kind: TokenManagerErrorKind, error: str | None = None) -> None:
        self.kind = kind
        details: dict = {"kind": kind.value}
        if error is not None:
            details["error"] = error
        super().__init__(_ERROR_MESSAGES[kind], details=details)


_TOKEN_TYPES = {scheme.value.casefold(): scheme for scheme in AuthorizationScheme}


def _token_type(value: object) -> AuthorizationScheme:
    """*value* as an :class:`AuthorizationScheme` (case-insensitive, RFC 6749
    §5.1), or :class:`TokenManagerError` when it is not Bearer or DPoP."""
    scheme = (
        value
        if isinstance(value, AuthorizationScheme)
        else _TOKEN_TYPES.get(value.casefold())
        if isinstance(value, str)
        else None
    )
    if scheme is None:
        raise TokenManagerError(TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE)
    return scheme


def _is_token(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _expiry(expires_in: float | None) -> datetime | None:
    """When a token issued now with *expires_in* seconds to live expires."""
    if expires_in is None:
        return None
    return datetime.now(UTC) + timedelta(seconds=expires_in)


def _response_expiry(value: object) -> datetime | None:
    """When a token response's access token expires, from its ``expires_in``.

    Raises:
        TokenManagerError: ``REFRESH_FAILED`` when the value is not a
            lifetime in seconds (RFC 6749 §5.1) an expiry can be computed
            from: not a number, negative, or past the last date. A string
            of decimal digits is read as a number, as some providers send it.
    """
    if value is None:
        return None
    try:
        if isinstance(value, str) and value.isascii() and value.isdigit():
            value = int(value)
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
        ):
            return _expiry(value)
    except (OverflowError, ValueError):
        pass
    raise TokenManagerError(
        TokenManagerErrorKind.REFRESH_FAILED, "expires_in is not a number of seconds"
    )


def _rejection(response: RefreshTokenResponse) -> TokenManagerError:
    """The error for an unsuccessful refresh *response*."""
    rejected = response.rejected_token
    if (
        rejected is not None
        and response.error_kind is TokenErrorKind.INVALID_TOKEN_RESPONSE
    ):
        # RFC 6749 §5.1 requires both members as non-empty strings.
        if not _is_token(rejected.get("access_token")):
            return TokenManagerError(TokenManagerErrorKind.MISSING_ACCESS_TOKEN)
        if not _is_token(rejected.get("token_type")):
            return TokenManagerError(TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE)
    error = response.error
    prefix = "Token refresh failed with status code: "
    if not error:
        detail = "no token in response"
    elif error.startswith(prefix):
        # Older supported core releases append the raw response body here.
        status = error[len(prefix) :].partition(".")[0]
        detail = (
            f"{prefix}{status}"
            if re.fullmatch(r"[0-9]{3}", status)
            else "Token refresh failed"
        )
    elif error.startswith("Network error during token refresh:"):
        detail = "Network error during token refresh"
    elif response.error_kind is TokenErrorKind.INVALID_TOKEN_RESPONSE and re.fullmatch(
        r"Token response is not a JSON object: (?:str|int|float|bool|NoneType|list)",
        error,
    ):
        # The JSON parser's type names are fixed; the rest may echo secrets.
        detail = error
    else:
        detail = "Token refresh failed"
    return TokenManagerError(TokenManagerErrorKind.REFRESH_FAILED, detail)


class TokenManager:
    """Manage an access token, refreshing it automatically before expiry.

    Example:
        ```python
        manager = TokenManager(
            discovery_url="https://auth.example.com/.well-known/openid-configuration",
            client_id="my-client-id",
            client_secret="my-client-secret",
        )
        manager.set_tokens(
            access_token="initial_access_token",
            refresh_token="initial_refresh_token",
            expires_in=3600,
            token_type="Bearer",
        )
        token = await manager.get_access_token()  # auto-refreshes if near expiry
        headers = {"Authorization": f"{manager.token_type.value} {token}"}
        ```

    A ``DPoP`` access token also needs a DPoP proof on every request
    (RFC 9449 §7.1).
    """

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str | None = None,
        refresh_before_seconds: int = 300,
        *,
        http_client: AsyncHTTPClient | None = None,
    ):
        """Initialize the token manager.

        Args:
            discovery_url: The OpenID Connect discovery document URL.
            client_id: The OAuth2 client ID.
            client_secret: The OAuth2 client secret (omit for public clients).
            refresh_before_seconds: Refresh this many seconds before expiry.
            http_client: Managed HTTP client for discovery and the refresh
                grant, built from your ``HTTPConfig``. ``None`` uses the library
                default client.
        """
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_before_seconds = refresh_before_seconds
        self.http_client = http_client

        self._access_token: str | None = None
        self._token_type: AuthorizationScheme | None = None
        self._refresh_token: str | None = None
        self._expires_at: datetime | None = None
        # Serialize refreshes so concurrent callers don't each fire the grant
        # (which, with refresh-token rotation, would invalidate the family).
        self._refresh_lock = asyncio.Lock()

    def set_tokens(
        self,
        access_token: str,
        refresh_token: str | None = None,
        expires_in: float | None = None,
        *,
        token_type: str | AuthorizationScheme,
    ) -> None:
        """Store the current token pair, its type and (optionally) its expiry.

        Args:
            access_token: The access token.
            refresh_token: The refresh token, if any.
            expires_in: Seconds until the access token expires.
            token_type: The token response's ``token_type``, matched
                case-insensitively (RFC 6749 §5.1).

        Raises:
            TokenManagerError: ``UNSUPPORTED_TOKEN_TYPE`` when *token_type* is
                not ``Bearer`` or ``DPoP`` (RFC 6749 §7.1: the token must not
                be used). Nothing is stored.
        """
        # expires_in=0 means "already expired", not "no expiry".
        self._store(
            access_token, refresh_token, _expiry(expires_in), _token_type(token_type)
        )

    def _store(
        self,
        access_token: str,
        refresh_token: str | None,
        expires_at: datetime | None,
        token_type: AuthorizationScheme,
    ) -> None:
        self._token_type = token_type
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = expires_at

    def is_token_expired(self) -> bool:
        """Return True if the access token is expired or within the refresh window."""
        if not self._expires_at:
            return False
        return datetime.now(UTC) >= (
            self._expires_at - timedelta(seconds=self.refresh_before_seconds)
        )

    async def _resolve_token_endpoint(self) -> str:
        """Resolve the token endpoint from discovery (per-process cached by the library)."""
        disco = await get_discovery_document(
            DiscoveryDocumentRequest(address=self.discovery_url),
            http_client=self.http_client,
        )
        if not disco.is_successful or not disco.token_endpoint:
            raise TokenManagerError(
                TokenManagerErrorKind.DISCOVERY_FAILED,
                disco.error or "no token endpoint",
            )
        return disco.token_endpoint

    async def get_access_token(self) -> str | None:
        """Return the current access token, refreshing it first if necessary.

        Raises:
            TokenManagerError: If a refresh is required but no refresh token
                is available, discovery or the refresh grant fails, or the
                refreshed token's type is not ``Bearer`` or ``DPoP``.
                ``kind`` says which.
        """
        if self._access_token and not self.is_token_expired():
            return self._access_token

        async with self._refresh_lock:
            # Re-check under the lock: a concurrent caller may have already
            # refreshed while this one waited to acquire it.
            if self._access_token and not self.is_token_expired():
                return self._access_token

            if not self._refresh_token:
                raise TokenManagerError(TokenManagerErrorKind.NO_REFRESH_TOKEN)

            token_endpoint = await self._resolve_token_endpoint()
            response = await refresh_token(
                RefreshTokenRequest(
                    address=token_endpoint,
                    client_id=self.client_id,
                    refresh_token=self._refresh_token,
                    client_secret=self.client_secret,
                ),
                http_client=self.http_client,
            )

            # Keep a rotated refresh token even when the response or its access
            # token is refused: the server may already have invalidated the
            # old one.
            token = response.token if response.is_successful else None
            issued = (token or response.rejected_token or {}).get("refresh_token")
            refreshed = issued if _is_token(issued) else self._refresh_token
            try:
                if token is None:
                    raise _rejection(response)
                new_access_token = token["access_token"]
                token_type = _token_type(token["token_type"])
                expires_at = _response_expiry(token.get("expires_in"))
            except TokenManagerError:
                self._refresh_token = refreshed
                raise
            self._store(new_access_token, refreshed, expires_at, token_type)
            return self._access_token

    @property
    def access_token(self) -> str | None:
        """The current access token, without triggering a refresh."""
        return self._access_token

    @property
    def token_type(self) -> AuthorizationScheme | None:
        """The access token's scheme (``Bearer`` or ``DPoP``) for the
        ``Authorization`` header, or ``None`` before :meth:`set_tokens`."""
        return self._token_type

    @property
    def refresh_token(self) -> str | None:
        """The current refresh token."""
        return self._refresh_token
