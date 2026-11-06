"""Access-token lifecycle management for FastAPI applications.

``TokenManager`` keeps an access/refresh token pair and transparently refreshes
the access token (via the library's native async refresh grant) shortly before
it expires. It is a thin convenience layer over
:func:`py_identity_model.aio.refresh_token` — all protocol work lives in the
core library.
"""

import asyncio
from datetime import UTC, datetime, timedelta

from py_identity_model import PyIdentityModelException
from py_identity_model.aio import (
    AsyncHTTPClient,
    DiscoveryDocumentRequest,
    RefreshTokenRequest,
    get_discovery_document,
    refresh_token,
)


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
        )
        token = await manager.get_access_token()  # auto-refreshes if near expiry
        ```
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
                grant, built from your ``Config``. ``None`` uses the library
                default client.
        """
        self.discovery_url = discovery_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_before_seconds = refresh_before_seconds
        self.http_client = http_client

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at: datetime | None = None
        # Serialize refreshes so concurrent callers don't each fire the grant
        # (which, with refresh-token rotation, would invalidate the family).
        self._refresh_lock = asyncio.Lock()

    def set_tokens(
        self,
        access_token: str,
        refresh_token: str | None = None,
        expires_in: int | None = None,
    ) -> None:
        """Store the current token pair and (optionally) its expiry."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        # ``is not None`` (not truthiness) so expires_in=0 means "already
        # expired" rather than "no expiry / never refresh".
        self._expires_at = (
            datetime.now(UTC) + timedelta(seconds=expires_in)
            if expires_in is not None
            else None
        )

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
            raise PyIdentityModelException(
                f"Discovery failed while refreshing token: {disco.error or 'no token endpoint'}",
            )
        return disco.token_endpoint

    async def get_access_token(self) -> str | None:
        """Return the current access token, refreshing it first if necessary.

        Raises:
            PyIdentityModelException: If a refresh is required but no refresh
                token is available, or the refresh grant fails.
        """
        if self._access_token and not self.is_token_expired():
            return self._access_token

        async with self._refresh_lock:
            # Re-check under the lock: a concurrent caller may have already
            # refreshed while this one waited to acquire it.
            if self._access_token and not self.is_token_expired():
                return self._access_token

            if not self._refresh_token:
                raise PyIdentityModelException(
                    "Token expired and no refresh token available",
                )

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

            if not response.is_successful or not response.token:
                raise PyIdentityModelException(
                    f"Token refresh failed: {response.error or 'no token in response'}",
                )

            new_access_token = response.token.get("access_token")
            if not new_access_token:
                raise PyIdentityModelException(
                    "Token refresh succeeded but no access token returned",
                )

            self.set_tokens(
                access_token=new_access_token,
                refresh_token=response.token.get("refresh_token")
                or self._refresh_token,
                expires_in=response.token.get("expires_in"),
            )
            return self._access_token

    @property
    def access_token(self) -> str | None:
        """The current access token, without triggering a refresh."""
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        """The current refresh token."""
        return self._refresh_token
