"""Typed configuration for the FastAPI OIDC integration."""

from __future__ import annotations

from dataclasses import dataclass, field


def _default_excluded_paths() -> list[str]:
    # Exact paths (the middleware matches excluded_paths exactly by default;
    # append ``/*`` for a subtree). ``/docs/oauth2-redirect`` is listed
    # explicitly because exact matching no longer implies the ``/docs`` subtree.
    return ["/docs", "/docs/oauth2-redirect", "/openapi.json", "/health"]


@dataclass
class OIDCSettings:
    """Configuration shared by the RP login router and the resource-server middleware.

    Attributes:
        discovery_url: OpenID Connect discovery document URL of the provider.
        client_id: OAuth2 client identifier.
        redirect_uri: Absolute callback URL registered with the provider
            (must match the router's ``/callback`` route). Only required for the
            login router; a resource-server-only deployment may leave it empty.
        client_secret: Client secret; omit for public/PKCE clients.
        scope: Space-delimited scopes requested at authorization.
        audience: Expected ``aud`` for the resource-server middleware. Defaults
            to ``client_id`` when not set.
        post_login_redirect: Where ``/callback`` redirects after a successful login.
        post_logout_redirect: Where ``/logout`` redirects after clearing the session.
        excluded_paths: Paths the resource-server middleware skips (health/docs).
    """

    discovery_url: str
    client_id: str
    redirect_uri: str = ""
    client_secret: str | None = None
    scope: str = "openid profile email"
    audience: str | None = None
    post_login_redirect: str = "/"
    post_logout_redirect: str = "/"
    excluded_paths: list[str] = field(default_factory=_default_excluded_paths)

    def __post_init__(self) -> None:
        # Validate required fields are non-empty.
        for name in ("discovery_url", "client_id"):
            if not getattr(self, name):
                raise ValueError(f"OIDCSettings requires a non-empty {name}")
        # The middleware validates the ID/access token audience; default it to
        # the client_id, which is the audience Descope and most OPs mint.
        if self.audience is None:
            self.audience = self.client_id
