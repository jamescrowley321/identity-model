"""Typed configuration for the FastAPI OIDC integration."""

from __future__ import annotations

from dataclasses import dataclass, field

from py_identity_model import TokenBinding

from .options import normalize_origin


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
        client_secret: Client secret; omit for public/PKCE clients. Kept out
            of ``repr()``.
        scope: Space-delimited scopes requested at authorization.
        audience: Expected ``aud`` for the resource-server middleware. Defaults
            to ``client_id`` when not set.
        post_login_redirect: Where ``/callback`` redirects after a successful login.
        post_logout_redirect: Where ``/logout`` redirects after clearing the session.
        excluded_paths: Paths the resource-server middleware skips (health/docs).
        required_binding: The sender constraint the resource-server middleware
            and WebSocket authenticator require of every token
            (``TokenBinding.NONE``, ``DPOP``, ``MTLS``). Both read it when
            given ``settings=`` and no explicit ``options=``. ``MTLS`` needs a
            client certificate source: ``client_certificate_header`` or a
            ``client_certificate`` callable passed to
            :meth:`~fastapi_identity_model.AuthOptions.from_settings`.
        client_certificate_header: Request header your TLS terminator sets to
            the client certificate (PEM, optionally URL-encoded, e.g. nginx's
            ``$ssl_client_escaped_cert``). Only trust a header the terminator
            sets and strips from client requests.
        expected_origin: The origin clients address (``scheme://host[:port]``)
            for the DPoP ``htu`` check. ``None`` takes the origin from the
            request's ``Host`` header; see
            :class:`~fastapi_identity_model.AuthOptions`.
    """

    discovery_url: str
    client_id: str
    redirect_uri: str = ""
    client_secret: str | None = field(default=None, repr=False)
    scope: str = "openid profile email"
    audience: str | None = None
    post_login_redirect: str = "/"
    post_logout_redirect: str = "/"
    excluded_paths: list[str] = field(default_factory=_default_excluded_paths)
    required_binding: TokenBinding = TokenBinding.NONE
    client_certificate_header: str | None = None
    expected_origin: str | None = None

    def __post_init__(self) -> None:
        self.required_binding = TokenBinding(self.required_binding)
        if self.expected_origin is not None:
            self.expected_origin = normalize_origin(self.expected_origin)
        # Validate required fields are non-empty.
        for name in ("discovery_url", "client_id"):
            if not getattr(self, name):
                raise ValueError(f"OIDCSettings requires a non-empty {name}")
        # The middleware validates the ID/access token audience; default it to
        # the client_id, which is the audience Descope and most OPs mint.
        if self.audience is None:
            self.audience = self.client_id
