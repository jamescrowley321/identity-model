"""Typed configuration for the FastAPI OIDC integration."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from py_identity_model import TokenBinding

from .options import normalize_origin


def _default_excluded_paths() -> list[str]:
    # Exact paths (the middleware matches excluded_paths exactly by default;
    # append ``/*`` for a subtree). ``/docs/oauth2-redirect`` is listed
    # explicitly because exact matching no longer implies the ``/docs`` subtree.
    return ["/docs", "/docs/oauth2-redirect", "/openapi.json", "/health"]


# RFC 9110 §5.1 field-name = token (§5.6.2).
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _check_trusted_audiences(audiences: object) -> list[str]:
    # A bare string would be read as a list of its characters.
    if isinstance(audiences, str) or not isinstance(audiences, (list, tuple)):
        raise ValueError(
            "trusted_audiences must be a list of strings; "
            f"got {type(audiences).__name__}"
        )
    for audience in audiences:
        if not isinstance(audience, str) or not audience:
            raise ValueError(
                f"trusted_audiences entries must be non-empty strings; got {audience!r}"
            )
    return list(audiences)


@dataclass(frozen=True, kw_only=True)
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
        audience: Expected ``aud`` for the resource-server middleware.
            ``None`` (default) means ``client_id``; read the resolved value
            from :attr:`expected_audience`.
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
        trusted_audiences: Audiences besides ``client_id`` that the login
            callback accepts in an ID Token's ``aud``. Empty (the default)
            rejects any additional audience, as OIDC Core §3.1.3.7 requires
            of audiences the client does not trust. Entries must be non-empty
            strings.
        validate_azp: Opt in to the ``azp`` rules on the login callback's ID
            Token: an ID Token with several audiences must carry ``azp``, and a
            present ``azp`` must equal ``client_id`` (OIDC Core §3.1.3.7, a
            SHOULD), so it is off by default. Set it whenever you set
            ``trusted_audiences``: otherwise an ID Token issued to another
            client that also lists yours in ``aud`` logs in.
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
    trusted_audiences: list[str] = field(default_factory=list)
    validate_azp: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "required_binding", TokenBinding(self.required_binding)
        )
        object.__setattr__(
            self,
            "trusted_audiences",
            _check_trusted_audiences(self.trusted_audiences),
        )
        if not isinstance(self.validate_azp, bool):
            # A truthy string such as "false" would silently turn the check on.
            raise ValueError(
                f"validate_azp must be a bool; got {type(self.validate_azp).__name__}"
            )
        header = self.client_certificate_header
        if header is not None and not _HEADER_NAME.fullmatch(header):
            # A name that can never match a request header would refuse every
            # certificate-bound token with no startup error.
            raise ValueError(
                "client_certificate_header must be an RFC 9110 header name "
                f"(token characters only); got {header!r}"
            )
        if self.expected_origin is not None:
            object.__setattr__(
                self, "expected_origin", normalize_origin(self.expected_origin)
            )
        # Validate required fields are non-empty.
        for name in ("discovery_url", "client_id"):
            if not getattr(self, name):
                raise ValueError(f"OIDCSettings requires a non-empty {name}")

    @property
    def expected_audience(self) -> str:
        """``audience``, or ``client_id`` when ``audience`` is ``None``.

        Worked out on read, so a copy made with :func:`dataclasses.replace`
        and a new ``client_id`` follows it.
        """
        return self.client_id if self.audience is None else self.audience
