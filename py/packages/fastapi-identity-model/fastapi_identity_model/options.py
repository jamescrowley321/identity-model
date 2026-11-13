"""Options shared by the HTTP middleware and the WebSocket authenticator."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from py_identity_model import (
    DPoPReplayCheck,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenBinding,
)
from py_identity_model.core.process_local import ProcessLocal


if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import HTTPConnection

    from .config import OIDCSettings


__all__ = ["AuthOptions"]

_DEFAULT_PORTS = {"http": 80, "https": 443}
_HOST = re.compile(r"[a-z0-9._-]+")


def normalize_origin(origin: str) -> str:
    """*origin* as ``scheme://host[:port]``, lower-cased, default port dropped.

    Raises:
        ValueError: *origin* is not an ``http``/``https`` origin, or carries a
            path, query, fragment or userinfo.
    """
    try:
        parts = urlsplit(origin)
        port = parts.port
    except ValueError as e:
        raise ValueError(f"expected_origin is not a valid URL: {origin!r}") from e
    scheme = parts.scheme.lower()
    if (
        scheme not in _DEFAULT_PORTS
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or "@" in parts.netloc
    ):
        raise ValueError(
            "expected_origin must be scheme://host[:port] with an http or https "
            f"scheme and nothing after the authority; got {origin!r}"
        )
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    elif not _HOST.fullmatch(host):
        # A client's htu carries the wire (ASCII/punycode) host, so any other
        # form never matches and every DPoP proof would be refused.
        raise ValueError(
            "expected_origin host must be ASCII letters, digits, '.', '_' and '-' "
            f"(punycode for internationalized names); got {origin!r}"
        )
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def _certificate_from_header(
    header: str,
) -> Callable[[HTTPConnection], str | None]:
    def client_certificate(connection: HTTPConnection) -> str | None:
        # More than one copy means the terminator appended rather than
        # replaced; trust none of them. A raw "," or a second PEM block means
        # an intermediary folded several copies into one line (RFC 9110 §5.3).
        values = connection.headers.getlist(header)
        if len(values) != 1 or not values[0] or "," in values[0]:
            return None
        pem = unquote(values[0])
        if pem.count("-----BEGIN") > 1:
            return None
        return pem

    return client_certificate


# One replay cache for every entry point built without dpop= options, so a
# proof accepted on a WebSocket handshake cannot be replayed on an HTTP GET.
# A forked child builds its own.
_default_replay_cache: ProcessLocal[InMemoryDPoPReplayCache] = ProcessLocal(
    lambda _inherited: InMemoryDPoPReplayCache()
)


class _ProcessReplayCache:
    """Records into this process's default cache, looked up on every check.

    Options built before a fork (``gunicorn --preload``) therefore use the
    worker's cache, the same one as entry points built in the worker.
    """

    def check_and_store(
        self, jkt: str, jti: str, expires_at: float, now: float
    ) -> DPoPReplayCheck:
        return _default_replay_cache.get().check_and_store(jkt, jti, expires_at, now)

    def __reduce__(self) -> str:
        # A module singleton: copy and deepcopy return it.
        return "_PROCESS_REPLAY_CACHE"


_PROCESS_REPLAY_CACHE = _ProcessReplayCache()


def default_dpop_options() -> DPoPVerificationOptions:
    """Library-default DPoP options with this process's shared replay cache."""
    return DPoPVerificationOptions(replay_cache=_PROCESS_REPLAY_CACHE)


@dataclass(frozen=True, kw_only=True)
class AuthOptions:
    """Token-binding and validation options for one resource server.

    Pass the same instance to :class:`~fastapi_identity_model.TokenValidationMiddleware`
    and :func:`~fastapi_identity_model.build_ws_authenticator` so HTTP and
    WebSocket routes enforce the same rules. New validation options are added
    here, not as further keyword arguments on either entry point.

    Attributes:
        required_binding: The sender constraint every token must carry.
            ``TokenBinding.NONE`` (default) accepts unbound bearer tokens; a
            bound token is checked either way (RFC 9449 §7.1, RFC 8705 §3).
            ``DPOP`` refuses tokens without ``cnf.jkt`` and a valid proof;
            ``MTLS`` refuses tokens without a matching client certificate and
            needs ``client_certificate``.
        dpop: :class:`~py_identity_model.DPoPVerificationOptions` for DPoP
            proofs (algorithms, ``iat`` window, replay cache). The default is
            the library defaults with one
            :class:`~py_identity_model.InMemoryDPoPReplayCache` per process,
            shared by every HTTP middleware and WebSocket authenticator built
            without explicit ``dpop`` options. Behind a load balancer, pass a
            shared cache. ``None`` means the default.
        client_certificate: Returns the connection's mTLS client certificate
            (PEM or DER) for certificate-bound tokens, or ``None``. It receives
            the ``Request`` (HTTP) or ``WebSocket`` (handshake). Without it
            every certificate-bound token is refused.
        expected_origin: The origin clients address, ``scheme://host[:port]``.
            When set, a DPoP proof's ``htu`` is checked against this origin plus
            the request path and query. When ``None`` (default), the origin
            comes from the request (``Host`` header and ASGI scheme), so a
            client that can choose the ``Host`` header the app sees can make a
            proof minted for another origin pass the ``htu`` check. Set it
            unless a trusted proxy pins ``Host``.

    Raises:
        ValueError: ``required_binding`` is ``MTLS`` without
            ``client_certificate`` (every token would be refused), or
            ``expected_origin`` is not an ``http``/``https`` origin.
    """

    required_binding: TokenBinding = TokenBinding.NONE
    dpop: DPoPVerificationOptions = field(default_factory=default_dpop_options)
    client_certificate: Callable[[HTTPConnection], str | bytes | None] | None = None
    expected_origin: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "required_binding", TokenBinding(self.required_binding)
        )
        if self.dpop is None:
            object.__setattr__(self, "dpop", default_dpop_options())
        if (
            self.required_binding is TokenBinding.MTLS
            and self.client_certificate is None
        ):
            raise ValueError(
                "required_binding=MTLS needs client_certificate; without it "
                "every token is refused."
            )
        if self.expected_origin is not None:
            object.__setattr__(
                self, "expected_origin", normalize_origin(self.expected_origin)
            )

    @classmethod
    def from_settings(
        cls,
        settings: OIDCSettings,
        *,
        dpop: DPoPVerificationOptions | None = None,
        client_certificate: Callable[[HTTPConnection], str | bytes | None]
        | None = None,
    ) -> AuthOptions:
        """Options from *settings*, plus the parts settings cannot hold.

        ``required_binding`` and ``expected_origin`` come from *settings*. The
        client certificate is *client_certificate* when given, else read from
        ``settings.client_certificate_header`` (URL-decoded), else ``None``.
        """
        if client_certificate is None and settings.client_certificate_header:
            client_certificate = _certificate_from_header(
                settings.client_certificate_header
            )
        return cls(
            required_binding=settings.required_binding,
            dpop=dpop,
            client_certificate=client_certificate,
            expected_origin=settings.expected_origin,
        )


def resolve_auth_options(
    settings: OIDCSettings | None, options: AuthOptions | None
) -> AuthOptions:
    """The options an entry point uses: *options*, else *settings*, else defaults.

    Raises:
        ValueError: *options* would drop a ``required_binding``,
            ``expected_origin`` or client certificate source that *settings*
            sets.
    """
    if options is None:
        return AuthOptions.from_settings(settings) if settings else AuthOptions()
    if settings is not None:
        if (
            settings.required_binding is not TokenBinding.NONE
            and options.required_binding is not settings.required_binding
        ):
            raise ValueError(
                f"options.required_binding={options.required_binding.value!r} "
                "conflicts with settings.required_binding="
                f"{settings.required_binding.value!r}; build options with "
                "AuthOptions.from_settings(settings, ...)."
            )
        if (
            settings.expected_origin is not None
            and options.expected_origin != settings.expected_origin
        ):
            raise ValueError(
                "options.expected_origin conflicts with settings.expected_origin; "
                "build options with AuthOptions.from_settings(settings, ...)."
            )
        if settings.client_certificate_header and options.client_certificate is None:
            raise ValueError(
                "options has no client_certificate but "
                "settings.client_certificate_header is set; build options with "
                "AuthOptions.from_settings(settings, ...)."
            )
    return options
