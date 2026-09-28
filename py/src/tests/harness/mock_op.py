"""Controllable mock OpenID Provider for the token-blaster harness (TH-1.1).

The mock OP holds a *known* signing key (unlike real IdPs, whose keys are
ephemeral and not exportable), which lets the harness:

1. mint genuinely valid tokens, and
2. forge the negative corpus (:mod:`corpus`) — tampered signatures, unknown
   ``kid``, ``alg:none``, wrong ``iss``/``aud``, etc. — that a real OP will
   never emit.

It is a framework-free ASGI application (``fastapi``/``starlette`` are not root
test dependencies), so it is both:

* unit-testable in-process via ``httpx.ASGITransport`` (no network), and
* bootable out-of-process under ``uvicorn`` for the load/soak suite (T311).

The :class:`MockOPControls` object drives T311's failure injection: injected
latency, ``429``/``Retry-After``, ``5xx``, key-rotation-on-command,
``Cache-Control`` directives, and empty/oversized JWKS.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
import json
import time
from typing import Any, get_args, get_type_hints
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jwt


# HTTP status codes
HTTP_OK = 200
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY_REQUESTS = 429

DEFAULT_ISSUER = "http://mock-op.local"
DEFAULT_TOKEN_LIFETIME = 300  # seconds — mirrors the real-IdP 300s TTL (design §3)


# P-256 coordinates are 32 bytes (RFC 7518 §6.2.1.2).
_P256_COORD_BYTES = 32


def _b64url_uint(value: int, length: int | None = None) -> str:
    """Encode an unsigned integer as base64url (JWK ``n``/``e``/``x``/``y``).

    ``length`` fixes the byte width: EC coordinates must be the full curve size
    (RFC 7518 §6.2.1.2), or a coordinate with a leading zero byte is rejected.
    """
    length = length or (value.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


@dataclass(frozen=True)
class SigningKey:
    """A signing key the mock OP controls end-to-end.

    Holds the private key (for signing / forging) and its public JWK (for the
    ``/jwks`` document), so the harness can both mint valid tokens and forge
    negatives keyed to a known public key.
    """

    alg: str
    kid: str
    private_key: Any  # cryptography private key object
    public_jwk: dict[str, Any]


def _rsa_signing_key(kid: str) -> SigningKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }
    return SigningKey(alg="RS256", kid=kid, private_key=private_key, public_jwk=jwk)


def _ec_signing_key(kid: str) -> SigningKey:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "crv": "P-256",
        "x": _b64url_uint(numbers.x, _P256_COORD_BYTES),
        "y": _b64url_uint(numbers.y, _P256_COORD_BYTES),
    }
    return SigningKey(alg="ES256", kid=kid, private_key=private_key, public_jwk=jwk)


@dataclass
class RequestStats:
    """Per-path upstream-request tallies (design §5 — upstream fetches/issuer).

    Ground truth for how many times the resource server actually reached each
    endpoint, letting the load/soak harness assert single-flight behaviour (e.g.
    S3: a cold stampede must produce exactly one discovery + one JWKS fetch).
    Every request that reaches a document handler is counted, regardless of the
    injected response status — a ``429``/``5xx`` still cost an upstream round trip.

    The mock OP runs on a single uvicorn event loop, so these plain ``int``
    increments are serialised without a lock (unlike the threaded
    :class:`~py_identity_model.core.cache_metrics.CacheCounters`).
    """

    discovery: int = 0
    jwks: int = 0
    token: int = 0
    introspect: int = 0

    def snapshot(self) -> dict[str, int]:
        """Return a detached copy of every counter."""
        return {
            "discovery": self.discovery,
            "jwks": self.jwks,
            "token": self.token,
            "introspect": self.introspect,
        }

    def reset(self) -> None:
        """Zero every counter (per-scenario baselines)."""
        self.discovery = self.jwks = self.token = self.introspect = 0


@dataclass
class MockOPControls:
    """Mutable failure-injection knobs (design §2).

    Every request consults the *live* object, so a test (or a T311 control
    route) can flip a knob between requests and observe the effect.
    """

    latency_seconds: float = 0.0
    discovery_status: int = HTTP_OK
    jwks_status: int = HTTP_OK
    token_status: int = HTTP_OK
    retry_after: str | None = None
    discovery_cache_control: str | None = None
    jwks_cache_control: str | None = None
    serve_empty_jwks: bool = False
    oversized_jwks_padding: int = 0


def _resolve_control_types() -> dict[str, tuple[type, ...]]:
    """Resolved ``{field_name: accepted_types}`` for :class:`MockOPControls`."""
    mapping: dict[str, tuple[type, ...]] = {}
    for name, anno in get_type_hints(MockOPControls).items():
        args = get_args(anno)
        mapping[name] = tuple(a for a in (args or (anno,)) if isinstance(a, type))
    return mapping


# Field -> accepted types, resolved once (the dataclass is immutable in shape).
_CONTROL_TYPES: dict[str, tuple[type, ...]] = _resolve_control_types()


def _set_control(controls: MockOPControls, name: str, value: Any) -> bool:
    """Type-checked control mutation; returns True if the value was applied.

    A stray ``{"jwks_status": "boom"}`` or ``{"retry_after": 3}`` (JSON number,
    not string) would otherwise poison a *later* request — an ``int`` handed to
    an ASGI ``status`` field, or a ``.encode()`` on a non-string. Reject the
    mismatch at the control call so the failure is local and obvious.
    """
    types = _CONTROL_TYPES.get(name)
    if not types:
        return False
    # ``bool`` is a subclass of ``int``: accept it only for genuine bool knobs,
    # and never let it (or a JSON int) masquerade as a status/int field's value.
    if isinstance(value, bool):
        accepted = bool in types
    elif isinstance(value, int) and float in types:
        accepted = True  # JSON ints are fine for float knobs (latency_seconds)
    else:
        accepted = isinstance(value, types)
    if accepted:
        setattr(controls, name, value)
    return accepted


# ASGI scope/messages are MutableMapping (matching httpx.ASGITransport's spec).
ASGIScope = MutableMapping[str, Any]
ASGIReceive = Callable[[], Awaitable[MutableMapping[str, Any]]]
ASGISend = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[ASGIScope, ASGIReceive, ASGISend], Awaitable[None]]


class MockOP:
    """A controllable OIDC provider serving discovery, JWKS, token, introspect.

    Args:
        issuer: The issuer / base URL. All endpoint URLs derive from it, and
            minted tokens carry it as ``iss``.
        controls: Failure-injection knobs. A fresh :class:`MockOPControls` is
            created when omitted.
    """

    def __init__(
        self,
        issuer: str = DEFAULT_ISSUER,
        *,
        controls: MockOPControls | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.controls = controls or MockOPControls()
        # Per-path upstream-request counters (design §5). Read/reset over HTTP via
        # ``GET``/``POST /_stats`` so the out-of-process load driver can scrape
        # them, or in-process for unit assertions.
        self.stats = RequestStats()
        # Primary RS256 signs valid tokens and is published by default.
        self.primary_key = _rsa_signing_key("mock-rs256-1")
        # EC key exercises the ES256 path; also published.
        self.ec_key = _ec_signing_key("mock-es256-1")
        # Rotation spare — NOT published until :meth:`rotate_keys` publishes it,
        # so a token freshly signed by it presents an unknown ``kid`` (design §2
        # key-rotation-on-command failure injection).
        self.rotation_key = _rsa_signing_key("mock-rs256-2")
        # A key that is never published — the source of unknown-``kid`` forgeries.
        self.unpublished_key = _rsa_signing_key("mock-rs256-unpublished")
        self._signing_key = self.primary_key
        self._published: list[SigningKey] = [self.primary_key, self.ec_key]

    # -- URLs ---------------------------------------------------------------

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/jwks"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/token"

    @property
    def introspection_endpoint(self) -> str:
        return f"{self.issuer}/introspect"

    @property
    def signing_key(self) -> SigningKey:
        """The key currently used to sign freshly minted tokens."""
        return self._signing_key

    # -- Control ------------------------------------------------------------

    def rotate_keys(self, *, publish: bool = False) -> SigningKey:
        """Rotate the active signing key to the spare.

        With ``publish=False`` (the default) the new key is withheld from the
        JWKS, so tokens minted afterwards fail validation with an unknown
        ``kid`` until :meth:`publish_signing_key` is called — the head-of-line
        rotation scenario the harness needs to reproduce.
        """
        self._signing_key = self.rotation_key
        if publish:
            self.publish_signing_key()
        return self._signing_key

    def publish_signing_key(self) -> None:
        """Add the active signing key to the published JWKS (idempotent)."""
        if self._signing_key not in self._published:
            self._published.append(self._signing_key)

    # -- Documents ----------------------------------------------------------

    def discovery_document(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "token_endpoint": self.token_endpoint,
            "introspection_endpoint": self.introspection_endpoint,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": [
                "client_credentials",
                "authorization_code",
                "refresh_token",
            ],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "scopes_supported": ["openid", "profile", "email"],
            "code_challenge_methods_supported": ["S256"],
            "subject_types_supported": ["public"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
            ],
        }

    def jwks(self) -> dict[str, Any]:
        if self.controls.serve_empty_jwks:
            return {"keys": []}
        keys = [dict(k.public_jwk) for k in self._published]
        for i in range(self.controls.oversized_jwks_padding):
            pad = _rsa_signing_key(f"mock-pad-{i}")
            keys.append(dict(pad.public_jwk))
        return {"keys": keys}

    # -- Minting ------------------------------------------------------------

    def sign(
        self,
        claims: dict[str, Any],
        *,
        key: SigningKey | None = None,
        alg: str | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        """Sign *claims* into a compact JWS with a mock-OP key.

        Used both by the token endpoint (valid tokens) and by
        :mod:`corpus` (forged negatives keyed to a known public key).
        """
        signing_key = key or self._signing_key
        merged_headers = {"kid": signing_key.kid}
        if headers:
            merged_headers.update(headers)
        return jwt.encode(
            claims,
            signing_key.private_key,
            algorithm=alg or signing_key.alg,
            headers=merged_headers,
        )

    def mint_access_token(
        self,
        *,
        scopes: str | None = None,
        tenant: str | None = None,
        audience: str = "mock-api",
        subject: str = "mock-subject",
        lifetime: int = DEFAULT_TOKEN_LIFETIME,
        extra_claims: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Mint a valid access token, returning an OAuth token-response dict.

        ``tenant`` shapes the Descope-style multi-tenant claims (``dct`` +
        ``tenants``) the node-oidc offline fixture also carries (design §2/§3).
        """
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "client_id": "mock-client",
            "scope": scopes or "read",
        }
        if tenant is not None:
            claims["dct"] = tenant
            claims["tenants"] = {tenant: {"roles": ["user"]}}
        if extra_claims:
            claims.update(extra_claims)
        access_token = self.sign(claims)
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": lifetime,
            "scope": claims["scope"],
        }

    def introspect(self, token: str) -> dict[str, Any]:
        """Best-effort introspection: decode without verification and echo."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return {"active": False}
        now = int(time.time())
        try:
            active = int(claims.get("exp", 0)) > now
        except (TypeError, ValueError):
            # A malformed ``exp`` (exactly the kind of token this harness feeds)
            # must report inactive, not 500 the endpoint.
            active = False
        return {"active": active, **claims}

    # -- ASGI application ---------------------------------------------------

    @property
    def app(self) -> ASGIApp:
        """The ASGI application callable (uvicorn-bootable, httpx-drivable)."""
        return self._app

    async def _app(
        self, scope: ASGIScope, receive: ASGIReceive, send: ASGISend
    ) -> None:
        if scope["type"] == "lifespan":
            await self._handle_lifespan(receive, send)
            return
        if scope["type"] != "http":  # pragma: no cover - defensive
            return
        if self.controls.latency_seconds:
            await asyncio.sleep(self.controls.latency_seconds)
        path = scope["path"].rstrip("/") or "/"
        method = scope["method"]
        handler = self._route(method, path)
        if handler is None:
            await self._send_json(send, HTTP_NOT_FOUND, {"error": "not_found"})
            return
        await handler(receive, send)

    def _route(
        self, method: str, path: str
    ) -> Callable[[ASGIReceive, ASGISend], Awaitable[None]] | None:
        routes: dict[tuple[str, str], Callable[..., Awaitable[None]]] = {
            ("GET", "/.well-known/openid-configuration"): self._handle_discovery,
            ("GET", "/jwks"): self._handle_jwks,
            ("POST", "/token"): self._handle_token,
            ("POST", "/introspect"): self._handle_introspect,
            ("POST", "/_control"): self._handle_control,
            ("GET", "/_stats"): self._handle_stats,
            ("POST", "/_stats"): self._handle_stats_reset,
        }
        return routes.get((method, path))

    async def _handle_lifespan(self, receive: ASGIReceive, send: ASGISend) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _handle_discovery(self, _receive: ASGIReceive, send: ASGISend) -> None:
        self.stats.discovery += 1
        headers = self._cache_control_headers(self.controls.discovery_cache_control)
        if self.controls.discovery_status != HTTP_OK:
            await self._send_status(send, self.controls.discovery_status, headers)
            return
        await self._send_json(send, HTTP_OK, self.discovery_document(), headers)

    async def _handle_jwks(self, _receive: ASGIReceive, send: ASGISend) -> None:
        self.stats.jwks += 1
        headers = self._cache_control_headers(self.controls.jwks_cache_control)
        if self.controls.jwks_status != HTTP_OK:
            await self._send_status(send, self.controls.jwks_status, headers)
            return
        await self._send_json(send, HTTP_OK, self.jwks(), headers)

    async def _handle_token(self, receive: ASGIReceive, send: ASGISend) -> None:
        self.stats.token += 1
        if self.controls.token_status != HTTP_OK:
            await self._send_status(send, self.controls.token_status)
            return
        form = parse_qs((await _read_body(receive)).decode())
        scope = form.get("scope", [None])[0]
        await self._send_json(send, HTTP_OK, self.mint_access_token(scopes=scope))

    async def _handle_introspect(self, receive: ASGIReceive, send: ASGISend) -> None:
        self.stats.introspect += 1
        form = parse_qs((await _read_body(receive)).decode())
        token = form.get("token", [""])[0]
        await self._send_json(send, HTTP_OK, self.introspect(token))

    async def _handle_stats(self, _receive: ASGIReceive, send: ASGISend) -> None:
        """Read the per-path upstream-request counters (design §5)."""
        await self._send_json(send, HTTP_OK, self.stats.snapshot())

    async def _handle_stats_reset(self, _receive: ASGIReceive, send: ASGISend) -> None:
        """Zero the per-path counters, returning the (now-zero) snapshot."""
        self.stats.reset()
        await self._send_json(send, HTTP_OK, {"ok": True, **self.stats.snapshot()})

    async def _handle_control(self, receive: ASGIReceive, send: ASGISend) -> None:
        """Out-of-process control endpoint for the uvicorn-booted case (T311).

        Accepts a JSON body: ``{"rotate": true, "publish": false}`` and/or any
        subset of :class:`MockOPControls` field names to set. Field values are
        type-checked against the dataclass; mismatches are reported back in the
        ``rejected`` list rather than poisoning a later request.

        Security: this route performs key rotation and failure injection with no
        authentication. It is a *test* fixture — bind it to loopback only. Do NOT
        expose the booted mock OP on a routable interface.
        """
        try:
            payload = json.loads((await _read_body(receive)).decode() or "{}")
        except json.JSONDecodeError:
            payload = {}
        if payload.pop("rotate", False):
            self.rotate_keys(publish=bool(payload.pop("publish", False)))
        else:
            # ``publish`` is only meaningful alongside ``rotate``; drop it so it
            # is not mistaken for a control field below.
            payload.pop("publish", None)
        rejected = [
            name
            for name, value in payload.items()
            if not _set_control(self.controls, name, value)
        ]
        await self._send_json(send, HTTP_OK, {"ok": True, "rejected": rejected})

    # -- ASGI helpers -------------------------------------------------------

    def _cache_control_headers(
        self, cache_control: str | None
    ) -> list[tuple[bytes, bytes]]:
        if cache_control is None:
            return []
        return [(b"cache-control", cache_control.encode())]

    async def _send_status(
        self,
        send: ASGISend,
        status: int,
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        body = {"error": "injected_failure", "status": status}
        extra = list(headers or [])
        if status == HTTP_TOO_MANY_REQUESTS and self.controls.retry_after is not None:
            extra.append((b"retry-after", self.controls.retry_after.encode()))
        await self._send_json(send, status, body, extra)

    async def _send_json(
        self,
        send: ASGISend,
        status: int,
        body: dict[str, Any],
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        payload = json.dumps(body).encode()
        response_headers = [(b"content-type", b"application/json")]
        response_headers.extend(headers or [])
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": payload})


async def _read_body(receive: ASGIReceive) -> bytes:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body
