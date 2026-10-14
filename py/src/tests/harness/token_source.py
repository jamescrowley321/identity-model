"""Unified multi-provider ``TokenSource`` minter for the harness (TH-1.1, #463).

One :meth:`TokenSource.mint` call unifies what the integration ``conftest``
previously spread across ``client_credentials_token``, ``jwt_access_token``,
``opaque_access_token`` and the ``auth_code_result`` helpers, plus the
Descope-shaped multi-tenant minter — capability/credential-gated exactly like
``provider_matrix.detect_capabilities``.

* Real providers (node-oidc, Keycloak, Ory, Descope) mint through the library's
  own token logic (``request_client_credentials_token`` / an injected auth-code
  minter) — never reimplemented.
* The ``MOCK`` provider mints valid tokens and, via ``malform=``, the forged
  corpus (:mod:`corpus`) off the controllable mock OP (:mod:`mock_op`).

Gating raises typed errors (:class:`HarnessCapabilityError` /
:class:`HarnessCredentialError`) that the ``conftest`` fixture translates to
``pytest.skip`` — so Ory/Descope skip cleanly when secret-gated, while ``MOCK``
is always available.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
import contextlib
from dataclasses import dataclass, field
from enum import StrEnum
import json
import time
from typing import TYPE_CHECKING, Any
import uuid

import httpx

from py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)

from .corpus import build_corpus
from .mock_op import MockOP
from .provider_matrix import detect_capabilities


if TYPE_CHECKING:
    from collections.abc import Iterable


JWT_SEGMENT_SEPARATOR_COUNT = 2


class Provider(StrEnum):
    """Identity providers the harness can mint against."""

    NODE_OIDC = "node-oidc"
    KEYCLOAK = "keycloak"
    ORY = "ory"
    DESCOPE = "descope"
    MOCK = "mock"


class Grant(StrEnum):
    """OAuth grant types the minter understands."""

    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "device_code"


class Malform(StrEnum):
    """Forged-token classes (MOCK provider only)."""

    VALID = "valid"
    EXPIRED = "expired"
    NBF_FUTURE = "nbf_future"
    WRONG_ISS = "wrong_iss"
    WRONG_AUD = "wrong_aud"
    TAMPERED_SIG = "tampered_sig"
    UNKNOWN_KID = "unknown_kid"
    WRONG_ALG = "wrong_alg"
    ALG_NONE = "alg_none"
    ID_AS_ACCESS = "id_as_access"
    CNF_BOUND = "cnf_bound"
    OVERSIZED = "oversized"
    MULTI_AUD_UNTRUSTED = "multi_aud_untrusted"


# Grant -> provider_matrix capability key.
_GRANT_CAPABILITY: dict[Grant, str] = {
    Grant.CLIENT_CREDENTIALS: "client_credentials",
    Grant.AUTHORIZATION_CODE: "authorization_code",
    Grant.REFRESH_TOKEN: "refresh_token",
    Grant.DEVICE_CODE: "device_authorization",
}


class HarnessError(Exception):
    """Base class for token-harness errors."""


class HarnessCapabilityError(HarnessError):
    """The provider does not advertise the requested grant/capability."""


class HarnessCredentialError(HarnessError):
    """The provider supports the grant but the required credentials are absent."""


@dataclass(frozen=True)
class MintedToken:
    """The result of a mint — a replayable token plus its provenance."""

    access_token: str
    provider: Provider
    grant: Grant
    token_type: str = "Bearer"
    id_token: str | None = None
    expires_at: float | None = None
    tenant: str | None = None
    alg: str | None = None
    kid: str | None = None
    malform: Malform | None = None

    def is_expired(self, *, now: float | None = None, leeway: float = 0.0) -> bool:
        """Whether the token is past its expiry (for T311 re-mint cadence)."""
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at - leeway


# An auth-code minter returns an OAuth token-response dict (``access_token`` …),
# letting the conftest inject ``perform_auth_code_flow`` without this module
# importing pytest.
AuthCodeMinter = Callable[[str | None, str | None], dict[str, Any]]


@dataclass
class ProviderConfig:
    """Per-provider configuration and capabilities for the minter."""

    provider: Provider
    capabilities: set[str] = field(default_factory=set)
    token_endpoint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None
    mock_op: MockOP | None = None
    auth_code_minter: AuthCodeMinter | None = None
    # Descope multi-tenant (access-key -> /v1/auth/accesskey/exchange) config.
    # When present, ``mint(DESCOPE, tenant=…)`` produces a session JWT carrying
    # distinct ``dct``/``tenants`` claims (AC-3); absent -> credential skip.
    descope_project_id: str | None = None
    descope_management_key: str | None = None
    descope_base_url: str | None = None

    @classmethod
    def from_discovery(
        cls,
        provider: Provider,
        raw_discovery: dict[str, Any],
        *,
        token_endpoint: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        scope: str | None = None,
        auth_code_minter: AuthCodeMinter | None = None,
        descope_project_id: str | None = None,
        descope_management_key: str | None = None,
        descope_base_url: str | None = None,
    ) -> ProviderConfig:
        """Build a real-provider config, deriving capabilities from discovery.

        Reuses ``provider_matrix.detect_capabilities`` so the harness and the
        capability matrix never drift.
        """
        caps = {name for name, ok in detect_capabilities(raw_discovery).items() if ok}
        return cls(
            provider=provider,
            capabilities=caps,
            token_endpoint=token_endpoint or raw_discovery.get("token_endpoint"),
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            auth_code_minter=auth_code_minter,
            descope_project_id=descope_project_id,
            descope_management_key=descope_management_key,
            descope_base_url=descope_base_url,
        )


class TokenSource:
    """The unified minter. One :meth:`mint` for every provider/grant/forgery."""

    def __init__(self, configs: Iterable[ProviderConfig]) -> None:
        self._configs: dict[Provider, ProviderConfig] = {
            cfg.provider: cfg for cfg in configs
        }

    @classmethod
    def with_mock(
        cls, mock_op: MockOP | None = None, *, extra: Iterable[ProviderConfig] = ()
    ) -> TokenSource:
        """Convenience builder wiring a ``MOCK`` provider (always mintable)."""
        mock = mock_op or MockOP()
        mock_cfg = ProviderConfig(
            provider=Provider.MOCK,
            capabilities={_GRANT_CAPABILITY[g] for g in Grant},
            mock_op=mock,
        )
        return cls([mock_cfg, *extra])

    @property
    def providers(self) -> list[Provider]:
        return list(self._configs)

    def config(self, provider: Provider) -> ProviderConfig:
        try:
            return self._configs[provider]
        except KeyError:
            raise HarnessCapabilityError(
                f"provider {provider.value} is not configured in this TokenSource"
            ) from None

    def mint(
        self,
        provider: Provider,
        grant: Grant = Grant.CLIENT_CREDENTIALS,
        *,
        tenant: str | None = None,
        scopes: str | None = None,
        malform: Malform | None = None,
    ) -> MintedToken:
        """Mint a token.

        Args:
            provider: The provider to mint against.
            grant: The grant type (``client_credentials`` by default).
            tenant: Optional tenant, shaping Descope-style multi-tenant claims.
            scopes: Space-delimited scopes.
            malform: A forged class — MOCK-only; raises
                :class:`HarnessCapabilityError` for any real provider.

        Raises:
            HarnessCapabilityError: provider/grant/forgery unsupported.
            HarnessCredentialError: grant supported but credentials absent.
        """
        cfg = self.config(provider)
        if malform is not None:
            return self._mint_forged(cfg, grant, tenant, malform)
        if provider is Provider.MOCK:
            return self._mint_mock_valid(cfg, grant, tenant, scopes)
        if (
            provider is Provider.DESCOPE
            and grant is Grant.CLIENT_CREDENTIALS
            and tenant is not None
        ):
            # AC-3: the Descope multi-tenant path is the access-key -> session-JWT
            # exchange (distinct dct/tenants), NOT the plain OIDC token endpoint.
            return self._mint_descope_tenant(cfg, tenant)
        self._check_capability(cfg, grant)
        self._check_credentials(cfg, grant)
        if grant is Grant.CLIENT_CREDENTIALS:
            return self._mint_client_credentials(cfg, tenant, scopes)
        if grant is Grant.AUTHORIZATION_CODE:
            return self._mint_auth_code(cfg, tenant, scopes)
        raise HarnessCapabilityError(
            f"grant {grant.value} is not implemented for provider {provider.value}"
        )

    # -- Gating -------------------------------------------------------------

    def _check_capability(self, cfg: ProviderConfig, grant: Grant) -> None:
        capability = _GRANT_CAPABILITY[grant]
        if capability not in cfg.capabilities:
            raise HarnessCapabilityError(
                f"{cfg.provider.value} does not advertise {capability} "
                f"(grant {grant.value})"
            )

    def _check_credentials(self, cfg: ProviderConfig, grant: Grant) -> None:
        if grant is Grant.CLIENT_CREDENTIALS:
            if not (cfg.client_id and cfg.client_secret and cfg.token_endpoint):
                raise HarnessCredentialError(
                    f"{cfg.provider.value}: client_credentials requires "
                    f"client_id, client_secret and a token endpoint"
                )
        elif grant is Grant.AUTHORIZATION_CODE and cfg.auth_code_minter is None:
            raise HarnessCredentialError(
                f"{cfg.provider.value}: no auth-code minter configured"
            )

    # -- Real-provider mints ------------------------------------------------

    def _mint_client_credentials(
        self, cfg: ProviderConfig, tenant: str | None, scopes: str | None
    ) -> MintedToken:
        assert cfg.token_endpoint
        assert cfg.client_id
        assert cfg.client_secret
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                client_id=cfg.client_id,
                client_secret=cfg.client_secret,
                address=cfg.token_endpoint,
                scope=scopes or cfg.scope,
            )
        )
        if not response.is_successful:
            raise HarnessError(
                f"{cfg.provider.value}: client_credentials mint failed: "
                f"{response.error}"
            )
        assert response.token is not None
        return self._from_token_response(
            cfg.provider, Grant.CLIENT_CREDENTIALS, response.token, tenant
        )

    def _mint_auth_code(
        self, cfg: ProviderConfig, tenant: str | None, scopes: str | None
    ) -> MintedToken:
        assert cfg.auth_code_minter is not None
        token = cfg.auth_code_minter(tenant, scopes)
        return self._from_token_response(
            cfg.provider, Grant.AUTHORIZATION_CODE, token, tenant
        )

    def _mint_descope_tenant(self, cfg: ProviderConfig, tenant: str) -> MintedToken:
        """Reuse the identity-stack access-key -> session-JWT exchange (AC-3).

        Creates a temporary tenant-scoped access key, exchanges it via
        ``/v1/auth/accesskey/exchange`` for a Descope *session JWT* carrying
        distinct ``dct``/``tenants`` claims, then deletes the key. Credential-
        gated: absent Descope management config raises
        :class:`HarnessCredentialError` (translated to ``pytest.skip``).
        """
        if not (
            cfg.descope_project_id
            and cfg.descope_management_key
            and cfg.descope_base_url
        ):
            raise HarnessCredentialError(
                "descope: multi-tenant mint requires descope_project_id, "
                "descope_management_key and descope_base_url"
            )
        session_jwt = _descope_accesskey_exchange(
            base_url=cfg.descope_base_url,
            project_id=cfg.descope_project_id,
            management_key=cfg.descope_management_key,
            tenant=tenant,
        )
        return self._from_token_response(
            Provider.DESCOPE,
            Grant.CLIENT_CREDENTIALS,
            {"access_token": session_jwt, "token_type": "Bearer"},
            tenant,
        )

    def _from_token_response(
        self,
        provider: Provider,
        grant: Grant,
        token: dict[str, Any],
        tenant: str | None,
    ) -> MintedToken:
        access_token = token["access_token"]
        expires_in = token.get("expires_in")
        expires_at = time.time() + expires_in if expires_in else None
        alg, kid = _peek_jwt_header(access_token)
        return MintedToken(
            access_token=access_token,
            provider=provider,
            grant=grant,
            token_type=token.get("token_type", "Bearer"),
            id_token=token.get("id_token"),
            expires_at=expires_at,
            tenant=tenant,
            alg=alg,
            kid=kid,
        )

    # -- MOCK mints ---------------------------------------------------------

    def _mint_mock_valid(
        self,
        cfg: ProviderConfig,
        grant: Grant,
        tenant: str | None,
        scopes: str | None,
    ) -> MintedToken:
        mock = self._require_mock(cfg)
        token = mock.mint_access_token(scopes=scopes, tenant=tenant)
        return MintedToken(
            access_token=token["access_token"],
            provider=Provider.MOCK,
            grant=grant,
            token_type=token["token_type"],
            expires_at=time.time() + token["expires_in"],
            tenant=tenant,
            alg=mock.signing_key.alg,
            kid=mock.signing_key.kid,
            malform=Malform.VALID,
        )

    def _mint_forged(
        self,
        cfg: ProviderConfig,
        grant: Grant,
        tenant: str | None,
        malform: Malform,
    ) -> MintedToken:
        if cfg.provider is not Provider.MOCK:
            raise HarnessCapabilityError(
                "forged tokens are only available from the MOCK provider "
                "(real OPs will not emit invalid tokens)"
            )
        mock = self._require_mock(cfg)
        forged = build_corpus(mock)[malform.value]
        return MintedToken(
            access_token=forged.jwt,
            provider=Provider.MOCK,
            grant=grant,
            tenant=tenant,
            malform=malform,
        )

    def _require_mock(self, cfg: ProviderConfig) -> MockOP:
        if cfg.mock_op is None:
            raise HarnessCapabilityError("MOCK provider has no mock OP configured")
        return cfg.mock_op


_DESCOPE_HTTP_TIMEOUT = 30.0


def _descope_accesskey_exchange(
    *,
    base_url: str,
    project_id: str,
    management_key: str,
    tenant: str,
    roles: Iterable[str] = ("owner", "admin"),
) -> str:
    """Access-key create -> exchange -> delete, returning the session JWT.

    Mirrors the identity-stack e2e minter: a ``keyTenants`` (array) access key
    is required so the exchanged session JWT includes ``dct``/``tenants`` claims
    (a top-level ``tenantId`` does not). The temporary key is deleted best-effort.
    """
    base = base_url.rstrip("/")
    mgmt_headers = {"Authorization": f"Bearer {project_id}:{management_key}"}
    with httpx.Client(timeout=_DESCOPE_HTTP_TIMEOUT) as client:
        created = client.post(
            f"{base}/v1/mgmt/accesskey/create",
            headers=mgmt_headers,
            json={
                "name": f"harness-{uuid.uuid4().hex[:8]}",
                "keyTenants": [{"tenantId": tenant, "roleNames": list(roles)}],
            },
        )
        created.raise_for_status()
        data = created.json()
        key_id = data.get("key", {}).get("id", "")
        cleartext = data.get("cleartext", "")
    # Once a key exists, the finally must delete it — even if ``cleartext`` is
    # absent — so the raise lives inside the try, not before it.
    try:
        if not cleartext:
            raise HarnessError(
                f"descope access-key create returned no cleartext: {data}"
            )
        with httpx.Client(timeout=_DESCOPE_HTTP_TIMEOUT) as client:
            exchanged = client.post(
                f"{base}/v1/auth/accesskey/exchange",
                headers={"Authorization": f"Bearer {project_id}:{cleartext}"},
                json={},
            )
            exchanged.raise_for_status()
            session_jwt = exchanged.json().get("sessionJwt", "")
            if not session_jwt:
                raise HarnessError(
                    f"descope access-key exchange returned no sessionJwt: "
                    f"{exchanged.json()}"
                )
            return session_jwt
    finally:
        if key_id:
            with (
                contextlib.suppress(Exception),
                httpx.Client(timeout=_DESCOPE_HTTP_TIMEOUT) as client,
            ):
                client.post(
                    f"{base}/v1/mgmt/accesskey/delete",
                    headers=mgmt_headers,
                    json={"id": key_id},
                )


def _peek_jwt_header(token: str) -> tuple[str | None, str | None]:
    """Best-effort ``(alg, kid)`` from a compact JWT header; ``(None, None)``
    for opaque tokens."""
    if token.count(".") != JWT_SEGMENT_SEPARATOR_COUNT:
        return None, None
    header_segment = token.split(".", 1)[0]
    padding = "=" * (-len(header_segment) % 4)
    try:
        header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
    except (ValueError, json.JSONDecodeError):
        return None, None
    if not isinstance(header, dict):
        return None, None
    return header.get("alg"), header.get("kid")


# -- Replay pool ------------------------------------------------------------


@dataclass(frozen=True)
class MintSpec:
    """A single mint request for :func:`prime_pool`."""

    provider: Provider
    grant: Grant = Grant.CLIENT_CREDENTIALS
    tenant: str | None = None
    scopes: str | None = None
    malform: Malform | None = None

    def key(self) -> str:
        parts = [
            self.provider.value,
            self.grant.value,
            self.tenant or "-",
            self.scopes or "-",
            self.malform.value if self.malform else "-",
        ]
        return "|".join(parts)


class ReplayPool:
    """Pre-mint once, replay many (design §3).

    Real IdPs rate-limit and validation is stateless, so the harness mints each
    distinct spec a single time and replays the token. ``expires_at`` is tracked
    so T311 can re-mint across the 300s TTL / classify post-expiry 401s as
    expected rather than error-budget.
    """

    def __init__(self) -> None:
        self._by_key: dict[str, MintedToken] = {}

    def add(self, spec: MintSpec, token: MintedToken) -> None:
        self._by_key[spec.key()] = token

    def get(self, spec: MintSpec) -> MintedToken:
        return self._by_key[spec.key()]

    def all(self) -> list[MintedToken]:
        return list(self._by_key.values())

    def __len__(self) -> int:
        return len(self._by_key)

    def __iter__(self):
        return iter(self._by_key.values())


def prime_pool(source: TokenSource, specs: Iterable[MintSpec]) -> ReplayPool:
    """Mint each spec once into a :class:`ReplayPool` (skips duplicate specs)."""
    pool = ReplayPool()
    seen: set[str] = set()
    for spec in specs:
        if spec.key() in seen:
            continue
        seen.add(spec.key())
        pool.add(
            spec,
            source.mint(
                spec.provider,
                spec.grant,
                tenant=spec.tenant,
                scopes=spec.scopes,
                malform=spec.malform,
            ),
        )
    return pool
