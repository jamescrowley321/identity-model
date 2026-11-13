"""DoD: real-IdP proof for the unified ``TokenSource`` minter (TH-1.1, #463).

This is the Definition-of-Done evidence for the minter: it mints tokens through
a **live** identity provider (node-oidc / Keycloak under ``make
test-integration-node-oidc`` / ``-keycloak``; Ory / Descope when secret-gated)
and validates them end-to-end with the real library
(:func:`py_identity_model.validate_token`) against the provider's live JWKS.

The deterministic, network-free proofs (forged corpus, mock-OP failure
injection, capability/credential gating) live in the unit suite
(``test_mock_op.py`` / ``test_token_source_gating.py``); here we prove the one
thing only a real IdP can: that a ``TokenSource.mint`` result is a genuine,
signature-valid token the library accepts.
"""

from __future__ import annotations

import base64
import json

import pytest

from py_identity_model import (
    TokenValidationConfig,
    validate_token,
)

from ..harness import (
    Grant,
    HarnessCapabilityError,
    HarnessCredentialError,
    Malform,
    MintSpec,
    Provider,
    ProviderConfig,
    TokenSource,
    prime_pool,
)
from .conftest import DEFAULT_VALIDATION_OPTIONS


pytestmark = pytest.mark.integration

# JWT format: three dot-separated segments (two separators).
JWT_SEGMENT_SEPARATOR_COUNT = 2


def _mint_or_skip(source: TokenSource, provider: Provider, grant: Grant, **kwargs):
    """Mint, translating the typed gating errors to ``pytest.skip``.

    This is the contract the harness relies on: secret-gated providers
    (Ory/Descope) and unsupported grants skip cleanly rather than failing.
    """
    try:
        return source.mint(provider, grant, **kwargs)
    except HarnessCapabilityError as exc:
        pytest.skip(f"capability-gated: {exc}")
    except HarnessCredentialError as exc:
        pytest.skip(f"credential-gated: {exc}")


def _validate(token: str, test_config, require_https) -> dict:
    """Validate a token against the live provider's discovery + JWKS."""
    config = TokenValidationConfig(
        perform_disco=True,
        options=DEFAULT_VALIDATION_OPTIONS,
        require_https=require_https,
    )
    return validate_token(
        jwt=token,
        disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        token_validation_config=config,
    )


def test_client_credentials_mint_validates_end_to_end(
    token_source, harness_provider, test_config, require_https
):
    """DoD: a client-credentials mint validates against the live JWKS."""
    if harness_provider is None:
        pytest.skip("no real provider wired for this env file")

    minted = _mint_or_skip(token_source, harness_provider, Grant.CLIENT_CREDENTIALS)
    assert minted.access_token
    assert minted.provider is harness_provider
    assert minted.grant is Grant.CLIENT_CREDENTIALS

    claims = _validate(minted.access_token, test_config, require_https)
    assert claims["iss"]
    assert claims["exp"]


def test_auth_code_mint_validates_when_capable(
    token_source, harness_provider, test_config, require_https
):
    """Auth-code mint validates end-to-end where the provider supports it.

    Skips (capability/credential-gated) on providers without devInteractions
    or an auth-code client — the same gating the correctness matrix relies on.
    """
    if harness_provider is None:
        pytest.skip("no real provider wired for this env file")

    minted = _mint_or_skip(token_source, harness_provider, Grant.AUTHORIZATION_CODE)
    assert minted.access_token
    assert minted.grant is Grant.AUTHORIZATION_CODE

    # Only JWT-format access tokens are library-validatable; opaque tokens are
    # a legitimate outcome for some providers (introspection territory).
    if minted.access_token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT:
        claims = _validate(minted.access_token, test_config, require_https)
        assert claims["iss"]


def test_replay_pool_mints_once_and_replays(token_source, harness_provider):
    """The pre-minted pool mints each spec once and replays the same token."""
    if harness_provider is None:
        pytest.skip("no real provider wired for this env file")

    spec = MintSpec(provider=harness_provider, grant=Grant.CLIENT_CREDENTIALS)
    try:
        pool = prime_pool(token_source, [spec, spec])
    except (HarnessCapabilityError, HarnessCredentialError) as exc:
        pytest.skip(f"gated: {exc}")

    # Duplicate specs collapse to a single mint (rate-limit friendly).
    assert len(pool) == 1
    minted = pool.get(spec)
    assert minted.access_token
    # expires_at is tracked so T311 can re-mint across the 300s TTL.
    assert minted.expires_at is None or minted.expires_at > 0


def test_forged_tokens_require_mock_provider(token_source, harness_provider):
    """A real provider refuses to emit forged tokens (deterministic gating).

    Real OPs will not mint invalid tokens; the harness enforces that forgery
    is MOCK-only, so the forged corpus stays in one controllable place.
    """
    if harness_provider is None:
        pytest.skip("no real provider wired for this env file")

    with pytest.raises(HarnessCapabilityError):
        token_source.mint(
            harness_provider,
            Grant.CLIENT_CREDENTIALS,
            malform=Malform.TAMPERED_SIG,
        )


def test_descope_multitenant_mint_carries_dct_tenants(
    token_source, harness_provider, test_config
):
    """AC-3: the Descope multi-tenant path yields distinct ``dct``/``tenants``.

    Reuses the identity-stack access-key -> ``/v1/auth/accesskey/exchange`` flow
    (credential-gated on ``DESCOPE_PROJECT_ID``/``DESCOPE_MANAGEMENT_KEY``/
    ``DESCOPE_BASE_URL`` + a tenant id) so it skips cleanly off Descope.
    """
    if harness_provider is not Provider.DESCOPE:
        pytest.skip("Descope-only: multi-tenant access-key exchange")
    tenant = test_config.get("DESCOPE_TEST_TENANT_ID")
    if not tenant:
        pytest.skip("DESCOPE_TEST_TENANT_ID not configured")

    minted = _mint_or_skip(
        token_source, Provider.DESCOPE, Grant.CLIENT_CREDENTIALS, tenant=tenant
    )
    assert minted.tenant == tenant
    # Session JWT must carry the Descope multi-tenant claims (dct/tenants).
    payload_segment = minted.access_token.split(".")[1]
    payload = json.loads(
        base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4))
    )
    assert payload.get("dct") == tenant
    assert tenant in payload.get("tenants", {})


def test_mock_provider_always_mintable(token_source):
    """MOCK is always available regardless of which real provider is wired."""
    minted = token_source.mint(Provider.MOCK, Grant.CLIENT_CREDENTIALS)
    assert minted.provider is Provider.MOCK
    assert minted.malform is Malform.VALID
    assert minted.access_token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT


def test_credential_gating_raises_typed_error():
    """A real provider without credentials raises ``HarnessCredentialError``.

    Proves the contract the ``token_source`` fixture leans on to turn
    secret-gated providers (Ory/Descope) into clean ``pytest.skip``.
    """
    credentialless = ProviderConfig(
        provider=Provider.ORY,
        capabilities={"client_credentials"},
        token_endpoint="https://example.test/oauth2/token",
    )
    source = TokenSource.with_mock(extra=[credentialless])
    with pytest.raises(HarnessCredentialError):
        source.mint(Provider.ORY, Grant.CLIENT_CREDENTIALS)
