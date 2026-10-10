"""
Proves the one-shot ``logger.warning`` for the injected-``http_client`` bypass
path so operators can detect accidental cache opt-out in production logs.

The ``http_client`` parameter on ``validate_token`` skips the discovery cache,
the JWKS cache, the kid-miss cooldown, and the signature-failure cooldown
(see PR #395 C-1 — cooldown is gated only on the cached path). A caller who
expects "I'm just controlling the HTTP client" gets a silent DoS amplifier
unless the bypass is surfaced at runtime.

Pinned contract:
- A warning is emitted the first time ``validate_token`` is called with an
  injected client.
- Subsequent calls in the same process do NOT emit the warning.
- The cached-path (no injected client) never emits the warning.
- Sync and aio modules each have their own one-shot flag, so a process that
  uses both APIs sees at most two warnings.

See https://github.com/jamescrowley321/identity-model/issues/402
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = "https://example.com/jwks"


@pytest.fixture(autouse=True)
async def _reset_state():
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    sync_tv._reset_injected_http_client_warning_for_testing()
    aio_tv._reset_injected_http_client_warning_for_testing()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    sync_tv._reset_injected_http_client_warning_for_testing()
    aio_tv._reset_injected_http_client_warning_for_testing()


def _make_validation_setup() -> tuple[str, dict, TokenValidationConfig]:
    key_dict, pem = generate_rsa_keypair()
    key_dict["kid"] = "test-kid"
    token = sign_jwt(
        pem,
        {"sub": "user1", "iss": "https://example.com"},
        headers={"kid": "test-kid"},
    )
    config = TokenValidationConfig(
        perform_disco=True, audience=None, issuer="https://example.com"
    )
    return token, key_dict, config


def _mock_disco_and_jwks(key_dict: dict) -> None:
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    respx.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )


def _count_bypass_warnings(records: list[logging.LogRecord]) -> int:
    return sum(
        1
        for r in records
        if r.levelno == logging.WARNING and "injected http_client" in r.getMessage()
    )


# ============================================================================
# Sync: warning fires exactly once across multiple injected-client calls;
# never fires on the cached path.
# ============================================================================


class TestSyncInjectedClientWarning:
    @respx.mock
    def test_warning_emitted_on_first_injected_client_call(self, caplog):
        token, key_dict, config = _make_validation_setup()
        _mock_disco_and_jwks(key_dict)

        with (
            caplog.at_level(logging.WARNING, logger="py_identity_model"),
            HTTPClient() as client,
        ):
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
                http_client=client,
            )

        assert _count_bypass_warnings(caplog.records) == 1

    @respx.mock
    def test_warning_emitted_only_once_across_repeated_calls(self, caplog):
        token, key_dict, config = _make_validation_setup()
        _mock_disco_and_jwks(key_dict)

        with (
            caplog.at_level(logging.WARNING, logger="py_identity_model"),
            HTTPClient() as client,
        ):
            for _ in range(5):
                validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                    http_client=client,
                )

        assert _count_bypass_warnings(caplog.records) == 1

    @respx.mock
    def test_warning_not_emitted_on_cached_path(self, caplog):
        """The default (no http_client) path must never log the bypass
        warning — it's specifically for the injected-client opt-out."""
        token, key_dict, config = _make_validation_setup()
        _mock_disco_and_jwks(key_dict)

        with caplog.at_level(logging.WARNING, logger="py_identity_model"):
            for _ in range(3):
                validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )

        assert _count_bypass_warnings(caplog.records) == 0


# ============================================================================
# Async mirror: same contract on the aio API.
# ============================================================================


class TestAsyncInjectedClientWarning:
    @pytest.mark.asyncio
    @respx.mock
    async def test_warning_emitted_on_first_injected_client_call(self, caplog):
        token, key_dict, config = _make_validation_setup()
        _mock_disco_and_jwks(key_dict)

        with caplog.at_level(logging.WARNING, logger="py_identity_model"):
            async with AsyncHTTPClient() as client:
                await async_validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                    http_client=client,
                )

        assert _count_bypass_warnings(caplog.records) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_warning_emitted_only_once_across_repeated_calls(self, caplog):
        token, key_dict, config = _make_validation_setup()
        _mock_disco_and_jwks(key_dict)

        with caplog.at_level(logging.WARNING, logger="py_identity_model"):
            async with AsyncHTTPClient() as client:
                for _ in range(5):
                    await async_validate_token(
                        jwt=token,
                        token_validation_config=config,
                        disco_doc_address=DISCO_URL,
                        http_client=client,
                    )

        assert _count_bypass_warnings(caplog.records) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_warning_not_emitted_on_cached_path(self, caplog):
        token, key_dict, config = _make_validation_setup()
        _mock_disco_and_jwks(key_dict)

        with caplog.at_level(logging.WARNING, logger="py_identity_model"):
            for _ in range(3):
                await async_validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )

        assert _count_bypass_warnings(caplog.records) == 0


# ============================================================================
# The warning helper directly: race-free first-emit guarantee under the
# threading.Lock + flag combination, independent of the validate_token plumbing.
# ============================================================================


class TestWarningHelperContract:
    def test_sync_helper_emits_once_on_repeated_calls(self):
        sync_tv._reset_injected_http_client_warning_for_testing()
        with patch.object(sync_tv, "logger") as mock_logger:
            for _ in range(10):
                sync_tv._maybe_warn_injected_http_client()
            assert mock_logger.warning.call_count == 1

    def test_async_helper_emits_once_on_repeated_calls(self):
        aio_tv._reset_injected_http_client_warning_for_testing()
        with patch.object(aio_tv, "logger") as mock_logger:
            for _ in range(10):
                aio_tv._maybe_warn_injected_http_client()
            assert mock_logger.warning.call_count == 1

    def test_sync_reset_helper_reactivates_warning(self):
        warnings_after_reset = 2
        sync_tv._reset_injected_http_client_warning_for_testing()
        with patch.object(sync_tv, "logger") as mock_logger:
            sync_tv._maybe_warn_injected_http_client()
            sync_tv._maybe_warn_injected_http_client()
            assert mock_logger.warning.call_count == 1
            sync_tv._reset_injected_http_client_warning_for_testing()
            sync_tv._maybe_warn_injected_http_client()
            assert mock_logger.warning.call_count == warnings_after_reset
