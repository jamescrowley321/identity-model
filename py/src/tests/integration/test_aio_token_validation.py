"""
Integration tests for async token validation.

These tests verify async token validation with real tokens and async claims validators.
"""

import pytest

from py_identity_model.aio.http_client import close_async_http_client
from py_identity_model.aio.token_validation import validate_token
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException

from .conftest import DEFAULT_VALIDATION_OPTIONS as DEFAULT_OPTIONS


@pytest.mark.integration
class TestAsyncTokenValidation:
    """Test async token validation with real tokens.

    Each test closes the async HTTP client to prevent ResourceWarning
    from unclosed sockets/transports during garbage collection.
    """

    @pytest.mark.asyncio
    async def test_async_claims_validator_success(
        self,
        test_config,
        client_credentials_token,
        require_https,
    ):
        """Test async claims validator that succeeds."""
        assert client_credentials_token.token is not None
        called = []

        async def async_validate_claims(token: dict):  # noqa: ARG001
            """Async claims validator."""
            called.append(True)

        validation_config = TokenValidationConfig(
            perform_disco=True,
            options=DEFAULT_OPTIONS,
            claims_validator=async_validate_claims,
            require_https=require_https,
        )

        try:
            decoded_token = await validate_token(
                jwt=client_credentials_token.token["access_token"],
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

            assert decoded_token is not None
            assert decoded_token["iss"] is not None
            assert len(called) == 1, (
                "async claims_validator should be invoked exactly once"
            )
        finally:
            await close_async_http_client()

    @pytest.mark.asyncio
    async def test_async_claims_validator_failure(
        self,
        test_config,
        client_credentials_token,
        require_https,
    ):
        """Test async claims validator that fails."""
        assert client_credentials_token.token is not None

        async def async_validate_claims(_token: dict):
            """Async claims validator that fails."""
            raise ValueError("Custom validation failed")

        validation_config = TokenValidationConfig(
            perform_disco=True,
            options=DEFAULT_OPTIONS,
            claims_validator=async_validate_claims,
            require_https=require_https,
        )

        try:
            with pytest.raises(
                TokenValidationException, match="Claims validation failed"
            ):
                await validate_token(
                    jwt=client_credentials_token.token["access_token"],
                    disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                    token_validation_config=validation_config,
                )
        finally:
            await close_async_http_client()

    @pytest.mark.asyncio
    async def test_sync_claims_validator_in_async_context(
        self,
        test_config,
        client_credentials_token,
        require_https,
    ):
        """Test that sync claims validator works in async validation."""
        assert client_credentials_token.token is not None
        called = []

        def sync_validate_claims(token: dict):  # noqa: ARG001
            """Sync claims validator."""
            called.append(True)

        validation_config = TokenValidationConfig(
            perform_disco=True,
            options=DEFAULT_OPTIONS,
            claims_validator=sync_validate_claims,
            require_https=require_https,
        )

        try:
            decoded_token = await validate_token(
                jwt=client_credentials_token.token["access_token"],
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

            assert decoded_token is not None
            assert decoded_token["iss"] is not None
            assert len(called) == 1, (
                "sync claims_validator should be invoked exactly once in async context"
            )
        finally:
            await close_async_http_client()
