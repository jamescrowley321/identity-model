"""Tests for HTTP client retry logic and edge cases."""

import httpx
import pytest

from py_identity_model import Config
from py_identity_model.aio.http_client import (
    _reset_async_http_client,
    close_async_http_client,
    get_async_http_client,
    retry_with_backoff_async,
)
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.core.http_utils import DEFAULT_RETRY_MAX_ATTEMPTS
from py_identity_model.sync.http_client import (
    _reset_http_client,
    close_http_client,
    get_http_client,
    retry_with_backoff,
)
from py_identity_model.sync.managed_client import HTTPClient


# Test constants
HTTP_OK = 200
EXPECTED_CALLS_AFTER_TWO_RETRIES = 3
EXPECTED_CALLS_AFTER_ONE_RETRY = 2
CALLS_BEFORE_SUCCESS_ON_THIRD = 3
CALLS_BEFORE_SUCCESS_ON_SECOND = 2

TWO_RETRIES = 2
THREE_RETRIES = 3
EXPLICIT_RETRIES = 1
CALLS_WITHOUT_RETRY = 1


def _retry_config(max_attempts: int) -> Config:
    """Config with *max_attempts* retries and no backoff sleep."""
    return Config(http_retry_max_attempts=max_attempts, http_retry_base_delay=0)


@pytest.fixture
def sync_client_factory():
    """Build managed sync clients from a Config; closes them after the test."""
    clients: list[HTTPClient] = []

    def factory(config: Config) -> HTTPClient:
        client = HTTPClient(config=config)
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.close()


@pytest.fixture
async def async_client_factory():
    """Build managed async clients from a Config; closes them after the test."""
    clients: list[AsyncHTTPClient] = []

    def factory(config: Config) -> AsyncHTTPClient:
        client = AsyncHTTPClient(config=config)
        clients.append(client)
        return client

    yield factory
    for client in clients:
        await client.close()


class TestSyncRetryWithBackoff:
    """Tests for synchronous retry_with_backoff decorator."""

    def test_retry_exhaustion_raises_last_exception(self, sync_client_factory):
        """Test that after exhausting retries, the last exception is raised."""
        client = sync_client_factory(_retry_config(TWO_RETRIES))

        call_count = 0

        @retry_with_backoff()
        def failing_request(_client: httpx.Client):
            nonlocal call_count
            call_count += 1
            raise httpx.RequestError("Connection failed")

        with pytest.raises(httpx.RequestError, match="Connection failed"):
            failing_request(client)

        # Should have attempted max_retries + 1 times (initial + retries)
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    def test_retry_on_429_then_success(self, sync_client_factory):
        """Test that retry works when server returns 429 then succeeds."""
        client = sync_client_factory(_retry_config(THREE_RETRIES))

        call_count = 0

        @retry_with_backoff()
        def rate_limited_then_success(_client: httpx.Client):
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_THIRD:
                return httpx.Response(429)
            return httpx.Response(HTTP_OK)

        result = rate_limited_then_success(client)
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    def test_retry_on_5xx_errors(self, sync_client_factory):
        """Test that retry works on 5xx server errors."""
        client = sync_client_factory(_retry_config(TWO_RETRIES))

        call_count = 0

        @retry_with_backoff()
        def server_error_then_success(_client: httpx.Client):
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_SECOND:
                return httpx.Response(503)
            return httpx.Response(HTTP_OK)

        result = server_error_then_success(client)
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_ONE_RETRY


class TestAsyncRetryWithBackoff:
    """Tests for asynchronous retry_with_backoff_async decorator."""

    @pytest.mark.asyncio
    async def test_retry_exhaustion_raises_last_exception(self, async_client_factory):
        """Test that after exhausting retries, the last exception is raised."""
        client = async_client_factory(_retry_config(TWO_RETRIES))

        call_count = 0

        @retry_with_backoff_async()
        async def failing_request(_client: httpx.AsyncClient):
            nonlocal call_count
            call_count += 1
            raise httpx.RequestError("Connection failed")

        with pytest.raises(httpx.RequestError, match="Connection failed"):
            await failing_request(client)

        # Should have attempted max_retries + 1 times (initial + retries)
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    @pytest.mark.asyncio
    async def test_retry_on_429_then_success(self, async_client_factory):
        """Test that retry works when server returns 429 then succeeds."""
        client = async_client_factory(_retry_config(THREE_RETRIES))

        call_count = 0

        @retry_with_backoff_async()
        async def rate_limited_then_success(_client: httpx.AsyncClient):
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_THIRD:
                return httpx.Response(429)
            return httpx.Response(HTTP_OK)

        result = await rate_limited_then_success(client)
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_TWO_RETRIES

    @pytest.mark.asyncio
    async def test_retry_on_5xx_errors(self, async_client_factory):
        """Test that retry works on 5xx server errors."""
        client = async_client_factory(_retry_config(TWO_RETRIES))

        call_count = 0

        @retry_with_backoff_async()
        async def server_error_then_success(_client: httpx.AsyncClient):
            nonlocal call_count
            call_count += 1
            if call_count < CALLS_BEFORE_SUCCESS_ON_SECOND:
                return httpx.Response(503)
            return httpx.Response(HTTP_OK)

        result = await server_error_then_success(client)
        assert result.status_code == HTTP_OK
        assert call_count == EXPECTED_CALLS_AFTER_ONE_RETRY


class TestSyncHTTPClientLifecycle:
    """Tests for sync HTTP client lifecycle management."""

    def test_close_http_client_when_none(self):
        """Test closing HTTP client when it was never created."""
        _reset_http_client()

        # Should not raise even when no client exists
        close_http_client()

    def test_get_http_client_returns_same_instance(self):
        """Test that get_http_client returns the same instance for same thread."""
        _reset_http_client()

        client1 = get_http_client()
        client2 = get_http_client()

        assert client1 is client2

        # Cleanup
        close_http_client()


class TestAsyncHTTPClientLifecycle:
    """Tests for async HTTP client lifecycle management."""

    @pytest.mark.asyncio
    async def test_close_async_http_client_when_none(self):
        """Test closing async HTTP client when it was never created."""
        _reset_async_http_client()

        # Should not raise even when no client exists
        await close_async_http_client()

    @pytest.mark.asyncio
    async def test_close_async_http_client_twice(self):
        """Test closing async HTTP client twice is safe."""
        _reset_async_http_client()

        # Create a client
        client = get_async_http_client()
        assert client is not None

        # Close it twice - should not raise
        await close_async_http_client()
        await close_async_http_client()

    @pytest.mark.asyncio
    async def test_get_async_http_client_returns_same_instance(self):
        """Test that get_async_http_client returns the same instance."""
        _reset_async_http_client()

        client1 = get_async_http_client()
        client2 = get_async_http_client()

        assert client1 is client2

        # Cleanup
        await close_async_http_client()


class TestRetrySettingsFromConfig:
    """Retry count comes from the managed client's Config unless given explicitly."""

    @staticmethod
    def _counting_failure():
        calls: list[int] = []

        def failing_request(_client: httpx.Client) -> httpx.Response:
            calls.append(len(calls))
            raise httpx.RequestError("Connection failed")

        return calls, failing_request

    def test_default_config_retry_count(self, sync_client_factory):
        client = sync_client_factory(Config(http_retry_base_delay=0))
        calls, request = self._counting_failure()

        with pytest.raises(httpx.RequestError):
            retry_with_backoff()(request)(client)

        assert len(calls) == DEFAULT_RETRY_MAX_ATTEMPTS + 1

    def test_zero_max_attempts_disables_retries(self, sync_client_factory):
        client = sync_client_factory(_retry_config(0))
        calls, request = self._counting_failure()

        with pytest.raises(httpx.RequestError):
            retry_with_backoff()(request)(client)

        assert len(calls) == CALLS_WITHOUT_RETRY

    def test_explicit_max_retries_overrides_config(self, sync_client_factory):
        client = sync_client_factory(_retry_config(THREE_RETRIES))
        calls, request = self._counting_failure()

        with pytest.raises(httpx.RequestError):
            retry_with_backoff(max_retries=EXPLICIT_RETRIES)(request)(client)

        assert len(calls) == EXPLICIT_RETRIES + 1

    def test_each_client_uses_its_own_config(self, sync_client_factory):
        few = sync_client_factory(_retry_config(EXPLICIT_RETRIES))
        many = sync_client_factory(_retry_config(THREE_RETRIES))
        few_calls, few_request = self._counting_failure()
        many_calls, many_request = self._counting_failure()

        with pytest.raises(httpx.RequestError):
            retry_with_backoff()(few_request)(few)
        with pytest.raises(httpx.RequestError):
            retry_with_backoff()(many_request)(many)

        assert {"few": len(few_calls), "many": len(many_calls)} == {
            "few": EXPLICIT_RETRIES + 1,
            "many": THREE_RETRIES + 1,
        }

    @pytest.mark.parametrize(
        "kwargs", [{"max_retries": -1}, {"base_delay": -1.0}], ids=["retries", "delay"]
    )
    def test_negative_explicit_settings_rejected(self, kwargs):
        with pytest.raises(ValueError, match="must be at least 0"):
            retry_with_backoff(**kwargs)
        with pytest.raises(ValueError, match="must be at least 0"):
            retry_with_backoff_async(**kwargs)

    @pytest.mark.asyncio
    async def test_async_zero_max_attempts_disables_retries(self, async_client_factory):
        client = async_client_factory(_retry_config(0))
        calls: list[int] = []

        async def failing_request(_client: httpx.AsyncClient) -> httpx.Response:
            calls.append(len(calls))
            raise httpx.RequestError("Connection failed")

        with pytest.raises(httpx.RequestError):
            await retry_with_backoff_async()(failing_request)(client)

        assert len(calls) == CALLS_WITHOUT_RETRY
