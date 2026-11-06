"""Unit tests for managed HTTP client classes (sync and async)."""

import certifi
import httpx
import pytest

from py_identity_model import Config
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.sync.managed_client import HTTPClient


# Custom timeout value for testing (seconds)
CUSTOM_TIMEOUT = 60.0
# Timeout of a caller-built httpx client that the wrapper must not override
WRAPPED_CLIENT_TIMEOUT = 5.0


@pytest.fixture
def recorded_client_kwargs(monkeypatch) -> list[dict]:
    """Record the keyword arguments of every httpx.Client/AsyncClient built."""
    recorded: list[dict] = []

    class RecordingClient(httpx.Client):
        def __init__(self, **kwargs):
            recorded.append(kwargs)
            super().__init__(**kwargs)

    class RecordingAsyncClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            recorded.append(kwargs)
            super().__init__(**kwargs)

    monkeypatch.setattr(httpx, "Client", RecordingClient)
    monkeypatch.setattr(httpx, "AsyncClient", RecordingAsyncClient)
    return recorded


@pytest.mark.unit
class TestHTTPClient:
    """Tests for the sync HTTPClient wrapper."""

    def test_creates_owned_client_by_default(self):
        client = HTTPClient()
        assert isinstance(client.client, httpx.Client)
        client.close()

    def test_wraps_existing_client(self):
        raw = httpx.Client()
        client = HTTPClient(client=raw)
        assert client.client is raw
        client.close()  # Should NOT close raw (not owned)
        assert not raw.is_closed
        raw.close()

    def test_close_owned_client(self):
        client = HTTPClient()
        underlying = client.client
        client.close()
        assert underlying.is_closed

    def test_close_unowned_is_noop(self):
        raw = httpx.Client()
        client = HTTPClient(client=raw)
        client.close()
        assert not raw.is_closed
        raw.close()

    def test_context_manager(self):
        with HTTPClient() as client:
            assert isinstance(client.client, httpx.Client)
            underlying = client.client
        assert underlying.is_closed

    def test_context_manager_unowned(self):
        raw = httpx.Client()
        with HTTPClient(client=raw) as client:
            assert client.client is raw
        assert not raw.is_closed
        raw.close()

    def test_default_config(self):
        client = HTTPClient()
        assert client.config == Config()
        client.close()

    def test_custom_timeout(self):
        client = HTTPClient(config=Config(http_timeout=CUSTOM_TIMEOUT))
        assert client.client.timeout.connect == CUSTOM_TIMEOUT
        client.close()

    def test_custom_ca_bundle(self, recorded_client_kwargs):
        ca_bundle = certifi.where()
        client = HTTPClient(config=Config(ca_bundle=ca_bundle))
        assert isinstance(client.client, httpx.Client)
        assert [kwargs["verify"] for kwargs in recorded_client_kwargs] == [ca_bundle]
        client.close()

    def test_default_verifies_tls(self, recorded_client_kwargs):
        client = HTTPClient()
        assert [kwargs["verify"] for kwargs in recorded_client_kwargs] == [True]
        client.close()

    def test_access_after_close_raises(self):
        client = HTTPClient()
        client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client

    def test_double_close_is_idempotent(self):
        client = HTTPClient()
        client.close()
        client.close()  # Should not raise

    def test_wrapped_client_keeps_its_own_timeout(self):
        raw = httpx.Client(timeout=WRAPPED_CLIENT_TIMEOUT)
        config = Config(http_timeout=CUSTOM_TIMEOUT)
        client = HTTPClient(client=raw, config=config)
        assert client.client.timeout.connect == WRAPPED_CLIENT_TIMEOUT
        assert client.config is config
        client.close()
        raw.close()

    def test_each_client_owns_its_caches(self):
        first = HTTPClient()
        second = HTTPClient()
        assert first.caches is not second.caches
        assert first.caches.jwks is not second.caches.jwks
        assert first.caches.disco is not second.caches.disco
        first.close()
        second.close()

    def test_unowned_close_blocks_further_access(self):
        raw = httpx.Client()
        client = HTTPClient(client=raw)
        client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client
        assert not raw.is_closed
        raw.close()


@pytest.mark.unit
class TestAsyncHTTPClient:
    """Tests for the async AsyncHTTPClient wrapper."""

    def test_creates_owned_client_by_default(self):
        client = AsyncHTTPClient()
        assert isinstance(client.client, httpx.AsyncClient)

    def test_wraps_existing_client(self):
        raw = httpx.AsyncClient()
        client = AsyncHTTPClient(client=raw)
        assert client.client is raw

    @pytest.mark.asyncio
    async def test_close_owned_client(self):
        client = AsyncHTTPClient()
        underlying = client.client
        await client.close()
        assert underlying.is_closed

    @pytest.mark.asyncio
    async def test_close_unowned_is_noop(self):
        raw = httpx.AsyncClient()
        client = AsyncHTTPClient(client=raw)
        await client.close()
        assert not raw.is_closed
        await raw.aclose()

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with AsyncHTTPClient() as client:
            assert isinstance(client.client, httpx.AsyncClient)
            underlying = client.client
        assert underlying.is_closed

    @pytest.mark.asyncio
    async def test_async_context_manager_unowned(self):
        raw = httpx.AsyncClient()
        async with AsyncHTTPClient(client=raw) as client:
            assert client.client is raw
        assert not raw.is_closed
        await raw.aclose()

    def test_default_config(self):
        client = AsyncHTTPClient()
        assert client.config == Config()

    def test_custom_timeout(self):
        client = AsyncHTTPClient(config=Config(http_timeout=CUSTOM_TIMEOUT))
        assert client.client.timeout.connect == CUSTOM_TIMEOUT

    def test_custom_ca_bundle(self, recorded_client_kwargs):
        ca_bundle = certifi.where()
        client = AsyncHTTPClient(config=Config(ca_bundle=ca_bundle))
        assert isinstance(client.client, httpx.AsyncClient)
        assert [kwargs["verify"] for kwargs in recorded_client_kwargs] == [ca_bundle]

    def test_default_verifies_tls(self, recorded_client_kwargs):
        AsyncHTTPClient()
        assert [kwargs["verify"] for kwargs in recorded_client_kwargs] == [True]

    @pytest.mark.asyncio
    async def test_access_after_close_raises(self):
        client = AsyncHTTPClient()
        await client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client

    @pytest.mark.asyncio
    async def test_double_close_is_idempotent(self):
        client = AsyncHTTPClient()
        await client.close()
        await client.close()  # Should not raise

    def test_wrapped_client_keeps_its_own_timeout(self):
        raw = httpx.AsyncClient(timeout=WRAPPED_CLIENT_TIMEOUT)
        config = Config(http_timeout=CUSTOM_TIMEOUT)
        client = AsyncHTTPClient(client=raw, config=config)
        assert client.client.timeout.connect == WRAPPED_CLIENT_TIMEOUT
        assert client.config is config

    def test_each_client_owns_its_caches(self):
        first = AsyncHTTPClient()
        second = AsyncHTTPClient()
        assert first.caches is not second.caches
        assert first.caches.jwks is not second.caches.jwks
        assert first.caches.disco is not second.caches.disco

    @pytest.mark.asyncio
    async def test_unowned_close_blocks_further_access(self):
        raw = httpx.AsyncClient()
        client = AsyncHTTPClient(client=raw)
        await client.close()
        with pytest.raises(RuntimeError, match="has been closed"):
            _ = client.client
        assert not raw.is_closed
        await raw.aclose()
