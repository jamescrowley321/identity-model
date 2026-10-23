"""Clients take an injected ``Config``; the library reads no environment (#753).

Covers Story 25.2: ``HTTPClient`` / ``AsyncHTTPClient`` accept ``config=``,
``None`` means ``Config()`` defaults (not the environment), and each client
owns its discovery cache, JWKS cache and kid-miss cooldown state.
"""

import time

import httpx
import pytest
import respx

from py_identity_model import Config, ConfigError, PyIdentityModelException
from py_identity_model.aio.jwks import get_jwks as aio_get_jwks
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as aio_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import validate_token as aio_validate_token
from py_identity_model.core.models import (
    DiscoveryDocumentRequest,
    JwksRequest,
    TokenValidationConfig,
)
from py_identity_model.sync.discovery import get_discovery_document
from py_identity_model.sync.http_client import (
    get_default_http_client,
    retry_with_backoff,
)
from py_identity_model.sync.jwks import get_jwks
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
CUSTOM_TIMEOUT = 7.5
CUSTOM_RETRIES = 2
CUSTOM_MAX_KEYS = 1
CUSTOM_MAX_SIZE = 16
TWO_CLIENTS = 2


def _token(pem: bytes, kid: str = "test-key-1") -> str:
    now = int(time.time())
    return sign_jwt(
        pem,
        {"iss": ISSUER, "aud": "api", "sub": "u", "iat": now, "exp": now + 300},
        headers={"kid": kid},
    )


def _validation_config() -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=True, audience="api")


def _no_sleep_config(retries: int) -> Config:
    return Config(http_retry_base_delay=0, http_retry_max_attempts=retries)


@pytest.mark.unit
class TestClientConfig:
    def test_config_none_means_defaults(self):
        with HTTPClient() as client:
            assert client.config == Config()

    def test_config_none_ignores_environment(self, monkeypatch):
        monkeypatch.setenv("HTTP_TIMEOUT", "1")
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "9")
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "2")
        with HTTPClient() as client:
            assert client.config == Config()
            assert client.client.timeout.read == Config().http_timeout

    def test_config_timeout_applies_to_owned_client(self):
        with HTTPClient(config=Config(http_timeout=CUSTOM_TIMEOUT)) as client:
            assert client.client.timeout.read == CUSTOM_TIMEOUT

    def test_wrapped_client_keeps_config(self):
        raw = httpx.Client()
        config = Config(http_retry_max_attempts=0)
        client = HTTPClient(client=raw, config=config)
        assert client.config is config
        assert client.client is raw
        raw.close()

    async def test_async_config_none_means_defaults(self, monkeypatch):
        monkeypatch.setenv("HTTP_TIMEOUT", "1")
        async with AsyncHTTPClient() as client:
            assert client.config == Config()
            assert client.client.timeout.read == Config().http_timeout

    def test_default_client_uses_config_defaults_not_env(self, monkeypatch):
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "9")
        assert get_default_http_client().config.http_retry_max_attempts == (
            Config().http_retry_max_attempts
        )


@pytest.mark.unit
class TestRetriesFromConfig:
    @respx.mock
    def test_retry_count_comes_from_client_config(self):
        route = respx.get(DISCO_URL).mock(return_value=httpx.Response(503))
        with HTTPClient(config=_no_sleep_config(CUSTOM_RETRIES)) as client:
            response = get_discovery_document(
                DiscoveryDocumentRequest(address=DISCO_URL), http_client=client
            )
        assert not response.is_successful
        assert route.call_count == CUSTOM_RETRIES + 1

    @respx.mock
    def test_zero_retries_makes_one_request(self):
        route = respx.get(JWKS_URL).mock(return_value=httpx.Response(503))
        with HTTPClient(config=_no_sleep_config(0)) as client:
            response = get_jwks(JwksRequest(address=JWKS_URL), http_client=client)
        assert not response.is_successful
        assert route.call_count == 1

    def test_negative_retry_count_cannot_reach_the_retry_loop(self):
        """#728: a negative count is rejected before any client exists."""
        with pytest.raises(ConfigError) as excinfo:
            HTTPClient(config=Config(http_retry_max_attempts=-1))
        assert [issue.setting for issue in excinfo.value.issues] == [
            "http_retry_max_attempts"
        ]

    def test_explicit_negative_decorator_retries_rejected(self):
        with pytest.raises(ValueError, match="max_retries"):
            retry_with_backoff(max_retries=-1)


@pytest.mark.unit
class TestJwksLimitsFromConfig:
    @respx.mock
    def test_max_keys_from_config(self):
        key, _ = generate_rsa_keypair()
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key, key]})
        )
        with HTTPClient(config=Config(jwks_max_keys=CUSTOM_MAX_KEYS)) as client:
            response = get_jwks(JwksRequest(address=JWKS_URL), http_client=client)
        assert not response.is_successful
        assert "too many keys" in (response.error or "")

    @respx.mock
    async def test_max_size_from_config_async(self):
        key, _ = generate_rsa_keypair()
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [key]}))
        async with AsyncHTTPClient(
            config=Config(jwks_max_size=CUSTOM_MAX_SIZE)
        ) as client:
            response = await aio_get_jwks(
                JwksRequest(address=JWKS_URL), http_client=client
            )
        assert not response.is_successful
        assert "too large" in (response.error or "")


@pytest.mark.unit
class TestCachesLiveOnTheClient:
    @respx.mock
    def test_injected_client_caches_discovery_and_jwks(self):
        key, pem = generate_rsa_keypair()
        disco = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        with HTTPClient() as client:
            for _ in range(TWO_CLIENTS):
                validate_token(
                    _token(pem), _validation_config(), DISCO_URL, http_client=client
                )
        assert disco.call_count == 1
        assert jwks.call_count == 1

    @respx.mock
    def test_two_clients_do_not_share_cached_documents(self):
        key, pem = generate_rsa_keypair()
        disco = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        with HTTPClient() as first, HTTPClient() as second:
            for client in (first, second):
                validate_token(
                    _token(pem), _validation_config(), DISCO_URL, http_client=client
                )
        assert disco.call_count == TWO_CLIENTS
        assert jwks.call_count == TWO_CLIENTS

    @respx.mock
    def test_clear_caches_targets_the_given_client(self):
        key, pem = generate_rsa_keypair()
        disco = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        with HTTPClient() as client:
            validate_token(_token(pem), _validation_config(), DISCO_URL, client)
            clear_discovery_cache(http_client=client)
            clear_jwks_cache(http_client=client)
            validate_token(_token(pem), _validation_config(), DISCO_URL, client)
        assert disco.call_count == TWO_CLIENTS
        assert jwks.call_count == TWO_CLIENTS

    @respx.mock
    def test_cache_max_entries_from_config(self):
        """One entry: the second issuer's JWKS evicts the first's."""
        key, pem = generate_rsa_keypair()
        other_disco = "https://other.example.com/.well-known/openid-configuration"
        other_jwks = "https://other.example.com/jwks"
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(other_disco).mock(
            return_value=httpx.Response(
                200,
                json={
                    name: value.replace(ISSUER, "https://other.example.com")
                    if isinstance(value, str)
                    else value
                    for name, value in DISCO_RESPONSE_WITH_JWKS.items()
                },
            )
        )
        jwks = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        respx.get(other_jwks).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        other_token = sign_jwt(
            pem,
            {
                "iss": "https://other.example.com",
                "aud": "api",
                "sub": "u",
                "exp": int(time.time()) + 300,
            },
            headers={"kid": "test-key-1"},
        )
        with HTTPClient(config=Config(cache_max_entries=1)) as client:
            validate_token(_token(pem), _validation_config(), DISCO_URL, client)
            validate_token(other_token, _validation_config(), other_disco, client)
            validate_token(_token(pem), _validation_config(), DISCO_URL, client)
        assert jwks.call_count == TWO_CLIENTS

    @respx.mock
    def test_kid_miss_cooldown_from_config(self):
        """Cooldown 0 disables it: every unknown kid refreshes."""
        key, pem = generate_rsa_keypair()
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        attempts = 3
        with HTTPClient(config=Config(jwks_kid_miss_cooldown=0)) as client:
            for _ in range(attempts):
                with pytest.raises(PyIdentityModelException):
                    validate_token(
                        _token(pem, kid="unknown"),
                        _validation_config(),
                        DISCO_URL,
                        client,
                    )
        # one initial fetch + one forced refresh per unknown-kid token
        assert jwks.call_count == 1 + attempts

    @respx.mock
    async def test_async_injected_client_caches(self):
        key, pem = generate_rsa_keypair()
        disco = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key]})
        )
        async with AsyncHTTPClient() as client:
            for _ in range(TWO_CLIENTS):
                await aio_validate_token(
                    _token(pem), _validation_config(), DISCO_URL, http_client=client
                )
            await aio_clear_jwks_cache(http_client=client)
            await aio_validate_token(
                _token(pem), _validation_config(), DISCO_URL, http_client=client
            )
        assert disco.call_count == 1
        assert jwks.call_count == TWO_CLIENTS
