"""The library reads no environment variable (#756, Story 25.5).

``os.environ`` is replaced by a trap that fails on any access made by library
code (``py_identity_model`` or ``fastapi_identity_model``), then client
operations run with an injected ``Config``. A reintroduced ``os.getenv`` or
``os.environ`` read anywhere on these paths turns the tests red.

Reads made by httpx itself (``trust_env``: proxy variables, ``SSL_CERT_FILE``)
pass through to the real environment. That is httpx's own documented
behaviour, which the library leaves at its default.
"""

from collections.abc import Iterator, MutableMapping
import os
import sys
import time

import certifi
import httpx
import pytest
import respx

from py_identity_model import Config, PyIdentityModelException
from py_identity_model.aio.discovery import (
    get_discovery_document as aio_get_discovery_document,
)
from py_identity_model.aio.jwks import get_jwks as aio_get_jwks
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import validate_token as aio_validate_token
from py_identity_model.core.models import (
    DiscoveryDocumentRequest,
    JwksRequest,
    TokenValidationConfig,
)
from py_identity_model.sync.discovery import get_discovery_document
from py_identity_model.sync.jwks import get_jwks
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import validate_token

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
KID = "test-key-1"
UNKNOWN_KID = "rotated-away"
LIBRARY_PACKAGES = frozenset({"py_identity_model", "fastapi_identity_model"})
# Frames between the accessing code and the trap: os.getenv, the
# MutableMapping mixins (get, items, ...) and this module.
_PASS_THROUGH_MODULES = frozenset({os.__name__, MutableMapping.__module__, __name__})


class LibraryEnvironmentRead(AssertionError):
    """Library code touched ``os.environ``."""


class EnvironmentTrap(MutableMapping[str, str]):
    """Stands in for ``os.environ``; any access by library code fails.

    Each library access is recorded before it raises, so a broad ``except``
    in the library can't hide it.
    """

    def __init__(self, real: MutableMapping[str, str]) -> None:
        self._real = real
        self.library_reads: list[str] = []

    def _check(self) -> MutableMapping[str, str]:
        frame = sys._getframe(2)
        while frame is not None and (
            frame.f_globals.get("__name__") in _PASS_THROUGH_MODULES
        ):
            frame = frame.f_back
        module = frame.f_globals.get("__name__", "") if frame is not None else ""
        if module.split(".")[0] in LIBRARY_PACKAGES:
            self.library_reads.append(module)
            raise LibraryEnvironmentRead(f"{module} read os.environ")
        return self._real

    def __getitem__(self, key: str) -> str:
        return self._check()[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._check()[key] = value

    def __delitem__(self, key: str) -> None:
        del self._check()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._check())

    def __len__(self) -> int:
        return len(self._check())

    def copy(self) -> dict[str, str]:
        return dict(self._check())


@pytest.fixture
def env_trap(monkeypatch) -> EnvironmentTrap:
    trap = EnvironmentTrap(os.environ)
    monkeypatch.setattr(os, "environ", trap)
    return trap


def _config() -> Config:
    return Config(
        http_timeout=5.0,
        http_retry_max_attempts=1,
        http_retry_base_delay=0,
        ca_bundle=certifi.where(),
    )


def _token(pem: bytes, kid: str = KID) -> str:
    now = int(time.time())
    return sign_jwt(
        pem,
        {"iss": ISSUER, "aud": "api", "sub": "u", "iat": now, "exp": now + 300},
        headers={"kid": kid},
    )


def _validation_config() -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=True, audience="api")


def _mock_provider(key: dict) -> None:
    """The first discovery request fails with 503, so the retry path runs."""
    calls: list[httpx.Request] = []

    def discovery(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)

    respx.get(DISCO_URL).mock(side_effect=discovery)
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [key]}))


@pytest.mark.unit
class TestTrap:
    """The trap catches the read styles the library used before #753."""

    @pytest.mark.parametrize(
        "read",
        [
            pytest.param(lambda: os.getenv("HTTP_TIMEOUT"), id="os.getenv"),
            pytest.param(lambda: os.environ.get("HTTP_TIMEOUT"), id="environ.get"),
            pytest.param(lambda: os.environ["HTTP_TIMEOUT"], id="environ[key]"),
            pytest.param(lambda: "HTTP_TIMEOUT" in os.environ, id="in"),
        ],
    )
    def test_library_read_is_caught(self, env_trap, read):
        # Run the read as if it were defined in a library module.
        library_globals = {"__name__": "py_identity_model.core.config", "os": os}
        library_read = type(read)(read.__code__, library_globals)
        with pytest.raises(LibraryEnvironmentRead):
            library_read()
        assert env_trap.library_reads == ["py_identity_model.core.config"]

    def test_third_party_read_passes_through(self, env_trap):
        with httpx.Client():
            pass
        assert env_trap.library_reads == []


@pytest.mark.unit
class TestSyncReadsNoEnvironment:
    @respx.mock
    def test_discovery_jwks_and_validation(self, env_trap):
        key, pem = generate_rsa_keypair()
        _mock_provider(key)
        with HTTPClient(config=_config()) as client:
            disco = get_discovery_document(
                DiscoveryDocumentRequest(address=DISCO_URL), http_client=client
            )
            jwks = get_jwks(JwksRequest(address=JWKS_URL), http_client=client)
            first = validate_token(
                _token(pem), _validation_config(), DISCO_URL, http_client=client
            )
            cached = validate_token(
                _token(pem), _validation_config(), DISCO_URL, http_client=client
            )
        assert disco.is_successful
        assert jwks.is_successful
        assert first["sub"] == cached["sub"] == "u"
        assert env_trap.library_reads == []

    @respx.mock
    def test_kid_miss_refresh(self, env_trap):
        key, pem = generate_rsa_keypair()
        _mock_provider(key)
        with (
            HTTPClient(config=_config()) as client,
            pytest.raises(PyIdentityModelException),
        ):
            validate_token(
                _token(pem, UNKNOWN_KID),
                _validation_config(),
                DISCO_URL,
                http_client=client,
            )
        assert env_trap.library_reads == []

    def test_default_config_client(self, env_trap):
        with HTTPClient() as client:
            assert client.config == Config()
        assert env_trap.library_reads == []


@pytest.mark.unit
class TestAsyncReadsNoEnvironment:
    @respx.mock
    async def test_discovery_jwks_and_validation(self, env_trap):
        key, pem = generate_rsa_keypair()
        _mock_provider(key)
        async with AsyncHTTPClient(config=_config()) as client:
            disco = await aio_get_discovery_document(
                DiscoveryDocumentRequest(address=DISCO_URL), http_client=client
            )
            jwks = await aio_get_jwks(JwksRequest(address=JWKS_URL), http_client=client)
            first = await aio_validate_token(
                _token(pem), _validation_config(), DISCO_URL, http_client=client
            )
            cached = await aio_validate_token(
                _token(pem), _validation_config(), DISCO_URL, http_client=client
            )
        assert disco.is_successful
        assert jwks.is_successful
        assert first["sub"] == cached["sub"] == "u"
        assert env_trap.library_reads == []

    @respx.mock
    async def test_kid_miss_refresh(self, env_trap):
        key, pem = generate_rsa_keypair()
        _mock_provider(key)
        async with AsyncHTTPClient(config=_config()) as client:
            with pytest.raises(PyIdentityModelException):
                await aio_validate_token(
                    _token(pem, UNKNOWN_KID),
                    _validation_config(),
                    DISCO_URL,
                    http_client=client,
                )
        assert env_trap.library_reads == []

    async def test_default_config_client(self, env_trap):
        async with AsyncHTTPClient() as client:
            assert client.config == Config()
        assert env_trap.library_reads == []
