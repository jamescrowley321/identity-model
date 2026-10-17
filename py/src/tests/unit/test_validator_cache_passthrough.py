"""The ID Token and Logout Token validators pass ``cache=`` to ``validate_token`` (#953).

Each validator is called with a ``cache`` and an ``http_client``; a stand-in
``validate_token`` records what it was given and stops the call.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from py_identity_model import ValidationCache
from py_identity_model.aio import AsyncHTTPClient, AsyncValidationCache
from py_identity_model.aio import id_token as aio_id_token
from py_identity_model.aio import logout as aio_logout
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.sync import id_token as sync_id_token
from py_identity_model.sync import logout as sync_logout
from py_identity_model.sync.managed_client import HTTPClient

from ..constants import DISCO_URL, ISSUER


TOKEN = "header.payload.signature"
VALIDATION = TokenValidationConfig(
    perform_disco=True, audience="client-id", issuer=ISSUER
)


class _Stop(Exception):
    """Raised by the stand-in ``validate_token`` once it has recorded its call."""


def _passed(mock: Mock) -> dict:
    [call] = mock.call_args_list
    return {"http_client": call.kwargs["http_client"], "cache": call.kwargs["cache"]}


@pytest.mark.parametrize(
    ("module", "name"),
    [
        pytest.param(sync_logout, "validate_logout_token", id="logout"),
        pytest.param(sync_id_token, "validate_id_token", id="id-token"),
    ],
)
def test_sync_validators_pass_the_cache(monkeypatch, module, name):
    stand_in = Mock(side_effect=_Stop)
    monkeypatch.setattr(module, "validate_token", stand_in)
    validator = getattr(module, name)
    cache = ValidationCache()
    with HTTPClient() as client, pytest.raises(_Stop):
        validator(TOKEN, VALIDATION, DISCO_URL, http_client=client, cache=cache)
    assert _passed(stand_in) == {"http_client": client, "cache": cache}


@pytest.mark.parametrize(
    ("module", "name"),
    [
        pytest.param(aio_logout, "validate_logout_token", id="logout"),
        pytest.param(aio_id_token, "validate_id_token", id="id-token"),
    ],
)
async def test_async_validators_pass_the_cache(monkeypatch, module, name):
    stand_in = AsyncMock(side_effect=_Stop)
    monkeypatch.setattr(module, "validate_token", stand_in)
    validator = getattr(module, name)
    cache = AsyncValidationCache()
    async with AsyncHTTPClient() as client:
        with pytest.raises(_Stop):
            await validator(
                TOKEN, VALIDATION, DISCO_URL, http_client=client, cache=cache
            )
    assert _passed(stand_in) == {"http_client": client, "cache": cache}


@pytest.mark.parametrize(
    ("module", "name"),
    [
        pytest.param(sync_logout, "validate_logout_token", id="logout"),
        pytest.param(sync_id_token, "validate_id_token", id="id-token"),
    ],
)
def test_sync_validators_default_to_no_cache(monkeypatch, module, name):
    stand_in = Mock(side_effect=_Stop)
    monkeypatch.setattr(module, "validate_token", stand_in)
    validator = getattr(module, name)
    with pytest.raises(_Stop):
        validator(TOKEN, VALIDATION, DISCO_URL)
    assert _passed(stand_in) == {"http_client": None, "cache": None}
