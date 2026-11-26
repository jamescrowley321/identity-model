"""Discovery takes the issuer: input checks and URL building (#1154).

The issuer is checked before any request, and the RFC 8414 location keeps the
issuer's path exactly, so a crafted path cannot steer the fetch elsewhere.
"""

import logging

import httpx
import pytest
import respx

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.aio import token_validation as aio_token_validation
from py_identity_model.core.discovery_policy import (
    DiscoveryLocation,
    discovery_document_url,
)
from py_identity_model.exceptions import ConfigurationException
from py_identity_model.sync import token_validation as sync_token_validation


ISSUER = "https://op.example.com/tenant"
DISCOVERY_URL = "https://op.example.com/tenant/.well-known/openid-configuration"
MISSING_ISSUER = r"^issuer is required when perform_disco is True$"


@pytest.mark.unit
class TestMissingIssuer:
    def test_sync_missing_issuer_is_a_configuration_error(self):
        with pytest.raises(ConfigurationException, match=MISSING_ISSUER):
            sync_token_validation._get_disco_response(None)

    @pytest.mark.asyncio
    async def test_aio_missing_issuer_is_a_configuration_error(self):
        with pytest.raises(ConfigurationException, match=MISSING_ISSUER):
            await aio_token_validation._get_disco_response(None)


@pytest.mark.unit
class TestRfc8414PathIsKeptExactly:
    @pytest.mark.parametrize(
        ("issuer", "expected"),
        [
            (
                "https://op.example.com/tenantX",
                "https://op.example.com/.well-known/oauth-authorization-server/tenantX",
            ),
            (
                "https://op.example.com/tenantX/",
                "https://op.example.com/.well-known/oauth-authorization-server/tenantX",
            ),
        ],
    )
    def test_path_characters_survive_the_terminating_slash_removal(
        self, issuer, expected
    ):
        assert (
            discovery_document_url(issuer, DiscoveryLocation.OAUTH_AUTHORIZATION_SERVER)
            == expected
        )


@pytest.mark.unit
class TestFetchedUrlIsLogged:
    @respx.mock
    def test_log_names_the_url_built_from_the_issuer(self, caplog):
        respx.get(DISCOVERY_URL).mock(return_value=httpx.Response(404))
        with caplog.at_level(logging.INFO, logger="py_identity_model"):
            get_discovery_document(DiscoveryDocumentRequest(issuer=ISSUER))
        assert f"Fetching discovery document from {DISCOVERY_URL}" in caplog.messages
