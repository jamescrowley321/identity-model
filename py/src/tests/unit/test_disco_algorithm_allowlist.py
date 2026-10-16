"""Caller's ``algorithms`` allowlist is enforced on discovery validation (#905).

The discovery path resolves the signing algorithm from the JWKS key / JWT
header; that resolved algorithm must still be a member of
``TokenValidationConfig.algorithms`` when the caller sets one.
"""

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.discovery import (
    get_discovery_document as aio_get_discovery_document,
)
from py_identity_model.core.models import (
    DiscoveryDocumentRequest,
    TokenValidationConfig,
)
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.discovery import get_discovery_document

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
KID = "test-key-1"
SUBJECT = "user1"
FAPI2_ALGS = ["PS256", "ES256"]
# An explicitly empty allowlist permits nothing; only None means unset.
REJECTING_ALLOWLISTS = [FAPI2_ALGS, []]


@pytest.fixture(autouse=True)
async def _clear_caches():
    sync_tv.clear_discovery_cache()
    sync_tv.clear_jwks_cache()
    await aio_tv.clear_discovery_cache()
    await aio_tv.clear_jwks_cache()
    yield
    sync_tv.clear_discovery_cache()
    sync_tv.clear_jwks_cache()
    await aio_tv.clear_discovery_cache()
    await aio_tv.clear_jwks_cache()


@pytest.fixture
def rs256_token_and_jwks():
    """An RS256 token and a JWKS serving its (RS256) verification key."""
    key_dict, pem = generate_rsa_keypair()
    token = sign_jwt(pem, {"sub": SUBJECT, "iss": ISSUER}, headers={"kid": KID})
    return token, {"keys": [key_dict]}


def _mock_op(jwks: dict) -> None:
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks))


def _config(algorithms: list[str] | None) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=None,
        issuer=ISSUER,
        algorithms=algorithms,
    )


class TestSyncDiscoAlgorithmAllowlist:
    @pytest.mark.parametrize("allowed", REJECTING_ALLOWLISTS)
    @respx.mock
    def test_rejects_alg_outside_allowlist(self, rs256_token_and_jwks, allowed):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)

        with pytest.raises(TokenValidationException) as exc_info:
            sync_tv.validate_token(token, _config(allowed), DISCO_URL)

        assert exc_info.value.message == (
            "Algorithm 'RS256' is not in the allowed algorithms"
        )
        assert exc_info.value.token_part == "header"
        assert exc_info.value.details == {"alg": "RS256", "allowed": allowed}

    @pytest.mark.parametrize("allowed", REJECTING_ALLOWLISTS)
    @respx.mock
    def test_retry_path_rejects_alg_outside_allowlist(
        self, rs256_token_and_jwks, allowed
    ):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)
        disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_URL))

        with pytest.raises(TokenValidationException) as exc_info:
            sync_tv._retry_with_refreshed_jwks(token, _config(allowed), disco)

        assert exc_info.value.message == (
            "Algorithm 'RS256' is not in the allowed algorithms"
        )
        assert exc_info.value.token_part == "header"
        assert exc_info.value.details == {"alg": "RS256", "allowed": allowed}

    @pytest.mark.parametrize("algorithms", [["RS256"], None])
    @respx.mock
    def test_accepts_alg_in_allowlist_or_unset(self, rs256_token_and_jwks, algorithms):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)

        decoded = sync_tv.validate_token(token, _config(algorithms), DISCO_URL)

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}

    @pytest.mark.parametrize("algorithms", [["RS256"], None])
    @respx.mock
    def test_retry_path_accepts_alg_in_allowlist_or_unset(
        self, rs256_token_and_jwks, algorithms
    ):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)
        disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_URL))

        decoded = sync_tv._retry_with_refreshed_jwks(token, _config(algorithms), disco)

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}


class TestAsyncDiscoAlgorithmAllowlist:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("allowed", REJECTING_ALLOWLISTS)
    @respx.mock
    async def test_rejects_alg_outside_allowlist(self, rs256_token_and_jwks, allowed):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)

        with pytest.raises(TokenValidationException) as exc_info:
            await aio_tv.validate_token(token, _config(allowed), DISCO_URL)

        assert exc_info.value.message == (
            "Algorithm 'RS256' is not in the allowed algorithms"
        )
        assert exc_info.value.token_part == "header"
        assert exc_info.value.details == {"alg": "RS256", "allowed": allowed}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("allowed", REJECTING_ALLOWLISTS)
    @respx.mock
    async def test_retry_path_rejects_alg_outside_allowlist(
        self, rs256_token_and_jwks, allowed
    ):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)
        disco = await aio_get_discovery_document(
            DiscoveryDocumentRequest(address=DISCO_URL)
        )

        with pytest.raises(TokenValidationException) as exc_info:
            await aio_tv._retry_with_refreshed_jwks(token, _config(allowed), disco)

        assert exc_info.value.message == (
            "Algorithm 'RS256' is not in the allowed algorithms"
        )
        assert exc_info.value.token_part == "header"
        assert exc_info.value.details == {"alg": "RS256", "allowed": allowed}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithms", [["RS256"], None])
    @respx.mock
    async def test_accepts_alg_in_allowlist_or_unset(
        self, rs256_token_and_jwks, algorithms
    ):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)

        decoded = await aio_tv.validate_token(token, _config(algorithms), DISCO_URL)

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithms", [["RS256"], None])
    @respx.mock
    async def test_retry_path_accepts_alg_in_allowlist_or_unset(
        self, rs256_token_and_jwks, algorithms
    ):
        token, jwks = rs256_token_and_jwks
        _mock_op(jwks)
        disco = await aio_get_discovery_document(
            DiscoveryDocumentRequest(address=DISCO_URL)
        )

        decoded = await aio_tv._retry_with_refreshed_jwks(
            token, _config(algorithms), disco
        )

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}
