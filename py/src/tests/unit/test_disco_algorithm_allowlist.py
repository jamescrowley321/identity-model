"""The ``algorithms`` allowlist is enforced on discovery validation (#905, #952).

The discovery path resolves the signing algorithm from the JWKS key / JWT
header; that resolved algorithm must be a member of
``TokenValidationConfig.algorithms``, or of ``DEFAULT_ALLOWED_ALGORITHMS``
when the caller leaves it unset.
"""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.discovery import (
    get_discovery_document as aio_get_discovery_document,
)
from py_identity_model.aio.http_client import get_default_async_http_client
from py_identity_model.aio.validation_cache import (
    get_default_async_validation_cache,
)
from py_identity_model.core.jwt_signing import DEFAULT_ALLOWED_ALGORITHMS
from py_identity_model.core.models import (
    DiscoveryDocumentRequest,
    TokenValidationConfig,
)
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.discovery import get_discovery_document
from py_identity_model.sync.http_client import get_default_http_client
from py_identity_model.sync.validation_cache import get_default_validation_cache

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
            sync_tv._retry_with_refreshed_jwks(
                token,
                _config(allowed),
                disco,
                get_default_http_client(),
                get_default_validation_cache(),
            )

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

        decoded = sync_tv._retry_with_refreshed_jwks(
            token,
            _config(algorithms),
            disco,
            get_default_http_client(),
            get_default_validation_cache(),
        )

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
            await aio_tv._retry_with_refreshed_jwks(
                token,
                _config(allowed),
                disco,
                get_default_async_http_client(),
                get_default_async_validation_cache(),
            )

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
            token,
            _config(algorithms),
            disco,
            get_default_async_http_client(),
            get_default_async_validation_cache(),
        )

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}


# --- #952 / #907: algorithms=None means the default asymmetric allowlist ------

HS256_SECRET = b"a-shared-secret-of-at-least-32-bytes!"


@pytest.fixture
def hs256_token_and_jwks():
    """An HS256 token and a JWKS serving its shared secret as an oct key."""
    token = pyjwt.encode(
        {"sub": SUBJECT, "iss": ISSUER}, HS256_SECRET, "HS256", headers={"kid": KID}
    )
    oct_key = {
        "kty": "oct",
        "kid": KID,
        "k": base64.urlsafe_b64encode(HS256_SECRET).rstrip(b"=").decode(),
    }
    return token, {"keys": [oct_key]}


@pytest.fixture
def eddsa_token_and_jwks():
    """An EdDSA token and a JWKS serving its Ed25519 key with no ``alg``."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    x = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    okp_key = {
        "kty": "OKP",
        "kid": KID,
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(x).rstrip(b"=").decode(),
    }
    token = pyjwt.encode(
        {"sub": SUBJECT, "iss": ISSUER}, private_key, "EdDSA", headers={"kid": KID}
    )
    return token, {"keys": [okp_key]}


@pytest.fixture
def rs256_token_and_algless_jwks(rs256_token_and_jwks):
    """The RS256 token with its key served without ``alg`` (#880)."""
    token, jwks = rs256_token_and_jwks
    return token, {"keys": [{k: v for k, v in jwks["keys"][0].items() if k != "alg"}]}


DEFAULT_ALLOWED = sorted(DEFAULT_ALLOWED_ALGORITHMS)


def test_default_allowlist_matches_go_and_rust():
    assert DEFAULT_ALLOWED == [
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
        "PS256",
        "PS384",
        "PS512",
        "RS256",
        "RS384",
        "RS512",
    ]


class TestSyncDefaultAllowlist:
    @respx.mock
    def test_unset_algorithms_rejects_hs256(self, hs256_token_and_jwks):
        token, jwks = hs256_token_and_jwks
        _mock_op(jwks)

        with pytest.raises(TokenValidationException) as exc_info:
            sync_tv.validate_token(token, _config(None), DISCO_URL)

        assert exc_info.value.message == (
            "Algorithm 'HS256' is not in the allowed algorithms"
        )
        assert exc_info.value.details == {"alg": "HS256", "allowed": DEFAULT_ALLOWED}

    @respx.mock
    def test_unset_algorithms_accepts_eddsa(self, eddsa_token_and_jwks):
        token, jwks = eddsa_token_and_jwks
        _mock_op(jwks)

        decoded = sync_tv.validate_token(token, _config(None), DISCO_URL)

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}

    @respx.mock
    def test_explicit_hs256_still_allowed(self, hs256_token_and_jwks):
        token, jwks = hs256_token_and_jwks
        _mock_op(jwks)

        decoded = sync_tv.validate_token(token, _config(["HS256"]), DISCO_URL)

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}

    @respx.mock
    def test_algless_key_does_not_bypass_allowlist(self, rs256_token_and_algless_jwks):
        # #880: a key with no alg resolves to the header alg, which must still
        # be in the allowlist.
        token, jwks = rs256_token_and_algless_jwks
        _mock_op(jwks)

        with pytest.raises(TokenValidationException) as exc_info:
            sync_tv.validate_token(
                token, _config(["PS256", "ES256", "EdDSA"]), DISCO_URL
            )

        assert exc_info.value.details == {
            "alg": "RS256",
            "allowed": ["PS256", "ES256", "EdDSA"],
        }


class TestAsyncDefaultAllowlist:
    @pytest.mark.asyncio
    @respx.mock
    async def test_unset_algorithms_rejects_hs256(self, hs256_token_and_jwks):
        token, jwks = hs256_token_and_jwks
        _mock_op(jwks)

        with pytest.raises(TokenValidationException) as exc_info:
            await aio_tv.validate_token(token, _config(None), DISCO_URL)

        assert exc_info.value.details == {"alg": "HS256", "allowed": DEFAULT_ALLOWED}

    @pytest.mark.asyncio
    @respx.mock
    async def test_unset_algorithms_accepts_eddsa(self, eddsa_token_and_jwks):
        token, jwks = eddsa_token_and_jwks
        _mock_op(jwks)

        decoded = await aio_tv.validate_token(token, _config(None), DISCO_URL)

        assert decoded == {"sub": SUBJECT, "iss": ISSUER}

    @pytest.mark.asyncio
    @respx.mock
    async def test_algless_key_does_not_bypass_allowlist(
        self, rs256_token_and_algless_jwks
    ):
        token, jwks = rs256_token_and_algless_jwks
        _mock_op(jwks)

        with pytest.raises(TokenValidationException) as exc_info:
            await aio_tv.validate_token(
                token, _config(["PS256", "ES256", "EdDSA"]), DISCO_URL
            )

        assert exc_info.value.details == {
            "alg": "RS256",
            "allowed": ["PS256", "ES256", "EdDSA"],
        }
