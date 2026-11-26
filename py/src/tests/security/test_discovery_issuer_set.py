"""Discovery mode: a provider whose tokens carry several ``iss`` values.

One provider, one JWKS, several issuer values: the discovery document names
one, and other tokens name another that is not a URL and so has no discovery
document of its own. ``TokenValidationConfig.token_issuers`` names the values
an access token's ``iss`` may carry; the discovery document still supplies the
keys. The ``iss`` check is never off, and ID Tokens and Logout Tokens are
always checked against the discovery issuer.
"""

import time

import httpx
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    ValidationCache,
    get_discovery_document,
)
from py_identity_model.aio import AsyncValidationCache
from py_identity_model.aio import (
    get_discovery_document as aio_get_discovery_document,
)
from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.http_client import get_default_async_http_client
from py_identity_model.aio.id_token import (
    validate_id_token as aio_validate_id_token,
)
from py_identity_model.aio.logout import (
    validate_logout_token as aio_validate_logout_token,
)
from py_identity_model.aio.token_validation import (
    validate_token as aio_validate_token,
)
from py_identity_model.core.logout_logic import BACKCHANNEL_LOGOUT_EVENT
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import decode_with_config
from py_identity_model.core.validators import (
    TOKEN_ISSUERS_ENTRIES_MESSAGE,
    TOKEN_ISSUERS_ONE_PROVIDER_MESSAGE,
    TOKEN_ISSUERS_WITHOUT_DISCOVERY_MESSAGE,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    InvalidIssuerException,
    TokenValidationException,
)
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.http_client import get_default_http_client
from py_identity_model.sync.id_token import validate_id_token
from py_identity_model.sync.logout import validate_logout_token
from py_identity_model.sync.token_validation import validate_token

from ..constants import DISCO_URL
from ..token_validation_helpers import DISCO_RESPONSE_WITH_JWKS
from ._security_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit

DISCOVERY_ISSUER = DISCO_RESPONSE_WITH_JWKS["issuer"]
JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
# Not a URL: it can never have a discovery document of its own.
SESSION_ISSUER = "P2exampleproject"
OTHER_ISSUER = "https://other.example.com"
CLIENT_ID = "client-123"
NO_AUDIENCE = {"verify_aud": False}

SYNC = "sync"
ASYNC = "async"
BOTH_APIS = pytest.mark.parametrize("api", [SYNC, ASYNC])


@pytest.fixture(scope="module")
def keypair() -> tuple[dict, bytes]:
    return generate_rsa_keypair()


def _mock_provider(key_dict: dict) -> tuple[respx.Route, respx.Route]:
    disco = respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    jwks = respx.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )
    return disco, jwks


def _token(keypair: tuple[dict, bytes], **claims: object) -> str:
    key_dict, pem = keypair
    now = int(time.time())
    return sign_jwt(
        pem,
        {"sub": "user", "iat": now, "exp": now + 300, **claims},
        headers={"kid": key_dict["kid"]},
    )


def _config(**overrides: object) -> TokenValidationConfig:
    settings: dict = {
        "perform_disco": True,
        "algorithms": ["RS256"],
        "options": NO_AUDIENCE,
        **overrides,
    }
    return TokenValidationConfig(**settings)


async def _validate(api: str, token: str, config: TokenValidationConfig) -> dict:
    if api == SYNC:
        return validate_token(token, config, DISCOVERY_ISSUER, cache=ValidationCache())
    return await aio_validate_token(
        token, config, DISCOVERY_ISSUER, cache=AsyncValidationCache()
    )


async def _validate_id_token(
    api: str, token: str, config: TokenValidationConfig
) -> dict:
    if api == SYNC:
        return validate_id_token(
            token, config, DISCOVERY_ISSUER, nonce=None, cache=ValidationCache()
        )
    return await aio_validate_id_token(
        token, config, DISCOVERY_ISSUER, nonce=None, cache=AsyncValidationCache()
    )


async def _validate_logout_token(
    api: str, token: str, config: TokenValidationConfig
) -> dict:
    if api == SYNC:
        return validate_logout_token(
            token, config, DISCOVERY_ISSUER, cache=ValidationCache()
        )
    return await aio_validate_logout_token(
        token, config, DISCOVERY_ISSUER, cache=AsyncValidationCache()
    )


async def _retry_without_the_flag(
    api: str, token: str, config: TokenValidationConfig
) -> dict:
    request = DiscoveryDocumentRequest(issuer=DISCOVERY_ISSUER)
    if api == SYNC:
        return sync_tv._retry_with_refreshed_jwks(
            token,
            config,
            get_discovery_document(request),
            get_default_http_client(),
            ValidationCache(),
        )
    return await aio_tv._retry_with_refreshed_jwks(
        token,
        config,
        await aio_get_discovery_document(request),
        get_default_async_http_client(),
        AsyncValidationCache(),
    )


@BOTH_APIS
class TestTokenIssuers:
    @respx.mock
    async def test_listed_non_url_issuer_is_accepted(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER)

        claims = await _validate(
            api, token, _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])
        )

        assert claims["iss"] == SESSION_ISSUER

    @respx.mock
    async def test_listed_discovery_issuer_is_accepted(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=DISCOVERY_ISSUER)

        claims = await _validate(
            api, token, _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])
        )

        assert claims["iss"] == DISCOVERY_ISSUER

    @respx.mock
    async def test_issuer_outside_the_set_is_refused(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=OTHER_ISSUER)

        with pytest.raises(InvalidIssuerException):
            await _validate(
                api, token, _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])
            )

    @respx.mock
    async def test_token_without_iss_is_refused(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(keypair)

        with pytest.raises(TokenValidationException):
            await _validate(
                api, token, _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])
            )

    @respx.mock
    async def test_the_list_replaces_the_discovery_issuer(self, api, keypair):
        _mock_provider(keypair[0])
        config = _config(
            token_issuers=[SESSION_ISSUER], allowed_issuers=[DISCOVERY_ISSUER]
        )

        claims = await _validate(api, _token(keypair, iss=SESSION_ISSUER), config)
        assert claims["iss"] == SESSION_ISSUER

        with pytest.raises(InvalidIssuerException):
            await _validate(api, _token(keypair, iss=DISCOVERY_ISSUER), config)


@BOTH_APIS
class TestDiscoveryIssuerStaysPinned:
    @respx.mock
    async def test_discovery_issuer_missing_from_the_set_is_refused(self, api, keypair):
        """A listed ``iss`` is not accepted from a document the set does not name."""
        _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER)

        with pytest.raises(InvalidIssuerException) as exc_info:
            await _validate(api, token, _config(token_issuers=[SESSION_ISSUER]))

        assert exc_info.value.message == (
            "The discovery document's issuer is not in token_issuers; add it, "
            "or pin it as the single entry of allowed_issuers"
        )
        assert exc_info.value.details == {
            "issuer": DISCOVERY_ISSUER,
            "token_issuers": [SESSION_ISSUER],
        }

    @pytest.mark.parametrize(
        "allowed_issuers",
        [[], [DISCOVERY_ISSUER, OTHER_ISSUER]],
        ids=["none", "two-providers"],
    )
    @respx.mock
    async def test_allowed_issuers_must_name_one_provider(
        self, api, keypair, allowed_issuers
    ):
        """One provider's keys must not sign another pinned provider's ``iss``."""
        disco, jwks = _mock_provider(keypair[0])
        token = _token(keypair, iss=OTHER_ISSUER)
        config = _config(
            token_issuers=[DISCOVERY_ISSUER, OTHER_ISSUER],
            allowed_issuers=allowed_issuers,
        )

        with pytest.raises(ConfigurationException) as exc_info:
            await _validate(api, token, config)

        assert exc_info.value.message == TOKEN_ISSUERS_ONE_PROVIDER_MESSAGE
        assert (disco.call_count, jwks.call_count) == (0, 0)

    @respx.mock
    async def test_allowed_issuers_still_refuses_an_unapproved_discovery_issuer(
        self, api, keypair
    ):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER)
        config = _config(
            token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER],
            allowed_issuers=[OTHER_ISSUER],
        )

        with pytest.raises(InvalidIssuerException) as exc_info:
            await _validate(api, token, config)

        assert exc_info.value.details == {
            "issuer": DISCOVERY_ISSUER,
            "allowed_issuers": [OTHER_ISSUER],
        }


@BOTH_APIS
class TestIssuerCheckIsNeverOff:
    @pytest.mark.parametrize(
        "token_issuers",
        [None, [DISCOVERY_ISSUER, SESSION_ISSUER]],
        ids=["default", "set"],
    )
    @respx.mock
    async def test_verify_iss_false_is_a_configuration_error(
        self, api, keypair, token_issuers
    ):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER)
        config = _config(
            token_issuers=token_issuers, options={**NO_AUDIENCE, "verify_iss": False}
        )

        with pytest.raises(ConfigurationException):
            await _validate(api, token, config)

    @pytest.mark.parametrize(
        "token_issuers",
        [
            [],
            [SESSION_ISSUER, ""],
            [SESSION_ISSUER, "   "],
            [SESSION_ISSUER, None],
            SESSION_ISSUER,
            (DISCOVERY_ISSUER, SESSION_ISSUER),
        ],
        ids=["empty", "empty-entry", "whitespace-entry", "none-entry", "str", "tuple"],
    )
    @respx.mock
    async def test_unusable_list_is_a_configuration_error_before_any_request(
        self, api, keypair, token_issuers
    ):
        disco, jwks = _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER)

        with pytest.raises(ConfigurationException) as exc_info:
            await _validate(api, token, _config(token_issuers=token_issuers))

        assert exc_info.value.message == TOKEN_ISSUERS_ENTRIES_MESSAGE
        assert (disco.call_count, jwks.call_count) == (0, 0)

    async def test_without_discovery_is_a_configuration_error(self, api, keypair):
        key_dict, _ = keypair
        token = _token(keypair, iss=SESSION_ISSUER)
        config = _config(
            perform_disco=False, key=key_dict, token_issuers=[SESSION_ISSUER]
        )

        with pytest.raises(ConfigurationException) as exc_info:
            await _validate(api, token, config)

        assert exc_info.value.message == TOKEN_ISSUERS_WITHOUT_DISCOVERY_MESSAGE

    @pytest.mark.parametrize(
        "issuer",
        [None, [DISCOVERY_ISSUER, SESSION_ISSUER]],
        ids=["no-issuer", "issuer-list"],
    )
    @respx.mock
    async def test_without_token_issuers_the_discovery_issuer_is_checked(
        self, api, keypair, issuer
    ):
        """``issuer`` does not widen the set in discovery mode."""
        _mock_provider(keypair[0])
        config = _config(issuer=issuer)

        claims = await _validate(api, _token(keypair, iss=DISCOVERY_ISSUER), config)
        assert claims["iss"] == DISCOVERY_ISSUER

        with pytest.raises(InvalidIssuerException):
            await _validate(api, _token(keypair, iss=SESSION_ISSUER), config)


@BOTH_APIS
class TestKeyRotationRetry:
    """The retry after a signature failure checks ``iss`` against the same set."""

    @staticmethod
    def _mock_rotated_provider(keypair: tuple[dict, bytes]) -> None:
        stale_key, _ = generate_rsa_keypair()
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(
                    200, json={"keys": [{**stale_key, "kid": keypair[0]["kid"]}]}
                ),
                httpx.Response(200, json={"keys": [keypair[0]]}),
            ]
        )

    @respx.mock
    async def test_listed_issuer_is_accepted_after_rotation(self, api, keypair):
        self._mock_rotated_provider(keypair)
        token = _token(keypair, iss=SESSION_ISSUER)

        claims = await _validate(
            api, token, _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])
        )

        assert claims["iss"] == SESSION_ISSUER

    @respx.mock
    async def test_issuer_outside_the_set_is_refused_after_rotation(self, api, keypair):
        self._mock_rotated_provider(keypair)
        token = _token(keypair, iss=OTHER_ISSUER)

        with pytest.raises(InvalidIssuerException):
            await _validate(
                api, token, _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])
            )

    @respx.mock
    async def test_retry_checks_the_discovery_issuer_unless_told_otherwise(
        self, api, keypair
    ):
        """Called without the flag, as for an ID Token, the retry keeps the
        discovery issuer."""
        _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER)
        config = _config(token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])

        with pytest.raises(InvalidIssuerException):
            await _retry_without_the_flag(api, token, config)


@BOTH_APIS
class TestIdAndLogoutTokensKeepTheDiscoveryIssuer:
    """OIDC Core §3.1.3.7 step 2; Back-Channel Logout 1.0 §2.6."""

    @respx.mock
    async def test_id_token_with_a_listed_issuer_is_refused(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=SESSION_ISSUER, aud=CLIENT_ID)
        config = TokenValidationConfig(
            perform_disco=True,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER],
        )

        with pytest.raises(InvalidIssuerException):
            await _validate_id_token(api, token, config)

    @respx.mock
    async def test_id_token_with_the_discovery_issuer_is_accepted(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(keypair, iss=DISCOVERY_ISSUER, aud=CLIENT_ID)
        config = TokenValidationConfig(
            perform_disco=True,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            token_issuers=[SESSION_ISSUER],
        )

        claims = await _validate_id_token(api, token, config)

        assert claims["iss"] == DISCOVERY_ISSUER

    @respx.mock
    async def test_logout_token_with_a_listed_issuer_is_refused(self, api, keypair):
        _mock_provider(keypair[0])
        token = _token(
            keypair,
            iss=SESSION_ISSUER,
            aud=CLIENT_ID,
            jti="logout-jti-1",
            events={BACKCHANNEL_LOGOUT_EVENT: {}},
        )
        config = TokenValidationConfig(
            perform_disco=True,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER],
        )

        with pytest.raises(InvalidIssuerException):
            await _validate_logout_token(api, token, config)


class TestDecodeWithConfig:
    def test_discovery_issuer_is_checked_unless_the_caller_opts_in(self, keypair):
        """The default keeps the ID Token rule: the discovery issuer, exactly."""
        key_dict, _ = keypair
        token = _token(keypair, iss=SESSION_ISSUER)
        config = _config(key=key_dict, token_issuers=[DISCOVERY_ISSUER, SESSION_ISSUER])

        with pytest.raises(InvalidIssuerException):
            decode_with_config(token, config, DISCOVERY_ISSUER)

        claims = decode_with_config(
            token, config, DISCOVERY_ISSUER, accept_token_issuers=True
        )
        assert claims["iss"] == SESSION_ISSUER

    def test_without_a_discovery_issuer_the_configured_issuer_is_checked(self, keypair):
        key_dict, _ = keypair
        config = _config(
            key=key_dict, issuer=[SESSION_ISSUER], token_issuers=[DISCOVERY_ISSUER]
        )

        claims = decode_with_config(
            _token(keypair, iss=SESSION_ISSUER), config, accept_token_issuers=True
        )
        assert claims["iss"] == SESSION_ISSUER

        with pytest.raises(InvalidIssuerException):
            decode_with_config(
                _token(keypair, iss=DISCOVERY_ISSUER),
                config,
                accept_token_issuers=True,
            )

    def test_empty_list_is_a_configuration_error(self, keypair):
        key_dict, _ = keypair
        config = _config(key=key_dict, token_issuers=[])

        with pytest.raises(ConfigurationException):
            decode_with_config(
                _token(keypair, iss=DISCOVERY_ISSUER),
                config,
                DISCOVERY_ISSUER,
                accept_token_issuers=True,
            )
