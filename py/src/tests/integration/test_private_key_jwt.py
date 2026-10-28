"""Integration tests for ``private_key_jwt`` client authentication.

Exercises RFC 7523 / OpenID Connect Core 1.0 Section 9 client authentication
against a live OIDC provider.  The library signs a ``client_assertion`` with
the client's private key; the provider verifies it against the public JWK
registered for the client.

These tests are specific to the bundled node-oidc-provider fixture, which
registers a ``test-private-key-jwt`` client whose public key matches the
static private key embedded below.  They are skipped against any other
provider (remote providers in the CI matrix do not register this client).
"""

import base64
import secrets
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    create_request_object,
    generate_dpop_key,
    generate_pkce_pair,
    push_authorization_request,
    request_client_credentials_token,
)
from py_identity_model.aio import (
    request_client_credentials_token as async_request_client_credentials_token,
)

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


# Client registered in the node-oidc-provider fixture (provider.js).
PKJWT_CLIENT_ID = "test-private-key-jwt"
PKJWT_REDIRECT_URI = "http://localhost:8080/callback"
PKJWT_ALGORITHM = "ES256"
PKJWT_KID = "pkjwt-client-key"

# Static ES256 (P-256) private key. The matching public JWK is registered
# for ``test-private-key-jwt`` in the node-oidc-provider fixture. Test-only
# key — never use a checked-in key outside of a disposable test fixture.
PKJWT_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8WGr0RG4Zo7/WD6g
uOCH355J2/auzrggNZRPhCSxQfGhRANCAATbM7xgqsqkG4DJUQPYKHBlgV/OS3nZ
E2+SampTwVolT/BEG7coOzdYem3Yr2FkBicTXhqWNGiG7RWkD+d/rVhW
-----END PRIVATE KEY-----
"""

# Public JWK coordinates registered for ``test-private-key-jwt`` in
# ``infra/node-oidc-provider/provider.js``. The self-check below pins
# the coupling so a key/JWK mismatch fails loudly instead of surfacing as an
# opaque signature error (or a silent skip) during the live tests.
PKJWT_REGISTERED_JWK_X = "2zO8YKrKpBuAyVED2ChwZYFfzkt52RNvkmpqU8FaJU8"
PKJWT_REGISTERED_JWK_Y = "8EQbtyg7N1h6bdivYWQGJxNeGpY0aIbtFaQP53-tWFY"


def _b64url_uint(value: int) -> str:
    """Encode a P-256 coordinate as an unpadded base64url string (JWK form)."""
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()


@pytest.mark.unit
def test_static_private_key_matches_registered_jwk():
    """The checked-in private key's public half must equal the provider's JWK.

    Runs in the unit suite (no network) so a copy-paste drift between the
    private key here and the JWK in ``provider.js`` is caught immediately
    rather than as an opaque live-test signature failure.
    """
    public_key = load_pem_private_key(
        PKJWT_PRIVATE_KEY.encode(), password=None
    ).public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    public_numbers = public_key.public_numbers()
    assert _b64url_uint(public_numbers.x) == PKJWT_REGISTERED_JWK_X
    assert _b64url_uint(public_numbers.y) == PKJWT_REGISTERED_JWK_Y


def _is_node_oidc_fixture(raw_discovery: dict) -> bool:
    """Whether the active provider is the local private_key_jwt fixture.

    The static key only matches the ``test-private-key-jwt`` client in the
    bundled node-oidc-provider fixture, which runs on localhost, serves
    discovery at the host root, and advertises ``private_key_jwt`` support.

    The host-root check is what distinguishes node-oidc from other local
    providers: Keycloak also runs on localhost and advertises
    ``private_key_jwt``, but serves discovery under ``/realms/<realm>`` and
    does not register the static test client — so it must skip these tests.
    """
    issuer = raw_discovery.get("issuer", "")
    methods = raw_discovery.get("token_endpoint_auth_methods_supported", [])
    parsed = urlparse(issuer)
    is_local = parsed.hostname in ("localhost", "127.0.0.1")
    at_host_root = parsed.path in ("", "/")
    return is_local and at_host_root and "private_key_jwt" in methods


def _require_node_oidc(raw_discovery: dict) -> None:
    if not _is_node_oidc_fixture(raw_discovery):
        pytest.skip(
            "private_key_jwt fixture client only registered in node-oidc-provider"
        )


def _private_key_jwt(audience: str | None = None) -> PrivateKeyJwt:
    return PrivateKeyJwt(
        private_key=PKJWT_PRIVATE_KEY,
        algorithm=PKJWT_ALGORITHM,
        kid=PKJWT_KID,
        audience=audience,
    )


@pytest.mark.integration
class TestPrivateKeyJwtLive:
    """private_key_jwt client authentication against a live provider."""

    def test_client_credentials_with_private_key_jwt(
        self,
        raw_discovery,
        token_endpoint,
    ):
        """Token endpoint authenticates the client via a signed assertion.

        No ``client_secret`` is supplied — the provider must accept solely on
        the strength of the verified ``client_assertion``.
        """
        _require_node_oidc(raw_discovery)

        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=PKJWT_CLIENT_ID,
                scope="api",
                private_key_jwt=_private_key_jwt(),
            )
        )

        assert response.is_successful is True, (
            f"private_key_jwt client_credentials failed: {response.error}"
        )
        assert response.token is not None
        assert response.token.get("access_token")
        assert response.token.get("token_type", "").lower() == "bearer"

    def test_client_credentials_wrong_key_rejected(
        self,
        raw_discovery,
        token_endpoint,
    ):
        """A mismatched signing key is rejected — proves real verification.

        A freshly generated key does not match the client's registered public
        JWK, so the assertion signature must fail verification at the provider.
        """
        _require_node_oidc(raw_discovery)

        wrong_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=PKJWT_CLIENT_ID,
                scope="api",
                private_key_jwt=PrivateKeyJwt(
                    private_key=wrong_key,
                    algorithm=PKJWT_ALGORITHM,
                    kid=PKJWT_KID,
                ),
            )
        )

        assert response.is_successful is False
        assert response.error is not None

    def test_par_with_private_key_jwt(
        self,
        provider_capabilities,
        raw_discovery,
    ):
        """PAR endpoint authenticates the client via a signed assertion."""
        _require_node_oidc(raw_discovery)
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        endpoint = raw_discovery["pushed_authorization_request_endpoint"]
        _verifier, challenge = generate_pkce_pair()

        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=endpoint,
                client_id=PKJWT_CLIENT_ID,
                redirect_uri=PKJWT_REDIRECT_URI,
                scope="openid",
                code_challenge=challenge,
                code_challenge_method="S256",
                state=secrets.token_urlsafe(32),
                private_key_jwt=_private_key_jwt(),
            )
        )

        assert response.is_successful is True, f"PAR failed: {response.error}"
        assert response.request_uri is not None
        assert response.request_uri.startswith("urn:ietf:params:oauth:request_uri:")
        assert response.expires_in is not None
        assert response.expires_in > 0

    def _signed_par(
        self, raw_discovery: dict, signing_key: str
    ) -> PushedAuthorizationRequest:
        _verifier, challenge = generate_pkce_pair()
        request_object = create_request_object(
            private_key=signing_key,
            algorithm=PKJWT_ALGORITHM,
            kid=PKJWT_KID,
            client_id=PKJWT_CLIENT_ID,
            audience=raw_discovery["issuer"],
            redirect_uri=PKJWT_REDIRECT_URI,
            state=secrets.token_urlsafe(32),
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        return PushedAuthorizationRequest(
            address=raw_discovery["pushed_authorization_request_endpoint"],
            client_id=PKJWT_CLIENT_ID,
            request=request_object,
            private_key_jwt=_private_key_jwt(),
        )

    def test_par_with_signed_request_object(
        self,
        provider_capabilities,
        raw_discovery,
    ):
        """PAR accepts the authorization request as a signed request object.

        RFC 9126 §3: the form carries only ``request`` and client
        authentication; the provider verifies the JWT with the client's
        registered key.
        """
        _require_node_oidc(raw_discovery)
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        response = push_authorization_request(
            self._signed_par(raw_discovery, PKJWT_PRIVATE_KEY)
        )

        assert response.is_successful is True, f"PAR failed: {response.error}"
        assert response.request_uri is not None
        assert response.request_uri.startswith("urn:ietf:params:oauth:request_uri:")

    def test_par_with_request_object_signed_by_other_key_rejected(
        self,
        provider_capabilities,
        raw_discovery,
    ):
        """A request object the client's registered key did not sign is refused."""
        _require_node_oidc(raw_discovery)
        if "par" not in provider_capabilities:
            pytest.skip("Provider does not support PAR")

        response = push_authorization_request(
            self._signed_par(
                raw_discovery, generate_dpop_key("ES256").private_key_pem.decode()
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "invalid_request_object" in response.error

    def test_authorization_code_with_private_key_jwt(
        self,
        provider_capabilities,
        raw_discovery,
        discovery_document,
    ):
        """Full auth-code flow exchanges the code with a signed assertion.

        Drives the devInteractions login/consent to obtain a code, then
        authenticates the token request with ``private_key_jwt`` (no secret).
        """
        _require_node_oidc(raw_discovery)
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support automated auth code flow")

        result = perform_auth_code_flow(
            discovery=discovery_document,
            client_id=PKJWT_CLIENT_ID,
            redirect_uri=PKJWT_REDIRECT_URI,
            config=AuthCodeFlowConfig(
                scope="openid profile email offline_access",
                resource="urn:test:api",
                private_key_jwt=_private_key_jwt(),
            ),
        )

        token_response = result["token_response"]
        assert token_response.is_successful is True, (
            f"auth-code private_key_jwt token exchange failed: {token_response.error}"
        )
        assert token_response.token is not None
        assert token_response.token.get("access_token")


@pytest.mark.integration
class TestPrivateKeyJwtLiveAsync:
    """private_key_jwt via the async API against a live provider.

    Issue #213 requires both sync and async paths to be exercised against a
    real provider; the async client-authentication logic is shared with the
    sync path via ``core/`` but the aio wrapper wiring is covered here.
    """

    async def test_client_credentials_with_private_key_jwt(
        self,
        raw_discovery,
        token_endpoint,
    ):
        _require_node_oidc(raw_discovery)

        response = await async_request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=PKJWT_CLIENT_ID,
                scope="api",
                private_key_jwt=_private_key_jwt(),
            )
        )

        assert response.is_successful is True, (
            f"async private_key_jwt client_credentials failed: {response.error}"
        )
        assert response.token is not None
        assert response.token.get("access_token")
        assert response.token.get("token_type", "").lower() == "bearer"

    async def test_client_credentials_wrong_key_rejected(
        self,
        raw_discovery,
        token_endpoint,
    ):
        _require_node_oidc(raw_discovery)

        wrong_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

        response = await async_request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=PKJWT_CLIENT_ID,
                scope="api",
                private_key_jwt=PrivateKeyJwt(
                    private_key=wrong_key,
                    algorithm=PKJWT_ALGORITHM,
                    kid=PKJWT_KID,
                ),
            )
        )

        assert response.is_successful is False
        assert response.error is not None
