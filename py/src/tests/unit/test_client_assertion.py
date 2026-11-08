"""Unit tests for private_key_jwt client authentication (RFC 7523)."""

import time
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    DeviceAuthorizationRequest,
    DeviceTokenRequest,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    TokenExchangeRequest,
    TokenIntrospectionRequest,
    TokenRevocationRequest,
    request_authorization_code_token,
    request_client_credentials_token,
)
from py_identity_model.aio import (
    request_client_credentials_token as async_request_client_credentials_token,
)
from py_identity_model.core.client_assertion import (
    apply_private_key_jwt,
    build_client_assertion,
)
from py_identity_model.core.device_auth_logic import (
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
)
from py_identity_model.core.introspection_logic import (
    prepare_introspection_request_data,
)
from py_identity_model.core.par_logic import prepare_par_request_data
from py_identity_model.core.revocation_logic import prepare_revocation_request_data
from py_identity_model.core.token_client_logic import (
    prepare_auth_code_token_request_data,
    prepare_refresh_token_request_data,
    prepare_token_request_data,
)
from py_identity_model.core.token_exchange_logic import (
    prepare_token_exchange_request_data,
)


UUID_STRING_LENGTH = 36
ISSUER = "https://as.example.com"
JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _ec_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) for an ES256 key."""
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def _rsa_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) for a PS256/RS256 key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


@pytest.mark.unit
class TestBuildClientAssertion:
    def test_claims_ec256(self):
        private_pem, _ = _ec_keypair()
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=private_pem,
            algorithm="ES256",
            lifetime=120,
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "my-client"
        assert decoded["sub"] == "my-client"
        assert decoded["aud"] == "https://as.example.com/token"
        assert len(decoded["jti"]) == UUID_STRING_LENGTH
        assert isinstance(decoded["iat"], int)
        assert decoded["exp"] == decoded["iat"] + 120

    def test_iat_nbf_backdated_for_clock_skew(self):
        # iat/nbf are backdated a few seconds so an AS clock running slightly
        # ahead does not reject a freshly minted assertion as not-yet-valid.
        before = int(time.time())
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=_ec_keypair()[0],
            algorithm="ES256",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["nbf"] == decoded["iat"]
        # iat must be at or before "now" (never in the future).
        assert decoded["iat"] <= before

    def test_signature_verifies_ps256(self):
        private_pem, public_pem = _rsa_keypair()
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=private_pem,
            algorithm="PS256",
        )
        # Round-trips with the public key — proves a valid signature.
        decoded = pyjwt.decode(
            token,
            public_pem,
            algorithms=["PS256"],
            audience="https://as.example.com/token",
        )
        assert decoded["iss"] == "my-client"

    def test_signature_verifies_es256(self):
        private_pem, public_pem = _ec_keypair()
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=private_pem,
            algorithm="ES256",
        )
        decoded = pyjwt.decode(
            token,
            public_pem,
            algorithms=["ES256"],
            audience="https://as.example.com/token",
        )
        assert decoded["sub"] == "my-client"

    def test_signature_verifies_rs256(self):
        # RS256 is in SUPPORTED_SIGNING_ALGORITHMS; exercise it explicitly so
        # the non-FAPI2 algorithm is not left unverified (issue #213 asks for
        # RS256 + ES256 coverage).
        private_pem, public_pem = _rsa_keypair()
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=private_pem,
            algorithm="RS256",
        )
        decoded = pyjwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            audience="https://as.example.com/token",
        )
        assert decoded["sub"] == "my-client"

    def test_kid_header_included_when_provided(self):
        private_pem, _ = _ec_keypair()
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=private_pem,
            algorithm="ES256",
            kid="key-1",
        )
        assert pyjwt.get_unverified_header(token)["kid"] == "key-1"

    def test_kid_header_absent_by_default(self):
        private_pem, _ = _ec_keypair()
        token = build_client_assertion(
            client_id="my-client",
            audience="https://as.example.com/token",
            private_key=private_pem,
            algorithm="ES256",
        )
        assert "kid" not in pyjwt.get_unverified_header(token)

    @pytest.mark.parametrize("algorithm", ["HS256", "none", "RS1"])
    def test_unsupported_algorithm_raises(self, algorithm):
        private_pem, _ = _ec_keypair()
        with pytest.raises(ValueError, match="Unsupported client assertion algorithm"):
            build_client_assertion(
                client_id="my-client",
                audience="https://as.example.com/token",
                private_key=private_pem,
                algorithm=algorithm,
            )

    @pytest.mark.parametrize(
        ("client_id", "audience"),
        [("", "https://as.example.com"), ("my-client", "")],
    )
    def test_empty_required_params_raise(self, client_id, audience):
        private_pem, _ = _ec_keypair()
        with pytest.raises(ValueError, match="must not be empty"):
            build_client_assertion(
                client_id=client_id,
                audience=audience,
                private_key=private_pem,
                algorithm="ES256",
            )

    def test_empty_private_key_raises(self):
        with pytest.raises(ValueError, match="private_key must not be empty"):
            build_client_assertion(
                client_id="my-client",
                audience="https://as.example.com",
                private_key="",
                algorithm="ES256",
            )

    @pytest.mark.parametrize("lifetime", [0, -30, 1, 10])
    def test_lifetime_at_or_below_clock_skew_leeway_raises(self, lifetime):
        # A lifetime <= the clock-skew leeway would mint an already-expired
        # assertion (exp = (now - leeway) + lifetime <= now).
        private_pem, _ = _ec_keypair()
        with pytest.raises(ValueError, match="clock-skew leeway"):
            build_client_assertion(
                client_id="my-client",
                audience="https://as.example.com",
                private_key=private_pem,
                algorithm="ES256",
                lifetime=lifetime,
            )

    @pytest.mark.parametrize("value", [" ", "\t", "\n  "])
    def test_whitespace_only_client_id_raises(self, value):
        private_pem, _ = _ec_keypair()
        with pytest.raises(ValueError, match="client_id must not be empty"):
            build_client_assertion(
                client_id=value,
                audience="https://as.example.com",
                private_key=private_pem,
                algorithm="ES256",
            )

    def test_whitespace_only_kid_raises(self):
        private_pem, _ = _ec_keypair()
        with pytest.raises(ValueError, match="kid must be non-empty"):
            build_client_assertion(
                client_id="my-client",
                audience="https://as.example.com",
                private_key=private_pem,
                algorithm="ES256",
                kid="  ",
            )

    def test_jti_unique_across_builds(self):
        private_pem, _ = _ec_keypair()
        kwargs = {
            "client_id": "my-client",
            "audience": "https://as.example.com",
            "private_key": private_pem,
            "algorithm": "ES256",
        }
        first = pyjwt.decode(
            build_client_assertion(**kwargs), options={"verify_signature": False}
        )
        second = pyjwt.decode(
            build_client_assertion(**kwargs), options={"verify_signature": False}
        )
        assert first["jti"] != second["jti"]


@pytest.mark.unit
class TestPrivateKeyJwtRepr:
    """The PEM signing key must never surface in repr/str output."""

    def test_repr_does_not_leak_private_key(self):
        private_pem, _ = _ec_keypair()
        config = PrivateKeyJwt(private_key=private_pem, algorithm="ES256", kid="k1")
        rendered = repr(config)
        assert "BEGIN" not in rendered
        assert "PRIVATE KEY" not in rendered
        if isinstance(private_pem, str):
            assert private_pem not in rendered
        # Non-secret fields remain visible for debuggability.
        assert "ES256" in rendered
        assert "k1" in rendered

    def test_repr_of_request_holding_config_does_not_leak(self):
        private_pem, _ = _ec_keypair()
        request = ClientCredentialsTokenRequest(
            address="https://as.example.com/token",
            client_id="my-client",
            private_key_jwt=PrivateKeyJwt(private_key=private_pem, algorithm="ES256"),
        )
        assert "BEGIN" not in repr(request)


@pytest.mark.unit
class TestApplyPrivateKeyJwt:
    def test_injects_assertion_params(self):
        private_pem, _ = _ec_keypair()
        params: dict[str, str] = {"grant_type": "client_credentials"}
        apply_private_key_jwt(
            params,
            PrivateKeyJwt(private_key=private_pem, algorithm="ES256"),
            client_id="my-client",
            default_audience="https://as.example.com/token",
        )
        assert params["client_id"] == "my-client"
        assert params["client_assertion_type"] == JWT_BEARER_ASSERTION_TYPE
        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["iss"] == "my-client"

    def test_audience_defaults_to_address(self):
        private_pem, _ = _ec_keypair()
        params: dict[str, str] = {}
        apply_private_key_jwt(
            params,
            PrivateKeyJwt(private_key=private_pem, algorithm="ES256"),
            client_id="my-client",
            default_audience="https://as.example.com/token",
        )
        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["aud"] == "https://as.example.com/token"

    def test_audience_override(self):
        private_pem, _ = _ec_keypair()
        params: dict[str, str] = {}
        apply_private_key_jwt(
            params,
            PrivateKeyJwt(
                private_key=private_pem,
                algorithm="ES256",
                audience="https://issuer.example.com",
            ),
            client_id="my-client",
            default_audience="https://as.example.com/token",
        )
        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["aud"] == "https://issuer.example.com"

    def test_audience_defaults_to_issuer_when_known(self):
        # FAPI 2.0 Security Profile §5.3.3.1: the client sends the issuer
        # identifier as aud, so a known issuer beats the endpoint URL.
        private_pem, _ = _ec_keypair()
        params: dict[str, str] = {}
        apply_private_key_jwt(
            params,
            PrivateKeyJwt(private_key=private_pem, algorithm="ES256", issuer=ISSUER),
            client_id="my-client",
            default_audience="https://as.example.com/token",
        )
        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["aud"] == ISSUER

    def test_explicit_audience_beats_issuer(self):
        private_pem, _ = _ec_keypair()
        params: dict[str, str] = {}
        apply_private_key_jwt(
            params,
            PrivateKeyJwt(
                private_key=private_pem,
                algorithm="ES256",
                audience="https://override.example.com",
                issuer=ISSUER,
            ),
            client_id="my-client",
            default_audience="https://as.example.com/token",
        )
        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["aud"] == "https://override.example.com"

    @pytest.mark.parametrize("field", ["audience", "issuer"])
    @pytest.mark.parametrize(
        "value",
        [[ISSUER], (ISSUER,), b"https://as.example.com"],
        ids=["list", "tuple", "bytes"],
    )
    def test_aud_is_a_single_string(self, field, value):
        # The assertion aud is one string, never an array (FAPI 2.0 SP §5.3.3.1).
        private_pem, _ = _ec_keypair()
        config = PrivateKeyJwt(
            private_key=private_pem, algorithm="ES256", **{field: value}
        )
        params: dict[str, str] = {}

        with pytest.raises(ValueError, match=f"{field} must be a string"):
            apply_private_key_jwt(
                params,
                config,
                client_id="my-client",
                default_audience="https://as.example.com/token",
            )
        assert params == {}


# Every client-authenticating endpoint and its prepare function. Each tuple is
# (label, prepare_fn, request_obj) for every client-authenticating endpoint.
# Each request carries a client_secret; the precedence tests add a
# private_key_jwt on top to assert the assertion wins.
ADDR = "https://as.example.com/endpoint"


def _prepare_cases():
    return [
        (
            "client_credentials",
            prepare_token_request_data,
            ClientCredentialsTokenRequest(
                address=ADDR, client_id="c", client_secret="s", scope="api"
            ),
        ),
        (
            "auth_code",
            prepare_auth_code_token_request_data,
            AuthorizationCodeTokenRequest(
                address=ADDR,
                client_id="c",
                code="abc",
                redirect_uri="https://app/cb",
                client_secret="s",
            ),
        ),
        (
            "refresh",
            prepare_refresh_token_request_data,
            RefreshTokenRequest(
                address=ADDR, client_id="c", refresh_token="rt", client_secret="s"
            ),
        ),
        (
            "introspection",
            prepare_introspection_request_data,
            TokenIntrospectionRequest(
                address=ADDR, token="t", client_id="c", client_secret="s"
            ),
        ),
        (
            "revocation",
            prepare_revocation_request_data,
            TokenRevocationRequest(
                address=ADDR, token="t", client_id="c", client_secret="s"
            ),
        ),
        (
            "par",
            prepare_par_request_data,
            PushedAuthorizationRequest(
                address=ADDR,
                client_id="c",
                redirect_uri="https://app/cb",
                client_secret="s",
            ),
        ),
        (
            "device_auth",
            prepare_device_auth_request_data,
            DeviceAuthorizationRequest(address=ADDR, client_id="c", client_secret="s"),
        ),
        (
            "device_token",
            prepare_device_token_request_data,
            DeviceTokenRequest(
                address=ADDR, client_id="c", device_code="dc", client_secret="s"
            ),
        ),
        (
            "token_exchange",
            prepare_token_exchange_request_data,
            TokenExchangeRequest(
                address=ADDR,
                client_id="c",
                subject_token="st",
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                client_secret="s",
            ),
        ),
    ]


@pytest.mark.unit
class TestPrepareFunctionPrecedence:
    @pytest.mark.parametrize(
        ("label", "prepare_fn", "request_obj"),
        _prepare_cases(),
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_private_key_jwt_takes_precedence_over_secret(
        self, label, prepare_fn, request_obj
    ):
        # Both client_secret and private_key_jwt set — assertion must win.
        private_pem, _ = _ec_keypair()
        request_obj.private_key_jwt = PrivateKeyJwt(
            private_key=private_pem, algorithm="ES256"
        )
        params, _headers, auth = prepare_fn(request_obj)

        # No HTTP Basic auth when using private_key_jwt.
        assert auth is None, label
        # Assertion carried in the body.
        assert params["client_assertion_type"] == JWT_BEARER_ASSERTION_TYPE, label
        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["sub"] == "c", label
        assert decoded["aud"] == ADDR, label

    @pytest.mark.parametrize(
        ("label", "prepare_fn", "request_obj"),
        _prepare_cases(),
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_assertion_aud_is_the_issuer_at_every_endpoint(
        self, label, prepare_fn, request_obj
    ):
        # PAR, token, introspection, revocation, device and token exchange all
        # address the assertion to the issuer, not to their endpoint URL.
        private_pem, _ = _ec_keypair()
        request_obj.private_key_jwt = PrivateKeyJwt(
            private_key=private_pem, algorithm="ES256", issuer=ISSUER
        )
        params, _headers, _auth = prepare_fn(request_obj)

        decoded = pyjwt.decode(
            params["client_assertion"], options={"verify_signature": False}
        )
        assert decoded["aud"] == ISSUER, label

    @pytest.mark.parametrize(
        ("label", "prepare_fn", "request_obj"),
        _prepare_cases(),
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_client_secret_used_when_no_private_key_jwt(
        self, label, prepare_fn, request_obj
    ):
        # client_secret only — Basic auth, no assertion.
        params, _headers, auth = prepare_fn(request_obj)
        assert auth == ("c", "s"), label
        assert "client_assertion" not in params, label


@pytest.mark.unit
class TestEndToEndNoBasicHeader:
    @respx.mock
    def test_sync_client_credentials_sends_assertion_no_basic(self):
        private_pem, public_pem = _rsa_keypair()
        route = respx.post(ADDR).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = ClientCredentialsTokenRequest(
            address=ADDR,
            client_id="c",
            scope="api",
            private_key_jwt=PrivateKeyJwt(private_key=private_pem, algorithm="PS256"),
        )
        response = request_client_credentials_token(request)
        assert response.is_successful

        sent = route.calls.last.request
        # No HTTP Basic Authorization header.
        assert sent.headers.get("authorization") is None
        body = parse_qs(sent.content.decode())
        assert body["client_assertion_type"] == [JWT_BEARER_ASSERTION_TYPE]
        # Assertion verifies against the public key.
        decoded = pyjwt.decode(
            body["client_assertion"][0],
            public_pem,
            algorithms=["PS256"],
            audience=ADDR,
        )
        assert decoded["iss"] == "c"

    @respx.mock
    async def test_async_client_credentials_sends_assertion_no_basic(self):
        private_pem, _ = _ec_keypair()
        route = respx.post(ADDR).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = ClientCredentialsTokenRequest(
            address=ADDR,
            client_id="c",
            scope="api",
            private_key_jwt=PrivateKeyJwt(private_key=private_pem, algorithm="ES256"),
        )
        response = await async_request_client_credentials_token(request)
        assert response.is_successful

        sent = route.calls.last.request
        assert sent.headers.get("authorization") is None
        body = parse_qs(sent.content.decode())
        assert body["client_assertion_type"] == [JWT_BEARER_ASSERTION_TYPE]

    @respx.mock
    def test_sync_auth_code_sends_assertion_no_basic(self):
        private_pem, _ = _ec_keypair()
        route = respx.post(ADDR).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = AuthorizationCodeTokenRequest(
            address=ADDR,
            client_id="c",
            code="abc",
            redirect_uri="https://app/cb",
            private_key_jwt=PrivateKeyJwt(private_key=private_pem, algorithm="ES256"),
        )
        response = request_authorization_code_token(request)
        assert response.is_successful

        sent = route.calls.last.request
        assert sent.headers.get("authorization") is None
        body = parse_qs(sent.content.decode())
        assert "client_assertion" in body
        assert body["client_id"] == ["c"]


@pytest.mark.unit
class TestSigningFailureReturnsErrorResponse:
    """A malformed signing key must yield a structured error response.

    ``build_client_assertion`` runs inside the wrapper's ``try`` block, so a
    ``pyjwt.encode`` failure on a bad PEM is routed through the endpoint's
    error handler instead of propagating uncaught to the caller.
    """

    _BAD_KEY = PrivateKeyJwt(private_key="not-a-pem", algorithm="PS256")

    def test_sync_client_credentials_bad_key_returns_error(self):
        request = ClientCredentialsTokenRequest(
            address=ADDR, client_id="c", scope="api", private_key_jwt=self._BAD_KEY
        )
        response = request_client_credentials_token(request)
        assert response.is_successful is False
        assert response.error

    async def test_async_client_credentials_bad_key_returns_error(self):
        request = ClientCredentialsTokenRequest(
            address=ADDR, client_id="c", scope="api", private_key_jwt=self._BAD_KEY
        )
        response = await async_request_client_credentials_token(request)
        assert response.is_successful is False
        assert response.error
