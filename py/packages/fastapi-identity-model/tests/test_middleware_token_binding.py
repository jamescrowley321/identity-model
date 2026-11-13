"""Sender-constrained tokens through the FastAPI middleware and WebSocket auth (#1021).

The middleware and ``build_ws_authenticator`` hand ``validate_token`` a
``TokenPresentation`` for every request. ``validate_token`` is replaced by the real async validator run against
a static key instead of discovery, so the signature, claims and binding checks
(RFC 9449 §7.1, RFC 8705 §3) all run for real; only the key fetch is skipped.
"""

from base64 import urlsafe_b64encode
import copy
import dataclasses
from dataclasses import FrozenInstanceError, replace
import datetime
import logging
import time
from types import SimpleNamespace
from urllib.parse import quote
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, WebSocketException, status
import httpx
import jwt as pyjwt
import pytest
from starlette.datastructures import URL as StarletteURL
from starlette.datastructures import Headers

from fastapi_identity_model import (
    AuthOptions,
    OIDCSettings,
    TokenValidationMiddleware,
    build_ws_authenticator,
    get_claims,
    require_scope,
    ws,
)
from fastapi_identity_model.config_helpers import oidc_settings_from_env
import fastapi_identity_model.middleware as mw
from py_identity_model import (
    ConfigurationException,
    DPoPErrorKind,
    DPoPReplayCheck,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenBinding,
    compute_certificate_thumbprint,
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.aio import validate_token as avalidate_token
from py_identity_model.core import process_local


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"
ISSUER = "https://op"
AUDIENCE = "urn:api"
URL = "http://testserver/me"
GENERIC_BODY = {"detail": "Invalid or unauthorized token"}
ALGS = " ".join(
    DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()).accepted_algorithms
)
INVALID_TOKEN_DPOP = f'DPoP error="invalid_token", algs="{ALGS}"'
INVALID_PROOF_DPOP = f'DPoP error="invalid_dpop_proof", algs="{ALGS}"'


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def public_jwk(signing_key) -> dict:
    numbers = signing_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8)),
        "e": _b64(numbers.e.to_bytes(3)),
    }


@pytest.fixture(scope="module")
def client_cert_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def token(signing_key):
    def _token(cnf: dict | None = None) -> str:
        claims: dict[str, object] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        }
        if cnf is not None:
            claims["cnf"] = cnf
        pem = signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return pyjwt.encode(claims, pem, algorithm="RS256")

    return _token


@pytest.fixture
def client(monkeypatch, public_jwk):
    """An ASGI client for an app built with the given middleware options."""

    async def _validate(*, jwt, token_validation_config, presentation, **_):
        config = replace(
            token_validation_config,
            perform_disco=False,
            key=public_jwk,
            algorithms=["RS256"],
            issuer=ISSUER,
        )
        return await avalidate_token(jwt, config, presentation=presentation)

    monkeypatch.setattr(mw, "validate_token", _validate)

    def _client(**options) -> httpx.AsyncClient:
        app = FastAPI()
        app.add_middleware(
            TokenValidationMiddleware,
            discovery_url=DISCOVERY_URL,
            audience=AUDIENCE,
            excluded_paths=[],
            options=AuthOptions(
                dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
                **options,
            ),
        )

        @app.get("/me")
        async def me(claims: dict = Depends(get_claims)):
            return {"sub": claims["sub"]}

        @app.get("/scoped", dependencies=[Depends(require_scope("files.read"))])
        async def scoped():
            return {}

        @app.get("/files/{name}", dependencies=[Depends(get_claims)])
        async def files(name: str):
            return {"name": name}

        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        )

    return _client


def _dpop_headers(access_token: str, key, *, url: str = URL) -> dict[str, str]:
    return {
        "Authorization": f"DPoP {access_token}",
        "DPoP": create_dpop_proof(key, "GET", url, access_token=access_token),
    }


def _rejected(resp: httpx.Response) -> tuple:
    return resp.status_code, resp.headers["WWW-Authenticate"], resp.json()


class TestDPoPBoundToken:
    async def test_valid_proof_accepted(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})

        async with client() as c:
            resp = await c.get("/me", headers=_dpop_headers(access_token, key))

        assert (resp.status_code, resp.json()) == (200, {"sub": "user"})

    async def test_scheme_is_case_insensitive(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(access_token, key)
        headers["Authorization"] = f"dpop {access_token}"

        async with client() as c:
            resp = await c.get("/me", headers=headers)

        assert resp.status_code == 200

    async def test_presented_as_bearer_rejected(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})

        async with client() as c:
            resp = await c.get(
                "/me", headers={"Authorization": f"Bearer {access_token}"}
            )

        assert _rejected(resp) == (
            401,
            INVALID_TOKEN_DPOP,
            GENERIC_BODY,
        )

    async def test_missing_proof_rejected(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})

        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": f"DPoP {access_token}"})

        assert _rejected(resp) == (
            401,
            INVALID_TOKEN_DPOP,
            GENERIC_BODY,
        )

    async def test_proof_from_other_key_rejected(self, client, token):
        bound = generate_dpop_key()
        access_token = token({"jkt": bound.jwk_thumbprint})

        async with client() as c:
            resp = await c.get(
                "/me", headers=_dpop_headers(access_token, generate_dpop_key())
            )

        assert _rejected(resp) == (
            401,
            INVALID_TOKEN_DPOP,
            GENERIC_BODY,
        )

    async def test_proof_for_other_uri_rejected(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(access_token, key, url="http://testserver/other")

        async with client() as c:
            resp = await c.get("/me", headers=headers)

        assert _rejected(resp) == (
            401,
            INVALID_PROOF_DPOP,
            GENERIC_BODY,
        )

    async def test_replayed_proof_rejected(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(access_token, key)

        async with client() as c:
            first = await c.get("/me", headers=headers)
            replay = await c.get("/me", headers=headers)

        assert (first.status_code, _rejected(replay)) == (
            200,
            (401, INVALID_PROOF_DPOP, GENERIC_BODY),
        )


class TestUnboundToken:
    async def test_bearer_accepted_by_default(self, client, token):
        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": f"Bearer {token()}"})

        assert (resp.status_code, resp.json()) == (200, {"sub": "user"})

    async def test_dpop_scheme_rejected(self, client, token):
        access_token = token()

        async with client() as c:
            resp = await c.get(
                "/me", headers=_dpop_headers(access_token, generate_dpop_key())
            )

        assert _rejected(resp) == (
            401,
            INVALID_TOKEN_DPOP,
            GENERIC_BODY,
        )

    async def test_bearer_rejected_when_dpop_required(self, client, token):
        async with client(required_binding=TokenBinding.DPOP) as c:
            resp = await c.get("/me", headers={"Authorization": f"Bearer {token()}"})

        assert _rejected(resp) == (
            401,
            INVALID_TOKEN_DPOP,
            GENERIC_BODY,
        )

    async def test_missing_header_challenges_dpop_when_required(self, client):
        async with client(required_binding=TokenBinding.DPOP) as c:
            resp = await c.get("/me")

        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (
            401,
            f'DPoP algs="{ALGS}"',
        )

    async def test_unknown_scheme_rejected(self, client, token):
        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": f"Basic {token()}"})

        # RFC 6750 §3.1: an unsupported scheme gets no error code, but §3
        # still needs an auth-param.
        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (
            401,
            'Bearer realm="api"',
        )


class TestChallenge:
    """RFC 6750 §3 / §3.1 and RFC 9449 §7.1 ``WWW-Authenticate`` challenges."""

    async def test_missing_header_has_a_realm_and_no_error(self, client):
        async with client() as c:
            resp = await c.get("/me")

        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (
            401,
            'Bearer realm="api"',
        )

    async def test_configured_realm(self, client, token):
        async with client(realm="files") as c:
            missing = await c.get("/me")
            invalid = await c.get("/me", headers={"Authorization": "Bearer x.y.z"})
            dpop = await c.get(
                "/me", headers=_dpop_headers(token(), generate_dpop_key())
            )

        assert [r.headers["WWW-Authenticate"] for r in (missing, invalid, dpop)] == [
            'Bearer realm="files"',
            'Bearer realm="files", error="invalid_token"',
            f'DPoP realm="files", error="invalid_token", algs="{ALGS}"',
        ]

    @pytest.mark.parametrize(
        ("authorization", "challenge"),
        [
            ("Bearer", 'Bearer error="invalid_request"'),
            ("Bearer a b", 'Bearer error="invalid_request"'),
            ("dpop a b", f'DPoP error="invalid_request", algs="{ALGS}"'),
        ],
    )
    async def test_malformed_credentials_are_invalid_request(
        self, client, authorization, challenge
    ):
        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": authorization})

        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (
            400,
            challenge,
        )

    async def test_invalid_bearer_token_is_invalid_token(self, client):
        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": "Bearer x.y.z"})

        assert _rejected(resp) == (
            401,
            'Bearer error="invalid_token"',
            GENERIC_BODY,
        )

    async def test_invalid_dpop_scheme_token_gets_a_dpop_challenge(self, client):
        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": "DPoP x.y.z"})

        assert _rejected(resp) == (401, INVALID_TOKEN_DPOP, GENERIC_BODY)

    async def test_id_token_is_invalid_token(self, client, signing_key):
        pem = signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        id_token = pyjwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "user",
                "nonce": "n",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
            },
            pem,
            algorithm="RS256",
        )
        async with client() as c:
            resp = await c.get("/me", headers={"Authorization": f"Bearer {id_token}"})

        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (
            401,
            'Bearer error="invalid_token"',
        )

    async def test_insufficient_scope_uses_the_request_scheme(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        async with client() as c:
            resp = await c.get(
                "/scoped",
                headers=_dpop_headers(
                    access_token, key, url="http://testserver/scoped"
                ),
            )

        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (
            403,
            f'DPoP error="insufficient_scope", scope="files.read", algs="{ALGS}"',
        )

    @pytest.mark.parametrize("realm", ["", 'a"b', "a\\b", "caf\u00e9", "a\r\nb"])
    def test_realm_must_need_no_escaping(self, realm):
        with pytest.raises(ConfigurationException):
            AuthOptions(realm=realm)


class TestCertificateBoundToken:
    async def test_without_certificate_rejected(self, client, token, client_cert_pem):
        thumbprint = compute_certificate_thumbprint(client_cert_pem)
        access_token = token({"x5t#S256": thumbprint})

        async with client() as c:
            resp = await c.get(
                "/me", headers={"Authorization": f"Bearer {access_token}"}
            )

        assert _rejected(resp) == (
            401,
            'Bearer error="invalid_token"',
            GENERIC_BODY,
        )

    async def test_matching_certificate_accepted(self, client, token, client_cert_pem):
        thumbprint = compute_certificate_thumbprint(client_cert_pem)
        access_token = token({"x5t#S256": thumbprint})

        async with client(client_certificate=lambda _request: client_cert_pem) as c:
            resp = await c.get(
                "/me", headers={"Authorization": f"Bearer {access_token}"}
            )

        assert (resp.status_code, resp.json()) == (200, {"sub": "user"})


class TestPercentEncodedPath:
    async def test_proof_for_encoded_path_accepted(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        url = "http://testserver/files/a%20b"

        async with client() as c:
            resp = await c.get(url, headers=_dpop_headers(access_token, key, url=url))

        assert (resp.status_code, resp.json()) == (200, {"name": "a b"})

    async def test_encoded_query_delimiter_is_part_of_the_path(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(access_token, key, url="http://testserver/files/public")

        async with client() as c:
            resp = await c.get("http://testserver/files/public%3Fx", headers=headers)

        assert _rejected(resp) == (401, INVALID_PROOF_DPOP, GENERIC_BODY)


class TestDuplicateProofHeader:
    async def test_two_dpop_headers_rejected(self, client, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        proof = create_dpop_proof(key, "GET", URL, access_token=access_token)
        headers = [
            ("Authorization", f"DPoP {access_token}"),
            ("DPoP", proof),
            ("DPoP", proof),
        ]

        async with client() as c:
            resp = await c.get("/me", headers=headers)

        assert _rejected(resp) == (401, INVALID_PROOF_DPOP, GENERIC_BODY)


WS_URL = "ws://testserver/ws"
WS_PROOF_URL = "http://testserver/ws"


@pytest.fixture
def ws_authenticate(monkeypatch, public_jwk):
    """A WebSocket authenticator whose ``validate_token`` runs for real."""

    async def _validate(*, jwt, token_validation_config, presentation, **_):
        config = replace(
            token_validation_config,
            perform_disco=False,
            key=public_jwk,
            algorithms=["RS256"],
            issuer=ISSUER,
        )
        return await avalidate_token(jwt, config, presentation=presentation)

    monkeypatch.setattr(ws, "validate_token", _validate)

    async def _authenticate(headers=(), query_params=None, raw_path=None, **options):
        auth = build_ws_authenticator(
            discovery_url=DISCOVERY_URL,
            audience=AUDIENCE,
            options=AuthOptions(
                dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
                **options,
            ),
        )
        sock = SimpleNamespace(
            headers=Headers(raw=[(k.lower().encode(), v.encode()) for k, v in headers]),
            query_params=query_params or {},
            url=StarletteURL(WS_URL),
            scope={"raw_path": raw_path} if raw_path else {},
            state=SimpleNamespace(),
        )
        return await auth(sock)

    return _authenticate


class TestWebSocket:
    async def test_dpop_bound_token_with_proof_accepted(self, ws_authenticate, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        proof = create_dpop_proof(key, "GET", WS_PROOF_URL, access_token=access_token)

        claims = await ws_authenticate(
            [("Authorization", f"DPoP {access_token}"), ("DPoP", proof)]
        )

        assert claims["cnf"] == {"jkt": key.jwk_thumbprint}

    async def test_proof_for_encoded_handshake_path_accepted(
        self, ws_authenticate, token
    ):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        proof = create_dpop_proof(
            key, "GET", "http://testserver/ws%20room", access_token=access_token
        )

        claims = await ws_authenticate(
            [("Authorization", f"DPoP {access_token}"), ("DPoP", proof)],
            raw_path=b"/ws%20room",
        )

        assert claims["cnf"] == {"jkt": key.jwk_thumbprint}

    async def test_dpop_bound_token_as_query_bearer_rejected(
        self, ws_authenticate, token
    ):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})

        with pytest.raises(WebSocketException) as exc:
            await ws_authenticate(query_params={"access_token": access_token})

        assert exc.value.code == status.WS_1008_POLICY_VIOLATION

    async def test_two_dpop_headers_rejected(self, ws_authenticate, token):
        key = generate_dpop_key()
        access_token = token({"jkt": key.jwk_thumbprint})
        proof = create_dpop_proof(key, "GET", WS_PROOF_URL, access_token=access_token)

        with pytest.raises(WebSocketException) as exc:
            await ws_authenticate(
                [
                    ("Authorization", f"DPoP {access_token}"),
                    ("DPoP", proof),
                    ("DPoP", proof),
                ]
            )

        assert exc.value.code == status.WS_1008_POLICY_VIOLATION

    async def test_unbound_bearer_rejected_when_dpop_required(
        self, ws_authenticate, token
    ):
        with pytest.raises(WebSocketException) as exc:
            await ws_authenticate(
                [("Authorization", f"Bearer {token()}")],
                required_binding=TokenBinding.DPOP,
            )

        assert exc.value.code == status.WS_1008_POLICY_VIOLATION


def _static_key_validator(public_jwk):
    async def _validate(*, jwt, token_validation_config, presentation, **_):
        config = replace(
            token_validation_config,
            perform_disco=False,
            key=public_jwk,
            algorithms=["RS256"],
            issuer=ISSUER,
        )
        return await avalidate_token(jwt, config, presentation=presentation)

    return _validate


@pytest.fixture
def raw_client(monkeypatch, public_jwk):
    """An ASGI client for an app whose middleware takes *kwargs* unchanged."""
    monkeypatch.setattr(mw, "validate_token", _static_key_validator(public_jwk))

    def _raw_client(**kwargs) -> httpx.AsyncClient:
        app = FastAPI()
        app.add_middleware(TokenValidationMiddleware, **kwargs)

        @app.get("/me")
        async def me(claims: dict = Depends(get_claims)):
            return {"sub": claims["sub"]}

        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        )

    return _raw_client


@pytest.fixture
def raw_ws_authenticate(monkeypatch, public_jwk):
    """Authenticate a handshake to *url* with ``build_ws_authenticator(**kwargs)``."""
    monkeypatch.setattr(ws, "validate_token", _static_key_validator(public_jwk))

    async def _authenticate(headers, *, url=WS_URL, **kwargs):
        auth = build_ws_authenticator(**kwargs)
        sock = SimpleNamespace(
            headers=Headers(raw=[(k.lower().encode(), v.encode()) for k, v in headers]),
            query_params={},
            url=StarletteURL(url),
            scope={},
            state=SimpleNamespace(),
        )
        return await auth(sock)

    return _authenticate


@pytest.fixture
def oidc_env(monkeypatch):
    for name in (
        "REQUIRED_BINDING",
        "CLIENT_CERTIFICATE_HEADER",
        "EXPECTED_ORIGIN",
        "AUDIENCE",
        "EXCLUDED_PATHS",
    ):
        monkeypatch.delenv(f"OIDC_{name}", raising=False)
    monkeypatch.setenv("OIDC_DISCOVERY_URL", DISCOVERY_URL)
    monkeypatch.setenv("OIDC_CLIENT_ID", AUDIENCE)
    return monkeypatch


class TestSettingsWiring:
    async def test_env_required_binding_dpop_reaches_middleware(
        self, raw_client, oidc_env, token
    ):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "dpop")
        settings = oidc_settings_from_env()
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})

        async with raw_client(settings=settings) as c:
            bearer = await c.get("/me", headers={"Authorization": f"Bearer {token()}"})
            dpop = await c.get("/me", headers=_dpop_headers(bound, key))

        assert (_rejected(bearer), dpop.status_code, dpop.json()) == (
            (401, INVALID_TOKEN_DPOP, GENERIC_BODY),
            200,
            {"sub": "user"},
        )

    async def test_env_required_binding_dpop_reaches_ws_authenticator(
        self, raw_ws_authenticate, oidc_env, token
    ):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "dpop")
        settings = oidc_settings_from_env()

        with pytest.raises(WebSocketException) as exc:
            await raw_ws_authenticate(
                [("Authorization", f"Bearer {token()}")], settings=settings
            )

        assert exc.value.code == status.WS_1008_POLICY_VIOLATION

    async def test_proof_from_ws_handshake_is_refused_over_http(
        self, raw_client, raw_ws_authenticate, oidc_env, token
    ):
        # Entry points given the same settings share one replay cache, so a
        # handshake proof (htm=GET) cannot be replayed on an HTTP GET.
        oidc_env.setenv("OIDC_EXPECTED_ORIGIN", "https://api.example.com")
        settings = oidc_settings_from_env()
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(bound, key, url="https://api.example.com/me")

        ws_claims = await raw_ws_authenticate(
            list(headers.items()), url="ws://testserver/me", settings=settings
        )
        async with raw_client(settings=settings) as c:
            replayed = await c.get("/me", headers=headers)

        assert (ws_claims["cnf"], _rejected(replayed)) == (
            {"jkt": key.jwk_thumbprint},
            (401, INVALID_PROOF_DPOP, GENERIC_BODY),
        )

    async def test_entry_points_without_options_share_a_replay_cache(
        self, raw_client, raw_ws_authenticate, token, caplog
    ):
        # Built separately with only discovery_url=: a handshake proof
        # (htm=GET) replayed on an HTTP GET is still refused.
        common = {"discovery_url": DISCOVERY_URL, "audience": AUDIENCE}
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(bound, key)

        ws_claims = await raw_ws_authenticate(
            list(headers.items()), url="ws://testserver/me", **common
        )
        with caplog.at_level(logging.INFO, logger=mw.logger.name):
            async with raw_client(**common) as c:
                replayed = await c.get("/me", headers=headers)

        assert (ws_claims["cnf"], _rejected(replayed)) == (
            {"jkt": key.jwk_thumbprint},
            (401, INVALID_PROOF_DPOP, GENERIC_BODY),
        )
        assert (
            f"DPoP binding rejected: {DPoPErrorKind.REPLAYED_JTI.value}"
            in caplog.messages
        )

    async def test_misconfigured_replay_cache_is_a_server_error(
        self, raw_client, raw_ws_authenticate, token
    ):
        # A cache answering True instead of a DPoPReplayCheck is the server's
        # fault: 500 / 1011, not a 401 that blames the client.
        class BoolCache:
            def check_and_store(self, *_args: object) -> bool:
                return True

        options = AuthOptions(dpop=DPoPVerificationOptions(replay_cache=BoolCache()))
        common = {"discovery_url": DISCOVERY_URL, "audience": AUDIENCE}
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})

        async with raw_client(options=options, **common) as c:
            http = await c.get("/me", headers=_dpop_headers(bound, key))
        with pytest.raises(WebSocketException) as ws_exc:
            await raw_ws_authenticate(
                list(_dpop_headers(bound, key).items()),
                url="ws://testserver/me",
                options=options,
                **common,
            )

        assert (http.status_code, http.json(), ws_exc.value.code) == (
            500,
            {"detail": "Internal server error during authentication"},
            status.WS_1011_INTERNAL_ERROR,
        )

    async def test_other_configuration_errors_stay_401(self, raw_client, monkeypatch):
        # Only an unusable replay cache is a 500; a ConfigurationException from
        # the provider's data keeps the generic 401.
        async def bad_discovery(*_args: object, **_kwargs: object) -> dict:
            raise ConfigurationException("Discovery document missing jwks_uri")

        monkeypatch.setattr(mw, "validate_token", bad_discovery)

        async with raw_client(discovery_url=DISCOVERY_URL, audience=AUDIENCE) as c:
            resp = await c.get("/me", headers={"Authorization": "Bearer t"})

        assert (resp.status_code, resp.json()) == (401, GENERIC_BODY)

    async def test_env_mtls_reads_certificate_header(
        self, raw_client, oidc_env, token, client_cert_pem
    ):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "mtls")
        oidc_env.setenv("OIDC_CLIENT_CERTIFICATE_HEADER", "X-Client-Cert")
        settings = oidc_settings_from_env()
        bound = token({"x5t#S256": compute_certificate_thumbprint(client_cert_pem)})
        escaped = quote(client_cert_pem.decode())

        async with raw_client(settings=settings) as c:
            with_cert = await c.get(
                "/me",
                headers={"Authorization": f"Bearer {bound}", "X-Client-Cert": escaped},
            )
            without_cert = await c.get(
                "/me", headers={"Authorization": f"Bearer {bound}"}
            )
            unbound = await c.get(
                "/me",
                headers={
                    "Authorization": f"Bearer {token()}",
                    "X-Client-Cert": escaped,
                },
            )

        assert (
            (with_cert.status_code, with_cert.json()),
            _rejected(without_cert),
            unbound.status_code,
        ) == (
            (200, {"sub": "user"}),
            (401, 'Bearer error="invalid_token"', GENERIC_BODY),
            401,
        )

    async def test_duplicate_certificate_header_refused(
        self, raw_client, oidc_env, token, client_cert_pem
    ):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "mtls")
        oidc_env.setenv("OIDC_CLIENT_CERTIFICATE_HEADER", "X-Client-Cert")
        settings = oidc_settings_from_env()
        bound = token({"x5t#S256": compute_certificate_thumbprint(client_cert_pem)})
        escaped = quote(client_cert_pem.decode())

        async with raw_client(settings=settings) as c:
            resp = await c.get(
                "/me",
                headers=[
                    ("Authorization", f"Bearer {bound}"),
                    ("X-Client-Cert", escaped),
                    ("X-Client-Cert", escaped),
                ],
            )

        assert _rejected(resp) == (401, 'Bearer error="invalid_token"', GENERIC_BODY)

    @pytest.mark.parametrize("folded", ["comma", "second_pem"])
    async def test_folded_certificate_header_refused(
        self, raw_client, oidc_env, token, client_cert_pem, folded
    ):
        # An intermediary may join repeated lines into one comma-separated
        # value (RFC 9110 §5.3); the client's copy comes first.
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "mtls")
        oidc_env.setenv("OIDC_CLIENT_CERTIFICATE_HEADER", "X-Client-Cert")
        settings = oidc_settings_from_env()
        bound = token({"x5t#S256": compute_certificate_thumbprint(client_cert_pem)})
        escaped = quote(client_cert_pem.decode())
        value = (
            f"{escaped}, {escaped}"
            if folded == "comma"
            else quote(client_cert_pem.decode() * 2)
        )

        async with raw_client(settings=settings) as c:
            resp = await c.get(
                "/me",
                headers=[
                    ("Authorization", f"Bearer {bound}"),
                    ("X-Client-Cert", value),
                ],
            )

        assert _rejected(resp) == (401, 'Bearer error="invalid_token"', GENERIC_BODY)

    def test_env_mtls_without_certificate_source_fails_at_construction(self, oidc_env):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "mtls")
        settings = oidc_settings_from_env()

        with pytest.raises(ValueError, match="client_certificate"):
            TokenValidationMiddleware(FastAPI(), settings=settings)
        with pytest.raises(ValueError, match="client_certificate"):
            build_ws_authenticator(settings=settings)

    def test_settings_supply_endpoint_audience_and_exclusions(self, oidc_env):
        oidc_env.setenv("OIDC_EXCLUDED_PATHS", "/live")
        settings = oidc_settings_from_env()

        middleware = TokenValidationMiddleware(FastAPI(), settings=settings)

        assert (
            middleware.discovery_url,
            middleware.audience,
            middleware.excluded_paths,
            middleware.options,
        ) == (DISCOVERY_URL, AUDIENCE, ["/live"], AuthOptions())

    @pytest.mark.usefixtures("oidc_env")
    def test_explicit_arguments_win_over_settings(self):
        settings = oidc_settings_from_env()

        middleware = TokenValidationMiddleware(
            FastAPI(),
            discovery_url="https://other/.well-known/openid-configuration",
            audience="urn:other",
            excluded_paths=[],
            settings=settings,
        )

        assert (
            middleware.discovery_url,
            middleware.audience,
            middleware.excluded_paths,
        ) == ("https://other/.well-known/openid-configuration", "urn:other", [])

    def test_discovery_url_required_without_settings(self):
        with pytest.raises(ValueError, match="discovery_url"):
            TokenValidationMiddleware(FastAPI(), audience=AUDIENCE)
        with pytest.raises(ValueError, match="discovery_url"):
            build_ws_authenticator(audience=AUDIENCE)

    def test_options_dropping_settings_binding_rejected(self, oidc_env):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "dpop")
        settings = oidc_settings_from_env()

        with pytest.raises(ValueError, match="required_binding"):
            TokenValidationMiddleware(
                FastAPI(), settings=settings, options=AuthOptions()
            )
        with pytest.raises(ValueError, match="required_binding"):
            build_ws_authenticator(settings=settings, options=AuthOptions())

    def test_options_dropping_settings_origin_rejected(self, oidc_env):
        oidc_env.setenv("OIDC_EXPECTED_ORIGIN", "https://api.example.com")
        settings = oidc_settings_from_env()

        with pytest.raises(ValueError, match="expected_origin"):
            TokenValidationMiddleware(
                FastAPI(), settings=settings, options=AuthOptions()
            )
        with pytest.raises(ValueError, match="expected_origin"):
            build_ws_authenticator(settings=settings, options=AuthOptions())

    def test_options_dropping_settings_certificate_header_rejected(self, oidc_env):
        oidc_env.setenv("OIDC_CLIENT_CERTIFICATE_HEADER", "X-Client-Cert")
        settings = oidc_settings_from_env()

        with pytest.raises(ValueError, match="client_certificate"):
            TokenValidationMiddleware(
                FastAPI(), settings=settings, options=AuthOptions()
            )
        with pytest.raises(ValueError, match="client_certificate"):
            build_ws_authenticator(settings=settings, options=AuthOptions())

    async def test_env_mtls_certificate_header_reaches_ws_authenticator(
        self, raw_ws_authenticate, oidc_env, token, client_cert_pem
    ):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "mtls")
        oidc_env.setenv("OIDC_CLIENT_CERTIFICATE_HEADER", "X-Client-Cert")
        settings = oidc_settings_from_env()
        bound = token({"x5t#S256": compute_certificate_thumbprint(client_cert_pem)})
        escaped = quote(client_cert_pem.decode())

        claims = await raw_ws_authenticate(
            [("Authorization", f"Bearer {bound}"), ("X-Client-Cert", escaped)],
            settings=settings,
        )
        with pytest.raises(WebSocketException) as exc:
            await raw_ws_authenticate(
                [("Authorization", f"Bearer {bound}")], settings=settings
            )

        assert (claims["sub"], exc.value.code) == (
            "user",
            status.WS_1008_POLICY_VIOLATION,
        )

    @pytest.mark.usefixtures("oidc_env")
    def test_stricter_options_than_settings_accepted(self):
        settings = oidc_settings_from_env()
        options = AuthOptions(required_binding=TokenBinding.DPOP)

        middleware = TokenValidationMiddleware(
            FastAPI(), settings=settings, options=options
        )

        assert middleware.options is options

    def test_from_settings_keeps_explicit_parts(self, oidc_env):
        oidc_env.setenv("OIDC_REQUIRED_BINDING", "mtls")
        oidc_env.setenv("OIDC_CLIENT_CERTIFICATE_HEADER", "X-Client-Cert")
        oidc_env.setenv("OIDC_EXPECTED_ORIGIN", "HTTPS://API.example.com:443/")
        settings = oidc_settings_from_env()
        dpop = DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())

        def certificate(_connection):
            return None

        options = AuthOptions.from_settings(
            settings, dpop=dpop, client_certificate=certificate
        )

        assert options == AuthOptions(
            required_binding=TokenBinding.MTLS,
            dpop=dpop,
            client_certificate=certificate,
            expected_origin="https://api.example.com",
        )


class TestSharedOptions:
    async def test_one_instance_configures_both_entry_points(
        self, raw_client, raw_ws_authenticate, token
    ):
        options = AuthOptions(
            required_binding=TokenBinding.DPOP,
            expected_origin="https://api.example.com",
        )
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        http_headers = _dpop_headers(bound, key, url="https://api.example.com/me")
        ws_proof = create_dpop_proof(
            key, "GET", "https://api.example.com/ws", access_token=bound
        )
        common = {"discovery_url": DISCOVERY_URL, "audience": AUDIENCE}

        async with raw_client(options=options, **common) as c:
            http_ok = await c.get("/me", headers=http_headers)
            http_bearer = await c.get(
                "/me", headers={"Authorization": f"Bearer {token()}"}
            )
        ws_claims = await raw_ws_authenticate(
            [("Authorization", f"DPoP {bound}"), ("DPoP", ws_proof)],
            options=options,
            **common,
        )
        with pytest.raises(WebSocketException) as ws_bearer:
            await raw_ws_authenticate(
                [("Authorization", f"Bearer {token()}")], options=options, **common
            )

        assert (
            http_ok.status_code,
            _rejected(http_bearer),
            ws_claims["cnf"],
            ws_bearer.value.code,
        ) == (
            200,
            (401, INVALID_TOKEN_DPOP, GENERIC_BODY),
            {"jkt": key.jwk_thumbprint},
            status.WS_1008_POLICY_VIOLATION,
        )

    @pytest.mark.usefixtures("oidc_env")
    def test_default_dpop_options_share_one_replay_cache(self):
        # Every entry point built without dpop= shares this process's cache;
        # explicit dpop= options keep their own.
        first, second = AuthOptions(), AuthOptions()
        from_settings = AuthOptions.from_settings(oidc_settings_from_env())
        explicit = AuthOptions(
            dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())
        )
        caches = [o.dpop.replay_cache for o in (first, second, from_settings)]

        assert [c is first.dpop.replay_cache for c in caches] == [True] * 3
        assert explicit.dpop.replay_cache is not first.dpop.replay_cache

    @pytest.mark.usefixtures("oidc_env")
    def test_copies_keep_the_replay_cache(self):
        settings = oidc_settings_from_env()
        options = AuthOptions.from_settings(settings)
        cache = options.dpop.replay_cache

        assert dataclasses.asdict(settings) == dataclasses.asdict(
            copy.deepcopy(settings)
        )
        assert [
            dataclasses.asdict(options)["dpop"]["replay_cache"] is cache,
            copy.deepcopy(options).dpop.replay_cache is cache,
        ] == [True, True]

    def test_options_built_before_a_fork_use_the_childs_cache(self, monkeypatch):
        # gunicorn --preload builds the WS authenticator in the parent and the
        # middleware in the worker; both must record into the worker's cache.
        before_fork = AuthOptions().dpop.replay_cache
        args = ("jkt", str(uuid.uuid4()), 2_000_000_000.0, 1_000_000_000.0)
        in_parent = before_fork.check_and_store(*args)
        monkeypatch.setattr(process_local.os, "getpid", lambda: -1)
        in_child = [before_fork.check_and_store(*args) for _ in range(2)]
        built_in_child = AuthOptions().dpop.replay_cache.check_and_store(*args)

        assert [in_parent, *in_child, built_in_child] == [
            DPoPReplayCheck.RECORDED,
            DPoPReplayCheck.RECORDED,
            DPoPReplayCheck.REPLAYED,
            DPoPReplayCheck.REPLAYED,
        ]

    def test_dpop_none_means_the_default(self):
        given = DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())
        defaulted = AuthOptions(dpop=None)  # type: ignore[arg-type]

        assert defaulted.dpop.replay_cache is AuthOptions().dpop.replay_cache
        assert AuthOptions(dpop=given).dpop is given

    def test_options_are_frozen(self):
        options = AuthOptions()
        field_name = "required_binding"

        with pytest.raises(FrozenInstanceError):
            setattr(options, field_name, TokenBinding.DPOP)

    def test_mtls_without_certificate_rejected(self):
        with pytest.raises(ValueError, match="client_certificate"):
            AuthOptions(required_binding=TokenBinding.MTLS)


class TestExpectedOrigin:
    async def test_proof_for_spoofed_host_accepted_without_origin(
        self, raw_client, token
    ):
        # Default behaviour: the origin comes from the Host header.
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(bound, key, url="http://evil.example/me")
        headers["Host"] = "evil.example"

        async with raw_client(discovery_url=DISCOVERY_URL, audience=AUDIENCE) as c:
            resp = await c.get("/me", headers=headers)

        assert (resp.status_code, resp.json()) == (200, {"sub": "user"})

    async def test_proof_for_spoofed_host_rejected_with_origin(self, raw_client, token):
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(bound, key, url="http://evil.example/me")
        headers["Host"] = "evil.example"
        options = AuthOptions(expected_origin="https://api.example.com")

        async with raw_client(
            discovery_url=DISCOVERY_URL, audience=AUDIENCE, options=options
        ) as c:
            resp = await c.get("/me", headers=headers)

        assert _rejected(resp) == (401, INVALID_PROOF_DPOP, GENERIC_BODY)

    async def test_proof_for_expected_origin_accepted_whatever_host(
        self, raw_client, token
    ):
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        headers = _dpop_headers(bound, key, url="https://api.example.com/me?x=1")
        options = AuthOptions(expected_origin="https://api.example.com")

        async with raw_client(
            discovery_url=DISCOVERY_URL, audience=AUDIENCE, options=options
        ) as c:
            resp = await c.get("/me?x=1", headers=headers)

        assert (resp.status_code, resp.json()) == (200, {"sub": "user"})

    async def test_proof_for_request_host_rejected_with_origin(self, raw_client, token):
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        options = AuthOptions(expected_origin="https://api.example.com")

        async with raw_client(
            discovery_url=DISCOVERY_URL, audience=AUDIENCE, options=options
        ) as c:
            resp = await c.get("/me", headers=_dpop_headers(bound, key))

        assert _rejected(resp) == (401, INVALID_PROOF_DPOP, GENERIC_BODY)

    async def test_ws_proof_for_handshake_host_rejected_with_origin(
        self, raw_ws_authenticate, token
    ):
        key = generate_dpop_key()
        bound = token({"jkt": key.jwk_thumbprint})
        proof = create_dpop_proof(key, "GET", WS_PROOF_URL, access_token=bound)

        with pytest.raises(WebSocketException) as exc:
            await raw_ws_authenticate(
                [("Authorization", f"DPoP {bound}"), ("DPoP", proof)],
                discovery_url=DISCOVERY_URL,
                audience=AUDIENCE,
                options=AuthOptions(expected_origin="https://api.example.com"),
            )

        assert exc.value.code == status.WS_1008_POLICY_VIOLATION

    @pytest.mark.parametrize(
        ("origin", "normalized"),
        [
            ("https://api.example.com", "https://api.example.com"),
            ("HTTPS://API.Example.com/", "https://api.example.com"),
            ("http://localhost:8000", "http://localhost:8000"),
            ("https://[::1]:8443", "https://[::1]:8443"),
            ("https://api.example.com:443", "https://api.example.com"),
            ("http://api.example.com:80", "http://api.example.com"),
            ("https://api.example.com:80", "https://api.example.com:80"),
            ("http://api.example.com:443", "http://api.example.com:443"),
            ("http://my_service:8080", "http://my_service:8080"),
        ],
    )
    def test_origin_is_normalized(self, origin, normalized):
        assert AuthOptions(expected_origin=origin).expected_origin == normalized

    def test_default_port_origins_do_not_conflict(self, oidc_env):
        oidc_env.setenv("OIDC_EXPECTED_ORIGIN", "https://api.example.com:443")
        settings = oidc_settings_from_env()

        TokenValidationMiddleware(
            FastAPI(),
            settings=settings,
            options=AuthOptions(expected_origin="https://api.example.com"),
        )

    @pytest.mark.parametrize(
        "origin",
        [
            "api.example.com",
            "ftp://api.example.com",
            "https://api.example.com/v1",
            "https://api.example.com?x=1",
            "https://api.example.com#f",
            "https://user@api.example.com",
            "https://api.example.com:notaport",
            "https://",
            "https://[::1",
            "https://bücher.example",
            "https://api%2Eexample.com",
        ],
    )
    def test_invalid_origin_rejected(self, origin):
        with pytest.raises(ValueError, match="expected_origin"):
            AuthOptions(expected_origin=origin)

    @pytest.mark.parametrize(
        "header",
        [
            "",
            " X-Client-Cert",
            "X-Client-Cert ",
            "X-Clïent-Cert",
            "X-Client-Cert:",
            "X Client Cert",
            "X-Client\x00Cert",
        ],
    )
    def test_invalid_certificate_header_name_rejected(self, header):
        with pytest.raises(ValueError, match="client_certificate_header"):
            OIDCSettings(
                discovery_url=DISCOVERY_URL,
                client_id=AUDIENCE,
                client_certificate_header=header,
            )

    def test_token_character_certificate_header_name_accepted(self):
        settings = OIDCSettings(
            discovery_url=DISCOVERY_URL,
            client_id=AUDIENCE,
            client_certificate_header="x_ssl.client~cert",
        )
        assert settings.client_certificate_header == "x_ssl.client~cert"

    def test_invalid_settings_origin_rejected(self):
        with pytest.raises(ValueError, match="expected_origin"):
            OIDCSettings(
                discovery_url=DISCOVERY_URL,
                client_id=AUDIENCE,
                expected_origin="https://api.example.com/v1",
            )
