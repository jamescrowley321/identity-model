"""Sender-constrained tokens through the FastAPI middleware and WebSocket auth (#1021).

The middleware and ``build_ws_authenticator`` hand ``validate_token`` a
``TokenPresentation`` for every request. ``validate_token`` is replaced by the real async validator run against
a static key instead of discovery, so the signature, claims and binding checks
(RFC 9449 §7.1, RFC 8705 §3) all run for real; only the key fetch is skipped.
"""

from base64 import urlsafe_b64encode
from dataclasses import replace
import datetime
import time
from types import SimpleNamespace

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
    TokenValidationMiddleware,
    build_ws_authenticator,
    get_claims,
    ws,
)
import fastapi_identity_model.middleware as mw
from py_identity_model import (
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenBinding,
    compute_certificate_thumbprint,
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.aio import validate_token as avalidate_token


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"
ISSUER = "https://op"
AUDIENCE = "urn:api"
URL = "http://testserver/me"
GENERIC_BODY = {"detail": "Invalid or unauthorized token"}
ALGS = " ".join(DPoPVerificationOptions().accepted_algorithms)
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
            dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
            **options,
        )

        @app.get("/me")
        async def me(claims: dict = Depends(get_claims)):
            return {"sub": claims["sub"]}

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

        assert (resp.status_code, resp.headers["WWW-Authenticate"]) == (401, "Bearer")


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
            dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
            **options,
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
