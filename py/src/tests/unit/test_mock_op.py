"""Unit tests for the controllable mock OP and forged corpus (TH-1.1, #463).

Deterministic and network-free: the framework-free ASGI app is driven in-process
via ``httpx.ASGITransport``, and the *real* library
(:func:`py_identity_model.aio.validate_token`) validates minted / forged tokens
through the mock OP's discovery + JWKS documents.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
import httpx
import jwt
import pytest

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import validate_token
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import PyIdentityModelException

from ..harness import CORPUS_AUDIENCE, MockOP, build_corpus
from ..harness import mock_op as mock_op_mod


HTTP_OK = 200
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVICE_UNAVAILABLE = 503
PUBLISHED_KEY_COUNT = 2
OVERSIZED_PADDING = 50
P256_COORD_BITS = 256


def _client(mock: MockOP) -> AsyncHTTPClient:
    """An AsyncHTTPClient routed at the in-process mock OP (no network)."""
    transport = httpx.ASGITransport(app=mock.app)
    return AsyncHTTPClient(
        client=httpx.AsyncClient(
            transport=transport, base_url=mock.issuer, follow_redirects=False
        )
    )


def _validation_config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=CORPUS_AUDIENCE,
        algorithms=["RS256", "ES256"],
        require_https=False,
    )


async def _validate(mock: MockOP, token: str) -> dict:
    client = _client(mock)
    try:
        return await validate_token(
            token,
            _validation_config(),
            disco_doc_address=mock.discovery_url,
            http_client=client,
        )
    finally:
        await client.close()


# -- Documents served over ASGI --------------------------------------------


async def test_discovery_document_served() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.discovery_url)
    assert resp.status_code == HTTP_OK
    doc = resp.json()
    assert doc["issuer"] == mock.issuer
    assert doc["jwks_uri"] == mock.jwks_uri
    assert doc["token_endpoint"] == mock.token_endpoint


async def test_jwks_served_with_published_keys() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    kids = {k["kid"] for k in resp.json()["keys"]}
    assert mock.primary_key.kid in kids
    assert mock.ec_key.kid in kids
    assert mock.unpublished_key.kid not in kids


async def test_token_endpoint_mints_valid_token() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.post(
            mock.token_endpoint,
            data={"grant_type": "client_credentials", "scope": "read"},
        )
    body = resp.json()
    assert body["token_type"] == "Bearer"
    claims = await _validate(mock, body["access_token"])
    assert claims["iss"] == mock.issuer


# -- End-to-end validation of the corpus -----------------------------------


async def test_valid_token_validates_end_to_end() -> None:
    mock = MockOP()
    corpus = build_corpus(mock)
    claims = await _validate(mock, corpus["valid"].jwt)
    assert claims["scope"] == "read"


@pytest.mark.parametrize(
    "name",
    [
        "expired",
        "nbf_future",
        "wrong_iss",
        "wrong_aud",
        "tampered_sig",
        "unknown_kid",
        "wrong_alg",
        "alg_none",
    ],
)
async def test_forged_tokens_are_rejected(name: str) -> None:
    mock = MockOP()
    forged = build_corpus(mock)[name]
    assert forged.library_rejects is True
    with pytest.raises(PyIdentityModelException):
        await _validate(mock, forged.jwt)


@pytest.mark.parametrize("name", ["id_as_access", "cnf_bound", "oversized"])
async def test_library_accepted_classes_are_signature_valid(name: str) -> None:
    # These are validly signed for the audience — the library ACCEPTS them.
    # Only the RS access-token marker / require_scope layer (F-07/F-02) rejects
    # them; that distinction is proven in T302, not here.
    mock = MockOP()
    forged = build_corpus(mock)[name]
    assert forged.library_rejects is False
    claims = await _validate(mock, forged.jwt)
    assert claims["iss"] == mock.issuer


# -- Failure injection (design §2) -----------------------------------------


async def test_key_rotation_then_republish() -> None:
    mock = MockOP()
    # Rotate to the spare WITHOUT publishing -> tokens present an unknown kid.
    mock.rotate_keys(publish=False)
    token = mock.mint_access_token()["access_token"]
    with pytest.raises(PyIdentityModelException):
        await _validate(mock, token)
    # Publishing the rotated key lets the same token validate on refetch.
    mock.publish_signing_key()
    claims = await _validate(mock, token)
    assert claims["iss"] == mock.issuer


async def test_empty_jwks_control() -> None:
    mock = MockOP()
    mock.controls.serve_empty_jwks = True
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert resp.json()["keys"] == []


async def test_oversized_jwks_control() -> None:
    mock = MockOP()
    mock.controls.oversized_jwks_padding = OVERSIZED_PADDING
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert len(resp.json()["keys"]) == PUBLISHED_KEY_COUNT + OVERSIZED_PADDING


async def test_rate_limit_control_sets_retry_after() -> None:
    mock = MockOP()
    mock.controls.discovery_status = HTTP_TOO_MANY_REQUESTS
    mock.controls.retry_after = "3"
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.discovery_url)
    assert resp.status_code == HTTP_TOO_MANY_REQUESTS
    assert resp.headers["retry-after"] == "3"


async def test_no_store_cache_control_on_jwks() -> None:
    mock = MockOP()
    mock.controls.jwks_cache_control = "no-store"
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert resp.headers["cache-control"] == "no-store"


async def test_injected_latency(monkeypatch: pytest.MonkeyPatch) -> None:
    mock = MockOP()
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(mock_op_mod.asyncio, "sleep", fake_sleep)
    mock.controls.latency_seconds = 0.25
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        await client.get(mock.discovery_url)
    assert slept == [0.25]


async def test_control_route_rotates_and_sets_knobs() -> None:
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.post(
            f"{mock.issuer}/_control",
            json={
                "rotate": True,
                "publish": True,
                "jwks_status": HTTP_SERVICE_UNAVAILABLE,
            },
        )
    assert resp.json() == {"ok": True, "rejected": []}
    assert mock.controls.jwks_status == HTTP_SERVICE_UNAVAILABLE
    assert mock.signing_key is mock.rotation_key


async def test_control_route_rejects_type_mismatched_values() -> None:
    """A stray JSON type must be rejected at the control call, not crash a later
    request (design: fail local, not downstream)."""
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.post(
            f"{mock.issuer}/_control",
            json={
                "jwks_status": "boom",  # str for an int field -> reject
                "retry_after": 3,  # int for a str|None field -> reject
                "oversized_jwks_padding": "big",  # str for an int field -> reject
                "discovery_status": HTTP_SERVICE_UNAVAILABLE,  # valid int -> apply
            },
        )
        body = resp.json()
        # The valid knob applied; the mismatches were reported, not applied.
        assert body["ok"] is True
        assert set(body["rejected"]) == {
            "jwks_status",
            "retry_after",
            "oversized_jwks_padding",
        }
        assert mock.controls.jwks_status == HTTP_OK
        assert mock.controls.retry_after is None
        assert mock.controls.oversized_jwks_padding == 0
        assert mock.controls.discovery_status == HTTP_SERVICE_UNAVAILABLE
        # The next /jwks request must still succeed (no poisoned state).
        mock.controls.jwks_status = HTTP_OK
        jwks = await client.get(mock.jwks_uri)
        assert jwks.status_code == HTTP_OK


def test_introspect_reports_active_for_valid_token() -> None:
    mock = MockOP()
    minted = mock.mint_access_token()
    result = mock.introspect(minted["access_token"])
    assert result["active"] is True


def test_introspect_survives_malformed_exp() -> None:
    """A token with a non-numeric ``exp`` (exactly what this harness forges)
    must report inactive, not 500 the introspect endpoint."""
    token = jwt.encode({"exp": "not-a-number"}, "x" * 32, algorithm="HS256")
    result = MockOP().introspect(token)
    assert result["active"] is False


def test_introspect_reports_inactive_for_non_jwt() -> None:
    result = MockOP().introspect("not.a.jwt")
    assert result["active"] is False


# -- Per-path request counters (design §5 — upstream fetches/issuer) ---------


async def test_stats_count_each_upstream_request() -> None:
    """Every document handler bumps its counter — the S3 single-flight ground
    truth (a cold stampede must show exactly one discovery + one JWKS fetch)."""
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        await client.get(mock.discovery_url)
        await client.get(mock.jwks_uri)
        await client.get(mock.jwks_uri)
        await client.post(mock.token_endpoint, data={"scope": "read"})
    assert mock.stats.snapshot() == {
        "discovery": 1,
        "jwks": 2,
        "token": 1,
        "introspect": 0,
    }


async def test_stats_count_injected_failures() -> None:
    """A ``429``/``5xx`` still costs an upstream round trip, so it is counted."""
    mock = MockOP()
    mock.controls.jwks_status = HTTP_SERVICE_UNAVAILABLE
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        resp = await client.get(mock.jwks_uri)
    assert resp.status_code == HTTP_SERVICE_UNAVAILABLE
    assert mock.stats.jwks == 1


async def test_stats_route_reads_and_resets() -> None:
    """The ``/_stats`` route mirrors ``mock.stats`` and ``POST`` zeroes it — how
    the out-of-process load driver scrapes upstream-fetch counts per scenario."""
    mock = MockOP()
    transport = httpx.ASGITransport(app=mock.app)
    async with httpx.AsyncClient(transport=transport, base_url=mock.issuer) as client:
        await client.get(mock.discovery_url)
        read = await client.get(f"{mock.issuer}/_stats")
        assert read.json() == {
            "discovery": 1,
            "jwks": 0,
            "token": 0,
            "introspect": 0,
        }
        # The /_stats read itself must NOT count as an upstream document fetch.
        reset = await client.post(f"{mock.issuer}/_stats")
        assert reset.json() == {
            "ok": True,
            "discovery": 0,
            "jwks": 0,
            "token": 0,
            "introspect": 0,
        }
        assert mock.stats.snapshot() == {
            "discovery": 0,
            "jwks": 0,
            "token": 0,
            "introspect": 0,
        }


def _p256_key_with_short_x() -> ec.EllipticCurvePrivateKey:
    """A deterministic P-256 key whose ``x`` has a leading zero byte."""
    for scalar in range(1, 10_000):
        key = ec.derive_private_key(scalar, ec.SECP256R1())
        if key.public_key().public_numbers().x.bit_length() <= P256_COORD_BITS - 8:
            return key
    raise AssertionError("no short-x P-256 key in range")


def test_ec_jwk_keeps_full_width_coordinates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A coordinate with a leading zero byte is still published as 32 bytes.

    Otherwise PyJWT rejects the JWK and every ES256 token fails (a ~1/128 flake).
    """
    key = _p256_key_with_short_x()
    monkeypatch.setattr(mock_op_mod.ec, "generate_private_key", lambda _curve: key)
    signing_key = mock_op_mod._ec_signing_key("short-x")

    token = jwt.encode({"sub": "s"}, key, algorithm="ES256", headers={"kid": "short-x"})
    public = jwt.PyJWK(signing_key.public_jwk).key
    assert jwt.decode(token, public, algorithms=["ES256"]) == {"sub": "s"}
