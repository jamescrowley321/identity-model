"""WebSocket + exact-match-exclusion correctness matrix (issues #598, #600).

The HTTP correctness matrix (:mod:`test_correctness_matrix`) proves the resource
server rejects the forged corpus over real HTTP. This module proves the same
contract for the two surfaces that matrix cannot reach:

* **WebSocket auth (#598).** ``TokenValidationMiddleware`` never sees WebSocket
  scopes, so WS routes are guarded by ``build_ws_authenticator`` instead. Here
  the full forged corpus — real :class:`~harness.MockOP`-signed tokens (expired,
  wrong-iss/aud, tampered-sig, unknown-kid, alg-none/confusion, and an ID token
  presented as a bearer, F-07) — is pushed through a **real WebSocket handshake**
  against the booted RS (:func:`~harness.rs_server.boot_rs`, real uvicorn +
  ``websockets`` client). A valid token connects and receives its claims; every
  forged token is rejected at the handshake (a pre-accept ``close(1008)`` surfaces
  to the client as an HTTP 403 denial response), so the socket never opens and no
  data flows — nothing is silently accepted.

* **Exact-match exclusion (#600).** With exact matching the default, a route
  *under* an excluded prefix (``/health/deep`` under the excluded ``/health``) is
  no longer excluded: it is validated and, without a token, 401s (fail closed) —
  while ``/health`` itself stays open. Proven end-to-end against the booted RS.

Run via ``make test-harness-matrix`` (self-contained: the mock OP is served over
real localhost HTTP, no Docker). Under a plain env the module importorskips.
"""

import json
from urllib.parse import urlparse

import httpx
import pytest

from ..harness import CORPUS_AUDIENCE, build_corpus, serve_mock_op
from ..harness.rs_server import boot_rs


pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")
wsclient = pytest.importorskip("websockets.sync.client")
wserr = pytest.importorskip("websockets.exceptions")

pytestmark = pytest.mark.integration

GENERIC_401_BODY = {"detail": "Invalid or unauthorized token"}
ID_TOKEN_DETAIL = "ID token cannot be used as an access token"

# Every corpus class a validating RS rejects outright — the same set the HTTP
# matrix asserts, re-run over the WebSocket surface. ``id_as_access`` is called
# out separately (it rejects via the F-07 type check, not signature/claim
# validation), so it is not repeated here.
WS_REJECTED_CLASSES = [
    "expired",
    "nbf_future",
    "wrong_iss",
    "wrong_aud",
    "tampered_sig",
    "unknown_kid",
    "wrong_alg",
    "alg_none",
]

# Validly signed access tokens the library accepts — these connect over WS.
# ``id_as_access`` is deliberately NOT here: the library accepts it but the F-07
# type guard rejects it (proven in test_ws_id_token_as_access_rejected).
WS_ACCEPTED_CLASSES = {"valid", "cnf_bound", "oversized", "multi_aud_untrusted"}

# A pre-accept WebSocket close(1008 policy violation) is delivered to the client
# as an HTTP 403 denial response (ASGI WebSocket Denial Response extension).
_WS_DENIAL_STATUS = 403


def _ws_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}/ws"


def _ws_first_message(base_url: str, token: str, *, via_header: bool = False) -> dict:
    """Open the WS, return the first message, and close. Raises on a rejected
    handshake (``websockets.exceptions.InvalidStatus``)."""
    url = _ws_url(base_url)
    if via_header:
        target, kwargs = (
            url,
            {"additional_headers": {"Authorization": f"Bearer {token}"}},
        )
    else:
        target, kwargs = f"{url}?access_token={token}", {}
    with wsclient.connect(target, open_timeout=10, **kwargs) as sock:
        return json.loads(sock.recv())


@pytest.fixture(scope="module")
def ws_matrix():
    """One mock OP + one booted RS (audience=mock-api), reused across cases."""
    with (
        serve_mock_op() as op,
        boot_rs(
            discovery_url=op.discovery_url,
            audience=CORPUS_AUDIENCE,
            require_scope="read",
        ) as base_url,
    ):
        yield op, base_url, build_corpus(op)


# ---------------------------------------------------------------------------
# WebSocket auth (#598) — real handshake, forged corpus
# ---------------------------------------------------------------------------


def test_ws_valid_token_via_query_param_connects(ws_matrix):
    _op, base_url, corpus = ws_matrix
    claims = _ws_first_message(base_url, corpus["valid"].jwt)
    assert claims == {"sub": "mock-subject", "scope": "read"}


def test_ws_valid_token_via_authorization_header_connects(ws_matrix):
    _op, base_url, corpus = ws_matrix
    claims = _ws_first_message(base_url, corpus["valid"].jwt, via_header=True)
    assert claims["sub"] == "mock-subject"


@pytest.mark.parametrize("name", WS_REJECTED_CLASSES)
def test_ws_forged_token_rejected_at_handshake(ws_matrix, name):
    _op, base_url, corpus = ws_matrix
    with pytest.raises(wserr.InvalidStatus) as exc:
        _ws_first_message(base_url, corpus[name].jwt)
    assert exc.value.response.status_code == _WS_DENIAL_STATUS


def test_ws_id_token_as_access_rejected(ws_matrix):
    """F-07 over WebSocket: an ID token presented as a bearer is rejected before
    the socket is accepted — the same guard the HTTP middleware applies."""
    _op, base_url, corpus = ws_matrix
    with pytest.raises(wserr.InvalidStatus) as exc:
        _ws_first_message(base_url, corpus["id_as_access"].jwt)
    assert exc.value.response.status_code == _WS_DENIAL_STATUS


def test_ws_missing_token_rejected(ws_matrix):
    _op, base_url, _corpus = ws_matrix
    with pytest.raises(wserr.InvalidStatus) as exc:
        _ws_first_message(base_url, "")
    assert exc.value.response.status_code == _WS_DENIAL_STATUS


def test_ws_nothing_silently_accepted(ws_matrix):
    """Every corpus class except the validly-signed access tokens is rejected at
    the WS handshake — no forged token ever opens a socket."""
    _op, base_url, corpus = ws_matrix
    for name, forged in corpus.items():
        if name in WS_ACCEPTED_CLASSES:
            continue
        with pytest.raises(wserr.InvalidStatus) as exc:
            _ws_first_message(base_url, forged.jwt)
        assert exc.value.response.status_code == _WS_DENIAL_STATUS, (
            f"class {name!r} was not rejected at the WS handshake"
        )


# ---------------------------------------------------------------------------
# Exact-match exclusion (#600) — real HTTP against the booted RS
# ---------------------------------------------------------------------------


def _get(base_url: str, path: str, token: str | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.get(f"{base_url}{path}", headers=headers, timeout=10.0)


def test_excluded_prefix_itself_stays_open(ws_matrix):
    # "/health" is excluded exactly → reachable with no token.
    _op, base_url, _corpus = ws_matrix
    assert _get(base_url, "/health").status_code == httpx.codes.OK


def test_nested_route_under_excluded_prefix_requires_auth(ws_matrix):
    # "/health/deep" is NOT excluded under exact matching → the middleware blocks
    # it without a token (fail closed). No token is the structural "missing
    # header" 401, returned before routing — the un-authed nested route never
    # reaches its handler.
    _op, base_url, _corpus = ws_matrix
    resp = _get(base_url, "/health/deep")
    assert resp.status_code == httpx.codes.UNAUTHORIZED
    assert resp.json() == {"detail": "Missing Authorization header"}


def test_nested_route_under_excluded_prefix_reachable_with_valid_token(ws_matrix):
    _op, base_url, corpus = ws_matrix
    resp = _get(base_url, "/health/deep", token=corpus["valid"].jwt)
    assert resp.status_code == httpx.codes.OK
    assert resp.json() == {"deep": True, "sub": "mock-subject"}
