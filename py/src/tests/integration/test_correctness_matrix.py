"""Token correctness assertion matrix — TH-1.3 (#465 · epic #462, design §4 S8).

Sends ONE token per class through the **booted resource server**
(:func:`~harness.rs_server.boot_rs` — real uvicorn, real HTTP) and asserts the
contract: ``200`` for valid tokens, ``401`` with the uniform (F-18) body for
every validation-failure class, ``403``/``401`` for the RS-policy classes, and
that **nothing is silently accepted**.

Two groups:

* **Group A — forged-corpus matrix.** The controllable :class:`~harness.MockOP`
  (served over real localhost HTTP by :func:`~harness.serve_mock_op` so the
  out-of-process RS can fetch its discovery + JWKS) supplies the full forged
  corpus keyed to its known signing key. This is self-contained: no Docker, runs
  under ``uv run --all-packages``.
* **Group B — real-issuer leg.** A live node-oidc token proves the same contract
  against a REAL IdP over real HTTP. Gated to node-oidc (the remote matrix
  providers mint different aud/scope), mirroring ``test_rs_boot``.

Run via ``make test-harness-matrix`` (Docker node-oidc + ``--all-packages`` so
``fastapi_identity_model`` and ``uvicorn`` resolve). Under a plain env the module
importorskips cleanly.
"""

import base64
from collections import namedtuple
import hashlib
import hmac
import time
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
import httpx
import jwt
import pytest

from ..harness import CORPUS_AUDIENCE, build_corpus, serve_mock_op
from ..harness.rs_server import boot_rs


pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

pytestmark = pytest.mark.integration

GENERIC_401_BODY = {"detail": "Invalid or unauthorized token"}

# The 8 classes a validating library rejects outright (sig / iss / aud / exp /
# nbf / kid / alg). Every one must collapse to the SAME generic 401 body (F-18).
VALIDATION_FAIL_CLASSES = [
    "expired",
    "nbf_future",
    "wrong_iss",
    "wrong_aud",
    "tampered_sig",
    "unknown_kid",
    "wrong_alg",
    "alg_none",
]

# Validly signed, correct-audience tokens carrying the ``read`` scope — the
# library AND the RS scope guard accept them (200).
ACCEPTED_200_CLASSES = ["valid", "oversized", "multi_aud_untrusted"]

# The middleware's always-on negative ID-token defense (F-07): a token carrying
# an ID-token-only claim (``nonce``/``at_hash``/``c_hash``) is rejected before
# ``require_scope`` runs, regardless of the ``require_access_token_marker`` opt-in.
ID_TOKEN_DETAIL = "ID token cannot be used as an access token"

# What the module fixture exposes: the live mock OP (to mint bespoke tokens), the
# booted RS base URL, the forged corpus, and the mock OP discovery URL (so a
# second RS can be booted against the same issuer for the F-07 marker case).
MockMatrix = namedtuple("MockMatrix", "op base_url corpus discovery_url")


def _get_protected(base_url: str, token: str) -> httpx.Response:
    return httpx.get(
        f"{base_url}/protected",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )


# ---------------------------------------------------------------------------
# Group A — forged-corpus matrix through the mock-OP-backed RS
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mock_matrix():
    """One mock OP + one booted RS (audience=mock-api, require_scope=read).

    Yields a :class:`MockMatrix`. The mock OP runs in-process (a uvicorn daemon
    thread inside ``serve_mock_op``); the RS is a separate uvicorn subprocess
    (``boot_rs``). Both are reused across all parametrized cases — a boot is
    ~1-2s, so we batch rather than re-boot per case.
    """
    with (
        serve_mock_op() as op,
        boot_rs(
            discovery_url=op.discovery_url,
            audience=CORPUS_AUDIENCE,
            require_scope="read",
        ) as base_url,
    ):
        yield MockMatrix(op, base_url, build_corpus(op), op.discovery_url)


@pytest.mark.parametrize("name", ACCEPTED_200_CLASSES)
def test_accepted_classes_reach_protected(mock_matrix, name):
    """Validly signed, correctly scoped tokens → 200."""
    response = _get_protected(mock_matrix.base_url, mock_matrix.corpus[name].jwt)
    assert response.status_code == httpx.codes.OK


def test_valid_token_body_echoes_claims(mock_matrix):
    """The canonical valid token → 200 with the validated sub + scope echoed."""
    response = _get_protected(mock_matrix.base_url, mock_matrix.corpus["valid"].jwt)
    assert response.status_code == httpx.codes.OK
    body = response.json()
    assert body["sub"] == "mock-subject"
    assert body["scope"] == "read"


@pytest.mark.parametrize("name", VALIDATION_FAIL_CLASSES)
def test_validation_failures_are_uniform_401(mock_matrix, name):
    """Each validation-failure class → 401 with the generic (F-18) body."""
    response = _get_protected(mock_matrix.base_url, mock_matrix.corpus[name].jwt)
    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json() == GENERIC_401_BODY


def test_f18_body_uniform_across_all_failure_stages(mock_matrix):
    """F-18: every validation stage returns the *same* 401 body (no leakage).

    A single divergent body (e.g. an ``exp``-specific message) would let a
    caller distinguish rejection reasons — the vulnerability F-18 closed.
    """
    bodies = [
        _get_protected(mock_matrix.base_url, mock_matrix.corpus[name].jwt).json()
        for name in VALIDATION_FAIL_CLASSES
    ]
    assert bodies == [GENERIC_401_BODY] * len(VALIDATION_FAIL_CLASSES)


def test_id_as_access_rejected_by_negative_defense(mock_matrix):
    """F-07 negative (always on): an ID-token presented as a bearer → 401.

    The corpus ID-token carries ``nonce`` (an ID-token-only claim), so the
    middleware rejects it as the wrong token type BEFORE ``require_scope`` runs
    — on the default RS, with no marker opt-in required. This is the passive
    token-type-confusion defense; the opt-in *positive* marker path is proven in
    :func:`test_scopeless_access_token_marker_gate`.
    """
    response = _get_protected(
        mock_matrix.base_url, mock_matrix.corpus["id_as_access"].jwt
    )
    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json() == {"detail": ID_TOKEN_DETAIL}


def test_f02_cnf_bound_as_bearer_rejected(mock_matrix):
    """F-02: a DPoP-bound token presented as a plain bearer → 401 (RFC 9449 §7.1).

    The RS challenges with the DPoP scheme; the body is the generic F-18 body.
    """
    response = _get_protected(mock_matrix.base_url, mock_matrix.corpus["cnf_bound"].jwt)
    assert (
        response.status_code,
        response.headers["WWW-Authenticate"].split(",")[0],
        response.json(),
    ) == (httpx.codes.UNAUTHORIZED, 'DPoP error="invalid_token"', GENERIC_401_BODY)


def test_nothing_silently_accepted(mock_matrix):
    """Every class outside the accepted set is rejected with a CLIENT error.

    A negative token must draw a 401/403, never a 200 (silent accept) and never
    a 5xx: a 500/503 also satisfies "not 200" but means the middleware faulted
    rather than cleanly rejecting, so ``!= 200`` alone would mask a server-error
    regression. Asserting the status is exactly a client rejection closes that.
    """
    for name, forged in mock_matrix.corpus.items():
        if name in ACCEPTED_200_CLASSES:
            continue
        response = _get_protected(mock_matrix.base_url, forged.jwt)
        assert response.status_code in (
            httpx.codes.UNAUTHORIZED,
            httpx.codes.FORBIDDEN,
        ), f"class {name!r} drew {response.status_code} (want 401/403, not 200/5xx)"


def test_cross_issuer_token_from_a_different_issuer_is_rejected(mock_matrix):
    """A token 100% valid for a DIFFERENT issuer is rejected by this RS.

    Stands up a second, fully independent mock OP (issuer B — its own keys,
    discovery and JWKS) and mints a valid access token in B's world. Presented to
    an RS trusting B the token is accepted (200), so it is genuinely valid; but
    presented to this suite's RS (trusting issuer A) it is rejected (401). The
    rejection is therefore specifically cross-issuer: A's JWKS holds no key that
    verifies B's signature and B's ``iss`` does not match A's discovery issuer.

    This is the real mix-up that the forged ``wrong_iss`` class (A's own key with
    the ``iss`` claim mutated) cannot exercise — there, no second issuer exists.
    """
    with (
        serve_mock_op() as op_b,
        boot_rs(
            discovery_url=op_b.discovery_url,
            audience=CORPUS_AUDIENCE,
            require_scope="read",
        ) as rs_b,
    ):
        b_token = op_b.mint_access_token(scopes="read")["access_token"]
        accepted_by_b = _get_protected(rs_b, b_token).status_code
        rejected_by_a = _get_protected(mock_matrix.base_url, b_token)

    assert accepted_by_b == httpx.codes.OK, "token is not actually valid for issuer B"
    assert rejected_by_a.status_code == httpx.codes.UNAUTHORIZED
    assert rejected_by_a.json() == GENERIC_401_BODY


def test_alg_none_and_confusion_reject_via_their_intended_control(mock_matrix):
    """The two alg negatives reject via the RIGHT control, not a coincidental one.

    Both classes previously passed for partly the wrong reason (``alg_none`` via
    no-kid/multiple-key ambiguity rather than the none-defence; ``wrong_alg`` via
    an arbitrary HMAC secret that a *vulnerable* RS would also reject). This pins
    the isolation so the tests cannot silently rot back into vacuous passes:

    * ``alg_none`` carries a ``kid`` that resolves to a real published key, so the
      sole remaining rejection path is the RFC 8725 ``alg:none`` defence.
    * ``wrong_alg`` is HMAC'd with the RSA **public key** as the secret and claims
      the RSA ``kid``, so only the algorithm allow-list can reject it — verified
      by recomputing the HMAC over the public key and matching the signature.
    """
    op = mock_matrix.op
    published_kids = {op.primary_key.kid, op.ec_key.kid}

    none_tok = mock_matrix.corpus["alg_none"].jwt
    none_hdr = jwt.get_unverified_header(none_tok)
    assert none_hdr["alg"] == "none"
    assert (
        none_hdr.get("kid") in published_kids
    )  # resolvable → none-defence is sole cause

    conf_tok = mock_matrix.corpus["wrong_alg"].jwt
    conf_hdr = jwt.get_unverified_header(conf_tok)
    assert conf_hdr["alg"] == "HS256"
    assert conf_hdr.get("kid") == op.primary_key.kid  # HS256 claiming an RSA kid
    pub_pem = op.primary_key.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header_b64, payload_b64, sig_b64 = conf_tok.split(".")
    expected_sig = (
        base64.urlsafe_b64encode(
            hmac.new(
                pub_pem, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
            ).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    assert sig_b64 == expected_sig, (
        "wrong_alg is not HMAC'd with the RSA public key — not the real "
        "alg-confusion attack (an arbitrary secret would prove nothing)"
    )

    # Both are still rejected by the booted RS.
    assert (
        _get_protected(mock_matrix.base_url, none_tok).status_code
        == httpx.codes.UNAUTHORIZED
    )
    assert (
        _get_protected(mock_matrix.base_url, conf_tok).status_code
        == httpx.codes.UNAUTHORIZED
    )


def _mint_scopeless_access_token(op) -> str:
    """A validly signed token with NO ``scope``/``scp`` and NO ID-token-only
    claim — passes signature/aud/type validation but carries no access-token
    marker (the exact shape the positive F-07 marker gate exists to catch)."""
    now = int(time.time())
    return op.sign(
        {
            "iss": op.issuer,
            "sub": "marker-subject",
            "aud": CORPUS_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "client_id": "mock-client",
        }
    )


def test_scopeless_access_token_marker_gate(mock_matrix):
    """F-07 positive (opt-in ``require_access_token_marker``).

    A scope-less token with no ID-token-only claim slips past the negative
    defense. On the default RS it validates and is handed to
    ``require_scope("read")`` → 403 (missing scope). On a marker-enabled RS the
    access-token marker gate rejects it FIRST → 401 — proving the opt-in marker
    is what distinguishes the two, not the always-on negative check.
    """
    token = _mint_scopeless_access_token(mock_matrix.op)

    default = _get_protected(mock_matrix.base_url, token)
    assert default.status_code == httpx.codes.FORBIDDEN

    with boot_rs(
        discovery_url=mock_matrix.discovery_url,
        audience=CORPUS_AUDIENCE,
        require_scope="read",
        require_access_token_marker=True,
    ) as marker_base:
        marked = _get_protected(marker_base, token)
    assert marked.status_code == httpx.codes.UNAUTHORIZED


# ---------------------------------------------------------------------------
# Group B — real-issuer leg (node-oidc), gated like test_rs_boot
# ---------------------------------------------------------------------------

NODE_OIDC_AUDIENCE = "urn:test:api"


def _is_node_oidc_fixture(raw_discovery: dict) -> bool:
    """Whether the active provider is the bundled node-oidc-provider fixture.

    The fixed ``urn:test:api`` audience this leg asserts on only exists in the
    local node-oidc-provider; the remote matrix providers (Keycloak/Ory/Descope)
    mint a different audience, so they must skip. node-oidc serves discovery at
    the localhost host root — the check that distinguishes it from Keycloak,
    which also runs on localhost but under ``/realms/<realm>`` (mirrors
    ``test_rs_boot._is_node_oidc_fixture``).
    """
    parsed = urlparse(raw_discovery.get("issuer", ""))
    is_local = parsed.hostname in ("localhost", "127.0.0.1")
    at_host_root = parsed.path in ("", "/")
    return is_local and at_host_root


def _granted_scopes(access_token: str) -> list[str]:
    claims = jwt.decode(access_token, options={"verify_signature": False})
    raw = claims.get("scope") or claims.get("scp") or ""
    if isinstance(raw, str):
        return raw.split()
    if isinstance(raw, (list, tuple, set, frozenset)):
        return [s for s in raw if isinstance(s, str)]
    # A non-str, non-collection scope claim (e.g. a JSON int) is not iterable —
    # treat it as no granted scopes rather than crashing on ``for`` (edge guard).
    return []


@pytest.fixture(scope="module")
def node_oidc_discovery_url(test_config, raw_discovery) -> str:
    if not _is_node_oidc_fixture(raw_discovery):
        pytest.skip(
            "correctness-matrix real-issuer leg asserts node-oidc's "
            "urn:test:api audience; remote matrix providers mint different tokens"
        )
    return test_config["TEST_DISCO_ADDRESS"]


def test_real_issuer_valid_token_accepted(
    node_oidc_discovery_url, client_credentials_token
):
    """A REAL node-oidc CC token → 200 through the booted RS (real HTTP DoD)."""
    access_token = client_credentials_token.token.get("access_token", "")
    assert access_token, "CC fixture returned no access_token"
    scopes = _granted_scopes(access_token)
    assert scopes, "minted token carried no scopes to guard on"

    with boot_rs(
        discovery_url=node_oidc_discovery_url,
        audience=NODE_OIDC_AUDIENCE,
        require_scope=scopes[0],
    ) as base_url:
        response = _get_protected(base_url, access_token)

    assert response.status_code == httpx.codes.OK
    assert response.json()["sub"]


def test_real_issuer_wrong_aud_rejected(
    node_oidc_discovery_url, client_credentials_token
):
    """A REAL node-oidc token against an RS expecting a different aud → 401.

    A real-issuer negative the corpus cannot forge: a genuinely signed token
    whose ``aud`` does not match the RS's configured audience. Proves the
    uniform 401 contract end-to-end against a live IdP.
    """
    access_token = client_credentials_token.token.get("access_token", "")
    assert access_token, "CC fixture returned no access_token"

    with boot_rs(
        discovery_url=node_oidc_discovery_url,
        audience="urn:does-not-match-any-real-token",
    ) as base_url:
        response = _get_protected(base_url, access_token)

    assert response.status_code == httpx.codes.UNAUTHORIZED
    assert response.json() == GENERIC_401_BODY
