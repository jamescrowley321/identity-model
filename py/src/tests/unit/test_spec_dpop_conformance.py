"""Thin Python executor for the shared DPoP vectors (spec/vectors/dpop.json).

Data vectors run against ``py_identity_model.core.dpop``. HTTP vectors serve
their canned responses with respx at the fixture host and make the call through
``request_authorization_code_token`` or ``get_userinfo`` with a ``dpop_key``.
A proof is verified against the key-pair fixture, then compared by its decoded
header and payload; ``jti`` and ``iat`` are generated, so they are only checked
for presence and freshness, and every proof must carry a distinct ``jti``. The
Go runner executes the same file.

py-identity-model cannot load a DPoPKey from existing key material (#786),
so the fixture key is installed into a DPoPKey in place of a generated one.
"""

import base64
import json
from pathlib import Path
import time
from urllib.parse import parse_qs

import httpx
from jwt import PyJWK, PyJWS
import pytest
import respx

from py_identity_model.core import dpop
from py_identity_model.core.dpop import DPoPKey, compute_ath, create_dpop_proof
from py_identity_model.core.models import (
    AuthorizationCodeTokenRequest,
    UserInfoRequest,
)
from py_identity_model.sync.token_client import request_authorization_code_token
from py_identity_model.sync.userinfo import get_userinfo


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "dpop.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads((_REPO_ROOT / "spec" / "vectors" / "dpop.json").read_text())[
    "tests"
]
_BASE = "https://server.example.com"
_IAT_WINDOW = 60


class KnownGap(Exception):
    """Raised where py-identity-model does not meet a vector yet."""


#: Cases (or single vectors, by param id) py-identity-model does not meet yet.
#: Strict, so a fix fails the suite until the entry is removed.
_KNOWN_GAPS = {
    "DPOP-004-nonce-cached": "the DPoP-Nonce is not cached for later requests (#784)",
    "DPOP-006": "no DPoP proof verifier (#478)",
}


def _params() -> list:
    params = []
    for case in _CASES:
        assert case.get("vectors"), f"{case['id']}: case has no vectors"
        for idx, vector in enumerate(case["vectors"]):
            param_id = f"{case['id']}-{vector.get('name') or idx}"
            reason = _KNOWN_GAPS.get(param_id) or _KNOWN_GAPS.get(case["id"])
            marks = []
            if reason:
                marks.append(
                    pytest.mark.xfail(reason=reason, raises=KnownGap, strict=True)
                )
            params.append(pytest.param(case["id"], vector, id=param_id, marks=marks))
    return params


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURE_ROOT / name).read_text())


def _fixture_key(name: str) -> tuple[DPoPKey, object]:
    """Return a DPoPKey holding the fixture's private key, and its public key."""
    doc = _fixture(name)
    key = DPoPKey.__new__(DPoPKey)
    key._algorithm = doc["algorithm"]
    key._private_key = PyJWK(doc["private"]).key
    return key, PyJWK(doc["public"]).key


def _jti(proof: str) -> str:
    payload = PyJWS().decode_complete(proof, options={"verify_signature": False})
    return json.loads(payload["payload"])["jti"]


def _assert_proof(case_id: str, proof: str, key: tuple, want: dict) -> None:
    dpop_key, public_key = key
    decoded = PyJWS().decode_complete(
        proof, key=public_key, algorithms=[dpop_key.algorithm]
    )
    assert decoded["header"] == want["header"], case_id
    payload = json.loads(decoded["payload"])
    jti = payload.pop("jti")
    assert isinstance(jti, str), case_id
    assert jti, case_id
    assert abs(payload.pop("iat") - time.time()) <= _IAT_WINDOW, case_id
    assert payload == want["payload"], case_id


def _run_thumbprint(case_id: str, vector: dict) -> None:
    inp = vector["input"]
    thumbprint = _fixture_key(inp["key"])[0].jwk_thumbprint
    assert thumbprint == vector["expect"]["result"]["thumbprint"], case_id
    if "bound_token" in inp:
        assert _fixture(inp["bound_token"])["payload"]["cnf"]["jkt"] == thumbprint


def _run_generate_key(case_id: str, vector: dict) -> None:
    alg, expect = vector["input"]["alg"], vector["expect"]
    if expect["outcome"] == "reject":
        assert expect["error"] == "unsupported_algorithm", case_id
        with pytest.raises(ValueError, match="Unsupported DPoP algorithm"):
            dpop.generate_dpop_key(alg)
        return
    jwk = dpop.generate_dpop_key(alg).public_jwk
    want = dict(expect["result"])
    min_bits = want.pop("min_modulus_bits", None)
    got = {"kty": jwk["kty"]}
    if "crv" in jwk:
        got["crv"] = jwk["crv"]
    assert ("n" in jwk) == (min_bits is not None), case_id
    if min_bits is not None:
        n = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
        assert int.from_bytes(n, "big").bit_length() >= min_bits, case_id
    assert got == want, case_id


def _run_data(case_id: str, vector: dict) -> None:
    inp, expect = vector["input"], vector["expect"]
    op = inp["operation"]
    if op == "create_proof":
        key = _fixture_key(inp["key"])
        # Build two proofs: each must match the vector, and their jti must differ.
        proofs = [
            create_dpop_proof(
                key[0], inp["htm"], inp["htu"], access_token=inp.get("access_token")
            )
            for _ in range(2)
        ]
        for proof in proofs:
            _assert_proof(case_id, proof, key, expect["result"])
        assert _jti(proofs[0]) != _jti(proofs[1]), f"{case_id}: jti reused"
    elif op == "ath":
        pairs = _fixture(inp["pairs"])["pairs"]
        assert pairs, f"{case_id}: no pairs in {inp['pairs']}"
        for pair in pairs:
            assert compute_ath(pair["access_token"]) == pair["ath"]
    elif op == "thumbprint":
        _run_thumbprint(case_id, vector)
    elif op == "verify_proof":
        raise KnownGap(_KNOWN_GAPS["DPOP-006"])
    elif op == "generate_key":
        _run_generate_key(case_id, vector)
    else:
        pytest.fail(f"{case_id}: unknown operation {op!r}")


def _response(resp: dict) -> httpx.Response:
    body = b""
    if "body_fixture" in resp:
        body = (_FIXTURE_ROOT / resp["body_fixture"]).read_bytes()
    headers = {"Content-Type": "application/json"} if body else {}
    headers.update(resp.get("headers", {}))
    return httpx.Response(resp["status"], content=body, headers=headers)


def _mock(vector: dict) -> dict[str, respx.Route]:
    routes = {}
    for path, resp in vector.get("http", {}).items():
        routes[path] = respx.route(url=_BASE + path).mock(return_value=_response(resp))
    for path, seq in vector.get("http_sequence", {}).items():
        responses = [_response(r) for r in seq]
        routes[path] = respx.route(url=_BASE + path).mock(
            side_effect=lambda _request, route, r=responses: r[
                min(route.call_count, len(r) - 1)
            ]
        )
    return routes


def _assert_request(route: respx.Route, want: dict) -> None:
    """An empty expected header or form value means it must be absent."""
    assert route.called, f"no request to {want['path']}"
    request = route.calls.last.request
    assert request.method == want["method"]
    for name, value in want.get("headers", {}).items():
        if not value:
            assert name not in request.headers, f"header {name} must be absent"
            continue
        have = request.headers.get(name, "")
        if name.lower() == "content-type":
            have = have.split(";")[0].strip()
        assert have == value, f"header {name}: {have!r} != {value!r}"
    form = {
        k: v[0]
        for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
    }
    for name, value in want.get("form", {}).items():
        if not value:
            assert name not in form, f"form {name} must be absent"
            continue
        have = form.get(name, "")
        assert have == value, f"form {name}: {have!r} != {value!r}"


def _run_http(case_id: str, vector: dict) -> None:
    routes = _mock(vector)
    inp, expect = vector["input"], vector["expect"]
    assert expect["outcome"] == "accept", case_id
    key = _fixture_key(inp["key"])
    if inp["operation"] == "resource_request":
        path = "/userinfo"
        request = UserInfoRequest(
            address=_BASE + path, token=inp["access_token"], dpop_key=key[0]
        )

        def send() -> bool:
            return get_userinfo(request).is_successful

    else:
        path = "/token"
        token_request = AuthorizationCodeTokenRequest(
            address=_BASE + path,
            client_id="cid",
            code=inp["code"],
            redirect_uri=inp["redirect_uri"],
            client_secret="secret",
            dpop_key=key[0],
        )

        def send() -> bool:
            return request_authorization_code_token(token_request).is_successful

    for n in range(inp.get("requests", 1)):
        assert send(), case_id
        if n > 0 and "nonce" in expect["result"]["payload"]:
            raise KnownGap(_KNOWN_GAPS["DPOP-004-nonce-cached"])
        proof = routes[path].calls.last.request.headers["DPoP"]
        _assert_proof(case_id, proof, key, expect["result"])

    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)
    for path_, count in vector.get("expect_calls", {}).items():
        assert routes[path_].call_count == count, f"{case_id}: calls to {path_}"
    # Every proof sent, including a nonce retry's, must carry a fresh jti.
    jtis = [_jti(call.request.headers["DPoP"]) for call in routes[path].calls]
    assert jtis, f"{case_id}: no requests to {path}"
    assert len(set(jtis)) == len(jtis), f"{case_id}: jti reused across {jtis}"


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_dpop_vector(case_id: str, vector: dict) -> None:
    if vector["input"]["operation"] in ("token_request", "resource_request"):
        _run_http(case_id, vector)
    else:
        _run_data(case_id, vector)
