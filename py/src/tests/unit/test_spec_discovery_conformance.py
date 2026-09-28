"""Thin Python executor for the shared discovery vectors (spec/vectors/discovery.json).

Each vector's canned responses are served with respx at the fixture host and
the outcome, the request sent and the request count are asserted. The Go and
Rust runners execute the same file.

Single calls go through ``get_discovery_document``. Cache vectors go through the
TTL cache that token validation uses, with the cache clock replaced by one the
vector drives. py-identity-model reports discovery errors as a message, so a
reject is asserted by the text that names its canonical error.
"""

import json
from pathlib import Path
import time

import httpx
import pytest
import respx

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.core import jwks_cache
from py_identity_model.sync import token_validation


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "discovery.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads((_REPO_ROOT / "spec" / "vectors" / "discovery.json").read_text())[
    "tests"
]
_BASE = "https://server.example.com"
_WELL_KNOWN = "/.well-known/openid-configuration"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


#: Vectors py-identity-model does not meet yet. Strict, and pinned to KnownGap,
#: so a fix (or a different failure) fails the suite until the entry is removed.
_KNOWN_GAPS = {
    "DISC-003-issuer-mismatch": "no check that the issuer matches the requested issuer (#574)",
    "DISC-008-missing-multiple-fields": (
        "token_endpoint and authorization_endpoint are not required fields (#771)"
    ),
}

#: The text each canonical reject error puts in py-identity-model's message.
_ERROR_TEXT = {
    "issuer_mismatch": "issuer mismatch",
    "http_status": "status code: {status}",
    "parse": "Invalid JSON response",
    "https_required": "HTTPS is required",
}

#: Required fields py-identity-model does not check yet (#771).
_UNCHECKED_FIELDS = {"token_endpoint", "authorization_endpoint"}


def _params() -> list:
    params = []
    for case in _CASES:
        assert case.get("vectors"), f"{case['id']}: case has no vectors"
        for idx, vector in enumerate(case["vectors"]):
            param_id = f"{case['id']}-{vector.get('name') or idx}"
            marks = []
            if param_id in _KNOWN_GAPS:
                marks.append(
                    pytest.mark.xfail(
                        reason=_KNOWN_GAPS[param_id],
                        raises=KnownGap,
                        strict=True,
                    )
                )
            params.append(pytest.param(case["id"], vector, id=param_id, marks=marks))
    return params


def _mock(base: str, vector: dict) -> dict[str, respx.Route]:
    routes = {}
    for path, resp in vector["http"].items():
        body = b""
        if "body_fixture" in resp:
            body = (_FIXTURE_ROOT / resp["body_fixture"]).read_bytes()
        headers = {"Content-Type": "application/json"} if body else {}
        routes[path] = respx.route(url=base + path).mock(
            return_value=httpx.Response(resp["status"], content=body, headers=headers)
        )
    return routes


def _cached_calls(address: str, inp: dict, monkeypatch: pytest.MonkeyPatch) -> list:
    monkeypatch.setenv("DISCO_CACHE_TTL", str(inp["cache_ttl_seconds"]))
    jwks_cache._reset_env_for_testing()
    now = [time.monotonic()]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    token_validation.clear_discovery_cache()
    responses = []
    try:
        start = now[0]
        for at in inp["calls_at_seconds"]:
            now[0] = start + at
            responses.append(token_validation._get_disco_response(address))
    finally:
        token_validation.clear_discovery_cache()
        monkeypatch.undo()
        jwks_cache._reset_env_for_testing()
    return responses


def _check_reject(case_id: str, response, expect: dict) -> None:
    if response.is_successful and expect["error"] == "issuer_mismatch":
        raise KnownGap(f"{case_id}: issuer mismatch accepted (#574)")
    assert not response.is_successful, f"{case_id}: expected reject, got accept"
    error = response.error or ""
    if expect["error"] == "missing_fields":
        unreported = {f for f in expect["fields"] if f not in error}
        if unreported and unreported <= _UNCHECKED_FIELDS:
            raise KnownGap(f"{case_id}: {sorted(unreported)} not required (#771)")
        assert not unreported, f"{case_id}: {sorted(unreported)} not in {error!r}"
    else:
        text = _ERROR_TEXT[expect["error"]].format(status=expect.get("status"))
        assert text in error, f"{case_id}: {text!r} not in {error!r}"


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_discovery_vector(
    case_id: str, vector: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    inp = vector["input"]
    base = "http://server.example.com" if inp.get("require_https") else _BASE
    routes = _mock(base, vector)
    address = base + _WELL_KNOWN

    if "calls_at_seconds" in inp:
        responses = _cached_calls(address, inp, monkeypatch)
    else:
        responses = [get_discovery_document(DiscoveryDocumentRequest(address=address))]
    response = responses[-1]

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        for r in responses:
            assert r.is_successful, f"{case_id}: {r.error}"
        for name, value in expect.get("result", {}).items():
            assert getattr(response, name) == value, f"{case_id}: {name}"
    elif expect["outcome"] == "reject":
        _check_reject(case_id, response, expect)
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")

    want = vector.get("expect_request")
    if want:
        route = routes[want["path"]]
        assert route.called, f"no request to {want['path']}"
        assert route.calls.last.request.method == want["method"]
    for path, count in vector.get("expect_calls", {}).items():
        calls = routes[path].call_count if path in routes else 0
        assert calls == count, f"{case_id}: requests to {path}"
