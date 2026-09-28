"""Thin Python executor for the shared UserInfo vectors (spec/vectors/userinfo.json).

Each vector's canned responses are served with respx at the fixture host, the
call is made through ``get_userinfo``, and the request the client sent and the
outcome are asserted. The Go and Rust runners execute the same file.

py-identity-model surfaces UserInfo errors as a message on an unsuccessful
response rather than a typed error, so a reject is asserted by finding the
HTTP status (or the subject mismatch) in that message.
"""

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model.sync.userinfo import UserInfoRequest, get_userinfo


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "userinfo.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads((_REPO_ROOT / "spec" / "vectors" / "userinfo.json").read_text())[
    "tests"
]
_BASE = "https://server.example.com"

_NO_TYPED_CLAIMS = (
    "UserInfoResponse has no typed standard claims (#768)",
    AttributeError,
)
_NO_CHALLENGE = (
    "UserInfoResponse does not carry the WWW-Authenticate challenge (#769)",
    AttributeError,
)

#: Cases (or single vectors, by param id) py-identity-model does not meet yet.
#: Strict, so a fix fails the suite until the entry is removed.
_KNOWN_GAPS = {
    "UI-001": _NO_TYPED_CLAIMS,
    "UI-003-missing-sub": (
        "a response with no sub is accepted without expected_sub (#773)",
        AssertionError,
    ),
    "UI-004": _NO_CHALLENGE,
    "UI-005": _NO_CHALLENGE,
    "UI-006": _NO_CHALLENGE,
    "UI-007": _NO_TYPED_CLAIMS,
}


def _params() -> list:
    params = []
    for case in _CASES:
        assert case.get("vectors"), f"{case['id']}: case has no vectors"
        for idx, vector in enumerate(case["vectors"]):
            param_id = f"{case['id']}-{vector.get('name') or idx}"
            gap = _KNOWN_GAPS.get(param_id) or _KNOWN_GAPS.get(case["id"])
            marks = []
            if gap:
                reason, raises = gap
                marks.append(
                    pytest.mark.xfail(reason=reason, raises=raises, strict=True)
                )
            params.append(pytest.param(case["id"], vector, id=param_id, marks=marks))
    return params


def _mock(vector: dict) -> dict[str, respx.Route]:
    routes = {}
    for path, resp in vector["http"].items():
        body = b""
        if "body_fixture" in resp:
            body = (_FIXTURE_ROOT / resp["body_fixture"]).read_bytes()
        headers = {"Content-Type": "application/json"} if body else {}
        headers.update(resp.get("headers", {}))
        routes[path] = respx.route(url=_BASE + path).mock(
            return_value=httpx.Response(resp["status"], content=body, headers=headers)
        )
    return routes


def _assert_request(route: respx.Route, want: dict) -> None:
    assert route.called, f"no request to {want['path']}"
    request = route.calls.last.request
    assert request.method == want["method"]
    for name, value in want.get("headers", {}).items():
        have = request.headers.get(name, "")
        assert have == value, f"header {name}: {have!r} != {value!r}"
    form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
    for name, value in want.get("form", {}).items():
        assert form.get(name) == value, f"form {name}: {form.get(name)!r} != {value!r}"


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_userinfo_vector(case_id: str, vector: dict) -> None:
    routes = _mock(vector)
    inp = vector["input"]
    response = get_userinfo(
        UserInfoRequest(
            address=_BASE + "/userinfo",
            token=inp["token"],
            expected_sub=inp.get("expected_sub"),
        )
    )
    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        claims = response.claims or {}
        for name, value in expect.get("custom_claims", {}).items():
            assert claims.get(name) == value, f"claim map {name}"
        for name, value in expect.get("claims", {}).items():
            assert getattr(response, name) == value, f"typed claim {name}"
    elif expect["outcome"] == "reject":
        assert not response.is_successful, f"{case_id}: expected reject"
        error = expect.get("error")
        if error == "subject_mismatch":
            assert "sub mismatch" in (response.error or "")
            return
        if error == "missing_sub":
            assert "missing required 'sub' claim" in (response.error or "")
            return
        assert not error, f"{case_id}: unknown expected error {error!r}"
        assert f"status code: {expect['status']}" in (response.error or "")
        assert response.www_authenticate == expect.get("www_authenticate")
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")
