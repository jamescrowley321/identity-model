"""Thin Python executor for the shared authorization code vectors (spec/vectors/authorization-code.json).

PKCE vectors are pure data run against ``generate_code_verifier`` and
``generate_code_challenge``. HTTP vectors serve their canned responses with
respx at the fixture host, make the call through
``request_authorization_code_token``, and assert the outcome and the request
the client sent. The Go and Rust runners execute the same file.

py-identity-model surfaces token endpoint errors as the raw response body in a
message on an unsuccessful response rather than a typed error (#791), so a
reject checks the HTTP status and then raises ``KnownGap``. Its
``AuthorizationCodeTokenResponse`` exposes the token members only through the
raw ``token`` dict (#783), so an accept checks the raw values and then raises
``KnownGap`` at the first missing typed member.
"""

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model.core.models import AuthorizationCodeTokenRequest
from py_identity_model.core.pkce import generate_code_challenge, generate_code_verifier
from py_identity_model.sync.token_client import request_authorization_code_token


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "authorization-code.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads(
    (_REPO_ROOT / "spec" / "vectors" / "authorization-code.json").read_text()
)["tests"]
_BASE = "https://server.example.com"
#: distinct_samples must be at least this, or distinctness proves nothing.
_MIN_SAMPLES = 2


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


_UNTYPED = "AuthorizationCodeTokenResponse has no typed token members (#783)"

#: Vectors py-identity-model does not meet yet, keyed by parametrize id. Strict,
#: and pinned to KnownGap, so a fix (or a different failure) fails the suite
#: until the entry is removed.
_KNOWN_GAPS = {
    "ACG-001-public-client": _UNTYPED,
    "ACG-001-confidential-client-basic": _UNTYPED,
    "ACG-004-code-verifier": _UNTYPED,
    "ACG-005-invalid-grant": (
        "token errors are not parsed into a typed OAuth error (#791)"
    ),
}


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
                        reason=_KNOWN_GAPS[param_id], raises=KnownGap, strict=True
                    )
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
        routes[path] = respx.route(url=_BASE + path).mock(
            return_value=httpx.Response(resp["status"], content=body, headers=headers)
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
        assert form.get(name, "") == value, (
            f"form {name}: {form.get(name)!r} != {value!r}"
        )


def _run_pkce(case_id: str, vector: dict) -> None:
    inp, result = vector["input"], vector["expect"]["result"]
    if inp["operation"] == "generate_code_verifier":
        samples = result["distinct_samples"]
        assert samples >= _MIN_SAMPLES, f"{case_id}: distinct_samples = {samples}"
        verifiers = [generate_code_verifier() for _ in range(samples)]
        for verifier in verifiers:
            assert result["min_length"] <= len(verifier) <= result["max_length"]
            assert set(verifier) <= set(result["alphabet"]), f"{case_id}: {verifier!r}"
        assert len(set(verifiers)) == samples, f"{case_id}: repeated verifier"
    elif inp["operation"] == "s256_challenge":
        challenge = generate_code_challenge(inp["code_verifier"], "S256")
        assert challenge == result["code_challenge"]
    else:
        pytest.fail(f"{case_id}: unknown operation {inp['operation']!r}")


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_authorization_code_vector(case_id: str, vector: dict) -> None:
    if "operation" in vector["input"]:
        _run_pkce(case_id, vector)
        return

    routes = _mock(vector)
    inp = vector["input"]
    response = request_authorization_code_token(
        AuthorizationCodeTokenRequest(
            address=_BASE + "/token",
            client_id="cid",
            code=inp["code"],
            redirect_uri=inp["redirect_uri"],
            code_verifier=inp.get("code_verifier"),
            client_secret=inp.get("client_secret"),
        )
    )

    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        assert response.token is not None
        result = expect.get("result", {})
        # Until the typed members land (#783), check the raw values first.
        for name, value in result.items():
            assert response.token.get(name) == value, f"{case_id}: {name}"
        for name, value in result.items():
            if not hasattr(response, name):
                raise KnownGap(f"{case_id}: no typed member {name} (#783)")
            assert getattr(response, name) == value, f"{case_id}: typed {name}"
    elif expect["outcome"] == "reject":
        assert not response.is_successful, f"{case_id}: expected reject"
        assert f"status code: {expect['status']}" in (response.error or "")
        # The error code appears in the raw body (and in the error_uri), so a
        # substring check proves nothing until the error is typed (#791).
        raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")
