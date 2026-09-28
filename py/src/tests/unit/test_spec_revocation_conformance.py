"""Thin Python executor for the shared revocation vectors (spec/vectors/revocation.json).

Each vector's canned responses are served with respx at the fixture host, the
call is made through ``revoke_token``, and the outcome and the request the
client sent are asserted. The Go and Rust runners execute the same file.

py-identity-model surfaces revocation errors as the raw response body in a
message on an unsuccessful response rather than a typed error (#791), so a
reject checks the HTTP status and then raises ``KnownGap``: the ``error`` code
cannot be compared against a parsed member.
"""

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.sync.revocation import (
    TokenRevocationRequest,
    revoke_token,
)


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "revocation.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads((_REPO_ROOT / "spec" / "vectors" / "revocation.json").read_text())[
    "tests"
]
_BASE = "https://server.example.com"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


_UNTYPED_ERROR = "revocation errors are not parsed into a typed OAuth error (#791)"

#: Vectors py-identity-model does not meet yet, keyed by parametrize id. Strict,
#: and pinned to KnownGap, so a fix (or a different failure) fails the suite
#: until the entry is removed.
_KNOWN_GAPS = {
    "REV-003-unsupported-token-type": _UNTYPED_ERROR,
    "REV-004-invalid-client": _UNTYPED_ERROR,
    "REV-005-endpoint-from-discovery": (
        "DiscoveryDocumentResponse has no revocation_endpoint (#766)"
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


def _endpoint(vector: dict) -> str:
    if not vector["input"].get("discover"):
        return _BASE + "/revoke"
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=_BASE + "/.well-known/openid-configuration")
    )
    assert disco.is_successful, disco.error
    endpoint = getattr(disco, "revocation_endpoint", None)
    if endpoint is None:
        raise KnownGap("DiscoveryDocumentResponse has no revocation_endpoint (#766)")
    return endpoint


def _assert_request(route: respx.Route, want: dict) -> None:
    assert route.called, f"no request to {want['path']}"
    request = route.calls.last.request
    assert request.method == want["method"]
    for name, value in want.get("headers", {}).items():
        have = request.headers.get(name, "")
        if name.lower() == "content-type":
            have = have.split(";")[0].strip()
        assert have == value, f"header {name}: {have!r} != {value!r}"
    form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
    for name, value in want.get("form", {}).items():
        assert form.get(name) == value, f"form {name}: {form.get(name)!r} != {value!r}"


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_revocation_vector(case_id: str, vector: dict) -> None:
    routes = _mock(vector)
    inp = vector["input"]
    response = revoke_token(
        TokenRevocationRequest(
            address=_endpoint(vector),
            token=inp["token"],
            token_type_hint=inp.get("token_type_hint"),
            client_id="cid",
            client_secret="secret",
        )
    )

    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
    elif expect["outcome"] == "reject":
        assert not response.is_successful, f"{case_id}: expected reject"
        assert f"status code: {expect['status']}" in (response.error or "")
        # The error code appears in the raw body (and in any error_uri), so a
        # substring check proves nothing until the error is typed (#791).
        raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")
