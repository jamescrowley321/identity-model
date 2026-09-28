"""Thin Python executor for the shared client credentials vectors (spec/vectors/client-credentials.json).

Each vector's canned responses are served with respx at the fixture host, the
call is made through ``request_client_credentials_token``, and the request the
client sent and the outcome are asserted. The Go and Rust runners execute the
same file.

py-identity-model surfaces token errors as the raw response body in a message
on an unsuccessful response rather than a typed error (#791), so a reject
checks the HTTP status and then raises ``KnownGap``: the error members cannot
be compared against parsed values.
"""

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model import ClientAuthMethod
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_client import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "client-credentials.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads(
    (_REPO_ROOT / "spec" / "vectors" / "client-credentials.json").read_text()
)["tests"]
_BASE = "https://server.example.com"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


#: Vectors py-identity-model does not meet yet, keyed by parametrize id. Strict,
#: and pinned to KnownGap, so a fix (or a different failure) fails the suite
#: until the entry is removed.
_KNOWN_GAPS = {
    "CC-003-client-secret-post": (
        "ClientCredentialsTokenRequest has no client_secret_post option (#574)"
    ),
    "CC-004-invalid-client": (
        "token errors are not parsed into a typed OAuth error (#791)"
    ),
    "CC-006-extra-params": (
        "ClientCredentialsTokenRequest has no extra parameters (#778)"
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


def _require_field(name: str, gap: str) -> None:
    if name not in ClientCredentialsTokenRequest.__dataclass_fields__:
        raise KnownGap(f"ClientCredentialsTokenRequest has no {name} ({gap})")


def _request(inp: dict) -> ClientCredentialsTokenRequest:
    kwargs: dict[str, Any] = {}
    if inp.get("client_auth") == "client_secret_post":
        _require_field("client_auth_method", "#574")
        kwargs["client_auth_method"] = ClientAuthMethod.CLIENT_SECRET_POST
    if "extra_params" in inp:
        _require_field("extra_params", "#778")
        kwargs["extra_params"] = inp["extra_params"]
    return ClientCredentialsTokenRequest(
        address=_BASE + "/token",
        client_id="cid",
        client_secret=inp.get("client_secret", "secret"),
        scope=" ".join(inp["scopes"]) if "scopes" in inp else None,
        **kwargs,
    )


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


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_client_credentials_vector(case_id: str, vector: dict) -> None:
    routes = _mock(vector)
    inp = vector["input"]
    http_client = None
    if "http_client_headers" in inp:
        http_client = HTTPClient(
            client=httpx.Client(headers=inp["http_client_headers"])
        )
    response = request_client_credentials_token(_request(inp), http_client)
    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        assert response.token is not None
        for name, value in expect.get("result", {}).items():
            assert response.token.get(name) == value, f"{case_id}: {name}"
    elif expect["outcome"] == "reject":
        assert not response.is_successful, f"{case_id}: expected reject"
        assert f"status code: {expect['status']}" in (response.error or "")
        # The error code appears in the raw body (and in the error_uri), so a
        # substring check proves nothing until the error is typed (#791).
        raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")
