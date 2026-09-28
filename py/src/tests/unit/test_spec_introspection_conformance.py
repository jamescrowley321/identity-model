"""Thin Python executor for the shared introspection vectors (spec/vectors/introspection.json).

Each vector's canned responses are served with respx at the fixture host, the
call is made through ``introspect_token``, and the request the client sent and
the outcome are asserted. The Go and Rust runners execute the same file.

py-identity-model surfaces introspection errors as a message on an unsuccessful
response rather than a typed error, so a reject is asserted by finding the
canonical ``error`` code and the HTTP status in that message.
"""

import inspect
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model import (
    ClientAuthMethod,
    DiscoveryDocumentRequest,
    get_discovery_document,
)
from py_identity_model.sync.introspection import (
    TokenIntrospectionRequest,
    introspect_token,
)


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "introspection.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads(
    (_REPO_ROOT / "spec" / "vectors" / "introspection.json").read_text()
)["tests"]
_BASE = "https://server.example.com"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


#: Vectors py-identity-model does not meet yet, keyed by parametrize id. Strict,
#: and pinned to KnownGap, so a fix (or a different failure) fails the suite
#: until the entry is removed.
_KNOWN_GAPS = {
    "INTR-001-active-token": "TokenIntrospectionResponse has no typed §2.2 members (#772)",
    "INTR-001-missing-active": "a response with no active member is accepted (#782)",
    "INTR-001-active-not-boolean": "a non-boolean active member is accepted (#782)",
    "INTR-002-inactive-token": "TokenIntrospectionResponse has no typed §2.2 members (#772)",
    "INTR-003-client-secret-post": (
        "TokenIntrospectionRequest has no client_secret_post option (#574)"
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
        return _BASE + "/introspect"
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=_BASE + "/.well-known/openid-configuration")
    )
    assert disco.is_successful, disco.error
    assert disco.introspection_endpoint, "discovery has no introspection_endpoint"
    return disco.introspection_endpoint


def _request(vector: dict) -> TokenIntrospectionRequest:
    inp = vector["input"]
    kwargs: dict[str, Any] = {}
    if inp.get("client_auth") == "client_secret_post":
        if (
            "client_auth_method"
            not in inspect.signature(TokenIntrospectionRequest).parameters
        ):
            raise KnownGap("TokenIntrospectionRequest has no client_auth_method")
        kwargs["client_auth_method"] = ClientAuthMethod.CLIENT_SECRET_POST
    return TokenIntrospectionRequest(
        address=_endpoint(vector),
        token=inp["token"],
        token_type_hint=inp.get("token_type_hint"),
        client_id="cid",
        client_secret=inp.get("client_secret", "secret"),
        **kwargs,
    )


def _assert_request(route: respx.Route, want: dict) -> None:
    """An empty expected header or form value means the key must be absent."""
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
    form = parse_qs(request.content.decode(), keep_blank_values=True)
    for name, value in want.get("form", {}).items():
        if not value:
            assert name not in form, f"form {name} must be absent"
            continue
        have = form.get(name, [""])[0]
        assert have == value, f"form {name}: {have!r} != {value!r}"


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_introspection_vector(case_id: str, vector: dict) -> None:
    routes = _mock(vector)
    response = introspect_token(_request(vector))
    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        claims = response.claims or {}
        for name, value in expect.get("custom_claims", {}).items():
            assert claims.get(name) == value, f"overflow member {name}"
        # Until the typed members land (#772), check active in the raw map.
        if "active" in expect.get("claims", {}):
            assert claims.get("active") is expect["claims"]["active"], "active"
        for name, value in expect.get("claims", {}).items():
            if not hasattr(response, name):
                raise KnownGap(f"{case_id}: no typed member {name} (#772)")
            assert getattr(response, name) == value, f"typed member {name}"
    elif expect["outcome"] == "reject":
        if response.is_successful and expect["error"] == "malformed":
            raise KnownGap(f"{case_id}: malformed response accepted (#782)")
        assert not response.is_successful, f"{case_id}: expected reject"
        assert expect["error"] in (response.error or "")
        assert f"status code: {expect['status']}" in (response.error or "")
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")
