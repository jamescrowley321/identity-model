"""Thin Python executor for the shared token exchange vectors (spec/vectors/token-exchange.json).

Each vector's canned responses are served with respx at the fixture host, the
call is made through ``exchange_token``, and the outcome and the request the
client sent are asserted. The Go and Rust runners execute the same file.

py-identity-model surfaces token exchange errors as a message on an
unsuccessful response rather than a typed error, so a reject is asserted by
finding the error code, HTTP status and error members in that message.
"""

import inspect
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from py_identity_model import ClientAuthMethod
from py_identity_model.sync.token_exchange import (
    TokenExchangeRequest,
    exchange_token,
)


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "token-exchange.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads(
    (_REPO_ROOT / "spec" / "vectors" / "token-exchange.json").read_text()
)["tests"]
_BASE = "https://server.example.com"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


_UNTYPED = "TokenExchangeResponse has no typed token members (#783)"

#: Vectors py-identity-model does not meet yet. Strict, and pinned to KnownGap,
#: so a fix (or a different failure) fails the suite until the entry is removed.
_KNOWN_GAPS = {
    "EXCH-001-impersonation": _UNTYPED,
    "EXCH-001-client-secret-post": (
        "TokenExchangeRequest has no client_secret_post option (#574)"
    ),
    "EXCH-002-delegation": _UNTYPED,
    "EXCH-005-n_a-token-type": _UNTYPED,
    "EXCH-005-optional-fields": _UNTYPED,
    "EXCH-006-invalid-request": "the error_uri is dropped from the error (#777)",
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
        have = form.get(name, "")
        assert have == value, f"form {name}: {have!r} != {value!r}"


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_token_exchange_vector(case_id: str, vector: dict) -> None:
    routes = _mock(vector)
    inp = vector["input"]
    kwargs: dict[str, Any] = {}
    if inp.get("client_auth") == "client_secret_post":
        if (
            "client_auth_method"
            not in inspect.signature(TokenExchangeRequest).parameters
        ):
            raise KnownGap("TokenExchangeRequest has no client_auth_method")
        kwargs["client_auth_method"] = ClientAuthMethod.CLIENT_SECRET_POST
    response = exchange_token(
        TokenExchangeRequest(
            address=_BASE + "/token",
            client_id="cid",
            client_secret="secret",
            subject_token=inp["subject_token"],
            subject_token_type=inp["subject_token_type"],
            actor_token=inp.get("actor_token"),
            actor_token_type=inp.get("actor_token_type"),
            resource=inp.get("resource"),
            audience=inp.get("audience"),
            scope=inp.get("scope"),
            requested_token_type=inp.get("requested_token_type"),
            **kwargs,
        )
    )

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
        message = response.error or ""
        assert f"status code: {expect['status']}" in message
        assert f"Error: {expect['error']}" in message
        assert expect["error_description"] in message
        if "error_uri" in expect and expect["error_uri"] not in message:
            raise KnownGap(f"{case_id}: error_uri missing from {message!r}")
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")

    want = vector.get("expect_request")
    if want:
        _assert_request(routes[want["path"]], want)
