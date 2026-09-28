"""Thin Python executor for the shared JWKS vectors (spec/vectors/jwks.json).

Each vector's canned responses are served with respx at the fixture host, its
steps run against the library's JWKS cache, and the resulting keys (or error)
and the per-path request counts are asserted. The Go and Rust runners execute
the same file.

py-identity-model keeps its JWKS cache inside token validation, so the steps use
the helpers validate_token uses: ``fetch`` is ``_get_cached_jwks`` plus
``validate_jwks_response``, ``force_refresh`` is ``_refresh_jwks``, and
``resolve`` is ``_discover_and_resolve_key`` with a token header carrying the
kid and a discovery document pointing at /jwks. Errors are messages on
``TokenValidationException``, so a reject is asserted by its message.
"""

import base64
import json
from pathlib import Path

import httpx
import pytest
import respx

from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.token_validation_logic import validate_jwks_response
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.token_validation import (
    _discover_and_resolve_key,
    _get_cached_jwks,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)


def _find_repo_root() -> Path:
    marker = Path("spec") / "vectors" / "jwks.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"
_CASES = json.loads((_REPO_ROOT / "spec" / "vectors" / "jwks.json").read_text())[
    "tests"
]
_BASE = "https://server.example.com"
_JWKS_URI = _BASE + "/jwks"
_DISCO_PATH = "/.well-known/openid-configuration"
_DISCOVERY = {
    "issuer": _BASE,
    "authorization_endpoint": _BASE + "/authorize",
    "token_endpoint": _BASE + "/token",
    "jwks_uri": _JWKS_URI,
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256", "ES256"],
}
_MEMBERS = ("kty", "kid", "use", "alg", "n", "e", "crv", "x", "y")

#: Message each canonical reject code is surfaced with.
_ERRORS = {
    "malformed": "Invalid JSON",
    "empty_key_set": "No keys available",
    "key_not_found": "No matching kid found",
}


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


#: Vectors py-identity-model does not meet yet. Strict, and pinned to KnownGap,
#: so a fix (or a different failure) fails the suite until the entry is removed.
_KNOWN_GAPS = {
    "JWKS-007-malformed-json": (
        "a non-JSON JWKS body is reported as an unhandled exception, "
        "not a parse error (#770)"
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


def _response(resp: dict) -> httpx.Response:
    body = b""
    if "body_fixture" in resp:
        body = (_FIXTURE_ROOT / resp["body_fixture"]).read_bytes()
    headers = {"Content-Type": "application/json"} if body else {}
    return httpx.Response(resp["status"], content=body, headers=headers)


def _mock(vector: dict) -> dict[str, respx.Route]:
    routes = {}
    for path, resp in vector.get("http", {}).items():
        routes[path] = respx.get(_BASE + path).mock(return_value=_response(resp))
    for path, seq in vector.get("http_sequence", {}).items():
        responses = [_response(r) for r in seq]
        routes[path] = respx.get(_BASE + path).mock(
            side_effect=lambda _request, route, r=responses: r[
                min(route.call_count, len(r) - 1)
            ]
        )
    respx.get(_BASE + _DISCO_PATH).mock(
        return_value=httpx.Response(200, json=_DISCOVERY)
    )
    return routes


def _token_with_kid(kid: str) -> str:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'kid': kid})}.{b64({})}.sig"


def _run_step(step: str, kid: str | None) -> list[dict]:
    if step == "fetch":
        response = _get_cached_jwks(_JWKS_URI)
        validate_jwks_response(response)
        return [k.as_dict() for k in response.keys or []]
    if step == "force_refresh":
        response, _ = _refresh_jwks(_JWKS_URI)
        validate_jwks_response(response)
        return [k.as_dict() for k in response.keys or []]
    if step == "resolve":
        key, _, _, _ = _discover_and_resolve_key(
            _token_with_kid(kid or ""),
            _BASE + _DISCO_PATH,
            None,
            DiscoveryPolicy(),
        )
        return [key]
    pytest.fail(f"unknown step {step!r}")


def _run_steps(vector: dict) -> list[dict]:
    inp = vector["input"]
    # Each resolve takes the next of input.kids when given, else input.kid.
    kids = iter(inp.get("kids", []))
    steps = inp["steps"]
    keys: list[dict] = []
    for n, step in enumerate(steps, 1):
        kid = next(kids, inp.get("kid")) if step == "resolve" else None
        try:
            keys = _run_step(step, kid)
        except TokenValidationException as exc:
            # A key-not-found miss before the last step does not end the run.
            if n == len(steps) or _ERRORS["key_not_found"] not in str(exc):
                raise
            keys = []
    return [{m: k[m] for m in _MEMBERS if k.get(m)} for k in keys]


@pytest.mark.parametrize(("case_id", "vector"), _params())
@respx.mock
def test_jwks_vector(case_id: str, vector: dict) -> None:
    clear_jwks_cache()
    clear_discovery_cache()
    routes = _mock(vector)

    expect = vector["expect"]
    if expect["outcome"] == "accept":
        assert _run_steps(vector) == expect["keys"]
    elif expect["outcome"] == "reject":
        with pytest.raises(TokenValidationException) as excinfo:
            _run_steps(vector)
        message = str(excinfo.value)
        if expect["error"] == "malformed" and "Unhandled exception" in message:
            raise KnownGap(f"{case_id}: non-JSON body reported as {message!r}")
        assert _ERRORS[expect["error"]] in message
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")

    want = vector.get("expect_request")
    if want:
        route = routes[want["path"]]
        assert route.called, f"no request to {want['path']}"
        assert route.calls.last.request.method == want["method"]
    for path, count in vector.get("expect_calls", {}).items():
        assert routes[path].call_count == count, f"requests to {path}"
