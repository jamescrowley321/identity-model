"""Python runner for the shared HTTP vectors (spec/vectors/*.json).

The node-oidc fixture serves each vector's canned responses under its own base
URL (infra/node-oidc-provider/vectors.js). Per vector, the capability's adapter
calls py-identity-model against that base URL, the fixture's ``_check`` must
report that the client sent the expected requests, and the adapter compares the
result with ``expect``. The Go and Rust runners execute the same files.

A vector py-identity-model does not meet yet is a strict ``xfail`` pinned to
``KnownGap``, raised exactly where the gap shows, so a fix (or a different
failure) fails the suite until the entry is removed.
"""

import base64
from collections.abc import Callable
import json
from pathlib import Path
from typing import Any, NamedTuple
import uuid

import httpx
import pytest

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.token_validation_logic import validate_jwks_response
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.revocation import TokenRevocationRequest, revoke_token
from py_identity_model.sync.token_validation import (
    _discover_and_resolve_key,
    _get_cached_jwks,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.sync.userinfo import UserInfoRequest, get_userinfo


VECTOR_OP = "http://localhost:9010"
_RUN = uuid.uuid4().hex
_DISCO_PATH = "/.well-known/openid-configuration"


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "vectors").is_dir():
            return parent
    raise RuntimeError("spec/vectors not found above this file")


_VECTORS_DIR = _find_repo_root() / "spec" / "vectors"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


class Adapter(NamedTuple):
    """Calls py-identity-model for one vector, and checks the result.

    Keyed by vector file name (``spec/vectors/<name>.json``).
    """

    call: Callable[[str, dict], Any]
    expect: Callable[[str, dict, Any], None]


# --- revocation ---------------------------------------------------------------


def _revocation_call(base: str, inp: dict) -> Any:
    endpoint = base + "/revoke"
    if inp.get("discover"):
        disco = get_discovery_document(
            DiscoveryDocumentRequest(address=base + _DISCO_PATH)
        )
        assert disco.is_successful, disco.error
        endpoint = getattr(disco, "revocation_endpoint", None)
        if endpoint is None:
            raise KnownGap(
                "DiscoveryDocumentResponse has no revocation_endpoint (#766)"
            )
    return revoke_token(
        TokenRevocationRequest(
            address=endpoint,
            token=inp["token"],
            token_type_hint=inp.get("token_type_hint"),
            client_id="cid",
            client_secret="secret",
        )
    )


def _revocation_expect(case_id: str, expect: dict, response: Any) -> None:
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        return
    assert not response.is_successful, f"{case_id}: expected reject"
    assert f"status code: {expect['status']}" in (response.error or "")
    # The error code appears in the raw body (and in any error_uri), so a
    # substring check proves nothing until the error is typed (#791).
    raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")


# --- userinfo -----------------------------------------------------------------


def _userinfo_call(base: str, inp: dict) -> Any:
    return get_userinfo(
        UserInfoRequest(
            address=base + "/userinfo",
            token=inp["token"],
            expected_sub=inp.get("expected_sub"),
        )
    )


def _userinfo_expect(case_id: str, expect: dict, response: Any) -> None:
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        claims = response.claims or {}
        for name, value in expect.get("custom_claims", {}).items():
            assert claims.get(name) == value, f"claim map {name}"
        for name, value in expect.get("claims", {}).items():
            if not hasattr(response, name):
                raise KnownGap("UserInfoResponse has no typed standard claims (#768)")
            assert getattr(response, name) == value, f"typed claim {name}"
        return
    error = expect.get("error")
    if error == "missing_sub" and response.is_successful:
        raise KnownGap("a response with no sub is accepted without expected_sub (#773)")
    assert not response.is_successful, f"{case_id}: expected reject"
    if error == "subject_mismatch":
        assert "sub mismatch" in (response.error or "")
        return
    if error == "missing_sub":
        assert "missing required 'sub' claim" in (response.error or "")
        return
    assert not error, f"{case_id}: unknown expected error {error!r}"
    assert f"status code: {expect['status']}" in (response.error or "")
    if not hasattr(response, "www_authenticate"):
        raise KnownGap(
            "UserInfoResponse does not carry the WWW-Authenticate challenge (#769)"
        )
    assert response.www_authenticate == expect.get("www_authenticate")


# --- jwks ---------------------------------------------------------------------
#
# py-identity-model keeps its JWKS cache inside token validation, so the steps
# use the helpers validate_token uses: ``fetch`` is ``_get_cached_jwks`` plus
# ``validate_jwks_response``, ``force_refresh`` is ``_refresh_jwks``, and
# ``resolve`` is ``_discover_and_resolve_key`` with a token header carrying the
# kid. Errors are messages on ``TokenValidationException``.

_JWK_MEMBERS = ("kty", "kid", "use", "alg", "n", "e", "crv", "x", "y")

#: Message each canonical reject code is surfaced with.
_JWKS_ERRORS = {
    "malformed": "Invalid JSON",
    "empty_key_set": "No keys available",
    "key_not_found": "No matching kid found",
}


def _token_with_kid(kid: str) -> str:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'kid': kid})}.{b64({})}.sig"


def _jwks_step(base: str, step: str, kid: str | None) -> list[dict]:
    jwks_uri = base + "/jwks"
    if step == "fetch":
        response = _get_cached_jwks(jwks_uri)
        validate_jwks_response(response)
        return [k.as_dict() for k in response.keys or []]
    if step == "force_refresh":
        response, _ = _refresh_jwks(jwks_uri)
        validate_jwks_response(response)
        return [k.as_dict() for k in response.keys or []]
    if step == "resolve":
        key, _, _, _ = _discover_and_resolve_key(
            _token_with_kid(kid or ""), base + _DISCO_PATH, None, DiscoveryPolicy()
        )
        return [key]
    pytest.fail(f"unknown jwks step {step!r}")


def _jwks_call(base: str, inp: dict) -> list[dict] | TokenValidationException:
    clear_jwks_cache()
    clear_discovery_cache()
    # Each resolve takes the next of input.kids when given, else input.kid.
    kids = iter(inp.get("kids", []))
    steps = inp["steps"]
    keys: list[dict] = []
    for n, step in enumerate(steps, 1):
        kid = next(kids, inp.get("kid")) if step == "resolve" else None
        try:
            keys = _jwks_step(base, step, kid)
        except TokenValidationException as exc:
            # A key-not-found miss before the last step does not end the run.
            if n == len(steps) or _JWKS_ERRORS["key_not_found"] not in str(exc):
                return exc
            keys = []
    return [{m: k[m] for m in _JWK_MEMBERS if k.get(m)} for k in keys]


def _jwks_expect(case_id: str, expect: dict, result: Any) -> None:
    if expect["outcome"] == "accept":
        assert not isinstance(result, Exception), f"{case_id}: {result}"
        assert result == expect["keys"]
        return
    assert isinstance(result, TokenValidationException), f"{case_id}: {result!r}"
    message = str(result)
    if expect["error"] == "malformed" and "Unhandled exception" in message:
        raise KnownGap(
            f"{case_id}: a non-JSON JWKS body is reported as {message!r}, "
            "not a parse error (#770)"
        )
    assert _JWKS_ERRORS[expect["error"]] in message


ADAPTERS: dict[str, Adapter] = {
    "revocation": Adapter(_revocation_call, _revocation_expect),
    "userinfo": Adapter(_userinfo_call, _userinfo_expect),
    "jwks": Adapter(_jwks_call, _jwks_expect),
}

#: Vectors py-identity-model does not meet yet, by parametrize id or case id.
_KNOWN_GAPS = {
    "REV-003-unsupported-token-type": "revocation errors are untyped (#791)",
    "REV-004-invalid-client": "revocation errors are untyped (#791)",
    "REV-005-endpoint-from-discovery": "no revocation_endpoint in discovery (#766)",
    "UI-001": "UserInfoResponse has no typed standard claims (#768)",
    "UI-003-missing-sub": "no-sub response accepted without expected_sub (#773)",
    "UI-004": "UserInfoResponse has no WWW-Authenticate challenge (#769)",
    "UI-005": "UserInfoResponse has no WWW-Authenticate challenge (#769)",
    "UI-006": "UserInfoResponse has no WWW-Authenticate challenge (#769)",
    "UI-007": "UserInfoResponse has no typed standard claims (#768)",
    "JWKS-007-malformed-json": "non-JSON JWKS body is not a parse error (#770)",
}


def _is_http(vector: dict) -> bool:
    return "http" in vector or "http_sequence" in vector


def _params() -> list:
    params = []
    for path in sorted(_VECTORS_DIR.glob("*.json")):
        capability = path.stem
        for case in json.loads(path.read_text()).get("tests", []):
            vectors = case.get("vectors", [])
            if capability in ADAPTERS:
                assert vectors, f"{case['id']}: case has no vectors"
            for idx, vector in enumerate(vectors):
                if not _is_http(vector):
                    continue
                key = vector.get("name") or str(idx)
                param_id = f"{case['id']}-{key}"
                reason = _KNOWN_GAPS.get(param_id) or _KNOWN_GAPS.get(case["id"])
                marks = []
                if reason:
                    marks.append(
                        pytest.mark.xfail(reason=reason, raises=KnownGap, strict=True)
                    )
                params.append(
                    pytest.param(
                        capability, case["id"], key, vector, id=param_id, marks=marks
                    )
                )
    return params


@pytest.fixture(scope="module", autouse=True)
def _vector_op() -> None:
    try:
        httpx.get(VECTOR_OP + _DISCO_PATH, timeout=5).raise_for_status()
    except httpx.HTTPError as exc:
        pytest.fail(
            f"node-oidc fixture not reachable at {VECTOR_OP} "
            f"(run `make test-integration-node-oidc`): {exc}"
        )


@pytest.mark.parametrize(("capability", "case_id", "key", "vector"), _params())
def test_http_vector(capability: str, case_id: str, key: str, vector: dict) -> None:
    adapter = ADAPTERS.get(capability)
    assert adapter, f"{capability}.json has HTTP vectors but no adapter"
    base = f"{VECTOR_OP}/v/{_RUN}/{capability}/{case_id}/{key}"

    result = adapter.call(base, vector["input"])
    check = httpx.get(base + "/_check", timeout=5).json()
    assert check["ok"], f"{case_id}: {check['diffs']}"
    adapter.expect(case_id, vector["expect"], result)
