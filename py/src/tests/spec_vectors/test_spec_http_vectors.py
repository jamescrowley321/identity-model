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
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NamedTuple
import uuid

import httpx
import pytest

from py_identity_model import (
    ClientAuthMethod,
    DiscoveryDocumentRequest,
    DiscoveryErrorKind,
    get_discovery_document,
)
from py_identity_model.core import jwks_cache
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.models import AuthorizationCodeTokenRequest
from py_identity_model.core.token_validation_logic import validate_jwks_response
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync import token_validation
from py_identity_model.sync.introspection import (
    TokenIntrospectionRequest,
    introspect_token,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.revocation import TokenRevocationRequest, revoke_token
from py_identity_model.sync.token_client import (
    ClientCredentialsTokenRequest,
    request_authorization_code_token,
    request_client_credentials_token,
)
from py_identity_model.sync.token_exchange import (
    TokenExchangeRequest,
    exchange_token,
)
from py_identity_model.sync.token_validation import (
    _discover_and_resolve_key,
    _get_cached_jwks,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.sync.userinfo import UserInfoRequest, get_userinfo


VECTOR_OP = "http://localhost:9010"
#: Placeholder host in fixtures and expected results; the fixture serves it
#: rewritten to the vector's base URL.
_FIXTURE_HOST = "https://server.example.com"
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


# --- token-exchange -----------------------------------------------------------


def _token_exchange_call(base: str, inp: dict) -> Any:
    kwargs: dict[str, Any] = {}
    if inp.get("client_auth") == "client_secret_post":
        if (
            "client_auth_method"
            not in inspect.signature(TokenExchangeRequest).parameters
        ):
            raise KnownGap("TokenExchangeRequest has no client_auth_method")
        kwargs["client_auth_method"] = ClientAuthMethod.CLIENT_SECRET_POST
    return exchange_token(
        TokenExchangeRequest(
            address=base + "/token",
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


def _token_exchange_expect(case_id: str, expect: dict, response: Any) -> None:
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
        return
    assert not response.is_successful, f"{case_id}: expected reject"
    message = response.error or ""
    assert f"status code: {expect['status']}" in message
    if "error_uri" in expect and expect["error_uri"] not in message:
        raise KnownGap(f"{case_id}: error_uri missing from {message!r}")
    # The error members appear in the raw body, so substring checks prove
    # nothing until the error is typed (#791).
    if not hasattr(response, "error_code"):
        raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")
    assert response.error_code == expect["error"], f"{case_id}: error"
    for name in ("error_description", "error_uri"):
        if name in expect:
            assert getattr(response, name) == expect[name], f"{case_id}: {name}"


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


# --- authorization-code -------------------------------------------------------
#
# The HTTP vectors (the code exchange). The pure-logic PKCE vectors
# (input.operation) run in-process in src/tests/unit/test_spec_logic_vectors.py.


def _authorization_code_call(base: str, inp: dict) -> Any:
    return request_authorization_code_token(
        AuthorizationCodeTokenRequest(
            address=base + "/token",
            client_id="cid",
            code=inp["code"],
            redirect_uri=inp["redirect_uri"],
            code_verifier=inp.get("code_verifier"),
            client_secret=inp.get("client_secret"),
        )
    )


def _authorization_code_expect(case_id: str, expect: dict, response: Any) -> None:
    if expect["outcome"] == "accept":
        _token_exchange_expect(case_id, expect, response)
        return
    assert not response.is_successful, f"{case_id}: expected reject"
    assert f"status code: {expect['status']}" in (response.error or "")
    # The error code appears in the raw body (and in the error_uri), so a
    # substring check proves nothing until the error is typed (#791).
    raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")


# --- client-credentials -------------------------------------------------------


def _require_cc_field(name: str, gap: str) -> None:
    if name not in ClientCredentialsTokenRequest.__dataclass_fields__:
        raise KnownGap(f"ClientCredentialsTokenRequest has no {name} ({gap})")


def _client_credentials_call(base: str, inp: dict) -> Any:
    kwargs: dict[str, Any] = {}
    if inp.get("client_auth") == "client_secret_post":
        _require_cc_field("client_auth_method", "#574")
        kwargs["client_auth_method"] = ClientAuthMethod.CLIENT_SECRET_POST
    if "extra_params" in inp:
        _require_cc_field("extra_params", "#778")
        kwargs["extra_params"] = inp["extra_params"]
    request = ClientCredentialsTokenRequest(
        address=base + "/token",
        client_id="cid",
        client_secret=inp.get("client_secret", "secret"),
        scope=" ".join(inp["scopes"]) if "scopes" in inp else None,
        **kwargs,
    )
    http_client = None
    if "http_client_headers" in inp:
        http_client = HTTPClient(
            client=httpx.Client(headers=inp["http_client_headers"])
        )
    return request_client_credentials_token(request, http_client)


def _client_credentials_expect(case_id: str, expect: dict, response: Any) -> None:
    if expect["outcome"] == "accept":
        assert response.is_successful, f"{case_id}: {response.error}"
        assert response.token is not None
        for name, value in expect.get("result", {}).items():
            assert response.token.get(name) == value, f"{case_id}: {name}"
        return
    assert not response.is_successful, f"{case_id}: expected reject"
    assert f"status code: {expect['status']}" in (response.error or "")
    # The error code appears in the raw body (and in the error_uri), so a
    # substring check proves nothing until the error is typed (#791).
    raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")


# --- discovery ----------------------------------------------------------------
#
# The public fetch API is uncached. TTL vectors therefore use the private
# _get_disco_response path used by token validation; misses still call the public
# API and send real HTTP requests. Only the cache modules' local time references
# are replaced, using one clock for both insertion and expiry. The stdlib clock
# and HTTP timing remain real. Rejections compare library-produced structured
# error codes, exact HTTP statuses, and exact missing-field sets.


def _discovery_call(base: str, inp: dict) -> tuple[str, list]:
    address = base + _DISCO_PATH
    # The fixture is plain HTTP on loopback; require_https also withdraws the
    # loopback exemption so the HTTPS requirement applies.
    policy = (
        DiscoveryPolicy(allow_http_on_loopback=False)
        if inp.get("require_https")
        else DiscoveryPolicy()
    )
    if "calls_at_seconds" not in inp:
        request = DiscoveryDocumentRequest(address=address, policy=policy)
        return base, [get_discovery_document(request)]
    responses = []
    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("DISCO_CACHE_TTL", str(inp["cache_ttl_seconds"]))
            jwks_cache._reset_env_for_testing()
            now = [0.0]
            cache_clock = SimpleNamespace(monotonic=lambda: now[0])
            mp.setattr(token_validation, "time", cache_clock)
            mp.setattr(jwks_cache, "time", cache_clock)
            token_validation.clear_discovery_cache()
            start = now[0]
            for at in inp["calls_at_seconds"]:
                now[0] = start + at
                responses.append(token_validation._get_disco_response(address, policy))
    finally:
        # After the env var is restored, so the cache re-reads the default TTL.
        token_validation.clear_discovery_cache()
        jwks_cache._reset_env_for_testing()
    return base, responses


def _discovery_expect(case_id: str, expect: dict, result: Any) -> None:
    base, responses = result
    response = responses[-1]
    if expect["outcome"] == "accept":
        for r in responses:
            assert r.is_successful, f"{case_id}: {r.error}"
        want = json.loads(
            json.dumps(expect.get("result", {})).replace(_FIXTURE_HOST, base)
        )
        for name, value in want.items():
            assert getattr(response, name) == value, f"{case_id}: {name}"
        return
    if (
        case_id == "DISC-003"
        and expect["error"] == "issuer_mismatch"
        and response.is_successful
        and response.issuer == "https://attacker.example.com"
    ):
        raise KnownGap(f"{case_id}: issuer mismatch accepted (#574)")
    assert not response.is_successful, f"{case_id}: expected reject, got accept"
    assert response.error_kind is DiscoveryErrorKind(expect["error"]), (
        f"{case_id}: expected {expect['error']}, got {response.error_kind}: {response.error}"
    )
    if expect["error"] == "unexpected_status":
        assert response.status_code == expect["status"], f"{case_id}: HTTP status"
    if expect["error"] == "missing_fields":
        observed = set(response.missing_fields)
        expected = set(expect["fields"])
        if (
            case_id == "DISC-008"
            and expected == {"token_endpoint", "subject_types_supported"}
            and observed == {"subject_types_supported"}
        ):
            raise KnownGap(f"{case_id}: token_endpoint not required (#771)")
        assert observed == expected, (
            f"{case_id}: missing fields {sorted(observed)}, expected {sorted(expected)}"
        )


# --- introspection ------------------------------------------------------------


def _introspection_call(base: str, inp: dict) -> Any:
    endpoint = base + "/introspect"
    if inp.get("discover"):
        disco = get_discovery_document(
            DiscoveryDocumentRequest(address=base + _DISCO_PATH)
        )
        assert disco.is_successful, disco.error
        assert disco.introspection_endpoint, "discovery has no introspection_endpoint"
        endpoint = disco.introspection_endpoint
    kwargs: dict[str, Any] = {}
    if inp.get("client_auth") == "client_secret_post":
        if (
            "client_auth_method"
            not in inspect.signature(TokenIntrospectionRequest).parameters
        ):
            raise KnownGap("TokenIntrospectionRequest has no client_auth_method")
        kwargs["client_auth_method"] = ClientAuthMethod.CLIENT_SECRET_POST
    return introspect_token(
        TokenIntrospectionRequest(
            address=endpoint,
            token=inp["token"],
            token_type_hint=inp.get("token_type_hint"),
            client_id="cid",
            client_secret=inp.get("client_secret", "secret"),
            **kwargs,
        )
    )


def _introspection_expect(case_id: str, expect: dict, response: Any) -> None:
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
        return
    if response.is_successful and expect["error"] == "malformed":
        raise KnownGap(f"{case_id}: malformed response accepted (#782)")
    assert not response.is_successful, f"{case_id}: expected reject"
    assert f"status code: {expect['status']}" in (response.error or "")
    # The error code appears in the raw body, so a substring check proves
    # nothing until the error is typed (#791).
    raise KnownGap(f"{case_id}: no typed OAuth error {expect['error']!r} (#791)")


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
    "authorization-code": Adapter(_authorization_code_call, _authorization_code_expect),
    "client-credentials": Adapter(_client_credentials_call, _client_credentials_expect),
    "discovery": Adapter(_discovery_call, _discovery_expect),
    "introspection": Adapter(_introspection_call, _introspection_expect),
    "revocation": Adapter(_revocation_call, _revocation_expect),
    "token-exchange": Adapter(_token_exchange_call, _token_exchange_expect),
    "userinfo": Adapter(_userinfo_call, _userinfo_expect),
    "jwks": Adapter(_jwks_call, _jwks_expect),
}

#: Vectors py-identity-model does not meet yet, by parametrize id or case id.
_KNOWN_GAPS = {
    "ACG-001-public-client": "no typed token members (#783)",
    "ACG-001-confidential-client-basic": "no typed token members (#783)",
    "ACG-004-code-verifier": "no typed token members (#783)",
    "ACG-005-invalid-grant": "token errors are untyped (#791)",
    "CC-003-client-secret-post": "no client_secret_post for client credentials (#574)",
    "CC-004-invalid-client": "token errors are untyped (#791)",
    "CC-006-extra-params": "ClientCredentialsTokenRequest has no extra parameters (#778)",
    "EXCH-001-impersonation": "no typed token-exchange members (#783)",
    "EXCH-001-client-secret-post": "no client_secret_post for token exchange (#574)",
    "EXCH-002-delegation": "no typed token-exchange members (#783)",
    "EXCH-005-n_a-token-type": "no typed token-exchange members (#783)",
    "EXCH-005-optional-fields": "no typed token-exchange members (#783)",
    "EXCH-006-invalid-grant": "token-exchange errors are untyped (#791)",
    "EXCH-006-invalid-request": "the error_uri is dropped from the error (#777)",
    "INTR-001-active-token": "no typed §2.2 introspection members (#772)",
    "INTR-001-missing-active": "a response with no active member is accepted (#782)",
    "INTR-001-active-not-boolean": "a non-boolean active member is accepted (#782)",
    "INTR-002-inactive-token": "no typed §2.2 introspection members (#772)",
    "INTR-003-client-secret-post": "no client_secret_post for introspection (#574)",
    "INTR-005-invalid-client": "introspection errors are untyped (#791)",
    "DISC-003-issuer-mismatch": "no issuer-match check (#574)",
    "DISC-008-missing-multiple-fields": "token_endpoint not required (#771)",
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
        for case in json.loads(path.read_text())["tests"]:
            vectors = case.get("vectors", [])
            if capability in ADAPTERS:
                assert vectors, f"{case['id']}: case has no vectors"
            for idx, vector in enumerate(vectors):
                key = vector.get("name") or str(idx)
                if not _is_http(vector):
                    # In an adapted file, a vector that is not HTTP must be
                    # pure logic; anything else is a dropped HTTP vector.
                    assert capability not in ADAPTERS or "operation" in vector.get(
                        "input", {}
                    ), f"{case['id']}-{key}: neither an HTTP nor a pure-logic vector"
                    continue
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
    outcome = vector["expect"]["outcome"]
    assert outcome in ("accept", "reject"), f"{case_id}: unknown outcome {outcome!r}"
    base = f"{VECTOR_OP}/v/{_RUN}/{capability}/{case_id}/{key}"

    result = adapter.call(base, vector["input"])
    response = httpx.get(base + "/_check", timeout=5)
    assert response.is_success, f"{case_id}: _check: {response.text}"
    check = response.json()
    assert check["ok"], f"{case_id}: {check['diffs']}"
    adapter.expect(case_id, vector["expect"], result)
