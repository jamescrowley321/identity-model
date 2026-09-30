"""Regressions for the discovery vector adapter, including real socket calls."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time

import pytest

from py_identity_model.core import jwks_cache
from py_identity_model.core.models import DiscoveryDocumentResponse
from py_identity_model.sync import token_validation
from tests.spec_vectors.test_spec_http_vectors import (
    KnownGap,
    _discovery_call,
    _discovery_expect,
)


@pytest.fixture
def discovery_server():
    """A real HTTP endpoint; only its response and request count are controlled."""
    document = json.loads(
        (
            Path(__file__).parents[4] / "spec/test-fixtures/discovery/valid.json"
        ).read_text()
    )
    state = {"status": 200, "body": None, "calls": Counter(), "clocks": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["calls"][self.path] += 1
            state["clocks"].append(time.monotonic)
            body = state["body"] or json.dumps(document).replace(
                "https://server.example.com", base
            )
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    "expect",
    [
        {"outcome": "reject", "error": "parse"},
        {"outcome": "reject", "error": "https_required"},
        {"outcome": "reject", "error": "http_status", "status": 500},
        {"outcome": "reject", "error": "missing_fields", "fields": ["jwks_uri"]},
    ],
)
def test_upstream_prose_cannot_satisfy_wrong_failure(discovery_server, expect):
    base, state = discovery_server
    state["status"] = 404
    state["body"] = (
        "Invalid JSON response; HTTPS is required; status code: 500; jwks_uri"
    )
    result = _discovery_call(base, {})
    assert state["calls"]["/.well-known/openid-configuration"] == 1
    with pytest.raises(AssertionError):
        _discovery_expect("REGRESSION", expect, result)
    _discovery_expect(
        "REGRESSION",
        {"outcome": "reject", "error": "http_status", "status": 404},
        result,
    )


@pytest.mark.parametrize(
    ("code", "details"),
    [
        ("parse", {}),
        ("https_required", {}),
        ("http_status", {"status_code": 404}),
        ("missing_fields", {"missing_fields": ("jwks_uri",)}),
    ],
)
def test_structured_failure_accepts_changed_prose(code, details):
    response = DiscoveryDocumentResponse(
        is_successful=False,
        error="Entirely different diagnostic prose",
        error_code=code,
        **details,
    )
    expected = {"outcome": "reject", "error": code}
    if code == "http_status":
        expected["status"] = 404
    if code == "missing_fields":
        expected["fields"] = ["jwks_uri"]
    _discovery_expect("REGRESSION", expected, ("http://localhost", [response]))


@pytest.mark.parametrize(
    "fields",
    [
        ("jwks_uri", "issuer"),
        (),
        ("token_endpoint", "issuer"),
        ("subject_types_supported", "issuer"),
    ],
)
def test_wrong_field_sets_never_become_known_gap(fields):
    response = DiscoveryDocumentResponse(
        is_successful=False,
        error="subject_types_supported",
        error_code="missing_fields",
        missing_fields=fields,
    )
    with pytest.raises(AssertionError):
        _discovery_expect(
            "DISC-008",
            {
                "outcome": "reject",
                "error": "missing_fields",
                "fields": ["token_endpoint", "subject_types_supported"],
            },
            ("http://localhost", [response]),
        )


def test_only_specific_missing_endpoint_behavior_is_known_gap():
    response = DiscoveryDocumentResponse(
        is_successful=False,
        error="Changed prose",
        error_code="missing_fields",
        missing_fields=("subject_types_supported",),
    )
    with pytest.raises(KnownGap, match="#771"):
        _discovery_expect(
            "DISC-008",
            {
                "outcome": "reject",
                "error": "missing_fields",
                "fields": ["token_endpoint", "subject_types_supported"],
            },
            ("http://localhost", [response]),
        )


def test_cache_hits_exact_expiry_and_refetch_leave_stdlib_clock_alone(discovery_server):
    base, state = discovery_server
    stdlib_clock = time.monotonic
    result = _discovery_call(
        base, {"cache_ttl_seconds": 60, "calls_at_seconds": [0, 30, 60, 90, 120]}
    )
    _discovery_expect("REGRESSION", {"outcome": "accept"}, result)
    assert state["calls"]["/.well-known/openid-configuration"] == 3  # noqa: PLR2004 -- cold fetch, boundary expiry, second expiry
    assert all(clock is stdlib_clock for clock in state["clocks"])
    assert time.monotonic is stdlib_clock
    assert not token_validation._disco_cache


def test_cache_clock_and_environment_restore_after_call_failure(
    discovery_server, monkeypatch
):
    base, state = discovery_server
    original_time = token_validation.time
    original_cache_time = jwks_cache.time
    original_ttl = os.environ.get("DISCO_CACHE_TTL")
    real_call = token_validation._get_disco_response
    calls = 0

    def fail_on_second_call(*args):
        nonlocal calls
        calls += 1
        if calls == 2:  # noqa: PLR2004 -- inject failure after insertion
            raise RuntimeError("injected caller failure")
        return real_call(*args)

    monkeypatch.setattr(token_validation, "_get_disco_response", fail_on_second_call)
    with pytest.raises(RuntimeError, match="injected caller failure"):
        _discovery_call(base, {"cache_ttl_seconds": 60, "calls_at_seconds": [0, 30]})
    assert state["calls"]["/.well-known/openid-configuration"] == 1
    assert token_validation.time is original_time
    assert jwks_cache.time is original_cache_time
    assert os.environ.get("DISCO_CACHE_TTL") == original_ttl
    assert not token_validation._disco_cache
    # A subsequent call must refetch after failed-vector cleanup.
    result = _discovery_call(base, {"cache_ttl_seconds": 60, "calls_at_seconds": [0]})
    _discovery_expect("REGRESSION", {"outcome": "accept"}, result)
    assert state["calls"]["/.well-known/openid-configuration"] == 2  # noqa: PLR2004 -- initial fetch and post-cleanup refetch
