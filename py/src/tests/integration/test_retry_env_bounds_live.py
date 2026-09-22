"""Live proof that a mis-set retry variable cannot disable or stall the client.

Unit tests can only show the parse site returns a bounded number. These show the
consequence against a real provider and a real unreachable endpoint: that a
request is actually issued, and that the wait a failure costs is actually
bounded by the configured ceiling.
"""

import socket
import time

import pytest

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document


# Unbounded backoff at base=10 would be 10 + 20 = 30s for two retries; the
# ceiling under test is 1s, so a bounded run costs ~2s of sleeping. The
# thresholds sit well clear of both to survive a slow CI box.
BASE_DELAY_SECONDS = 10
RETRY_ATTEMPTS = 2
LOW_CEILING_SECONDS = 1
RAISED_CEILING_SECONDS = 3
BOUNDED_RUN_LIMIT_SECONDS = 8
RAISED_RUN_LIMIT_SECONDS = 20
UNBOUNDED_RUN_WOULD_EXCEED = 25


def _closed_port() -> int:
    """Bind and release a port so connections to it are refused, not hung."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.mark.usefixtures("env_file")
def test_negative_retry_count_still_reaches_the_provider(test_config, monkeypatch):
    """Test that a negative retry count no longer cancels the request itself."""
    monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "-1")

    response = get_discovery_document(
        DiscoveryDocumentRequest(address=test_config["TEST_DISCO_ADDRESS"])
    )

    # Before the floor, range(retries + 1) was range(0): no request was issued
    # and the caller got RuntimeError("No response received after retries").
    assert response.is_successful, response.error
    assert response.issuer


@pytest.mark.usefixtures("env_file")
def test_retry_backoff_is_bounded_by_the_configured_ceiling(monkeypatch):
    """Test that an unreachable endpoint cannot stall past the ceiling."""
    monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", str(RETRY_ATTEMPTS))
    monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", str(BASE_DELAY_SECONDS))
    monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", str(LOW_CEILING_SECONDS))
    address = f"http://127.0.0.1:{_closed_port()}/.well-known/openid-configuration"

    started = time.monotonic()
    response = get_discovery_document(DiscoveryDocumentRequest(address=address))
    elapsed = time.monotonic() - started

    assert response.is_successful is False
    # Unbounded this is 10 + 20 = 30s of sleeping on the connection-error path,
    # which is the branch that never consulted the documented maximum.
    assert elapsed < BOUNDED_RUN_LIMIT_SECONDS, (
        f"retry backoff took {elapsed:.1f}s against a ceiling of "
        f"{LOW_CEILING_SECONDS}s; unbounded would exceed "
        f"{UNBOUNDED_RUN_WOULD_EXCEED}s"
    )


@pytest.mark.usefixtures("env_file")
def test_a_raised_ceiling_is_honored_not_overridden(monkeypatch):
    """Test that raising the ceiling actually lengthens the wait."""
    monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", str(RETRY_ATTEMPTS))
    monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", str(BASE_DELAY_SECONDS))
    monkeypatch.setenv("HTTP_RETRY_MAX_DELAY", str(RAISED_CEILING_SECONDS))
    address = f"http://127.0.0.1:{_closed_port()}/.well-known/openid-configuration"

    started = time.monotonic()
    response = get_discovery_document(DiscoveryDocumentRequest(address=address))
    elapsed = time.monotonic() - started

    assert response.is_successful is False
    # The ceiling is a default, not a hard limit: a deployment that asks for
    # longer waits gets them. At 3s x 2 retries this must exceed the 1s-ceiling
    # run, proving the configured value is read rather than a constant applied.
    assert elapsed >= RAISED_CEILING_SECONDS, (
        f"raised ceiling of {RAISED_CEILING_SECONDS}s was ignored: "
        f"the run took only {elapsed:.1f}s"
    )
    assert elapsed < RAISED_RUN_LIMIT_SECONDS
