"""Boot the harness resource server (:mod:`rs_app`) under real uvicorn workers.

``boot_rs`` is deliberately free of any FastAPI / fastapi-identity-model import
so it stays inside the root pyrefly lint env. It launches uvicorn as a
subprocess by import-string (``src.tests.harness.rs_app:app``), passes RS
configuration through inherited ``RS_*`` environment variables, waits for the
``/health`` endpoint to answer over real HTTP, then tears the process down.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import IO, TYPE_CHECKING

import httpx


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


# py/src/tests/harness/rs_server.py -> parents[3] is the Python package root
# (``py/``, which holds ``src/``); uvicorn boots the RS from here so
# ``src.tests.harness.rs_app`` imports.
_PY_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class BootedRS:
    """A running resource server: its base URL and the uvicorn master PID.

    ``pid`` is the uvicorn *master* process; under ``--workers N`` the request
    handlers are child processes, so a resource sampler must walk the tree
    (master + recursive children) rather than sampling ``pid`` alone.
    """

    base_url: str
    pid: int


_HEALTH_POLL_INTERVAL = 0.25
_TERMINATE_GRACE = 10.0


def _free_port() -> int:
    """Bind to an ephemeral port, then release it for uvicorn to reuse.

    A TOCTOU window exists between close and re-bind; the ``/health`` readiness
    poll (which fails loudly if uvicorn never binds) is the real guard.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _drain(log: IO[str]) -> str:
    """Return everything uvicorn has written to its capture file so far.

    Reading from a seekable temp file (not a live PIPE) never blocks: the child
    writes to its own inherited fd and we snapshot from position 0. This also
    means the child can emit an arbitrarily large traceback without filling an
    OS pipe buffer and deadlocking on ``write()`` (blind/edge SHOULD-FIX).
    """
    try:
        log.seek(0)
        return log.read()
    except (OSError, ValueError):  # pragma: no cover - defensive, file closed
        return ""


def _wait_for_health(
    proc: subprocess.Popen[str], log: IO[str], base_url: str, timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no attempt made"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"uvicorn exited before becoming healthy "
                f"(code {proc.returncode}):\n{_drain(log)}"
            )
        try:
            response = httpx.get(f"{base_url}/health", timeout=2.0)
            if response.status_code == httpx.codes.OK:
                return
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(_HEALTH_POLL_INTERVAL)

    proc.terminate()
    raise RuntimeError(
        f"resource server did not become healthy within {timeout}s "
        f"(last: {last_error}):\n{_drain(log)}"
    )


@contextlib.contextmanager
def boot_rs_process(
    *,
    issuer: str,
    audience: str,
    require_scope: str = "api",
    workers: int = 1,
    require_access_token_marker: bool = False,
    excluded_paths: list[str] | None = None,
    extra_env: Mapping[str, str] | None = None,
    timeout: float = 30.0,
) -> Iterator[BootedRS]:
    """Boot a single-issuer resource server and yield a :class:`BootedRS`.

    Same boot as :func:`boot_rs`, but exposes the uvicorn master PID so a caller
    (the load runner) can sample the RS process tree's RSS/FD during a run. Most
    callers only need the URL — use :func:`boot_rs`.

    Args:
        issuer: Issuer identifier the middleware binds to (discovery is
            fetched for it).
        audience: Expected ``aud`` claim (middleware requires non-empty).
        require_scope: Scope enforced on ``/protected`` (403 if absent).
        workers: uvicorn ``--workers`` count (>=2 proves multi-worker boot).
        require_access_token_marker: F-07 ID-token-substitution defence opt-in.
        excluded_paths: Override middleware excluded paths (must keep
            ``/health`` for the readiness poll to pass).
        extra_env: Additional environment for the uvicorn subprocess.
        timeout: Seconds to wait for the first healthy ``/health`` response.

    Yields:
        A :class:`BootedRS` with the ``http://127.0.0.1:<port>`` base URL and
        the uvicorn master PID.
    """
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = dict(os.environ)
    env["RS_ISSUER"] = issuer
    env["RS_AUDIENCE"] = audience
    env["RS_REQUIRE_SCOPE"] = require_scope
    env["RS_REQUIRE_ACCESS_TOKEN_MARKER"] = (
        "true" if require_access_token_marker else "false"
    )
    if excluded_paths is not None:
        env["RS_EXCLUDED_PATHS"] = ",".join(excluded_paths)
    if extra_env:
        env.update(extra_env)

    # Capture uvicorn output to a seekable temp file rather than a PIPE. A PIPE
    # is only drained on the failure path, so a healthy-but-chatty worker could
    # fill the ~64KB OS pipe buffer and block on ``write()``, hanging the server
    # (blind/edge SHOULD-FIX). A temp file has no such backpressure and reading
    # it back on failure never blocks. ``TemporaryFile`` also unlinks itself on
    # close, so there is no lingering fd for the GC to ResourceWarning over.
    with tempfile.TemporaryFile(mode="w+") as log:
        proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell, test-only
            [
                sys.executable,
                "-m",
                "uvicorn",
                "src.tests.harness.rs_app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--workers",
                str(workers),
                "--log-level",
                "warning",
            ],
            cwd=str(_PY_ROOT),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            _wait_for_health(proc, log, base_url, timeout)
            yield BootedRS(base_url=base_url, pid=proc.pid)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=_TERMINATE_GRACE)
            except subprocess.TimeoutExpired:
                proc.kill()
                # A SIGKILL'd process stuck in uninterruptible I/O may still not
                # reap within the grace window. Swallow the second timeout so
                # teardown never raises out of ``finally`` and masks the real
                # test result (edge [CRASH]).
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=_TERMINATE_GRACE)


@contextlib.contextmanager
def boot_rs(
    *,
    issuer: str,
    audience: str,
    require_scope: str = "api",
    workers: int = 1,
    require_access_token_marker: bool = False,
    excluded_paths: list[str] | None = None,
    extra_env: Mapping[str, str] | None = None,
    timeout: float = 30.0,
) -> Iterator[str]:
    """Boot a single-issuer resource server and yield its base URL.

    A thin wrapper over :func:`boot_rs_process` for the common case that only
    needs the URL. See :func:`boot_rs_process` for the full argument reference.

    Yields:
        The ``http://127.0.0.1:<port>`` base URL of the running server.
    """
    with boot_rs_process(
        issuer=issuer,
        audience=audience,
        require_scope=require_scope,
        workers=workers,
        require_access_token_marker=require_access_token_marker,
        excluded_paths=excluded_paths,
        extra_env=extra_env,
        timeout=timeout,
    ) as rs:
        yield rs.base_url
