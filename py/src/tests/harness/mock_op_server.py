"""Serve the framework-free :class:`~mock_op.MockOP` over real localhost HTTP.

The RS boot (:func:`~rs_server.boot_rs`) launches uvicorn as a *subprocess*, so
it cannot reach an in-process ASGI mock OP — it fetches discovery + JWKS over
real HTTP. This helper runs the mock OP on a real loopback port so the booted RS
can validate against it.

The mock OP must run **in-process** (a uvicorn thread, not a subprocess): the
forged corpus (:func:`~corpus.build_corpus`) is keyed to the *same* ``MockOP``
instance's signing key, and a subprocess mock OP would re-import a fresh random
key, breaking every forgery.

``import uvicorn`` is deferred into the function so that plain unit-env
collection of importers does not fail (uvicorn is not a root test dependency).
This module is excluded from the root pyrefly lint env for the same reason
(see ``[tool.pyrefly] project_excludes`` in ``pyproject.toml``).
"""

from __future__ import annotations

import contextlib
import sys
import threading
import time
from typing import TYPE_CHECKING

import httpx

from .mock_op import MockOP, MockOPControls
from .rs_server import _free_port


if TYPE_CHECKING:
    from collections.abc import Iterator


_READY_POLL_INTERVAL = 0.05
_SHUTDOWN_TIMEOUT = 10.0


class _ServerThread(threading.Thread):
    """Run ``uvicorn.Server.run`` and remember any startup exception.

    ``server.run()`` raising inside a bare daemon thread is otherwise silently
    swallowed: the thread just dies and the readiness poll blocks for the full
    ``timeout`` before failing with an opaque message. Capturing the exception
    (and exposing liveness) lets the poll fail fast with the real cause, the way
    the sibling subprocess boot fails fast on ``proc.poll()`` (blind/edge
    SHOULD-FIX).
    """

    def __init__(self, server: object) -> None:
        super().__init__(daemon=True)
        self._server = server
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self._server.run()  # type: ignore[attr-defined]
        except BaseException as exc:
            self.error = exc


@contextlib.contextmanager
def serve_mock_op(
    *,
    controls: MockOPControls | None = None,
    timeout: float = 30.0,
) -> Iterator[MockOP]:
    """Serve a :class:`MockOP` over real localhost HTTP for the duration of the
    ``with`` block.

    Binds an ephemeral loopback port, builds a ``MockOP`` whose ``issuer`` is the
    bound ``http://127.0.0.1:<port>`` (so its discovery ``issuer`` and the RS
    ``iss`` check both match the URL the RS actually fetches), runs it under
    ``uvicorn`` in a daemon thread, and polls its discovery endpoint until it
    answers ``200``.

    Args:
        controls: Failure-injection knobs handed to the ``MockOP``.
        timeout: Seconds to wait for the first successful discovery response.

    Yields:
        The live :class:`MockOP` instance (use ``op.issuer`` for the RS,
        ``op.sign`` / :func:`~corpus.build_corpus` for forged tokens).
    """
    # Deferred so importing this module in the root env (where uvicorn is not
    # installed) does not ImportError — only calling serve_mock_op needs it, and
    # that path is only taken under `uv run --all-packages`.
    import uvicorn  # noqa: PLC0415 — intentional in-function import, see above

    port = _free_port()
    op = MockOP(issuer=f"http://127.0.0.1:{port}", controls=controls)
    # ``lifespan="off"``: the framework-free app needs no startup, and skipping
    # lifespan avoids driving ``MockOP._handle_lifespan`` through uvicorn.
    # ``interface="asgi3"``: ``op.app`` is a bare 3-arg ASGI callable (not a
    # class), which uvicorn's auto-detection otherwise mistakes for the legacy
    # 2-arg ASGI-2 factory and calls with a single ``scope`` argument.
    config = uvicorn.Config(
        op.app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        lifespan="off",
        interface="asgi3",
    )
    server = uvicorn.Server(config)
    thread = _ServerThread(server)
    thread.start()
    try:
        _wait_for_discovery(thread, op.discovery_url, timeout)
        yield op
    finally:
        server.should_exit = True
        thread.join(_SHUTDOWN_TIMEOUT)
        if thread.is_alive() and sys.exc_info()[0] is None:
            # The server never honoured ``should_exit`` within the shutdown
            # grace. The daemon thread — still bound to the loopback port —
            # leaks past the ``with`` block and can wedge the next
            # ``serve_mock_op`` reusing the port range (blind SHOULD-FIX).
            # Only raise when the body did not already fail: a raise here would
            # otherwise supersede the real test failure, demoting it to a
            # chained ``__context__`` and misreporting a body assertion as a
            # shutdown bug (delta SHOULD-FIX).
            raise RuntimeError(
                f"mock OP did not shut down within {_SHUTDOWN_TIMEOUT}s; "
                f"the uvicorn thread is still bound to {op.discovery_url}"
            )


def _wait_for_discovery(
    thread: _ServerThread, discovery_url: str, timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no attempt made"
    while time.monotonic() < deadline:
        if not thread.is_alive():
            # The uvicorn thread exited before discovery answered — a crash
            # (bind refused, port TOCTOU collision, ASGI misconfig) or an
            # unexpected clean exit. Surface it immediately instead of polling
            # the full timeout (edge [DEGRADED]); ``thread.error`` chains the
            # captured cause when there was one, else is ``None`` (clean exit).
            raise RuntimeError(
                f"mock OP uvicorn thread exited during startup (last: {last_error})"
            ) from thread.error
        try:
            response = httpx.get(discovery_url, timeout=2.0)
            if response.status_code == httpx.codes.OK:
                return
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(_READY_POLL_INTERVAL)
    raise RuntimeError(
        f"mock OP did not serve discovery within {timeout}s (last: {last_error})"
    )
