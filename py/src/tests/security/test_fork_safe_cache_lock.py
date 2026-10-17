"""The cache structure lock is replaced in a forked child (#953).

A parent thread may hold ``_CACHE_STRUCTURE_LOCK`` at the moment of a fork;
the child would inherit it held, with no thread left to release it, and every
cache write in the child would deadlock. ``_ForkSafeRLock`` registers an
after-fork hook that gives the child a fresh lock.
"""

import os
import threading

import pytest

from py_identity_model.core import jwks_cache
from py_identity_model.core.jwks_cache import _ForkSafeRLock


pytestmark = pytest.mark.unit

RLOCK_TYPE = type(threading.RLock())


def _free_in_another_thread(lock: _ForkSafeRLock) -> bool:
    """Whether another thread can take *lock* right now (it releases it again)."""
    result: list[bool] = []

    def try_acquire() -> None:
        acquired = lock._lock.acquire(blocking=False)
        if acquired:
            lock._lock.release()
        result.append(acquired)

    thread = threading.Thread(target=try_acquire)
    thread.start()
    thread.join()
    [acquired] = result
    return acquired


@pytest.fixture
def fork_hooks(monkeypatch) -> list:
    """Capture the ``after_in_child`` hooks registered while the test runs."""
    hooks: list = []
    monkeypatch.setattr(
        jwks_cache.os,
        "register_at_fork",
        lambda *, after_in_child: hooks.append(after_in_child),
    )
    return hooks


@pytest.mark.skipif(not hasattr(os, "register_at_fork"), reason="POSIX only")
def test_registers_an_after_fork_hook_that_replaces_the_lock(fork_hooks):
    lock = _ForkSafeRLock()
    parent_lock = lock._lock
    assert isinstance(parent_lock, RLOCK_TYPE)
    [after_in_child] = fork_hooks
    parent_lock.acquire()  # a parent thread holds it at the fork
    try:
        after_in_child()
        assert lock._lock is not parent_lock
        assert isinstance(lock._lock, RLOCK_TYPE)
        # The child can take the fresh lock even though the parent's is held.
        with lock:
            pass
    finally:
        parent_lock.release()


@pytest.mark.usefixtures("fork_hooks")
def test_context_manager_is_reentrant_and_releases():
    lock = _ForkSafeRLock()
    with lock, lock:
        assert not _free_in_another_thread(lock)
    assert _free_in_another_thread(lock)


def test_module_lock_is_fork_safe():
    assert isinstance(jwks_cache._CACHE_STRUCTURE_LOCK, _ForkSafeRLock)
