"""``ProcessLocal`` builds one value per process (#953).

A forked child is simulated by changing what ``os.getpid()`` returns; the real
fork path is covered in ``test_validation_cache.py``.
"""

import os

import pytest

from py_identity_model.core import process_local
from py_identity_model.core.process_local import ProcessLocal


PARENT_PID = 1000
CHILD_PID = 1001


class _Built:
    def __init__(self, inherited: "_Built | None") -> None:
        self.inherited = inherited


@pytest.fixture
def pid(monkeypatch):
    """Control the pid ``ProcessLocal`` sees; starts as the parent's."""
    current = {"pid": PARENT_PID}
    monkeypatch.setattr(process_local.os, "getpid", lambda: current["pid"])
    return current


@pytest.mark.usefixtures("pid")
def test_builds_once_per_process():
    holder = ProcessLocal(_Built)
    first = holder.get()
    assert holder.get() is first
    assert first.inherited is None


def test_rebuilds_after_pid_change_from_the_inherited_value(pid):
    holder = ProcessLocal(_Built)
    parent = holder.get()
    pid["pid"] = CHILD_PID
    child = holder.get()
    assert child is not parent
    assert child.inherited is parent
    assert holder.get() is child


def test_peek_never_builds_and_ignores_the_parents_value(pid):
    holder = ProcessLocal(_Built)
    assert holder.peek() is None
    parent = holder.get()
    assert holder.peek() is parent
    pid["pid"] = CHILD_PID
    assert holder.peek() is None


def test_replace_returns_only_this_processes_value(pid):
    holder = ProcessLocal(_Built)
    assert holder.replace(_Built(None)) is None
    installed = holder.get()
    replacement = _Built(None)
    assert holder.replace(replacement) is installed
    assert holder.get() is replacement
    pid["pid"] = CHILD_PID
    assert holder.replace(_Built(None)) is None


@pytest.mark.skipif(not hasattr(os, "register_at_fork"), reason="POSIX only")
def test_after_fork_hook_gives_a_fresh_creation_lock(monkeypatch):
    hooks = []
    monkeypatch.setattr(
        process_local.os,
        "register_at_fork",
        lambda *, after_in_child: hooks.append(after_in_child),
    )
    holder = ProcessLocal(_Built)
    parent_lock = holder._lock
    parent_lock.acquire()  # a parent thread holds it at the fork
    try:
        [after_in_child] = hooks
        after_in_child()
        assert holder._lock is not parent_lock
        assert isinstance(holder.get(), _Built)
    finally:
        parent_lock.release()
