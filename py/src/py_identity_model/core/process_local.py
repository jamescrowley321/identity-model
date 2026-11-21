"""
Per-process lazy singletons for the library defaults.

A pre-fork server (gunicorn, uWSGI, ``multiprocessing``) imports the library
in a parent and forks workers from it. Anything the parent built is copied
into every child: a cache whose locks a parent thread held at the moment of
the fork, an httpx client whose pooled TLS connections are now shared by two
processes. :class:`ProcessLocal` holds a value per process. It records the
pid that built the value and builds a fresh one when ``os.getpid()`` differs,
so a forked child never uses its parent's object.

The parent's object is dropped in the child, never closed: closing a pooled
TLS connection sends ``close_notify`` on a socket the parent still uses.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING
import weakref


if TYPE_CHECKING:
    from collections.abc import Callable


class ProcessLocal[T]:
    """A value built on first use in each process.

    :meth:`get` returns the value built in the calling process, building it
    with *factory* on first use and again after a fork (pid check). The
    creation lock is re-created in the child after ``os.fork()``, so a lock
    that another parent thread held at the fork cannot deadlock the child.

    Args:
        factory: Builds the value. It receives the value inherited from the
            parent process (``None`` on first use), so a child can be built
            from the same settings without sharing the parent's object.
    """

    def __init__(self, factory: Callable[[T | None], T]) -> None:
        self._factory = factory
        self._lock = threading.Lock()
        # The pid that built the value and the value, as one tuple: a reader
        # takes a single snapshot, so it never pairs one writer's pid with
        # another's value (a forked child could otherwise return the parent's
        # object after another thread stamped the child's pid).
        self._state: tuple[int, T] | None = None
        if hasattr(os, "register_at_fork"):
            ref = weakref.ref(self)

            def _after_fork_in_child() -> None:
                holder = ref()
                if holder is not None:
                    holder._lock = threading.Lock()

            os.register_at_fork(after_in_child=_after_fork_in_child)

    def get(self) -> T:
        """Return this process's value, building it on first use."""
        pid = os.getpid()
        state = self._state
        if state is not None and state[0] == pid:
            return state[1]
        with self._lock:
            state = self._state
            if state is None or state[0] != pid:
                state = (pid, self._factory(None if state is None else state[1]))
                self._state = state
            return state[1]

    def replace(self, value: T) -> T | None:
        """Install *value* for this process; return the previous one, if any.

        Returns ``None`` when nothing was built yet, or when the previous value
        was built by another process (the parent, before a fork).
        """
        pid = os.getpid()
        with self._lock:
            state = self._state
            self._state = (pid, value)
        return state[1] if state is not None and state[0] == pid else None

    def peek(self) -> T | None:
        """Return this process's value without building one."""
        state = self._state
        if state is not None and state[0] == os.getpid():
            return state[1]
        return None


__all__ = ["ProcessLocal"]
