"""Fail-closed tests for the shape of a DPoP replay cache (RFC 9449 §11.1).

A replay cache that cannot take ``(jkt, jti, expires_at, now)`` would fail
every request; it is refused when the options are built. A cache method with
no introspectable signature (a C extension) cannot be checked and is accepted.
A copy of an in-memory cache is the same cache, so it keeps its records.
"""

from __future__ import annotations

import copy
import dataclasses
import pickle

import pytest

from py_identity_model.core.dpop_verify import (
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
)


REPLAY_CACHE_MESSAGE = (
    "replay_cache must be a DPoPReplayCache or an AsyncDPoPReplayCache (RFC 9449 §11.1)"
)


class ThreeArgumentCache:
    """The 4.x shape: ``check_and_store(jti, expires_at, now)``."""

    def check_and_store(self, _jti: str, _expires_at: float, _now: float) -> bool:
        return True


class OpaqueCache:
    """A cache method with no introspectable signature."""

    check_and_store = staticmethod(max)


@pytest.mark.parametrize("cache", [ThreeArgumentCache(), InMemoryDPoPReplayCache])
def test_cache_that_cannot_take_the_proof_is_refused(cache):
    with pytest.raises(TypeError) as exc:
        DPoPVerificationOptions(replay_cache=cache)

    assert str(exc.value) == REPLAY_CACHE_MESSAGE


@pytest.mark.parametrize("cache", [InMemoryDPoPReplayCache(), OpaqueCache()])
def test_cache_that_takes_the_proof_is_accepted(cache):
    assert DPoPVerificationOptions(replay_cache=cache).replay_cache is cache


def test_a_copied_cache_is_the_same_cache():
    # A copy that forgot the records would accept a replay.
    cache = InMemoryDPoPReplayCache()
    options = DPoPVerificationOptions(replay_cache=cache)

    copies = [
        copy.copy(cache),
        copy.deepcopy(cache),
        copy.deepcopy(options).replay_cache,
        dataclasses.asdict(options)["replay_cache"],
    ]

    assert [c is cache for c in copies] == [True] * len(copies)


def test_cache_cannot_be_pickled():
    with pytest.raises(TypeError) as exc:
        pickle.dumps(InMemoryDPoPReplayCache())

    assert str(exc.value) == (
        "InMemoryDPoPReplayCache cannot be pickled: it is one process's replay "
        "records; give each process its own, or use a shared store"
    )
