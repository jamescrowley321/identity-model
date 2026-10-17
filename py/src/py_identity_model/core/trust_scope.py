"""
Transport trust scopes for the validation caches.

A discovery document or JWKS is only as trustworthy as the transport that
fetched it: a client built with ``verify=False``, behind a proxy, or one that
follows redirects can be served a document that a client pinned to a CA bundle
would have rejected. The validation caches are shared by every client that
uses them, so each cached document is keyed by the trust scope of the client
that fetched it, and a client only reads documents fetched under its own
scope. The kid-miss cooldown is not scoped: it is keyed by ``jwks_uri`` alone,
so short-lived clients still share it (#945).

Two scopes:

- A client that builds its own ``httpx`` client from a
  :class:`~py_identity_model.core.config.Config` verifies TLS against
  ``Config.ca_bundle`` and never follows redirects, so its scope is the
  ``ca_bundle`` value. Every such client with the same ``ca_bundle`` (the
  library default client included) shares documents.
- A client that wraps an ``httpx`` client you built keeps that client's TLS,
  proxy and redirect settings, which cannot be read back. Its scope is the
  identity of the wrapped ``httpx`` client: wrappers of the same ``httpx``
  client share documents, and no other client reads them. A scope is never
  reused, even after the ``httpx`` client is garbage-collected.
"""

from __future__ import annotations

from dataclasses import dataclass
import itertools
import threading
from typing import TYPE_CHECKING
import weakref


if TYPE_CHECKING:
    from .config import Config


@dataclass(frozen=True)
class TrustScope:
    """The trust scope of an HTTP client's transport.

    ``ca_bundle`` is set for a client built from a ``Config`` (``None`` means
    httpx's default bundle); ``wrapped_client`` numbers a wrapped ``httpx``
    client and is ``None`` otherwise.
    """

    ca_bundle: str | None = None
    wrapped_client: int | None = None


_wrapped_numbers: weakref.WeakKeyDictionary[object, int] = weakref.WeakKeyDictionary()
_wrapped_lock = threading.Lock()
_wrapped_counter = itertools.count(1)


def owned_trust_scope(config: Config) -> TrustScope:
    """Return the scope of a client built from *config*."""
    return TrustScope(ca_bundle=config.ca_bundle)


def wrapped_trust_scope(client: object) -> TrustScope:
    """Return the scope of a wrapper around the ``httpx`` client *client*."""
    with _wrapped_lock:
        number = _wrapped_numbers.get(client)
        if number is None:
            number = next(_wrapped_counter)
            _wrapped_numbers[client] = number
    return TrustScope(wrapped_client=number)


__all__ = ["TrustScope", "owned_trust_scope", "wrapped_trust_scope"]
