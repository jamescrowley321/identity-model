"""
SSL certificate configuration utilities.

Resolves the TLS verification setting for this library's own HTTPS requests
from an injected :class:`~py_identity_model.core.config.Config`. The library
reads no environment variables; build the ``Config`` (for example with
:func:`py_identity_model.config_helpers.config_from_env`) and pass it in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .core.config import Config


def get_ssl_verify(config: Config) -> str | bool:
    """Return the value for httpx's ``verify`` parameter.

    Args:
        config: The client's configuration.

    Returns:
        str: ``config.ca_bundle`` when set.
        bool: ``True`` to verify with the HTTP stack's default CA bundle.
    """
    return config.ca_bundle if config.ca_bundle is not None else True


__all__ = ["get_ssl_verify"]
