"""Unit tests for the provider capability matrix's logout/registration columns.

Guards the four columns added by KC.4 (registration_endpoint, end_session_endpoint,
backchannel_logout_supported, backchannel_logout_session_supported) against
regression in ``provider_matrix.detect_capabilities``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from types import ModuleType


def _load_provider_matrix() -> ModuleType:
    """Load the standalone provider_matrix script as a module."""
    try:
        return importlib.import_module("tests.harness.provider_matrix")
    except ImportError:
        path = Path(__file__).resolve().parents[1] / "harness" / "provider_matrix.py"
        spec = importlib.util.spec_from_file_location("provider_matrix", path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["provider_matrix"] = module
        spec.loader.exec_module(module)
        return module


provider_matrix = _load_provider_matrix()
detect_capabilities = provider_matrix.detect_capabilities

_LOGOUT_LABELS = (
    "registration (RFC7591)",
    "end_session",
    "backchannel_logout",
    "backchannel_logout_session",
)


def test_logout_registration_columns_present_when_advertised() -> None:
    """Full discovery advertising all four → all four capabilities True."""
    disco = {
        "issuer": "https://example.com",
        "registration_endpoint": "https://example.com/register",
        "end_session_endpoint": "https://example.com/logout",
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
    }
    caps = detect_capabilities(disco)
    for label in _LOGOUT_LABELS:
        # Truthiness (not ``is True``): endpoint-URL columns carry the URL
        # string's truthiness; only the backchannel booleans are strict bools.
        assert caps[label], label


def test_logout_registration_columns_absent() -> None:
    """Minimal discovery advertising none → all four capabilities False."""
    disco = {"issuer": "https://example.com"}
    caps = detect_capabilities(disco)
    for label in _LOGOUT_LABELS:
        assert not caps[label], label


def test_backchannel_logout_supported_false_is_false() -> None:
    """Explicit ``false`` boolean → False (not truthy-coerced)."""
    disco = {
        "issuer": "https://example.com",
        "backchannel_logout_supported": False,
        "backchannel_logout_session_supported": False,
    }
    caps = detect_capabilities(disco)
    assert caps["backchannel_logout"] is False
    assert caps["backchannel_logout_session"] is False


def test_endpoint_url_strings_are_truthy() -> None:
    """Endpoint-URL fields (strings) are treated as present → True."""
    disco = {
        "issuer": "https://example.com",
        "registration_endpoint": "https://example.com/register",
        "end_session_endpoint": "https://example.com/logout",
    }
    caps = detect_capabilities(disco)
    assert caps["registration (RFC7591)"]
    assert caps["end_session"]
