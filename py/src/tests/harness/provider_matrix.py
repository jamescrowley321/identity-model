#!/usr/bin/env python3
"""Provider capability matrix — probes configured providers via discovery.

Reads all .env* files matching the integration test pattern, fetches
each provider's discovery document, and outputs a feature support matrix.

Usage:
    uv run python src/tests/integration/provider_matrix.py
    make provider-matrix
"""

from __future__ import annotations

from pathlib import Path
import sys

from dotenv import dotenv_values
import httpx


# HTTP status codes
HTTP_OK = 200


# ============================================================================
# Capability definitions
# ============================================================================

GRANT_TYPES = [
    ("authorization_code", "authorization_endpoint"),
    ("client_credentials", None),
    ("refresh_token", None),
    ("introspection", "introspection_endpoint"),
    ("revocation", "revocation_endpoint"),
    ("device_authorization", None),
    ("token_exchange", None),
]

GRANT_TYPE_MAP = {
    "client_credentials": "client_credentials",
    "refresh_token": "refresh_token",
    "device_authorization": ("urn:ietf:params:oauth:grant-type:device_code"),
    "token_exchange": ("urn:ietf:params:oauth:grant-type:token-exchange"),
}

FEATURES = [
    ("PKCE (S256)", "code_challenge_methods_supported", "S256"),
    ("DPoP", "dpop_signing_alg_values_supported", None),
    ("JAR (request param)", "request_parameter_supported", None),
    ("PAR", "pushed_authorization_request_endpoint", None),
    ("userinfo", "userinfo_endpoint", None),
    ("registration (RFC7591)", "registration_endpoint", None),
    ("end_session", "end_session_endpoint", None),
    ("backchannel_logout", "backchannel_logout_supported", None),
    ("backchannel_logout_session", "backchannel_logout_session_supported", None),
    ("devInteractions", None, None),
]


def detect_capabilities(disco: dict) -> dict[str, bool]:
    """Derive capabilities from raw discovery JSON."""
    caps: dict[str, bool] = {}
    grants = set(disco.get("grant_types_supported", []))

    for name, endpoint_field in GRANT_TYPES:
        if endpoint_field:
            caps[name] = bool(disco.get(endpoint_field))
        elif name in GRANT_TYPE_MAP:
            caps[name] = GRANT_TYPE_MAP[name] in grants
        else:
            caps[name] = False

    for label, field, value in FEATURES:
        if label == "devInteractions":
            issuer = disco.get("issuer", "")
            caps[label] = issuer.startswith(("http://localhost", "http://127.0.0.1"))
        elif value:
            caps[label] = value in disco.get(field, [])
        elif field:
            caps[label] = bool(disco.get(field))
        else:
            caps[label] = False

    return caps


def find_env_files(
    root: Path,
) -> list[tuple[str, Path]]:
    """Find .env files matching integration test pattern."""
    results = []
    for path in sorted(root.glob(".env*")):
        if path.is_file() and not path.name.endswith((".example", ".bak")):
            name = path.name
            label = "default" if name == ".env" else name.replace(".env.", "")
            results.append((label, path))
    return results


def fetch_discovery(address: str) -> dict | None:
    """Fetch raw discovery JSON. Returns None if unreachable."""
    try:
        resp = httpx.get(address, timeout=10.0)
        if resp.status_code == HTTP_OK:
            return resp.json()
    except (httpx.TransportError, ValueError):
        pass
    return None


def _collect_providers(
    env_files: list[tuple[str, Path]],
) -> list[tuple[str, dict[str, bool] | None]]:
    """Fetch discovery for each env file and detect capabilities."""
    providers: list[tuple[str, dict[str, bool] | None]] = []
    for label, path in env_files:
        config = dotenv_values(path)
        address = config.get("TEST_DISCO_ADDRESS", "")
        if not address:
            continue
        disco = fetch_discovery(address)
        if disco is None:
            providers.append((label, None))
        else:
            providers.append((label, detect_capabilities(disco)))
    return providers


def _print_matrix(
    providers: list[tuple[str, dict[str, bool] | None]],
    all_caps: list[str],
) -> None:
    """Print the capability matrix table."""
    label_width = max(len(c) for c in all_caps)
    col_width = max(*(len(p[0]) for p in providers), 7)

    print()
    print("Provider Capability Matrix")
    print("=" * 26)
    print()

    header = " " * (label_width + 2)
    for name, _ in providers:
        header += f"{name:<{col_width + 2}}"
    print(header)

    separator = " " * (label_width + 2)
    for name, _ in providers:
        separator += f"{'-' * len(name):<{col_width + 2}}"
    print(separator)

    for cap in all_caps:
        row = f"{cap:<{label_width + 2}}"
        for _, caps in providers:
            if caps is None:
                cell = "[offline]"
            elif caps.get(cap, False):
                cell = "\u2713"
            else:
                cell = "\u2717"
            row += f"{cell:<{col_width + 2}}"
        print(row)

    # Summary: count missing capabilities per provider
    total = len(all_caps)
    print()
    summary = f"{'Unsupported':<{label_width + 2}}"
    for _, caps in providers:
        if caps is None:
            cell = "[offline]"
        else:
            missing = sum(1 for c in all_caps if not caps.get(c, False))
            cell = f"{missing}/{total}"
        summary += f"{cell:<{col_width + 2}}"
    print(summary)
    print()


def main() -> None:
    root = Path.cwd()
    env_files = find_env_files(root)

    if not env_files:
        print("No .env files found in", root)
        sys.exit(1)

    providers = _collect_providers(env_files)

    if not providers:
        print("No providers with TEST_DISCO_ADDRESS found")
        sys.exit(1)

    all_caps = [name for name, _ in GRANT_TYPES] + [label for label, _, _ in FEATURES]
    _print_matrix(providers, all_caps)


if __name__ == "__main__":
    main()
