"""fastapi-identity-model: OIDC/OAuth2 integration for FastAPI.

Built on `py-identity-model`. Provides:

- ``TokenValidationMiddleware`` — validate incoming Bearer tokens (resource server).
- ``build_oidc_router`` — a mountable authorization-code + PKCE login flow (RP).
- ``Depends``-based helpers — ``get_current_user``, ``require_scope``, ``require_claim`` …
- ``TokenManager`` — access-token refresh lifecycle.
"""

from importlib.metadata import PackageNotFoundError, version

from .config import OIDCSettings
from .dependencies import (
    Claims,
    CurrentUser,
    get_claim_value,
    get_claim_values,
    get_claims,
    get_current_user,
    get_token,
    require_claim,
    require_scope,
)
from .middleware import TokenValidationMiddleware
from .rp import build_oidc_router, oidc_public_paths
from .token_manager import TokenManager
from .ws import build_ws_authenticator


try:
    __version__ = version("fastapi-identity-model")
except PackageNotFoundError:  # pragma: no cover - only during local, uninstalled use
    __version__ = "0.0.0"

__all__ = [
    "Claims",
    "CurrentUser",
    "OIDCSettings",
    "TokenManager",
    "TokenValidationMiddleware",
    "build_oidc_router",
    "build_ws_authenticator",
    "get_claim_value",
    "get_claim_values",
    "get_claims",
    "get_current_user",
    "get_token",
    "oidc_public_paths",
    "require_claim",
    "require_scope",
]
