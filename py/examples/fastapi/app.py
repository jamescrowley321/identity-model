"""
Example FastAPI application demonstrating OAuth2/OIDC authentication.

This example shows how to use py-identity-model with FastAPI to:
- Validate JWT tokens using middleware
- Protect routes with authentication
- Access user claims via dependency injection
- Enforce authorization based on claims and scopes
"""

import os
import secrets
from typing import Annotated

from starlette.middleware.sessions import SessionMiddleware
import uvicorn

from fastapi import (  # type: ignore[attr-defined]
    Depends,
    FastAPI,
    HTTPException,
    Request,
)
from fastapi.responses import JSONResponse  # type: ignore[attr-defined]
from fastapi_identity_model import (
    Claims,
    CurrentUser,
    OIDCSettings,
    TokenValidationMiddleware,
    build_oidc_router,
    get_token,
    require_claim,
    require_scope,
)


# Annotated type alias for raw token dependency
Token = Annotated[str, Depends(get_token)]


# Browser-login (RP) and API-protection paths that must skip the Bearer middleware.
_SESSION_PATHS = [
    "/",
    "/health",
    "/docs",
    "/openapi.json",
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/me",
]

settings = OIDCSettings(
    discovery_url=os.getenv(
        "DISCOVERY_URL",
        "https://localhost:5001/.well-known/openid-configuration",
    ),
    client_id=os.getenv("CLIENT_ID", "py-identity-model-client"),
    redirect_uri=os.getenv("REDIRECT_URI", "http://localhost:8000/auth/callback"),
    client_secret=os.getenv("CLIENT_SECRET"),
    audience=os.getenv("AUDIENCE", "py-identity-model"),
    scope=os.getenv("SCOPE", "openid profile email"),
    post_login_redirect="/me",
    post_logout_redirect="/",
    excluded_paths=_SESSION_PATHS,
)

# Create FastAPI app
app = FastAPI(
    title="fastapi-identity-model example",
    description="OIDC browser login (relying party) + Bearer-token API protection",
    version="1.0.0",
)

# Signed-cookie session for the RP login flow.
#
# The signing key is never a hardcoded fallback: a published static key would
# let anyone forge a session cookie and impersonate any user. When
# SESSION_SECRET is unset we generate a random per-process key (sessions do not
# survive a restart — set SESSION_SECRET in production for that).
#
# same_site="lax" is required, not optional: the provider's redirect back to
# /auth/callback is a cross-site top-level GET, and only Lax (not Strict) sends
# the session cookie on it so state/nonce can be looked up. Set
# SESSION_HTTPS_ONLY=true behind TLS to add the Secure flag.
session_secret = os.getenv("SESSION_SECRET")
if not session_secret:
    session_secret = secrets.token_urlsafe(32)
    print("⚠️  SESSION_SECRET unset — using a random ephemeral key for this run.")
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    same_site="lax",
    https_only=os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true",
)

# Browser login: GET /auth/login -> provider -> /auth/callback -> session identity.
# store_tokens stays False: SessionMiddleware signs but does not encrypt the
# cookie, so raw access/refresh tokens must not be placed in it. This example
# only needs the session identity, not the tokens.
app.include_router(build_oidc_router(settings, store_tokens=False), prefix="/auth")

# Bearer-token validation for the /api/* resource-server routes.
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=settings.discovery_url,
    audience=settings.expected_audience,
    excluded_paths=settings.excluded_paths,
)


# Public routes (no authentication required)
@app.get("/", tags=["public"])
async def root():
    """Public root endpoint."""
    return {
        "message": "Welcome to the py-identity-model FastAPI example",
        "docs": "/docs",
        "authentication": "Bearer token required for protected endpoints",
    }


@app.get("/health", tags=["public"])
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/me", tags=["session"])
async def me(request: Request):
    """Return the browser-session identity established by the RP login flow.

    Unlike the ``/api/*`` routes (which require a Bearer token), this reads the
    logged-in user from the session cookie set by ``/auth/callback``.
    """
    user = request.session.get("oidc")
    if not user:
        return {"authenticated": False, "login": "/auth/login"}
    return {
        "authenticated": True,
        "sub": user.get("sub"),
        "claims": user.get("claims"),
        "userinfo": user.get("userinfo"),
    }


# Protected routes (authentication required)
@app.get("/api/me", tags=["protected"])
async def get_current_user_info(
    user: CurrentUser,
):
    """
    Get information about the currently authenticated user.

    Returns the user's claims principal information.
    """
    identity = user.identity
    if identity is None:
        raise HTTPException(status_code=401, detail="No identity found")
    return {
        "authenticated": bool(identity.is_authenticated),
        "authentication_type": identity.authentication_type,
        "name": identity.name,
        "claims_count": len(identity.claims),
    }


@app.get("/api/claims", tags=["protected"])
async def get_user_claims(claims: Claims):
    """
    Get all claims from the authenticated user's token.

    Returns the raw claims dictionary from the validated JWT.
    """
    return {"claims": claims}


@app.get("/api/token-info", tags=["protected"])
async def get_token_info(token: Token):
    """
    Get information about the current access token.

    Returns basic information about the JWT token.
    """
    return {
        "token_length": len(token),
        "token_preview": f"{token[:20]}...{token[-20:]}",
    }


# Routes using specific claim extraction
@app.get("/api/profile", tags=["protected"])
async def get_profile(
    user: CurrentUser,
):
    """
    Get the user's profile information from specific claims.

    Demonstrates extracting individual claims using the ClaimsPrincipal.
    """
    # Extract claims directly from the user principal
    user_id_claim = user.find_first("sub") or user.find_first("client_id")
    email_claim = user.find_first("email")
    role_claims = user.find_all("role")

    user_id = user_id_claim.value if user_id_claim else "Not provided"
    email = email_claim.value if email_claim else "Not provided"
    roles = [claim.value for claim in role_claims] if role_claims else []

    return {
        "user_id": user_id,
        "email": email,
        "roles": roles,
    }


# Routes with scope-based authorization
require_read_scope = require_scope("py-identity-model")
require_write_scope = require_scope("py-identity-model.write")


@app.get(
    "/api/data",
    tags=["protected"],
    dependencies=[Depends(require_read_scope)],
)
async def get_data():
    """
    Get data (requires 'py-identity-model' scope).

    This endpoint is protected by scope-based authorization.
    """
    return {
        "data": [
            {"id": 1, "name": "Item 1"},
            {"id": 2, "name": "Item 2"},
            {"id": 3, "name": "Item 3"},
        ],
    }


@app.post(
    "/api/data",
    tags=["protected"],
    dependencies=[Depends(require_write_scope)],
)
async def create_data(name: str):
    """
    Create data (requires 'py-identity-model.write' scope).

    This endpoint requires elevated permissions via the write scope.
    """
    return {
        "message": "Data created successfully",
        "data": {"id": 4, "name": name},
    }


# Routes with claim-based authorization
require_admin_role = require_claim("role", "admin")


@app.delete(
    "/api/admin/users/{user_id}",
    tags=["admin"],
    dependencies=[Depends(require_admin_role)],
)
async def delete_user(user_id: str):
    """
    Delete a user (requires 'admin' role).

    This endpoint is restricted to users with the admin role claim.
    """
    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": "admin",
    }


@app.get(
    "/api/admin/stats",
    tags=["admin"],
    dependencies=[Depends(require_admin_role)],
)
async def get_admin_stats():
    """
    Get admin statistics (requires 'admin' role).

    This endpoint is restricted to administrators.
    """
    return {
        "total_users": 42,
        "active_sessions": 15,
        "requests_today": 1337,
    }


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(_request, exc):
    """Custom error handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
        },
        headers=exc.headers,
    )


if __name__ == "__main__":
    print("🚀 Starting fastapi-identity-model example...")
    print(f"📍 Discovery URL: {settings.discovery_url}")
    print(f"🎯 Expected Audience: {settings.expected_audience}")
    print("\n🔐 Browser login (relying party): open http://localhost:8000/auth/login")
    print("   → after login, GET http://localhost:8000/me")
    print("\n💡 For API (Bearer) routes, get a token: python ../generate_token.py")
    print("\n📚 API documentation: http://localhost:8000/docs")
    print("\n🔐 Example API request:")
    print(
        '   curl -H "Authorization: Bearer <token>" http://localhost:8000/api/me',
    )

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=8000)
