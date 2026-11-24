"""
Descope FastAPI Example - Production-ready OAuth2/OIDC with Descope.

This example demonstrates integrating py-identity-model with Descope's OIDC provider:
- Descope-specific configuration and scopes
- Role and permission-based authorization
- Custom claims extraction
- Token validation with Descope JWKs
- Best practices for production deployments
"""

import os
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from examples.descope.dependencies import (
    Claims,
    DescopePermissions,
    DescopeRoles,
    get_token,
    require_descope_permission,
    require_descope_role,
    require_scope,
)
from fastapi_identity_model import CurrentUser, TokenValidationMiddleware


# Annotated type alias for raw token dependency
Token = Annotated[str, Depends(get_token)]


# Descope Configuration
DESCOPE_PROJECT_ID = os.getenv("DESCOPE_PROJECT_ID", "")
ISSUER = os.getenv("ISSUER", f"https://api.descope.com/{DESCOPE_PROJECT_ID}")
AUDIENCE = os.getenv("AUDIENCE", DESCOPE_PROJECT_ID)

# Create FastAPI app
app = FastAPI(
    title="Descope + py-identity-model FastAPI Example",
    description="Production-ready OAuth2/OIDC authentication with Descope",
    version="1.0.0",
)

# Add token validation middleware
app.add_middleware(
    TokenValidationMiddleware,
    issuer=ISSUER,
    audience=AUDIENCE,
    excluded_paths=["/", "/health", "/docs", "/openapi.json"],
)


# Public routes (no authentication required)
@app.get("/", tags=["public"])
async def root():
    """Public root endpoint with Descope information."""
    return {
        "message": "Descope FastAPI Example",
        "descope_project_id": DESCOPE_PROJECT_ID,
        "issuer": ISSUER,
        "docs": "/docs",
        "authentication": "Bearer token required for protected endpoints",
    }


@app.get("/health", tags=["public"])
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "provider": "descope"}


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

    user_id = user_id_claim.value if user_id_claim else "Not provided"
    email = email_claim.value if email_claim else "Not provided"

    return {
        "user_id": user_id,
        "email": email,
    }


# Descope-specific endpoints
@app.get("/api/descope/roles", tags=["descope"])
async def get_roles(roles: DescopeRoles):
    """
    Get user's Descope roles.

    Demonstrates extracting Descope-specific role claims.
    Requires token with 'descope.claims' scope.
    """
    return {"roles": roles}


@app.get("/api/descope/permissions", tags=["descope"])
async def get_permissions(
    permissions: DescopePermissions,
):
    """
    Get user's Descope permissions.

    Demonstrates extracting Descope-specific permission claims.
    Requires token with 'descope.claims' scope.
    """
    return {"permissions": permissions}


# Role-based authorization examples
require_admin_role = require_descope_role("admin")


@app.get(
    "/api/admin/users",
    tags=["admin"],
    dependencies=[Depends(require_admin_role)],
)
async def admin_users():
    """
    Admin-only endpoint (requires 'admin' Descope role).

    This endpoint is restricted to users with the admin role in Descope.
    """
    return {
        "message": "Admin access granted",
        "users": [
            {"id": 1, "name": "User 1"},
            {"id": 2, "name": "User 2"},
        ],
    }


@app.get(
    "/api/admin/stats",
    tags=["admin"],
    dependencies=[Depends(require_admin_role)],
)
async def admin_stats():
    """
    Get admin statistics (requires 'admin' Descope role).

    This endpoint is restricted to administrators.
    """
    return {
        "total_users": 42,
        "active_sessions": 15,
        "requests_today": 1337,
    }


# Permission-based authorization examples
require_users_create = require_descope_permission("users.create")
require_users_delete = require_descope_permission("users.delete")


@app.post(
    "/api/users",
    tags=["users"],
    dependencies=[Depends(require_users_create)],
)
async def create_user(name: str, email: str):
    """
    Create a new user (requires 'users.create' Descope permission).

    This endpoint requires specific Descope permission.
    """
    return {
        "message": "User creation permitted",
        "user": {"name": name, "email": email},
    }


@app.delete(
    "/api/users/{user_id}",
    tags=["users"],
    dependencies=[Depends(require_users_delete)],
)
async def delete_user(user_id: str):
    """
    Delete a user (requires 'users.delete' Descope permission).

    This endpoint requires specific Descope permission.
    """
    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": "admin",
    }


# Scope-based authorization examples
require_read_scope = require_scope("openid")


@app.get(
    "/api/data",
    tags=["data"],
    dependencies=[Depends(require_read_scope)],
)
async def get_data():
    """
    Get data (requires 'openid' scope).

    This endpoint is protected by scope-based authorization.
    """
    return {
        "data": [
            {"id": 1, "name": "Item 1"},
            {"id": 2, "name": "Item 2"},
            {"id": 3, "name": "Item 3"},
        ],
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
    print("🚀 Starting Descope FastAPI application...")
    print(f"📍 Descope Project ID: {DESCOPE_PROJECT_ID}")
    print(f"📍 Issuer: {ISSUER}")
    print(f"🎯 Expected Audience: {AUDIENCE}")
    print("\n💡 To get a token, configure a Descope OAuth application")
    print("   and use client credentials flow")
    print("\n📚 API documentation: http://localhost:8000/docs")
    print("\n🔐 Example request:")
    print(
        '   curl -H "Authorization: Bearer <token>" http://localhost:8000/api/me',
    )

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=8000)
