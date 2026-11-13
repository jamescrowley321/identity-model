"""
FastAPI dependency injection functions for accessing user claims and identity.

These dependencies can be used in FastAPI route handlers to access
validated token information and user claims.
"""

from collections.abc import Callable
import re
from typing import Annotated

from fastapi import (  # type: ignore[attr-defined]
    Depends,
    HTTPException,
    Request,
    status,
)

from py_identity_model import ConfigurationException
from py_identity_model.identity import ClaimsPrincipal

from .middleware import AuthChallenge, BearerError


# Error message constants
_NOT_AUTHENTICATED_MSG = "Not authenticated"

# RFC 6749 §3.3 scope-token.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


def _challenge(request: Request) -> AuthChallenge:
    """The middleware's challenge for *request*, or a ``Bearer`` one without it."""
    return getattr(request.state, "auth_challenge", None) or AuthChallenge()


def _not_authenticated(request: Request) -> HTTPException:
    # RFC 6750 §3.1: a request without credentials gets no error code.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_NOT_AUTHENTICATED_MSG,
        headers={"WWW-Authenticate": _challenge(request).header()},
    )


def _forbidden(
    request: Request, detail: str, scope: str | None = None
) -> HTTPException:
    # RFC 6750 §3: a token that does not enable access gets a challenge;
    # §3.1: insufficient_scope with 403.
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail,
        headers={
            "WWW-Authenticate": _challenge(request).header(
                error=BearerError.INSUFFICIENT_SCOPE, scope=scope
            )
        },
    )


def get_current_user(request: Request) -> ClaimsPrincipal:
    """
    Dependency to get the current authenticated user as a ClaimsPrincipal.

    This dependency should be used after the TokenValidationMiddleware has
    validated the token and attached the user to the request state.

    Args:
        request: The FastAPI request object

    Returns:
        ClaimsPrincipal: The authenticated user principal

    Raises:
        HTTPException: If no authenticated user is found

    Example:
        ```python
        @app.get("/profile")
        async def get_profile(
            user: ClaimsPrincipal = Depends(get_current_user),
        ):
            return {"user_id": user.identity.name}
        ```
    """
    if not hasattr(request.state, "user"):
        raise _not_authenticated(request)

    return request.state.user


def get_claims(request: Request) -> dict:
    """
    Dependency to get all claims from the validated token.

    Args:
        request: The FastAPI request object

    Returns:
        dict: Dictionary of all claims from the token

    Raises:
        HTTPException: If no claims are found

    Example:
        ```python
        @app.get("/claims")
        async def get_all_claims(claims: dict = Depends(get_claims)):
            return {"claims": claims}
        ```
    """
    if not hasattr(request.state, "claims"):
        raise _not_authenticated(request)

    return request.state.claims


def get_token(request: Request) -> str:
    """
    Dependency to get the raw JWT token.

    Args:
        request: The FastAPI request object

    Returns:
        str: The raw JWT token

    Raises:
        HTTPException: If no token is found

    Example:
        ```python
        @app.get("/token-info")
        async def get_token_info(token: str = Depends(get_token)):
            return {"token_length": len(token)}
        ```
    """
    if not hasattr(request.state, "token"):
        raise _not_authenticated(request)

    return request.state.token


# Annotated type aliases for FastAPI dependency injection (avoids B008)
CurrentUser = Annotated[ClaimsPrincipal, Depends(get_current_user)]
Claims = Annotated[dict, Depends(get_claims)]


def get_claim_value(claim_type: str) -> Callable[..., str | None]:
    """
    Factory function to create a dependency that extracts a specific claim value.

    Args:
        claim_type: The claim type to extract

    Returns:
        callable: A dependency function that extracts the claim value

    Example:
        ```python
        # Create a dependency for the 'sub' claim
        get_user_id = get_claim_value("sub")


        @app.get("/user-data")
        async def get_user_data(user_id: str = Depends(get_user_id)):
            return {"user_id": user_id}
        ```
    """

    def _get_claim(
        user: CurrentUser,
    ) -> str | None:
        if user.identity is None:
            return None
        claim = user.identity.find_first(claim_type)
        if claim:
            return claim.value
        return None

    return _get_claim


def get_claim_values(claim_type: str) -> Callable[..., list[str]]:
    """
    Factory function to create a dependency that extracts all values for a specific claim type.

    Useful for claims that can have multiple values (like roles).

    Args:
        claim_type: The claim type to extract

    Returns:
        callable: A dependency function that extracts all claim values

    Example:
        ```python
        # Create a dependency for the 'role' claim
        get_user_roles = get_claim_values("role")


        @app.get("/roles")
        async def get_roles(roles: List[str] = Depends(get_user_roles)):
            return {"roles": roles}
        ```
    """

    def _get_claims(
        user: CurrentUser,
    ) -> list[str]:
        if user.identity is None:
            return []
        claims = user.identity.find_all(claim_type)
        return [claim.value for claim in claims]

    return _get_claims


def require_claim(
    claim_type: str,
    claim_value: str | None = None,
) -> Callable[..., None]:
    """
    Factory function to create a dependency that requires a specific claim.

    This can be used to enforce authorization based on claims.

    Args:
        claim_type: The required claim type
        claim_value: Optional specific value the claim must have

    Returns:
        callable: A dependency function that validates the claim

    Raises:
        HTTPException: ``403`` with an ``insufficient_scope`` challenge if the
            required claim is not present or doesn't match the value

    Example:
        ```python
        # Require that the user has a 'role' claim with value 'admin'
        require_admin = require_claim("role", "admin")


        @app.delete("/users/{user_id}")
        async def delete_user(user_id: str, _: None = Depends(require_admin)):
            # Only users with admin role can access this
            return {"message": f"User {user_id} deleted"}
        ```
    """

    def _check_claim(
        request: Request,
        user: CurrentUser,
    ) -> None:
        if not user.has_claim(claim_type, claim_value):
            if claim_value is None:
                raise _forbidden(request, f"Required claim '{claim_type}' not found")
            raise _forbidden(
                request,
                f"Required claim '{claim_type}' with value '{claim_value}' not found",
            )

    return _check_claim


def require_scope(scope: str) -> Callable[..., None]:
    """
    Factory function to create a dependency that requires a specific OAuth scope.

    Args:
        scope: The required scope

    Returns:
        callable: A dependency function that validates the scope

    Raises:
        ConfigurationException: *scope* is not a single RFC 6749 §3.3
            scope-token.
        HTTPException: ``403`` with ``WWW-Authenticate: Bearer
            error="insufficient_scope", scope="<scope>"`` (or ``DPoP``) if
            the required scope is not present

    Example:
        ```python
        require_read_scope = require_scope("api.read")


        @app.get("/data")
        async def get_data(_: None = Depends(require_read_scope)):
            return {"data": "sensitive information"}
        ```
    """

    if not _SCOPE_TOKEN.fullmatch(scope):
        raise ConfigurationException(
            f"require_scope needs a single RFC 6749 scope-token; got {scope!r}"
        )

    def _check_scope(request: Request, claims: Claims) -> None:
        # Scopes live in 'scope' (space-separated string) or 'scp' (array).
        raw = claims.get("scope") or claims.get("scp")
        if isinstance(raw, str):
            scopes: list = raw.split()
        elif isinstance(raw, (list, tuple)):
            scopes = [s for s in raw if isinstance(s, str)]
        else:
            # A dict/number/None or any unexpected type is not a usable scope
            # claim — fail closed rather than letting `in` match dict keys or
            # raise a TypeError.
            scopes = []

        if scope not in scopes:
            raise _forbidden(request, f"Required scope '{scope}' not found", scope)

    return _check_scope
