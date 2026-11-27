"""
Authorization callback response parsing for OAuth 2.0 / OpenID Connect.

Parses redirect URIs from authorization callbacks into typed response objects,
supporting both query string (code flow) and fragment (implicit flow) parameters.

Reference: RFC 6749 Section 4.1.2, OpenID Connect Core Section 3.1.2.5
"""

import contextlib
from dataclasses import dataclass, fields
import types
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlparse

from ..exceptions import AuthorizeCallbackException
from ..oidc_constants import AuthorizeResponse as AuthorizeResponseParams
from .models import _GuardedResponseMixin


_ALLOWED_SCHEMES = frozenset({"https", "http"})

_SENSITIVE_FIELDS = frozenset(
    {"raw", "access_token", "code", "identity_token", "refresh_token"}
)


@dataclass(frozen=True, kw_only=True)
class AuthorizeCallbackResponse(_GuardedResponseMixin):
    """Parsed OAuth 2.0 / OIDC authorization callback response.

    Fields like ``code`` and ``access_token`` are guarded: accessing them
    raises ``FailedResponseAccessError`` when ``is_successful`` is
    ``False``.  The ``state`` field is *not* guarded, per RFC 6749 Section
    4.1.2.1 which requires ``state`` in error responses so callers can
    correlate errors with the original request.

    .. warning::

       The ``raw`` field contains the full redirect URI and ``values``
       contains all parsed parameters.  For implicit/hybrid flows these
       may include ``access_token`` in cleartext.  Avoid logging,
       serializing, or persisting these fields in production.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "code",
            "access_token",
            "identity_token",
            "token_type",
            "expires_in",
            "scope",
            "refresh_token",
            "session_state",
            "issuer",
        }
    )

    is_successful: bool
    raw: str
    values: dict[str, str]

    # OAuth 2.0 / OIDC response parameters (guarded)
    code: str | None = None
    access_token: str | None = None
    identity_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None
    state: str | None = None
    session_state: str | None = None
    issuer: str | None = None

    # Error fields
    error: str | None = None
    error_description: str | None = None

    def __repr__(self) -> str:
        """Redact sensitive fields to prevent token leakage in logs."""
        parts: list[str] = []
        for f in fields(self):
            val = object.__getattribute__(self, f.name)
            if f.name in _SENSITIVE_FIELDS and val is not None:
                parts.append(f"{f.name}='[REDACTED]'")
            elif f.name == "values":
                parts.append("values={...}")
            else:
                parts.append(f"{f.name}={val!r}")
        return f"{self.__class__.__name__}({', '.join(parts)})"


# Mapping from AuthorizeResponse enum values to dataclass field names.
# Most map 1:1; only id_token differs (field is ``identity_token``).
_PARAM_TO_FIELD: types.MappingProxyType[str, str] = types.MappingProxyType(
    {
        AuthorizeResponseParams.CODE.value: "code",
        AuthorizeResponseParams.ACCESS_TOKEN.value: "access_token",
        AuthorizeResponseParams.IDENTITY_TOKEN.value: "identity_token",
        AuthorizeResponseParams.TOKEN_TYPE.value: "token_type",
        AuthorizeResponseParams.EXPIRES_IN.value: "expires_in",
        AuthorizeResponseParams.SCOPE.value: "scope",
        AuthorizeResponseParams.REFRESH_TOKEN.value: "refresh_token",
        AuthorizeResponseParams.STATE.value: "state",
        AuthorizeResponseParams.SESSION_STATE.value: "session_state",
        AuthorizeResponseParams.ISSUER.value: "issuer",
        AuthorizeResponseParams.ERROR.value: "error",
        AuthorizeResponseParams.ERROR_DESCRIPTION.value: "error_description",
    }
)


def _map_params_to_fields(values: dict[str, Any]) -> dict[str, Any]:
    """Map raw authorization-response parameters to dataclass field names.

    Shared by :func:`parse_authorize_callback_response` (query/fragment
    parameters) and JARM processing (claims extracted from the response
    JWT), which use the identical ``code``/``state``/``iss``/``error``/…
    parameter names.  ``expires_in`` is coerced to ``int`` when possible;
    an uncoercible value is dropped rather than raising, matching the
    lenient parsing of the surrounding parameters.

    Args:
        values: Raw parameter name → value mapping.

    Returns:
        A mapping of dataclass field names to values, containing only the
        recognized parameters that were present in *values*.
    """
    field_values: dict[str, Any] = {}
    for param_name, field_name in _PARAM_TO_FIELD.items():
        if param_name in values:
            if field_name == "expires_in":
                with contextlib.suppress(ValueError, TypeError):
                    field_values[field_name] = int(values[param_name])
            else:
                field_values[field_name] = values[param_name]
    return field_values


def parse_authorize_callback_response(
    redirect_uri: str,
) -> AuthorizeCallbackResponse:
    """Parse an OAuth 2.0 / OIDC authorization callback redirect URI.

    Extracts parameters from the URL fragment (implicit / hybrid flows) or
    query string (authorization code flow).  Fragment takes precedence when
    both are present, matching standard browser behavior where the
    authorization server places parameters in one location.

    Args:
        redirect_uri: The full callback URL received from the authorization
            server (e.g. ``https://app.example.com/callback?code=abc&state=xyz``).

    Returns:
        An ``AuthorizeCallbackResponse`` with ``is_successful=False`` when the
        URL contains an ``error`` parameter, or ``True`` otherwise.

    Raises:
        AuthorizeCallbackException: If *redirect_uri* is ``None``, not a
            string, empty/whitespace-only, uses a non-HTTP(S) scheme, or
            contains no callback parameters.
    """
    if not isinstance(redirect_uri, str) or not redirect_uri.strip():
        raise AuthorizeCallbackException("redirect_uri must be a non-empty string")

    parsed = urlparse(redirect_uri)

    if parsed.scheme and parsed.scheme not in _ALLOWED_SCHEMES:
        raise AuthorizeCallbackException(
            f"redirect_uri scheme must be http or https, got '{parsed.scheme}'"
        )

    params_str = parsed.fragment or parsed.query

    # parse_qs returns dict[str, list[str]]; flatten to first value.
    # keep_blank_values=True preserves empty values (e.g. state=) so they
    # are distinguishable from absent parameters.
    raw_params = parse_qs(params_str, keep_blank_values=True)
    values: dict[str, str] = {k: v[0] for k, v in raw_params.items()}

    if not values:
        raise AuthorizeCallbackException("redirect_uri contains no callback parameters")

    # Map known parameters to dataclass fields
    field_values = _map_params_to_fields(values)

    if not field_values:
        raise AuthorizeCallbackException(
            "redirect_uri contains no recognized OAuth callback parameters"
        )

    has_error = "error" in field_values

    return AuthorizeCallbackResponse(
        is_successful=not has_error,
        raw=redirect_uri,
        values=values,
        **field_values,
    )


__all__ = [
    "AuthorizeCallbackResponse",
    "parse_authorize_callback_response",
]
