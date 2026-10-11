"""Logout logic — Back-Channel and RP-Initiated Logout.

Pure, protocol-agnostic logic shared by the synchronous and asynchronous
surfaces. Contains no I/O:

* Back-Channel Logout (OpenID Connect Back-Channel Logout 1.0 §2.6; claims
  defined in §2.4) — the
  standard JWT validation (signature, ``iss``, ``aud``, ``iat``, ``exp``) is
  performed by the existing ``validate_token`` path; ``validate_logout_token_claims``
  enforces only the additional rules unique to Logout Tokens.
* RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0 §2) —
  ``build_end_session_url`` constructs the end-session endpoint URL and
  ``validate_post_logout_state`` verifies the ``state`` round-trip on the
  post-logout redirect. Both are pure string operations, so — mirroring
  ``build_authorization_url`` and ``validate_authorize_callback_state`` — they
  are imported directly into both the sync and async surfaces with no wrappers.
"""

from __future__ import annotations

import hmac
from urllib.parse import urlencode, urlparse

from ..exceptions import (
    LogoutStateValidationException,
    LogoutTokenValidationException,
)
from ..oidc_constants import BackChannelLogoutRequest, Events


# The event member that MUST be present in a Logout Token's ``events`` claim
# (Back-Channel Logout 1.0 §2.6, validation step 6).
BACKCHANNEL_LOGOUT_EVENT = Events.BACK_CHANNEL_LOGOUT.value

# The request parameter name providers use to POST the Logout Token to the
# RP's ``backchannel_logout_uri`` (Back-Channel Logout 1.0 §2.5).
LOGOUT_TOKEN_PARAM = BackChannelLogoutRequest.LOGOUT_TOKEN.value

# Reserved RP-Initiated Logout parameters (RP-Initiated Logout 1.0 §2). These
# are set through the dedicated keyword arguments of ``build_end_session_url``
# and therefore must not be overridden via ``**extra_params``.
_RESERVED_END_SESSION_PARAMS = frozenset(
    {
        "id_token_hint",
        "logout_hint",
        "client_id",
        "post_logout_redirect_uri",
        "state",
        "ui_locales",
    }
)


# Claims that MUST be present in a Logout Token (Back-Channel Logout 1.0 §2.4).
# §2.4 also lists ``exp`` as REQUIRED (errata set 1) and §2.6 step 4 validates
# it; this library currently checks ``exp`` only when it is present.
# ``iss``/``aud``/``iat`` are also checked by standard JWT validation, but are
# enumerated here so a rule violation produces a precise, self-contained error
# and so the pure claim check is complete on its own.
_REQUIRED_CLAIMS = ("iss", "aud", "iat", "jti", "events")


def validate_logout_token_claims(claims: dict) -> None:
    """Validate the Logout-Token-specific claim rules (Back-Channel Logout 1.0 §2.6).

    Assumes the JWT signature, ``iss``, ``aud``, ``iat`` and (when present)
    ``exp`` have ALREADY been verified by the standard token-validation path.
    This function enforces only the rules unique to Logout Tokens (step
    numbers are §2.6's):

    * ``iss``, ``aud``, ``iat``, ``jti`` and ``events`` MUST be present
      (§2.4 claim list).
    * Step 6: ``events`` MUST be a JSON object containing the
      ``http://schemas.openid.net/event/backchannel-logout`` member.
    * Step 5: ``sub`` and/or ``sid`` MUST be present (at least one).
    * Step 7: a ``nonce`` claim MUST NOT be present (a Logout Token must not
      be usable as an ID Token).

    Args:
        claims: The decoded (and already signature/iss/aud/exp-validated)
            JWT claim set.

    Raises:
        LogoutTokenValidationException: If any Logout-Token rule is violated.
    """
    # §2.4 — required claims.
    for required in _REQUIRED_CLAIMS:
        if required not in claims:
            raise LogoutTokenValidationException(
                f"Logout token missing required '{required}' claim",
                token_part="payload",
            )

    # §2.6 step 7 — a Logout Token MUST NOT contain a ``nonce`` claim.
    if "nonce" in claims:
        raise LogoutTokenValidationException(
            "Logout token must not contain a 'nonce' claim",
            token_part="payload",
        )

    # §2.6 step 5 — at least one of ``sub`` / ``sid`` must be present.
    if claims.get("sub") is None and claims.get("sid") is None:
        raise LogoutTokenValidationException(
            "Logout token must contain at least one of 'sub' or 'sid'",
            token_part="payload",
        )

    # §2.6 step 6 — ``events`` must be a JSON object containing the
    # backchannel-logout member.
    events = claims.get("events")
    if not isinstance(events, dict):
        raise LogoutTokenValidationException(
            "Logout token 'events' claim must be a JSON object",
            token_part="payload",
        )
    if BACKCHANNEL_LOGOUT_EVENT not in events:
        raise LogoutTokenValidationException(
            "Logout token 'events' claim must contain the "
            f"'{BACKCHANNEL_LOGOUT_EVENT}' member",
            token_part="payload",
        )


def build_end_session_url(  # noqa: PLR0913  # RP-Initiated Logout 1.0 §2 defines these params
    end_session_endpoint: str,
    id_token_hint: str | None = None,
    client_id: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
    logout_hint: str | None = None,
    ui_locales: str | None = None,
    **extra_params: str,
) -> str:
    """Build an OpenID Connect RP-Initiated Logout end-session URL.

    Constructs the URL the RP redirects the End-User's user agent to in order
    to log out at the OP (OpenID Connect RP-Initiated Logout 1.0 §2). Only the
    parameters that are provided (non-``None``) are included; per the spec none
    of them is strictly required, so no parameter is hard-enforced here. When
    ``state`` is supplied it should be echoed back to
    ``post_logout_redirect_uri`` and checked with
    :func:`validate_post_logout_state`.

    Args:
        end_session_endpoint: The OP's end-session endpoint (typically
            ``DiscoveryDocumentResponse.end_session_endpoint``).
        id_token_hint: A previously issued ID Token passed as a hint about the
            End-User's session (RECOMMENDED by the spec).
        client_id: The RP's client identifier.
        post_logout_redirect_uri: URL to redirect to after logout. Must be
            registered with the OP and, per spec, is only honoured when
            ``id_token_hint`` or ``client_id`` is also present.
        state: Opaque value round-tripped to ``post_logout_redirect_uri`` for
            CSRF protection.
        logout_hint: Hint about the End-User to log out (spec §2).
        ui_locales: Preferred languages for the logout UI.
        **extra_params: Additional query parameters.

    Returns:
        The full end-session URL ready for redirect.

    Raises:
        ValueError: If *end_session_endpoint* is empty, or if *extra_params*
            collides with a reserved RP-Initiated Logout parameter.
    """
    if not end_session_endpoint or not end_session_endpoint.strip():
        raise ValueError("end_session_endpoint must not be empty")

    collisions = _RESERVED_END_SESSION_PARAMS & extra_params.keys()
    if collisions:
        raise ValueError(
            f"extra_params must not override reserved RP-Initiated Logout "
            f"parameters: {', '.join(sorted(collisions))}"
        )

    # Strip fragment — query params after a #fragment are ignored by browsers.
    parsed = urlparse(end_session_endpoint)
    if parsed.fragment:
        end_session_endpoint = end_session_endpoint.split("#", 1)[0]
        parsed = urlparse(end_session_endpoint)

    params: dict[str, str] = {}
    if id_token_hint is not None:
        params["id_token_hint"] = id_token_hint
    if logout_hint is not None:
        params["logout_hint"] = logout_hint
    if client_id is not None:
        params["client_id"] = client_id
    if post_logout_redirect_uri is not None:
        params["post_logout_redirect_uri"] = post_logout_redirect_uri
    if state is not None:
        params["state"] = state
    if ui_locales is not None:
        params["ui_locales"] = ui_locales
    params.update(extra_params)

    if not params:
        return end_session_endpoint

    query_string = urlencode(params)
    # A bare trailing "?" or "&" already introduces the query component; appending
    # another separator would corrupt the first parameter key (e.g. "logout??a=1").
    if end_session_endpoint.endswith(("?", "&")):
        return f"{end_session_endpoint}{query_string}"
    separator = "&" if parsed.query else "?"
    return f"{end_session_endpoint}{separator}{query_string}"


def validate_post_logout_state(
    expected_state: str | None,
    returned_state: str | None,
) -> None:
    """Validate the ``state`` returned to the post-logout redirect URI.

    Verifies the RP-Initiated Logout ``state`` round-trip: the value returned
    by the OP to ``post_logout_redirect_uri`` must equal the value the RP sent
    to :func:`build_end_session_url`. The comparison uses
    ``hmac.compare_digest`` (constant-time) to avoid timing side-channels,
    mirroring :func:`validate_authorize_callback_state`.

    Args:
        expected_state: The ``state`` value the RP sent to the end-session
            endpoint (from the RP's session). ``None``/empty means the RP has
            no stored state to compare against.
        returned_state: The ``state`` query parameter returned to the
            post-logout redirect URI.

    Raises:
        LogoutStateValidationException: If *expected_state* is missing/empty,
            *returned_state* is missing/empty, or the two do not match.
    """
    if not isinstance(expected_state, str) or not expected_state:
        raise LogoutStateValidationException(
            "Expected logout state is missing or empty (session may have expired)"
        )

    if not isinstance(returned_state, str) or not returned_state:
        raise LogoutStateValidationException(
            "State parameter not present in post-logout redirect"
        )

    if not hmac.compare_digest(returned_state, expected_state):
        raise LogoutStateValidationException(
            "State parameter does not match expected value"
        )


__all__ = [
    "BACKCHANNEL_LOGOUT_EVENT",
    "LOGOUT_TOKEN_PARAM",
    "build_end_session_url",
    "validate_logout_token_claims",
    "validate_post_logout_state",
]
