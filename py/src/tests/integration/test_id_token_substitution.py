"""Real-OP validation of the F-07 ID-token-substitution discriminator.

The FastAPI ``TokenValidationMiddleware`` gained an opt-in defence
(``require_access_token_marker``) that rejects a validated token carrying no
*positive* access-token marker claim — closing the gap where a code-flow ID
token (no nonce/at_hash/c_hash, ``aud == client_id``) is replayed as a bearer
access token. Its default marker set is ``("scope", "scp")``.

That defence is only safe if, for a real provider, the marker set actually
separates a genuine ID token from a genuine access token: the ID token must NOT
carry it (else the fix would be a no-op) and the access token MUST carry it
(else the fix would falsely reject real access tokens). The middleware logic
itself is deterministic and unit-tested against mocked claims; this test proves
the premise on REAL tokens minted against whatever provider ``--env-file``
selects, across the CI provider matrix.

Lives in the core integration suite (``src/tests -m integration``) because that
is where the real-token fixtures and the running OP fixtures are — the fastapi
package is not synced into this environment, so the middleware is not imported;
its decision predicate is mirrored locally and kept in lockstep by this test.
"""

import jwt as pyjwt
import pytest

from ..harness import Provider


pytestmark = pytest.mark.integration

# Mirrors ``_DEFAULT_ACCESS_TOKEN_MARKER_CLAIMS`` in the fastapi package's
# ``middleware.py``. Kept in sync deliberately: this suite cannot import the
# fastapi package (not synced here), so if the middleware default changes, this
# constant must change with it — the assertions below are what would catch a
# drift that makes the default unsafe for a real provider.
_ACCESS_TOKEN_MARKER_CLAIMS = ("scope", "scp")

# A JWT is three non-empty dot-separated segments.
_JWT_SEPARATOR_COUNT = 2


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == _JWT_SEPARATOR_COUNT and all(token.split("."))


def _claims(token: str) -> dict:
    """Decode a JWT WITHOUT signature verification (only to read claim names)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def _has_access_token_marker(claims: dict) -> bool:
    """The exact predicate the middleware applies when the defence is enabled."""
    return any(c in claims for c in _ACCESS_TOKEN_MARKER_CLAIMS)


@pytest.mark.integration
class TestIdTokenSubstitutionDiscriminator:
    """The default marker set must separate a real ID token from a real access
    token for the provider under test."""

    def test_marker_set_separates_id_and_access_tokens(
        self, auth_code_result, harness_provider, request
    ):
        if harness_provider is Provider.ZITADEL:
            # Known finding: Zitadel JWT access tokens carry neither
            # ``scope`` nor ``scp``, so the default marker set rejects them.
            request.applymarker(
                pytest.mark.xfail(
                    strict=True,
                    reason="Zitadel JWT access tokens carry no scope/scp claim",
                )
            )
        token = auth_code_result["token_response"].token or {}
        id_token = token.get("id_token")
        access_token = token.get("access_token")

        if not id_token:
            pytest.skip("Auth-code response carried no id_token — nothing to separate")
        assert _looks_like_jwt(id_token), "ID token is not a JWT — cannot inspect"
        assert access_token, "Auth-code flow returned no access_token"

        id_claims = _claims(id_token)
        # The ID token must NOT satisfy the access-token marker predicate,
        # otherwise the F-07 defence would let this provider's ID token through.
        assert not _has_access_token_marker(id_claims), (
            "real ID token carries an access-token marker claim "
            f"({[c for c in _ACCESS_TOKEN_MARKER_CLAIMS if c in id_claims]}); "
            "the default marker set does not separate ID from access tokens for "
            "this provider — the F-07 defence would be a no-op here"
        )

        # A JWT access token MUST satisfy the predicate, otherwise the defence
        # would falsely reject this provider's real access tokens.
        if not _looks_like_jwt(access_token):
            pytest.skip("Provider issued an opaque access token — marker check N/A")
        access_claims = _claims(access_token)
        assert _has_access_token_marker(access_claims), (
            "real access token carries none of the default marker claims "
            f"{_ACCESS_TOKEN_MARKER_CLAIMS}; enabling require_access_token_marker "
            "would falsely reject this provider's access tokens — the default "
            "marker set is unsafe for this OP"
        )
