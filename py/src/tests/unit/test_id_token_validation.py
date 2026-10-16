"""Unit tests for OpenID Connect ID Token profile validation.

Covers the ID-Token-specific rules from OpenID Connect Core 1.0 §3.1.3.7
(required ``sub``, the opt-in ``azp`` authorized-party rules, ``nonce`` binding, and
``auth_time``/``max_age`` freshness) and §3.3.2.11 (``at_hash``/``c_hash``
token/code binding). Structural rules are exercised directly against the pure
``validate_id_token_claims``; the accept/reject cases also run the full
signature + discovery flow through the sync and async ``validate_id_token``
wrappers via respx, and a parity block asserts the pure function and both
wrappers agree.
"""

import base64
import hashlib
import time

import httpx
import pytest
import respx

from py_identity_model.aio.id_token import validate_id_token as aio_validate_id_token
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as aio_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as aio_clear_jwks_cache,
)
from py_identity_model.core.id_token_logic import validate_id_token_claims
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    IdTokenValidationException,
    TokenValidationException,
    UntrustedAudienceException,
)
from py_identity_model.sync.id_token import validate_id_token
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


_ISSUER = "https://example.com"
_AUDIENCE = "client-123"
_JWKS_URI = "https://example.com/jwks"

# A fixed, injected "now" so the ``max_age``/``auth_time`` arithmetic is
# deterministic and does not depend on wall-clock time during the test run.
_NOW = 1_700_000_000.0


def _oidc_left_half(value: str, hasher) -> str:
    """Independently recompute an OIDC left-half hash (at_hash/c_hash).

    Deliberately *not* importing the library helper — the test pins the exact
    §3.3.2.11 construction (ASCII octets, left half of the digest, base64url
    without padding) so a regression in the library helper cannot make the
    test pass against its own wrong answer.
    """
    digest = hasher(value.encode("ascii")).digest()
    return (
        base64.urlsafe_b64encode(digest[: len(digest) // 2])
        .rstrip(b"=")
        .decode("ascii")
    )


def _valid_id_claims(**overrides) -> dict:
    """Build a well-formed ID Token claim set (single audience = client_id).

    ``iat``/``exp`` use wall-clock time so tokens run through the full
    signature + ``exp`` validation in ``validate_token`` unexpired. The
    ID-Token profile itself does not read ``iat``/``exp``; the injectable
    ``now``/``auth_time`` arithmetic in the pure tests uses the fixed ``_NOW``.
    """
    issued_at = int(time.time())
    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": "user-1",
        "iat": issued_at,
        "exp": issued_at + 3600,
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    return generate_rsa_keypair()


def _mock_disco_and_jwks(key_dict: dict) -> None:
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    respx.get(_JWKS_URI).mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )


def _config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=_AUDIENCE,
        issuer=_ISSUER,
    )


class TestIdTokenExceptionType:
    """The dedicated exception must fail closed under the token-validation handler."""

    def test_id_token_exception_is_token_validation_exception(self):
        # A profile failure is a token-validation failure: callers using the
        # idiomatic ``except TokenValidationException`` must catch it (fail
        # closed) rather than have it escape as an unrelated sibling.
        assert issubclass(IdTokenValidationException, TokenValidationException)


class TestPureIdTokenClaimValidation:
    """Structural ID-Token rules exercised against the pure claim function."""

    def test_valid_claims_accepted(self):
        # §3.1.3.7: a well-formed single-audience ID Token validates cleanly.
        validate_id_token_claims(
            _valid_id_claims(), "RS256", client_id=_AUDIENCE, now=_NOW
        )

    def test_missing_sub_rejected(self):
        # §2 / §3.1.3.7: ``sub`` is REQUIRED.
        claims = _valid_id_claims()
        del claims["sub"]
        with pytest.raises(IdTokenValidationException, match=r"sub"):
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_empty_sub_rejected(self):
        # §3.1.3.7: a present-but-empty ``sub`` is not a valid subject.
        with pytest.raises(IdTokenValidationException, match=r"sub"):
            validate_id_token_claims(
                _valid_id_claims(sub=""), "RS256", client_id=_AUDIENCE, now=_NOW
            )

    def test_multi_aud_without_azp_accepted_by_default(self):
        # azp is ignored unless the caller opts in (§2; errata 2 dropped the
        # Core 1.0 step-4 multiple-audience SHOULD).
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"])
        validate_id_token_claims(
            claims,
            "RS256",
            client_id=_AUDIENCE,
            trusted_audiences=["other-client"],
            now=_NOW,
        )

    def test_multi_aud_without_azp_rejected_when_opted_in(self):
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"])
        with pytest.raises(
            IdTokenValidationException, match=r"multiple audiences must contain"
        ):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                trusted_audiences=["other-client"],
                validate_azp=True,
                now=_NOW,
            )

    def test_multi_aud_with_wrong_azp_accepted_by_default(self):
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp="other-client")
        validate_id_token_claims(
            claims,
            "RS256",
            client_id=_AUDIENCE,
            trusted_audiences=["other-client"],
            now=_NOW,
        )

    def test_multi_aud_with_wrong_azp_rejected_when_opted_in(self):
        # Errata 2 §3.1.3.7 step 5: a present ``azp`` names this client.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp="other-client")
        with pytest.raises(IdTokenValidationException, match=r"'azp' claim does not"):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                trusted_audiences=["other-client"],
                validate_azp=True,
                now=_NOW,
            )

    @pytest.mark.parametrize("validate_azp", [False, True])
    def test_multi_aud_with_correct_azp_accepted(self, validate_azp):
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE)
        validate_id_token_claims(
            claims,
            "RS256",
            client_id=_AUDIENCE,
            trusted_audiences=["other-client"],
            validate_azp=validate_azp,
            now=_NOW,
        )

    def test_cross_client_azp_accepted_by_default(self):
        # Google's Android-to-backend flow: aud is this client, azp is the
        # presenting mobile client.
        claims = _valid_id_claims(azp="android-client")
        validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_single_aud_with_wrong_azp_rejected_when_opted_in(self):
        claims = _valid_id_claims(azp="android-client")
        with pytest.raises(IdTokenValidationException, match=r"'azp' claim does not"):
            validate_id_token_claims(
                claims, "RS256", client_id=_AUDIENCE, validate_azp=True, now=_NOW
            )

    def test_empty_azp_with_multi_aud_rejected_when_opted_in(self):
        # An empty-string ``azp`` counts as absent for the multi-audience rule.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp="")
        with pytest.raises(
            IdTokenValidationException, match=r"multiple audiences must contain"
        ):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                trusted_audiences=["other-client"],
                validate_azp=True,
                now=_NOW,
            )

    def test_azp_not_compared_without_client_id(self):
        claims = _valid_id_claims(azp="android-client")
        validate_id_token_claims(
            claims,
            "RS256",
            trusted_audiences=[_AUDIENCE],
            validate_azp=True,
            now=_NOW,
        )

    def test_nonce_match_accepted(self):
        # §3.1.3.7 step 11 (positive): matching ``nonce`` validates cleanly.
        claims = _valid_id_claims(nonce="n-abc")
        validate_id_token_claims(
            claims, "RS256", client_id=_AUDIENCE, nonce="n-abc", now=_NOW
        )

    def test_nonce_mismatch_rejected(self):
        # §3.1.3.7 step 11: a mismatched ``nonce`` is rejected.
        claims = _valid_id_claims(nonce="n-abc")
        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token_claims(
                claims, "RS256", client_id=_AUDIENCE, nonce="n-different", now=_NOW
            )

    def test_nonce_expected_but_absent_rejected(self):
        # §3.1.3.7 step 11: caller expected a ``nonce`` but the token has none.
        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token_claims(
                _valid_id_claims(),
                "RS256",
                client_id=_AUDIENCE,
                nonce="n-abc",
                now=_NOW,
            )

    def test_token_nonce_ignored_when_not_requested(self):
        # A ``nonce`` in the token is not checked when the caller does not pass
        # one — the RP only binds ``nonce`` when it sent one.
        claims = _valid_id_claims(nonce="left-over")
        validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_max_age_within_window_accepted(self):
        # §3.1.3.7 step 12 (positive): a recent ``auth_time`` is within max_age.
        claims = _valid_id_claims(auth_time=int(_NOW) - 100)
        validate_id_token_claims(
            claims, "RS256", client_id=_AUDIENCE, max_age=300, now=_NOW
        )

    def test_max_age_stale_auth_time_rejected(self):
        # §3.1.3.7 step 12: an ``auth_time`` older than max_age is rejected.
        claims = _valid_id_claims(auth_time=int(_NOW) - 3600)
        with pytest.raises(IdTokenValidationException, match=r"max_age"):
            validate_id_token_claims(
                claims, "RS256", client_id=_AUDIENCE, max_age=300, now=_NOW
            )

    def test_max_age_missing_auth_time_rejected(self):
        # §3.1.3.7 step 12: ``max_age`` requested but no ``auth_time`` present.
        with pytest.raises(IdTokenValidationException, match=r"auth_time"):
            validate_id_token_claims(
                _valid_id_claims(), "RS256", client_id=_AUDIENCE, max_age=300, now=_NOW
            )

    def test_max_age_boolean_auth_time_rejected(self):
        # ``bool`` is a subclass of ``int`` — a boolean ``auth_time`` is not a
        # valid timestamp and must be rejected.
        claims = _valid_id_claims(auth_time=True)
        with pytest.raises(IdTokenValidationException, match=r"auth_time"):
            validate_id_token_claims(
                claims, "RS256", client_id=_AUDIENCE, max_age=300, now=_NOW
            )

    def test_max_age_leeway_absorbs_small_skew(self):
        # §3.1.3.7 step 12: leeway widens the acceptance window by its amount.
        claims = _valid_id_claims(auth_time=int(_NOW) - 310)
        # Without leeway 310 > 300 would fail; leeway=30 pulls it back in.
        validate_id_token_claims(
            claims, "RS256", client_id=_AUDIENCE, max_age=300, leeway=30, now=_NOW
        )

    def test_max_age_uses_wall_clock_when_now_omitted(self):
        # ``now`` is injectable for tests but defaults to the wall clock; a
        # just-issued ``auth_time`` is comfortably within the window.
        claims = _valid_id_claims(auth_time=int(time.time()))
        validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, max_age=300)

    def test_at_hash_correct_accepted(self):
        # §3.3.2.11 (positive): a correct RS256 (SHA-256) ``at_hash`` validates.
        access_token = "SlAV32hkKG-access-token"
        claims = _valid_id_claims(at_hash=_oidc_left_half(access_token, hashlib.sha256))
        validate_id_token_claims(
            claims, "RS256", client_id=_AUDIENCE, access_token=access_token, now=_NOW
        )

    def test_at_hash_wrong_rejected(self):
        # §3.3.2.11: a wrong ``at_hash`` is rejected.
        claims = _valid_id_claims(
            at_hash=_oidc_left_half("some-other-token", hashlib.sha256)
        )
        with pytest.raises(IdTokenValidationException, match=r"at_hash"):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
                now=_NOW,
            )

    def test_at_hash_absent_accepted_for_token_endpoint_access_token(self):
        # §3.1.3.6: a token-endpoint ID Token may omit ``at_hash``, so an
        # access token not issued with the ID Token binds only if one is present.
        validate_id_token_claims(
            _valid_id_claims(),
            "RS256",
            client_id=_AUDIENCE,
            access_token="SlAV32hkKG-access-token",
            access_token_issued_with_id_token=False,
            now=_NOW,
        )

    def test_at_hash_missing_rejected_by_default(self):
        # §3.2.2.10 / §3.3.2.11: an access token from the same authorization
        # response as the ID Token REQUIRES ``at_hash``, and a supplied access
        # token is taken to be one unless the caller says otherwise.
        with pytest.raises(
            IdTokenValidationException, match=r"missing required 'at_hash'"
        ):
            validate_id_token_claims(
                _valid_id_claims(),
                "RS256",
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
                now=_NOW,
            )

    def test_at_hash_wrong_rejected_when_issued_with_id_token(self):
        # A present but wrong ``at_hash`` is a mismatch, not a missing claim.
        claims = _valid_id_claims(
            at_hash=_oidc_left_half("some-other-token", hashlib.sha256)
        )
        with pytest.raises(
            IdTokenValidationException, match=r"'at_hash' claim does not match"
        ):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
                access_token_issued_with_id_token=True,
                now=_NOW,
            )

    def test_at_hash_non_string_rejected_when_not_required(self):
        # A present ``at_hash`` must match even when presence is not required.
        with pytest.raises(
            IdTokenValidationException, match=r"'at_hash' claim does not match"
        ):
            validate_id_token_claims(
                _valid_id_claims(at_hash=None),
                "RS256",
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
                access_token_issued_with_id_token=False,
                now=_NOW,
            )

    def test_absent_unrequired_at_hash_skips_alg_lookup(self):
        # With nothing to verify, an unmappable ``alg`` is never consulted.
        validate_id_token_claims(
            _valid_id_claims(),
            "UNKNOWN",
            client_id=_AUDIENCE,
            access_token="SlAV32hkKG-access-token",
            access_token_issued_with_id_token=False,
            now=_NOW,
        )

    def test_issued_with_id_token_flags_without_values_are_noops(self):
        # The presence switches only apply to a supplied access token / code.
        validate_id_token_claims(
            _valid_id_claims(),
            "RS256",
            client_id=_AUDIENCE,
            access_token_issued_with_id_token=True,
            code_issued_with_id_token=True,
            now=_NOW,
        )

    def test_c_hash_absent_accepted_when_code_not_issued_with_id_token(self):
        validate_id_token_claims(
            _valid_id_claims(),
            "RS256",
            client_id=_AUDIENCE,
            code="Qcb0Orv1-authorization-code",
            code_issued_with_id_token=False,
            now=_NOW,
        )

    def test_c_hash_missing_rejected_by_default(self):
        # §3.3.2.11: a code from the same authorization response as the ID
        # Token (``code id_token``) REQUIRES ``c_hash``, the default.
        with pytest.raises(
            IdTokenValidationException, match=r"missing required 'c_hash'"
        ):
            validate_id_token_claims(
                _valid_id_claims(),
                "RS256",
                client_id=_AUDIENCE,
                code="Qcb0Orv1-authorization-code",
                now=_NOW,
            )

    def test_c_hash_correct_accepted_when_issued_with_id_token(self):
        code = "Qcb0Orv1-authorization-code"
        claims = _valid_id_claims(c_hash=_oidc_left_half(code, hashlib.sha256))
        validate_id_token_claims(
            claims,
            "RS256",
            client_id=_AUDIENCE,
            code=code,
            code_issued_with_id_token=True,
            now=_NOW,
        )

    def test_at_hash_ignored_when_no_access_token(self):
        # ``at_hash`` is not checked when the caller passes no access token.
        claims = _valid_id_claims(at_hash="whatever-unchecked")
        validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_c_hash_correct_accepted(self):
        # §3.3.2.11 (positive): a correct RS256 (SHA-256) ``c_hash`` validates.
        code = "SplxlOBeZQQYbYS6WxSbIA-code"
        claims = _valid_id_claims(c_hash=_oidc_left_half(code, hashlib.sha256))
        validate_id_token_claims(
            claims, "RS256", client_id=_AUDIENCE, code=code, now=_NOW
        )

    def test_c_hash_wrong_rejected(self):
        # §3.3.2.11: a wrong ``c_hash`` is rejected.
        claims = _valid_id_claims(c_hash=_oidc_left_half("other-code", hashlib.sha256))
        with pytest.raises(IdTokenValidationException, match=r"c_hash"):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                code="SplxlOBeZQQYbYS6WxSbIA-code",
                now=_NOW,
            )

    def test_at_hash_es384_uses_sha384(self):
        # §3.3.2.11: an ``*384`` alg selects SHA-384 for the left-half hash.
        access_token = "es384-access-token"
        claims = _valid_id_claims(at_hash=_oidc_left_half(access_token, hashlib.sha384))
        validate_id_token_claims(
            claims, "ES384", client_id=_AUDIENCE, access_token=access_token, now=_NOW
        )

    def test_c_hash_ps512_uses_sha512(self):
        # §3.3.2.11: a ``*512`` alg selects SHA-512 for the left-half hash.
        code = "ps512-code"
        claims = _valid_id_claims(c_hash=_oidc_left_half(code, hashlib.sha512))
        validate_id_token_claims(
            claims, "PS512", client_id=_AUDIENCE, code=code, now=_NOW
        )

    def test_at_hash_eddsa_uses_sha512(self):
        # §3.3.2.11: the EdDSA family hashes with SHA-512.
        access_token = "eddsa-access-token"
        claims = _valid_id_claims(at_hash=_oidc_left_half(access_token, hashlib.sha512))
        validate_id_token_claims(
            claims, "EdDSA", client_id=_AUDIENCE, access_token=access_token, now=_NOW
        )

    def test_unsupported_alg_for_hash_check_rejected(self):
        # §3.3.2.11 (fail closed): an ``alg`` that maps to no known hash must
        # raise rather than silently skip the binding check.
        claims = _valid_id_claims(at_hash="anything")
        with pytest.raises(IdTokenValidationException, match=r"[Aa]lg"):
            validate_id_token_claims(
                claims,
                "none",
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
                now=_NOW,
            )

    def test_missing_header_alg_for_hash_check_rejected(self):
        # §3.3.2.11 (fail closed): a hash check with no header ``alg`` raises.
        claims = _valid_id_claims(at_hash="anything")
        with pytest.raises(IdTokenValidationException, match=r"alg"):
            validate_id_token_claims(
                claims,
                None,
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
                now=_NOW,
            )


class TestNonAsciiInputsFailClosed:
    """Non-ASCII hash inputs must fail closed as ``IdTokenValidationException``.

    ``str.encode('ascii')`` (used to derive ``at_hash``/``c_hash``) raises
    ``UnicodeEncodeError`` and ``hmac.compare_digest`` (used for the
    ``nonce``/``at_hash``/``c_hash`` comparisons) raises ``TypeError`` on a
    non-ASCII ``str``. Both are re-raised as ``IdTokenValidationException`` so
    they stay inside the idiomatic ``except TokenValidationException``
    fail-closed handler instead of escaping as an unrelated builtin (LOW-1).
    Asserting ``IdTokenValidationException`` here would fail on the pre-fix
    code, where the raw ``UnicodeEncodeError``/``TypeError`` propagates.
    """

    def test_non_ascii_access_token_raises_id_token_exception(self):
        # A non-ASCII access token can't be ASCII-encoded for the at_hash
        # digest; surface IdTokenValidationException, not UnicodeEncodeError.
        with pytest.raises(IdTokenValidationException, match=r"ASCII"):
            validate_id_token_claims(
                _valid_id_claims(at_hash="present-so-the-hash-is-computed"),
                "RS256",
                client_id=_AUDIENCE,
                access_token="café-access-token",
                now=_NOW,
            )

    def test_non_ascii_code_raises_id_token_exception(self):
        # Same for a non-ASCII authorization code feeding the c_hash digest.
        with pytest.raises(IdTokenValidationException, match=r"ASCII"):
            validate_id_token_claims(
                _valid_id_claims(c_hash="present-so-the-hash-is-computed"),
                "RS256",
                client_id=_AUDIENCE,
                code="café-code",
                now=_NOW,
            )

    def test_non_ascii_expected_nonce_raises_id_token_exception(self):
        # A non-ASCII expected nonce makes hmac.compare_digest raise TypeError;
        # surface IdTokenValidationException instead of the bare TypeError.
        claims = _valid_id_claims(nonce="n-abc")
        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                nonce="café",
                now=_NOW,
            )


def _clear_sync_caches() -> None:
    clear_discovery_cache()
    clear_jwks_cache()


async def _clear_async_caches() -> None:
    await aio_clear_discovery_cache()
    await aio_clear_jwks_cache()


class TestUntrustedAudiences:
    """§3.1.3.7 step 3: reject additional audiences the client does not trust."""

    def test_untrusted_second_audience_rejected(self):
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE)
        with pytest.raises(UntrustedAudienceException) as exc_info:
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)
        assert exc_info.value.details == {"untrusted_audiences": ["other-client"]}

    def test_untrusted_audience_is_an_id_token_profile_failure(self):
        # Callers catching the profile (or token-validation) exception still
        # fail closed on the new rule.
        assert issubclass(UntrustedAudienceException, IdTokenValidationException)

    def test_trusted_second_audience_accepted(self):
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE)
        validate_id_token_claims(
            claims,
            "RS256",
            client_id=_AUDIENCE,
            trusted_audiences=["other-client"],
            now=_NOW,
        )

    def test_empty_trusted_list_still_rejects(self):
        # The trusted list only adds trusted values; it cannot switch the
        # check off.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE)
        with pytest.raises(UntrustedAudienceException):
            validate_id_token_claims(
                claims, "RS256", client_id=_AUDIENCE, trusted_audiences=[], now=_NOW
            )

    def test_only_the_untrusted_values_are_reported(self):
        claims = _valid_id_claims(
            aud=[_AUDIENCE, "trusted-api", "rogue-api"], azp=_AUDIENCE
        )
        with pytest.raises(UntrustedAudienceException) as exc_info:
            validate_id_token_claims(
                claims,
                "RS256",
                client_id=_AUDIENCE,
                trusted_audiences=["trusted-api"],
                now=_NOW,
            )
        assert exc_info.value.details == {"untrusted_audiences": ["rogue-api"]}

    def test_single_audience_unaffected_by_trusted_list(self):
        validate_id_token_claims(
            _valid_id_claims(),
            "RS256",
            client_id=_AUDIENCE,
            trusted_audiences=["other-client"],
            now=_NOW,
        )

    def test_untrusted_audience_checked_before_azp(self):
        # Step 3 precedes the opt-in multiple-audience ``azp`` requirement.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"])
        with pytest.raises(UntrustedAudienceException):
            validate_id_token_claims(
                claims, "RS256", client_id=_AUDIENCE, validate_azp=True, now=_NOW
            )

    def test_without_client_id_every_audience_is_untrusted(self):
        # Fails closed: with no client_id and no trusted list there is nothing
        # the token's audience can be trusted as.
        with pytest.raises(UntrustedAudienceException) as exc_info:
            validate_id_token_claims(_valid_id_claims(), "RS256", now=_NOW)
        assert exc_info.value.details == {"untrusted_audiences": [_AUDIENCE]}

    def test_non_string_audience_is_untrusted(self):
        claims = _valid_id_claims(aud=[_AUDIENCE, 7], azp=_AUDIENCE)
        with pytest.raises(UntrustedAudienceException) as exc_info:
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)
        assert exc_info.value.details == {"untrusted_audiences": [7]}

    @pytest.mark.parametrize(
        "bare", [_AUDIENCE, b"client-123", ""], ids=["str", "bytes", "empty"]
    )
    def test_bare_string_trusted_audiences_rejected(self, bare):
        # A bare ``str``/``bytes`` would iterate as single characters.
        with pytest.raises(ConfigurationException, match="trusted_audiences"):
            validate_id_token_claims(
                _valid_id_claims(),
                "RS256",
                client_id=_AUDIENCE,
                trusted_audiences=bare,
                now=_NOW,
            )

    @pytest.mark.parametrize("client_id", [_AUDIENCE, None], ids=["client", "none"])
    def test_absent_audience_rejected(self, client_id):
        # §2: aud is REQUIRED, with or without a configured client_id.
        claims = _valid_id_claims()
        del claims["aud"]
        with pytest.raises(IdTokenValidationException, match="missing required 'aud'"):
            validate_id_token_claims(claims, "RS256", client_id=client_id, now=_NOW)

    @pytest.mark.parametrize(
        "aud",
        [None, "", [], [""], ("", "")],
        ids=["null", "empty-str", "empty-list", "list-of-empty", "tuple-of-empty"],
    )
    def test_empty_audience_rejected(self, aud):
        with pytest.raises(IdTokenValidationException, match="missing required 'aud'"):
            validate_id_token_claims(
                _valid_id_claims(aud=aud), "RS256", client_id=_AUDIENCE, now=_NOW
            )

    def test_missing_audience_is_not_an_untrusted_audience(self):
        claims = _valid_id_claims(aud=[])
        with pytest.raises(IdTokenValidationException) as exc_info:
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)
        assert not isinstance(exc_info.value, UntrustedAudienceException)

    def test_empty_string_beside_a_real_audience_is_untrusted(self):
        claims = _valid_id_claims(aud=[_AUDIENCE, ""], azp=_AUDIENCE)
        with pytest.raises(UntrustedAudienceException) as exc_info:
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)
        assert exc_info.value.details == {"untrusted_audiences": [""]}

    @respx.mock
    def test_sync_wrapper_rejects_absent_audience_without_client_id(self, rsa_keypair):
        # Base validation with no configured audience does not require aud,
        # so the profile is what rejects the token.
        _clear_sync_caches()
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_id_claims()
        del claims["aud"]
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer=_ISSUER
        )
        with pytest.raises(IdTokenValidationException, match="missing required 'aud'"):
            validate_id_token(token, config, disco_doc_address=DISCO_URL)

    @respx.mock
    def test_sync_wrapper_rejects_untrusted_audience(self, rsa_keypair):
        _clear_sync_caches()
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE),
            headers={"kid": key_dict["kid"]},
        )
        with pytest.raises(UntrustedAudienceException):
            validate_id_token(token, _config(), disco_doc_address=DISCO_URL)

    @respx.mock
    def test_sync_wrapper_forwards_trusted_audiences(self, rsa_keypair):
        _clear_sync_caches()
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE),
            headers={"kid": key_dict["kid"]},
        )
        claims = validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            trusted_audiences=["other-client"],
        )
        assert claims["aud"] == [_AUDIENCE, "other-client"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_wrapper_rejects_untrusted_audience(self, rsa_keypair):
        await _clear_async_caches()
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE),
            headers={"kid": key_dict["kid"]},
        )
        with pytest.raises(UntrustedAudienceException):
            await aio_validate_id_token(token, _config(), disco_doc_address=DISCO_URL)

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_wrapper_forwards_trusted_audiences(self, rsa_keypair):
        await _clear_async_caches()
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE),
            headers={"kid": key_dict["kid"]},
        )
        claims = await aio_validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            trusted_audiences=["other-client"],
        )
        assert claims["aud"] == [_AUDIENCE, "other-client"]


class TestSyncValidateIdToken:
    """Full signature + discovery flow via the sync ``validate_id_token``."""

    @pytest.fixture(autouse=True)
    def _clear_caches(self):
        clear_discovery_cache()
        clear_jwks_cache()
        yield
        clear_discovery_cache()
        clear_jwks_cache()

    @respx.mock
    def test_valid_signed_id_token_accepted(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        claims = validate_id_token(token, _config(), disco_doc_address=DISCO_URL)

        assert claims["sub"] == "user-1"
        assert claims["aud"] == _AUDIENCE

    @respx.mock
    def test_signed_id_token_missing_sub_rejected(self, rsa_keypair):
        # The wrapper applies the profile after the signature/aud checks pass.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_id_claims()
        del claims["sub"]
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        with pytest.raises(IdTokenValidationException, match=r"sub"):
            validate_id_token(token, _config(), disco_doc_address=DISCO_URL)

    @respx.mock
    def test_signed_cross_client_azp_accepted_by_default(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token_claims = _valid_id_claims(azp="android-client")
        token = sign_jwt(pem, token_claims, headers={"kid": key_dict["kid"]})

        claims = validate_id_token(token, _config(), disco_doc_address=DISCO_URL)

        assert claims == token_claims

    @respx.mock
    def test_signed_cross_client_azp_rejected_when_opted_in(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(azp="android-client"),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(IdTokenValidationException, match=r"'azp' claim does not"):
            validate_id_token(
                token, _config(), disco_doc_address=DISCO_URL, validate_azp=True
            )

    @respx.mock
    def test_signed_id_token_nonce_mismatch_rejected(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem, _valid_id_claims(nonce="issued"), headers={"kid": key_dict["kid"]}
        )

        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token(
                token, _config(), disco_doc_address=DISCO_URL, nonce="expected"
            )

    @respx.mock
    def test_signed_id_token_nonce_match_accepted(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem, _valid_id_claims(nonce="n-42"), headers={"kid": key_dict["kid"]}
        )

        claims = validate_id_token(
            token, _config(), disco_doc_address=DISCO_URL, nonce="n-42"
        )
        assert claims["nonce"] == "n-42"

    @respx.mock
    def test_signed_id_token_at_hash_accepted(self, rsa_keypair):
        # A real RS256-signed ID token with the correct at_hash for a real
        # access token string is accepted.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        access_token = "real-access-token-xyz"
        token = sign_jwt(
            pem,
            _valid_id_claims(at_hash=_oidc_left_half(access_token, hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        claims = validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            access_token=access_token,
        )
        assert claims["sub"] == "user-1"

    @respx.mock
    def test_signed_id_token_at_hash_wrong_rejected(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(at_hash=_oidc_left_half("wrong-token", hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(IdTokenValidationException, match=r"at_hash"):
            validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                access_token="real-access-token-xyz",
            )

    @respx.mock
    def test_signed_id_token_at_hash_absent_accepted(self, rsa_keypair):
        # A token-endpoint ID Token without ``at_hash`` passes the wrapper.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        claims = validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            access_token="real-access-token-xyz",
            access_token_issued_with_id_token=False,
        )
        assert claims["sub"] == "user-1"

    @respx.mock
    def test_signed_id_token_at_hash_required_when_issued_with_it(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        with pytest.raises(
            IdTokenValidationException, match=r"missing required 'at_hash'"
        ):
            validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                access_token="real-access-token-xyz",
                access_token_issued_with_id_token=True,
            )

    @respx.mock
    def test_signed_id_token_c_hash_required_when_issued_with_it(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        with pytest.raises(
            IdTokenValidationException, match=r"missing required 'c_hash'"
        ):
            validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                code="real-auth-code-abc",
                code_issued_with_id_token=True,
            )

    @respx.mock
    def test_signed_id_token_c_hash_accepted(self, rsa_keypair):
        # §3.3.2.11: a real RS256-signed ID token whose ``c_hash`` matches the
        # supplied authorization code is accepted through the wrapper.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        code = "real-auth-code-abc"
        token = sign_jwt(
            pem,
            _valid_id_claims(c_hash=_oidc_left_half(code, hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        claims = validate_id_token(
            token, _config(), disco_doc_address=DISCO_URL, code=code
        )
        assert claims["sub"] == "user-1"

    @respx.mock
    def test_signed_id_token_c_hash_wrong_rejected(self, rsa_keypair):
        # §3.3.2.11: a ``c_hash`` that does not bind the supplied code is
        # rejected through the wrapper.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(c_hash=_oidc_left_half("wrong-code", hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(IdTokenValidationException, match=r"c_hash"):
            validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                code="real-auth-code-abc",
            )

    @respx.mock
    def test_signed_id_token_max_age_stale_rejected(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(auth_time=int(time.time()) - 3600),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(IdTokenValidationException, match=r"max_age"):
            validate_id_token(token, _config(), disco_doc_address=DISCO_URL, max_age=60)


class TestAsyncValidateIdToken:
    """Async parity for the ID-Token profile via ``aio.validate_id_token``."""

    @pytest.fixture(autouse=True)
    async def _clear_caches(self):
        await aio_clear_discovery_cache()
        await aio_clear_jwks_cache()
        yield
        await aio_clear_discovery_cache()
        await aio_clear_jwks_cache()

    @pytest.mark.asyncio
    @respx.mock
    async def test_valid_signed_id_token_accepted(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        claims = await aio_validate_id_token(
            token, _config(), disco_doc_address=DISCO_URL
        )

        assert claims["sub"] == "user-1"
        assert claims["aud"] == _AUDIENCE

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_missing_sub_rejected(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        claims = _valid_id_claims()
        del claims["sub"]
        token = sign_jwt(pem, claims, headers={"kid": key_dict["kid"]})

        with pytest.raises(IdTokenValidationException, match=r"sub"):
            await aio_validate_id_token(token, _config(), disco_doc_address=DISCO_URL)

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_cross_client_azp_accepted_by_default(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token_claims = _valid_id_claims(azp="android-client")
        token = sign_jwt(pem, token_claims, headers={"kid": key_dict["kid"]})

        claims = await aio_validate_id_token(
            token, _config(), disco_doc_address=DISCO_URL
        )

        assert claims == token_claims

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_cross_client_azp_rejected_when_opted_in(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(azp="android-client"),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(IdTokenValidationException, match=r"'azp' claim does not"):
            await aio_validate_id_token(
                token, _config(), disco_doc_address=DISCO_URL, validate_azp=True
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_at_hash_accepted(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        access_token = "real-access-token-xyz"
        token = sign_jwt(
            pem,
            _valid_id_claims(at_hash=_oidc_left_half(access_token, hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        claims = await aio_validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            access_token=access_token,
        )
        assert claims["sub"] == "user-1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_at_hash_absent_accepted(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        claims = await aio_validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            access_token="real-access-token-xyz",
            access_token_issued_with_id_token=False,
        )
        assert claims["sub"] == "user-1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_at_hash_required_when_issued_with_it(
        self, rsa_keypair
    ):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        with pytest.raises(
            IdTokenValidationException, match=r"missing required 'at_hash'"
        ):
            await aio_validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                access_token="real-access-token-xyz",
                access_token_issued_with_id_token=True,
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_c_hash_required_when_issued_with_it(
        self, rsa_keypair
    ):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(pem, _valid_id_claims(), headers={"kid": key_dict["kid"]})

        with pytest.raises(
            IdTokenValidationException, match=r"missing required 'c_hash'"
        ):
            await aio_validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                code="real-auth-code-abc",
                code_issued_with_id_token=True,
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_c_hash_accepted(self, rsa_keypair):
        # §3.3.2.11 (async parity): a matching ``c_hash`` is accepted.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        code = "real-auth-code-abc"
        token = sign_jwt(
            pem,
            _valid_id_claims(c_hash=_oidc_left_half(code, hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        claims = await aio_validate_id_token(
            token, _config(), disco_doc_address=DISCO_URL, code=code
        )
        assert claims["sub"] == "user-1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_c_hash_wrong_rejected(self, rsa_keypair):
        # §3.3.2.11 (async parity): a wrong ``c_hash`` is rejected.
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem,
            _valid_id_claims(c_hash=_oidc_left_half("wrong-code", hashlib.sha256)),
            headers={"kid": key_dict["kid"]},
        )

        with pytest.raises(IdTokenValidationException, match=r"c_hash"):
            await aio_validate_id_token(
                token,
                _config(),
                disco_doc_address=DISCO_URL,
                code="real-auth-code-abc",
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_signed_id_token_nonce_mismatch_rejected(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem, _valid_id_claims(nonce="issued"), headers={"kid": key_dict["kid"]}
        )

        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            await aio_validate_id_token(
                token, _config(), disco_doc_address=DISCO_URL, nonce="expected"
            )


class TestSyncAsyncPureAgreement:
    """The pure function and both wrappers must reach the same verdict."""

    @pytest.fixture(autouse=True)
    def _clear_sync_caches(self):
        clear_discovery_cache()
        clear_jwks_cache()
        yield
        clear_discovery_cache()
        clear_jwks_cache()

    @pytest.fixture(autouse=True)
    async def _clear_async_caches(self):
        await aio_clear_discovery_cache()
        await aio_clear_jwks_cache()
        yield
        await aio_clear_discovery_cache()
        await aio_clear_jwks_cache()

    @pytest.mark.asyncio
    @respx.mock
    async def test_all_three_surfaces_accept_valid_token(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        access_token = "agreement-access-token"
        base_claims = _valid_id_claims(
            nonce="n-shared",
            auth_time=int(time.time()) - 10,
            at_hash=_oidc_left_half(access_token, hashlib.sha256),
        )
        token = sign_jwt(pem, base_claims, headers={"kid": key_dict["kid"]})

        # Pure function: no raise.
        validate_id_token_claims(
            base_claims,
            "RS256",
            client_id=_AUDIENCE,
            nonce="n-shared",
            access_token=access_token,
            max_age=300,
        )
        # Sync wrapper.
        sync_claims = validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            nonce="n-shared",
            access_token=access_token,
            max_age=300,
        )
        # Async wrapper.
        async_claims = await aio_validate_id_token(
            token,
            _config(),
            disco_doc_address=DISCO_URL,
            nonce="n-shared",
            access_token=access_token,
            max_age=300,
        )

        assert sync_claims == base_claims
        assert async_claims == base_claims

    @pytest.mark.asyncio
    @respx.mock
    async def test_all_three_surfaces_reject_bad_nonce(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        bad_claims = _valid_id_claims(nonce="issued")
        token = sign_jwt(pem, bad_claims, headers={"kid": key_dict["kid"]})

        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token_claims(
                bad_claims, "RS256", client_id=_AUDIENCE, nonce="expected"
            )
        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token(
                token, _config(), disco_doc_address=DISCO_URL, nonce="expected"
            )
        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            await aio_validate_id_token(
                token, _config(), disco_doc_address=DISCO_URL, nonce="expected"
            )
