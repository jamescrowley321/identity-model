"""Unit tests for OpenID Connect ID Token profile validation.

Covers the ID-Token-specific rules from OpenID Connect Core 1.0 §3.1.3.7
(required ``sub``, the ``azp`` authorized-party rules, ``nonce`` binding, and
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
    IdTokenValidationException,
    TokenValidationException,
)
from py_identity_model.sync.id_token import validate_id_token
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


_ISSUER = "https://example.com"
_AUDIENCE = "client-123"
_DISCO_ADDRESS = "https://example.com/.well-known/openid-configuration"
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
    respx.get(_DISCO_ADDRESS).mock(
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

    def test_multi_aud_without_azp_rejected(self):
        # §3.1.3.7 step 4: multiple audiences require an ``azp`` claim.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"])
        with pytest.raises(IdTokenValidationException, match=r"azp"):
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_multi_aud_with_wrong_azp_rejected(self):
        # §3.1.3.7 step 6: ``azp`` present but not this client is rejected.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp="other-client")
        with pytest.raises(IdTokenValidationException, match=r"azp"):
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_multi_aud_with_correct_azp_accepted(self):
        # §3.1.3.7 steps 4-6 (positive): multiple audiences with a matching
        # ``azp`` validate cleanly.
        claims = _valid_id_claims(aud=[_AUDIENCE, "other-client"], azp=_AUDIENCE)
        validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

    def test_single_aud_with_wrong_azp_rejected(self):
        # §3.1.3.7 step 6: even with a single audience, a present ``azp`` that
        # is not this client is rejected.
        claims = _valid_id_claims(azp="other-client")
        with pytest.raises(IdTokenValidationException, match=r"azp"):
            validate_id_token_claims(claims, "RS256", client_id=_AUDIENCE, now=_NOW)

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

    def test_at_hash_missing_rejected(self):
        # §3.3.2.11: caller supplied an access token but the token has no
        # ``at_hash`` to bind it.
        with pytest.raises(IdTokenValidationException, match=r"at_hash"):
            validate_id_token_claims(
                _valid_id_claims(),
                "RS256",
                client_id=_AUDIENCE,
                access_token="SlAV32hkKG-access-token",
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
                _valid_id_claims(),
                "RS256",
                client_id=_AUDIENCE,
                access_token="café-access-token",
                now=_NOW,
            )

    def test_non_ascii_code_raises_id_token_exception(self):
        # Same for a non-ASCII authorization code feeding the c_hash digest.
        with pytest.raises(IdTokenValidationException, match=r"ASCII"):
            validate_id_token_claims(
                _valid_id_claims(),
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

        claims = validate_id_token(token, _config(), disco_doc_address=_DISCO_ADDRESS)

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
            validate_id_token(token, _config(), disco_doc_address=_DISCO_ADDRESS)

    @respx.mock
    def test_signed_id_token_nonce_mismatch_rejected(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem, _valid_id_claims(nonce="issued"), headers={"kid": key_dict["kid"]}
        )

        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            validate_id_token(
                token, _config(), disco_doc_address=_DISCO_ADDRESS, nonce="expected"
            )

    @respx.mock
    def test_signed_id_token_nonce_match_accepted(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        _mock_disco_and_jwks(key_dict)
        token = sign_jwt(
            pem, _valid_id_claims(nonce="n-42"), headers={"kid": key_dict["kid"]}
        )

        claims = validate_id_token(
            token, _config(), disco_doc_address=_DISCO_ADDRESS, nonce="n-42"
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
            disco_doc_address=_DISCO_ADDRESS,
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
                disco_doc_address=_DISCO_ADDRESS,
                access_token="real-access-token-xyz",
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
            token, _config(), disco_doc_address=_DISCO_ADDRESS, code=code
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
                disco_doc_address=_DISCO_ADDRESS,
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
            validate_id_token(
                token, _config(), disco_doc_address=_DISCO_ADDRESS, max_age=60
            )


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
            token, _config(), disco_doc_address=_DISCO_ADDRESS
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
            await aio_validate_id_token(
                token, _config(), disco_doc_address=_DISCO_ADDRESS
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
            disco_doc_address=_DISCO_ADDRESS,
            access_token=access_token,
        )
        assert claims["sub"] == "user-1"

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
            token, _config(), disco_doc_address=_DISCO_ADDRESS, code=code
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
                disco_doc_address=_DISCO_ADDRESS,
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
                token, _config(), disco_doc_address=_DISCO_ADDRESS, nonce="expected"
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
            disco_doc_address=_DISCO_ADDRESS,
            nonce="n-shared",
            access_token=access_token,
            max_age=300,
        )
        # Async wrapper.
        async_claims = await aio_validate_id_token(
            token,
            _config(),
            disco_doc_address=_DISCO_ADDRESS,
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
                token, _config(), disco_doc_address=_DISCO_ADDRESS, nonce="expected"
            )
        with pytest.raises(IdTokenValidationException, match=r"nonce"):
            await aio_validate_id_token(
                token, _config(), disco_doc_address=_DISCO_ADDRESS, nonce="expected"
            )
