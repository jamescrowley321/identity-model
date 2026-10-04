"""Adversarial exception-contract tests for the alg-consistency guard (F-01).

``_ALG_TO_KTY`` (``core/parsers.py``) maps only asymmetric algorithms, so
``_validate_key_alg_consistency`` NO-OPS for exactly the algorithms an
alg-confusion attacker chooses — ``HS256``/``HS384``/``HS512`` and ``none`` —
whenever the JWK omits its optional ``alg`` member (spec-legal per RFC 7517).

Reachability (default discovery path, no-kid token, single alg-less RSA JWKS
key):

    validate_token -> extract_jwt_header_fields (unverified alg)
      -> find_key_by_kid(None, [RSA, alg=None], "HS256")   # guard no-ops
      -> decode_and_validate_jwt(..., algorithms=["HS256"])
        -> PyJWK(rsa_key, "HS256")  # raises jwt.InvalidKeyError  (or, for
                                    # alg=none, NotImplementedError)

Neither ``InvalidKeyError`` nor ``NotImplementedError`` is caught by
``decode_and_validate_jwt``'s except chain, so an UNTYPED exception escapes the
documented "only ``PyIdentityModelException``" contract -> unhandled 500 /
traceback leak. This is the #488-490 alg-guard gap.

Not a forgery (PyJWT's own ``kty``/``from_jwk`` checks block that) — the defect
is the broken exception contract. These tests assert a typed
``PyIdentityModelException``/``TokenValidationException`` and XFAIL until the
guard rejects HS*/none and the decoder wraps the stray exception.
"""

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model.core.models import JsonWebKey, TokenValidationConfig
from py_identity_model.core.parsers import (
    _validate_key_alg_consistency,
    find_key_by_kid,
    jwks_from_dict,
)
from py_identity_model.exceptions import (
    PyIdentityModelException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ..unit.token_validation_helpers import DISCO_URL
from ._security_helpers import generate_rsa_keypair, unsigned_none_alg_jwt


pytestmark = pytest.mark.unit

_DISCO_DOC = {
    "issuer": "https://example.com",
    "jwks_uri": "https://example.com/jwks",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _alg_less_rsa_jwk() -> dict:
    """A spec-legal RSA JWK with the optional ``alg`` member omitted."""
    key_dict, _ = generate_rsa_keypair()
    key_dict.pop("alg", None)
    key_dict.pop("kid", None)
    return key_dict


@pytest.mark.parametrize("attacker_alg", ["HS256", "none"])
def test_find_key_by_kid_rejects_symmetric_alg_against_rsa_key(
    attacker_alg: str,
) -> None:
    key = jwks_from_dict(_alg_less_rsa_jwk())
    # No kid + a single signing key routes through the no-kid branch, where the
    # guard must reject an HS*/none alg paired with an RSA key.
    with pytest.raises(TokenValidationException):
        find_key_by_kid(None, [key], jwt_alg=attacker_alg)


@respx.mock
def test_validate_token_hs256_no_kid_raises_typed_exception() -> None:
    jwk = _alg_less_rsa_jwk()
    # >= 32 bytes so PyJWT does not raise InsecureKeyLengthWarning on encode;
    # the value is irrelevant — PyJWK(rsa_key, "HS256") fails before any verify.
    token = pyjwt.encode(
        {"sub": "attacker", "iss": "https://example.com"},
        "attacker-shared-secret-padding-0123456789",
        algorithm="HS256",
    )
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=_DISCO_DOC))
    respx.get("https://example.com/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [jwk]})
    )
    config = TokenValidationConfig(perform_disco=True, audience=None)
    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )


@respx.mock
def test_validate_token_none_alg_no_kid_raises_typed_exception() -> None:
    jwk = _alg_less_rsa_jwk()
    token = unsigned_none_alg_jwt({"sub": "attacker", "iss": "https://example.com"})
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=_DISCO_DOC))
    respx.get("https://example.com/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [jwk]})
    )
    config = TokenValidationConfig(perform_disco=True, audience=None)
    with pytest.raises(PyIdentityModelException):
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )


def test_hs256_against_symmetric_oct_key_is_allowed() -> None:
    """Positive control: HS* against a symmetric ``oct`` key is a LEGITIMATE
    OIDC configuration — a confidential client with
    ``id_token_signed_response_alg=HS256`` verifies the ID token with its client
    secret (an ``oct`` JWK). Only HS*/``none`` against an *asymmetric* key is the
    alg-confusion attack, so the guard must NOT reject this. Pins the kty-gated
    fix against over-rejecting the spec-permitted symmetric case.
    """
    oct_key = jwks_from_dict({"kty": "oct", "k": "A" * 43, "kid": "hs"})
    # Must not raise — HS256 is consistent with an oct key.
    _validate_key_alg_consistency(oct_key, "HS256")


def _key(kty: str = "RSA", *, kid: str = "k1", alg: str | None = None) -> JsonWebKey:
    """Minimal spec-valid JWK for the given key type. Only ``kty``/``kid``/``alg``
    are read by the guard; the material is placeholder-but-present so
    ``JsonWebKey.__post_init__`` validation passes."""
    if kty == "RSA":
        return JsonWebKey(kty="RSA", kid=kid, alg=alg, n="AQAB", e="AQAB")
    if kty == "oct":
        return JsonWebKey(kty="oct", kid=kid, alg=alg, k="AQAB")
    raise ValueError(f"unsupported test kty: {kty}")


class TestValidateKeyAlgConsistencyContract:
    """Full exception-contract pins for ``_validate_key_alg_consistency`` — the
    alg-confusion guard F-01 hardens. Each raising branch asserts type, message,
    ``token_part`` and ``details``; each accepting branch asserts a clean no-op.
    Together these kill the guard's mutants (mutation-security gate)."""

    @pytest.mark.parametrize("empty_alg", [None, ""])
    def test_falsy_alg_is_a_noop(self, empty_alg: str | None) -> None:
        # No JWT alg -> nothing to check. Also pins that None never reaches
        # ``.lower()`` (which would AttributeError if the early return were dropped).
        assert _validate_key_alg_consistency(_key("RSA"), empty_alg) is None

    @pytest.mark.parametrize("none_alg", ["none", "NONE", "None"])
    def test_none_alg_is_rejected_case_insensitively(self, none_alg: str) -> None:
        with pytest.raises(TokenValidationException) as exc_info:
            _validate_key_alg_consistency(_key("RSA", kid="rsa-1"), none_alg)
        exc = exc_info.value
        assert exc.message == (
            "Algorithm 'none' is not permitted for signed-token validation"
        )
        assert exc.token_part == "header"
        assert exc.details == {"kid": "rsa-1", "alg": none_alg}

    def test_symmetric_alg_against_asymmetric_key_is_rejected(self) -> None:
        # The alg-confusion attack: an HS* header verified against an RSA key.
        with pytest.raises(TokenValidationException) as exc_info:
            _validate_key_alg_consistency(_key("RSA", kid="rsa-2"), "HS256")
        exc = exc_info.value
        assert exc.message == (
            "Key type 'RSA' is incompatible with algorithm 'HS256' "
            "(expected key type 'oct')"
        )
        assert exc.token_part == "header"
        assert exc.details == {"kid": "rsa-2", "kty": "RSA", "alg": "HS256"}

    def test_asymmetric_alg_against_symmetric_key_is_rejected(self) -> None:
        with pytest.raises(TokenValidationException) as exc_info:
            _validate_key_alg_consistency(_key("oct", kid="oct-1"), "RS256")
        exc = exc_info.value
        assert exc.message == (
            "Key type 'oct' is incompatible with algorithm 'RS256' "
            "(expected key type 'RSA')"
        )
        assert exc.token_part == "header"
        assert exc.details == {"kid": "oct-1", "kty": "oct", "alg": "RS256"}

    def test_consistent_kty_and_no_declared_alg_is_a_noop(self) -> None:
        # RS256 against an RSA key that omits its optional ``alg`` — consistent.
        assert _validate_key_alg_consistency(_key("RSA"), "RS256") is None

    def test_alg_absent_from_map_is_not_kty_gated(self) -> None:
        # An alg with no entry in ``_ALG_TO_KTY`` has no expected kty, so the kty
        # branch must NOT fire (pins the ``expected_kty and ...`` short-circuit).
        assert _validate_key_alg_consistency(_key("oct"), "PS999") is None

    def test_declared_key_alg_mismatch_is_rejected(self) -> None:
        # kty is consistent (RSA/RS256) but the key's own ``alg`` disagrees.
        with pytest.raises(TokenValidationException) as exc_info:
            _validate_key_alg_consistency(
                _key("RSA", kid="rsa-3", alg="RS384"), "RS256"
            )
        exc = exc_info.value
        assert exc.message == (
            "Key algorithm 'RS384' does not match JWT algorithm 'RS256'"
        )
        assert exc.token_part == "header"
        assert exc.details == {"kid": "rsa-3", "key_alg": "RS384", "jwt_alg": "RS256"}

    def test_declared_key_alg_match_is_a_noop(self) -> None:
        # key.alg == jwt_alg and kty consistent — must pass (pins the ``!=`` check).
        assert _validate_key_alg_consistency(_key("RSA", alg="RS256"), "RS256") is None
