"""Security tests: weak verification keys never verify a token (#952).

RFC 7518 §3.3 requires RSA keys of at least 2048 bits for RS*/PS*, FAPI 2.0
Security Profile §5.4.1 requires at least 224 bits for EC keys, and RFC 7518
§3.2 requires HMAC keys at least as long as the hash output. The floor sits
in ``decode_and_validate_jwt``, which every token-verification path reaches, so
a token signed with a factorable key is refused whatever ``algorithms`` says.
Uses the shared ``spec/test-fixtures/validation`` keys and tokens (JWT-014).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import jwt as pyjwt
from jwt.utils import base64url_encode
import pytest

from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.core.key_strength import enforce_key_strength
from py_identity_model.exceptions import WeakKeyException


def _fixture_dir() -> Path:
    # Walk up to the repo root by its spec/ marker, so the test also runs from
    # the mutation gate's py/mutants/ sandbox.
    marker = Path("spec") / "test-fixtures" / "validation"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_dir():
            return parent / marker
    raise FileNotFoundError(marker)


_FIXTURES = _fixture_dir()
_KEYS = {k["kid"]: k for k in json.loads((_FIXTURES / "jwks.json").read_text())["keys"]}


_WEAK_KEY_CASES = {
    "rsa-1024": (
        "RS256",
        "weak-rsa-1024-token.txt",
        {"kid": "weak-rsa-1024", "kty": "RSA", "bits": 1024, "min_bits": 2048},
    ),
    "ec-p192": (
        "ES256",
        "weak-ec-p192-token.txt",
        {"kid": "weak-ec-p192", "kty": "EC", "bits": 192, "min_bits": 224},
    ),
}


@pytest.mark.parametrize("case", sorted(_WEAK_KEY_CASES))
def test_weak_key_refused_even_when_its_alg_is_allowed(case):
    alg, token_file, expected = _WEAK_KEY_CASES[case]
    token = (_FIXTURES / token_file).read_text().strip()

    with pytest.raises(WeakKeyException) as exc_info:
        decode_and_validate_jwt(token, _KEYS[expected["kid"]], [alg], None, None, None)

    assert exc_info.value.details == expected


def test_weak_key_with_bytes_modulus_is_refused():
    # PyJWT accepts bytes JWK members, so a bytes `n` must not skip the floor.
    weak = _KEYS["weak-rsa-1024"]
    token = (_FIXTURES / "weak-rsa-1024-token.txt").read_text().strip()
    as_bytes = {**weak, "n": weak["n"].encode("ascii")}

    with pytest.raises(WeakKeyException) as exc_info:
        decode_and_validate_jwt(token, as_bytes, ["RS256"], None, None, None)

    assert exc_info.value.details == _WEAK_KEY_CASES["rsa-1024"][2]


@pytest.mark.parametrize(
    "suffix", ["\u00e9", "\U0001f600"], ids=["two-octet", "four-octet"]
)
def test_weak_key_with_non_ascii_modulus_is_refused(suffix):
    # PyJWT encodes a str member as UTF-8 and its base64url decoder discards
    # the non-alphabet octets, so a weak modulus with a non-ASCII suffix still
    # converts to the weak key: the floor must measure it the same way.
    weak = _KEYS["weak-rsa-1024"]
    token = (_FIXTURES / "weak-rsa-1024-token.txt").read_text().strip()
    tainted = {**weak, "n": weak["n"] + suffix}

    with pytest.raises(WeakKeyException) as exc_info:
        decode_and_validate_jwt(token, tainted, ["RS256"], None, None, None)

    assert exc_info.value.details == _WEAK_KEY_CASES["rsa-1024"][2]


@pytest.mark.parametrize(
    "n", ["é" * 400, "", b""], ids=["non-ascii", "empty-str", "empty-bytes"]
)
def test_unmeasurable_modulus_is_left_to_key_conversion(n):
    # The floor only measures what decodes; key conversion rejects the rest.
    # Measuring garbage would report a misleading WeakKeyException instead.
    unmeasurable = {**_KEYS["weak-rsa-1024"], "n": n}

    assert enforce_key_strength(unmeasurable) is None


_HMAC_FLOORS = {"HS256": 32, "HS384": 48, "HS512": 64}


_HMAC_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _hmac_token(secret: bytes, alg: str) -> str:
    # Built by hand: PyJWT refuses to sign with a key under the floor.
    signing_input = b".".join(
        base64url_encode(json.dumps(part).encode())
        for part in ({"alg": alg, "typ": "JWT"}, {"sub": "s"})
    )
    signature = hmac.new(secret, signing_input, _HMAC_HASHES[alg]).digest()
    return (signing_input + b"." + base64url_encode(signature)).decode()


def _oct_jwk(octets: int) -> dict:
    return {"kty": "oct", "kid": "hmac", "k": base64url_encode(b"k" * octets).decode()}


@pytest.mark.parametrize("alg", sorted(_HMAC_FLOORS))
def test_short_hmac_key_refused(alg):
    # RFC 7518 §3.2: an HMAC key at least as long as the hash output MUST be used.
    octets = _HMAC_FLOORS[alg] - 1
    token = _hmac_token(b"k" * octets, alg)

    with pytest.raises(WeakKeyException) as exc_info:
        decode_and_validate_jwt(token, _oct_jwk(octets), [alg], None, None, None)

    assert exc_info.value.details == {
        "kid": "hmac",
        "kty": "oct",
        "bits": octets * 8,
        "min_bits": _HMAC_FLOORS[alg] * 8,
    }


@pytest.mark.parametrize("alg", sorted(_HMAC_FLOORS))
def test_hmac_key_at_floor_verifies(alg):
    octets = _HMAC_FLOORS[alg]
    token = pyjwt.encode({"sub": "s"}, b"k" * octets, algorithm=alg)

    claims = decode_and_validate_jwt(token, _oct_jwk(octets), [alg], None, None, None)

    assert claims == {"sub": "s"}


def test_oct_key_without_hmac_alg_has_no_floor():
    assert enforce_key_strength(_oct_jwk(1)) is None


@pytest.mark.parametrize("alg", sorted(_HMAC_FLOORS))
@pytest.mark.parametrize("k", ["", None, "é"], ids=["empty", "missing", "undecodable"])
def test_empty_hmac_key_refused(alg, k):
    # PyJWT accepts an empty HMAC secret, so an empty k must not skip the floor.
    jwk = {"kty": "oct", "kid": "hmac"}
    if k is not None:
        jwk["k"] = k
    token = _hmac_token(b"", alg)

    with pytest.raises(WeakKeyException) as exc_info:
        decode_and_validate_jwt(token, jwk, [alg], None, None, None)

    assert exc_info.value.details == {
        "kid": "hmac",
        "kty": "oct",
        "bits": 0,
        "min_bits": _HMAC_FLOORS[alg] * 8,
    }
