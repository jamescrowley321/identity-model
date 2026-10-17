"""Security tests: weak verification keys never verify a token (#952).

RFC 7518 §3.3 requires RSA keys of at least 2048 bits for RS*/PS*, and FAPI 2.0
Security Profile §5.4.1 requires at least 224 bits for EC keys. The floor sits
in ``decode_and_validate_jwt``, which every token-verification path reaches, so
a token signed with a factorable key is refused whatever ``algorithms`` says.
Uses the shared ``spec/test-fixtures/validation`` keys and tokens (JWT-014).
"""

from __future__ import annotations

import json
from pathlib import Path

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
    "n", ["é" * 400, "", b""], ids=["non-ascii", "empty-str", "empty-bytes"]
)
def test_unmeasurable_modulus_is_left_to_key_conversion(n):
    # The floor only measures what decodes; key conversion rejects the rest.
    # Measuring garbage would report a misleading WeakKeyException instead.
    unmeasurable = {**_KEYS["weak-rsa-1024"], "n": n}

    assert enforce_key_strength(unmeasurable) is None
