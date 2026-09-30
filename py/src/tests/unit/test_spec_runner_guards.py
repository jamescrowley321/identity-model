"""Regression checks for conformance assertions that must fail loudly."""

from jwt import InvalidSignatureError
import pytest

from py_identity_model.core.dpop import create_dpop_proof, generate_dpop_key

from ..dpop_proof_helpers import dpop_fixture_key, fixture, proof_jti
from ..spec_vectors.test_spec_http_vectors import KnownGap, _dpop_expect
from .test_spec_logic_vectors import test_logic_vector as run_logic_vector


def test_s256_vector_cannot_accept_a_reject_outcome() -> None:
    vector = {
        "input": {
            "operation": "s256_challenge",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        },
        "expect": {
            "outcome": "reject",
            "result": {"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
        },
    }
    with pytest.raises(AssertionError, match="want accept"):
        run_logic_vector("ACG-003", vector)


def _nonce_result(second_nonce: str | None) -> tuple[dict, tuple]:
    name = "dpop/dpop-keypair-es256.json"
    key = dpop_fixture_key(name)
    base = "http://localhost:9010"
    nonce = "cached-nonce"
    proofs = [
        create_dpop_proof(key[0], "POST", base + "/token", nonce=value)
        for value in (nonce, second_nonce)
    ]
    expect = {
        "outcome": "accept",
        "result": {
            "header": {
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": {
                    member: fixture(name)["public"][member]
                    for member in ("kty", "crv", "x", "y")
                },
            },
            "payload": {"htm": "POST", "htu": base + "/token", "nonce": nonce},
        },
    }
    return expect, (base, key, proofs, [proof_jti(p) for p in proofs])


def test_cached_nonce_fix_can_xpass() -> None:
    expect, result = _nonce_result("cached-nonce")
    _dpop_expect("DPOP-004", expect, result)


def test_missing_cached_nonce_is_a_known_gap() -> None:
    expect, result = _nonce_result(None)
    with pytest.raises(KnownGap, match="not cached"):
        _dpop_expect("DPOP-004", expect, result)


def test_wrong_cached_nonce_is_not_a_known_gap() -> None:
    expect, result = _nonce_result("wrong-nonce")
    with pytest.raises(AssertionError):
        _dpop_expect("DPOP-004", expect, result)


def test_nonce_gap_cannot_hide_reused_jti() -> None:
    expect, result = _nonce_result(None)
    result[3][1] = result[3][0]
    with pytest.raises(AssertionError, match="jti reused"):
        _dpop_expect("DPOP-004", expect, result)


def test_nonce_gap_cannot_hide_invalid_signature() -> None:
    expect, result = _nonce_result(None)
    result[2][1] = create_dpop_proof(
        generate_dpop_key("ES256"), "POST", result[0] + "/token"
    )
    result[3][1] = proof_jti(result[2][1])
    with pytest.raises(InvalidSignatureError):
        _dpop_expect("DPOP-004", expect, result)
