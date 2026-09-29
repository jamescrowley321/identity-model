"""Python runner for the shared pure-logic vectors (spec/vectors/*.json).

A pure-logic vector names an ``input.operation`` and carries no ``http`` or
``http_sequence``: it runs in-process against py-identity-model, and its
``expect`` is checked. HTTP vectors in the same files (including DPoP flows that
also name an operation) run in src/tests/spec_vectors against the node-oidc
fixture. The Go and Rust runners execute the same vectors.

A vector py-identity-model does not meet yet is a strict ``xfail`` pinned to
``KnownGap``, raised exactly where the gap shows.
"""

import base64
from collections.abc import Callable
import json
from pathlib import Path

import pytest

from py_identity_model.core import dpop
from py_identity_model.core.dpop import compute_ath, create_dpop_proof
from py_identity_model.core.pkce import generate_code_challenge, generate_code_verifier

from ..dpop_proof_helpers import (
    assert_dpop_proof,
    dpop_fixture_key,
    fixture,
    proof_jti,
)


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "vectors").is_dir():
            return parent
    raise RuntimeError("spec/vectors not found above this file")


_VECTORS_DIR = _find_repo_root() / "spec" / "vectors"


class KnownGap(Exception):
    """Raised at the check where a tracked py-identity-model gap shows."""


#: Vectors py-identity-model does not meet yet, by parametrize id or case id.
_KNOWN_GAPS = {
    "DPOP-006": "no DPoP proof verifier (#478)",
}

#: Fewest verifiers a generate_code_verifier vector may ask for, so a
#: repeated verifier can be detected at all.
_MIN_SAMPLES = 2


def _generate_code_verifier(case_id: str, _inp: dict, expect: dict) -> None:
    result = expect["result"]
    samples = result["distinct_samples"]
    assert samples >= _MIN_SAMPLES, f"{case_id}: distinct_samples = {samples}"
    verifiers = [generate_code_verifier() for _ in range(samples)]
    for verifier in verifiers:
        assert result["min_length"] <= len(verifier) <= result["max_length"]
        assert set(verifier) <= set(result["alphabet"]), f"{case_id}: {verifier!r}"
    assert len(set(verifiers)) == samples, f"{case_id}: repeated verifier"


def _s256_challenge(case_id: str, inp: dict, expect: dict) -> None:
    challenge = generate_code_challenge(inp["code_verifier"], "S256")
    assert challenge == expect["result"]["code_challenge"], case_id


# --- dpop ---------------------------------------------------------------------


def _create_proof(case_id: str, inp: dict, expect: dict) -> None:
    key = dpop_fixture_key(inp["key"])
    # Build two proofs: each must match the vector, and their jti must differ.
    proofs = [
        create_dpop_proof(
            key[0], inp["htm"], inp["htu"], access_token=inp.get("access_token")
        )
        for _ in range(2)
    ]
    for proof in proofs:
        assert_dpop_proof(case_id, proof, key, expect["result"])
    assert proof_jti(proofs[0]) != proof_jti(proofs[1]), f"{case_id}: jti reused"


def _ath(case_id: str, inp: dict, _expect: dict) -> None:
    pairs = fixture(inp["pairs"])["pairs"]
    assert pairs, f"{case_id}: no pairs in {inp['pairs']}"
    for pair in pairs:
        assert compute_ath(pair["access_token"]) == pair["ath"], case_id


def _thumbprint(case_id: str, inp: dict, expect: dict) -> None:
    thumbprint = dpop_fixture_key(inp["key"])[0].jwk_thumbprint
    assert thumbprint == expect["result"]["thumbprint"], case_id
    if "bound_token" in inp:
        assert fixture(inp["bound_token"])["payload"]["cnf"]["jkt"] == thumbprint


def _verify_proof(case_id: str, _inp: dict, _expect: dict) -> None:
    raise KnownGap(f"{case_id}: no DPoP proof verifier (#478)")


def _generate_key(case_id: str, inp: dict, expect: dict) -> None:
    if expect["outcome"] == "reject":
        assert expect["error"] == "unsupported_algorithm", case_id
        with pytest.raises(ValueError, match="Unsupported DPoP algorithm"):
            dpop.generate_dpop_key(inp["alg"])
        return
    jwk = dpop.generate_dpop_key(inp["alg"]).public_jwk
    want = dict(expect["result"])
    min_bits = want.pop("min_modulus_bits", None)
    got = {"kty": jwk["kty"]}
    if "crv" in jwk:
        got["crv"] = jwk["crv"]
    assert ("n" in jwk) == (min_bits is not None), case_id
    if min_bits is not None:
        n = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
        assert int.from_bytes(n, "big").bit_length() >= min_bits, case_id
    assert got == want, case_id


#: Operation name -> check(case_id, input, expect). An operation with no entry
#: fails the run.
OPERATIONS: dict[str, Callable[[str, dict, dict], None]] = {
    "generate_code_verifier": _generate_code_verifier,
    "s256_challenge": _s256_challenge,
    "create_proof": _create_proof,
    "ath": _ath,
    "thumbprint": _thumbprint,
    "verify_proof": _verify_proof,
    "generate_key": _generate_key,
}


def _params() -> list:
    params = []
    for path in sorted(_VECTORS_DIR.glob("*.json")):
        for case in json.loads(path.read_text())["tests"]:
            for idx, vector in enumerate(case.get("vectors", [])):
                if "operation" not in vector.get("input", {}):
                    continue
                if "http" in vector or "http_sequence" in vector:
                    continue
                key = vector.get("name") or str(idx)
                param_id = f"{case['id']}-{key}"
                reason = _KNOWN_GAPS.get(param_id) or _KNOWN_GAPS.get(case["id"])
                marks = []
                if reason:
                    marks.append(
                        pytest.mark.xfail(reason=reason, raises=KnownGap, strict=True)
                    )
                params.append(
                    pytest.param(case["id"], vector, id=param_id, marks=marks)
                )
    return params


@pytest.mark.parametrize(("case_id", "vector"), _params())
def test_logic_vector(case_id: str, vector: dict) -> None:
    operation = vector["input"]["operation"]
    check = OPERATIONS.get(operation)
    assert check, f"{case_id}: no runner for operation {operation!r}"
    outcome = vector["expect"]["outcome"]
    assert outcome in ("accept", "reject"), f"{case_id}: unknown outcome {outcome!r}"
    check(case_id, vector["input"], vector["expect"])
