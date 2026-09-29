"""Python runner for the shared pure-logic vectors (spec/vectors/*.json).

A pure-logic vector names an ``input.operation`` and needs no HTTP: it runs
in-process against py-identity-model, and its ``expect.result`` is checked.
HTTP vectors in the same files run in src/tests/spec_vectors against the
node-oidc fixture. The Go and Rust runners execute the same vectors.
"""

from collections.abc import Callable
import json
from pathlib import Path

import pytest

from py_identity_model.core.pkce import generate_code_challenge, generate_code_verifier


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "vectors").is_dir():
            return parent
    raise RuntimeError("spec/vectors not found above this file")


_VECTORS_DIR = _find_repo_root() / "spec" / "vectors"

#: Fewest verifiers a generate_code_verifier vector may ask for, so a
#: repeated verifier can be detected at all.
_MIN_SAMPLES = 2


def _generate_code_verifier(case_id: str, _inp: dict, result: dict) -> None:
    samples = result["distinct_samples"]
    assert samples >= _MIN_SAMPLES, f"{case_id}: distinct_samples = {samples}"
    verifiers = [generate_code_verifier() for _ in range(samples)]
    for verifier in verifiers:
        assert result["min_length"] <= len(verifier) <= result["max_length"]
        assert set(verifier) <= set(result["alphabet"]), f"{case_id}: {verifier!r}"
    assert len(set(verifiers)) == samples, f"{case_id}: repeated verifier"


def _s256_challenge(case_id: str, inp: dict, result: dict) -> None:
    challenge = generate_code_challenge(inp["code_verifier"], "S256")
    assert challenge == result["code_challenge"], case_id


#: Operation name -> check. An operation with no entry fails the run.
OPERATIONS: dict[str, Callable[[str, dict, dict], None]] = {
    "generate_code_verifier": _generate_code_verifier,
    "s256_challenge": _s256_challenge,
}


def _params() -> list:
    params = []
    for path in sorted(_VECTORS_DIR.glob("*.json")):
        for case in json.loads(path.read_text())["tests"]:
            for idx, vector in enumerate(case.get("vectors", [])):
                if "operation" not in vector.get("input", {}):
                    continue
                key = vector.get("name") or str(idx)
                params.append(
                    pytest.param(case["id"], vector, id=f"{case['id']}-{key}")
                )
    return params


@pytest.mark.parametrize(("case_id", "vector"), _params())
def test_logic_vector(case_id: str, vector: dict) -> None:
    operation = vector["input"]["operation"]
    check = OPERATIONS.get(operation)
    assert check, f"{case_id}: no runner for operation {operation!r}"
    assert vector["expect"]["outcome"] == "accept", f"{case_id}: outcome"
    check(case_id, vector["input"], vector["expect"]["result"])
