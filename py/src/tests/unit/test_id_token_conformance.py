"""Thin Python executor for the shared ID-Token /spec conformance vectors.

Drives every vector in ``spec/vectors/id-token.json`` — the language-neutral
source of truth for the OpenID Connect ID-Token *profile* rules (OIDC Core 1.0
§2 / §3.1.3.7 / §3.3.2.11) — through py-identity-model's pure claim validator
``core.id_token_logic.validate_id_token_claims``. The Go and Rust runners
execute the SAME vector set, so the "build the conformance vectors once"
constraint holds across languages.

The vectors are fully self-contained decoded claim sets plus caller inputs and a
fixed ``now`` — no network, no signing, no fixtures — so this suite is a plain,
deterministic **unit** test.

Thin-executor contract: the vectors carry the inputs and a canonical expected
outcome; only the mapping of each canonical ``reason`` label to py-identity-
model's exception surface lives here (``_REASON_MESSAGE``). Every reject path in
the pure validator raises :class:`IdTokenValidationException`; the ``reason``
label pins *which* profile rule fired.

"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from py_identity_model.core.id_token_logic import validate_id_token_claims
from py_identity_model.exceptions import IdTokenValidationException


def _find_repo_root() -> Path:
    """Locate the polyglot repo root by its ``/spec`` marker.

    Mirrors ``test_spec_conformance.py``: walking up to the marker (rather than
    a fixed ``parents[n]``) also resolves correctly inside the mutation-testing
    sandbox, which inserts a directory level.
    """
    marker = Path("spec") / "vectors" / "id-token.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_SPEC_FILE = _find_repo_root() / "spec" / "vectors" / "id-token.json"
_CAPABILITY = json.loads(_SPEC_FILE.read_text())
_CASES = _CAPABILITY["tests"]


# Each canonical reject ``reason`` maps to a stable substring of the message
# raised by ``validate_id_token_claims`` for that rule. Go/Rust map the same
# labels to their own error variants; keeping the map here is the ONLY
# per-language coupling (the vectors themselves stay language-neutral).
_REASON_MESSAGE = {
    "missing_sub": "missing required 'sub'",
    "azp_required_multi_aud": "multiple audiences must contain an 'azp'",
    "azp_mismatch": "'azp' claim does not match",
    "nonce_mismatch": "'nonce' claim does not match",
    "auth_time_stale": "'auth_time' is older than the permitted max_age",
    "auth_time_missing": "missing required numeric 'auth_time'",
    "at_hash_mismatch": "'at_hash' claim does not match",
    "c_hash_mismatch": "'c_hash' claim does not match",
    "unsupported_alg": "Unsupported ID token 'alg'",
    "alg_required": "'alg' is required to validate at_hash/c_hash",
}


def _run_vector(vector: dict) -> None:
    """Apply one vector's inputs to the pure ID-Token claim validator."""
    inp = vector["input"]
    validate_id_token_claims(
        inp["claims"],
        inp["header_alg"],
        client_id=inp.get("client_id"),
        nonce=inp.get("nonce"),
        access_token=inp.get("access_token"),
        code=inp.get("code"),
        max_age=inp.get("max_age"),
        leeway=inp.get("leeway", 0.0),
        now=inp.get("now"),
    )


def _vector_params() -> list:
    params = []
    for case in _CASES:
        vectors = case.get("vectors", [])
        assert vectors, f"{case['id']}: ID-Token vector case carries no vectors"
        for idx, vector in enumerate(vectors):
            label = vector.get("name") or str(idx)
            params.append(pytest.param(case["id"], vector, id=f"{case['id']}-{label}"))
    return params


_PARAMS = _vector_params()


@pytest.mark.unit
@pytest.mark.parametrize(("case_id", "vector"), _PARAMS)
def test_id_token_vector(case_id: str, vector: dict) -> None:
    expect = vector["expect"]
    outcome = expect["outcome"]
    if outcome == "accept":
        # A conforming ID Token: the profile validator must not raise.
        _run_vector(vector)
    elif outcome == "reject":
        assert expect.get("error") == "id_token_profile", (
            f"{case_id}: unexpected canonical error family {expect.get('error')!r}"
        )
        with pytest.raises(IdTokenValidationException) as exc_info:
            _run_vector(vector)
        reason = expect["reason"]
        want_substring = _REASON_MESSAGE.get(reason)
        assert want_substring is not None, (
            f"{case_id}: unknown canonical reason {reason!r} — extend _REASON_MESSAGE"
        )
        assert want_substring in str(exc_info.value), (
            f"{case_id}: reason {reason!r} expected message containing "
            f"{want_substring!r}, got: {exc_info.value}"
        )
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {outcome!r}")


@pytest.mark.unit
def test_every_id_token_case_is_executed() -> None:
    """Every case id in the spec file must be parametrized for execution."""
    executed = {p.values[0] for p in _PARAMS}
    declared = {c["id"] for c in _CASES}
    assert executed == declared, (
        f"ID-Token vector cases not parametrized by the Python runner: "
        f"{declared - executed}"
    )
