"""Thin Python executor for the shared ID-Token /spec conformance vectors.

Drives every vector in ``spec/conformance/id-token.json`` — the language-neutral
source of truth for the OpenID Connect ID-Token *profile* rules (OIDC Core 1.0
§2 / §3.1.3.7 / §3.3.2.11) — through py-identity-model's pure claim validator
``core.id_token_logic.validate_id_token_claims``. The Go and Rust runners will
execute the SAME vector set in later stack PRs, so the "build the conformance
vectors once" constraint holds across languages.

The vectors are fully self-contained decoded claim sets plus caller inputs and a
fixed ``now`` — no network, no signing, no fixtures — so this suite is a plain,
deterministic **unit** test.

Thin-executor contract: the vectors carry the inputs and a canonical expected
outcome; only the mapping of each canonical ``reason`` label to py-identity-
model's exception surface lives here (``_REASON_MESSAGE``). Every reject path in
the pure validator raises :class:`IdTokenValidationException`; the ``reason``
label pins *which* profile rule fired.

NOT wired into ``tools/spec_coverage_gate.py``: that gate enforces 100% vector
coverage *per language* and would fail the moment a second executable capability
appears without Go/Rust runners to match. ``id-token.json`` therefore carries
``cross_language_coverage_gate: "pending"`` (the gate skips it) and this file
runs as an ordinary unit test. Promoting ID-Token vectors into the cross-
language gate — adding the Go/Rust runners and flipping the marker to
``enforced`` — is Epic 23 story 23.2 follow-up.
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
    marker = Path("spec") / "conformance" / "id-token.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    return Path(__file__).resolve().parents[4]


_SPEC_FILE = _find_repo_root() / "spec" / "conformance" / "id-token.json"
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
_EXECUTED: set[str] = set()


@pytest.mark.unit
@pytest.mark.parametrize(("case_id", "vector"), _PARAMS)
def test_id_token_vector(case_id: str, vector: dict) -> None:
    _EXECUTED.add(case_id)
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
    """Runner-internal coverage check: every vector case id runs.

    The cross-language coverage gate (``tools/spec_coverage_gate.py``) does not
    yet cover this capability (see the module docstring — Epic 23 story 23.2),
    so this in-suite assertion is what guarantees no vector case is silently
    dropped from the Python leg.
    """
    executed = {p.values[0] for p in _PARAMS}
    declared = {c["id"] for c in _CASES}
    assert executed == declared, (
        f"ID-Token vector cases not parametrized by the Python runner: "
        f"{declared - executed}"
    )


@pytest.mark.unit
def test_capability_stays_out_of_cross_language_gate() -> None:
    """Guardrail: id-token.json must remain opted out of the shared gate.

    Until the Go and Rust runners exist (Epic 23 story 23.2), the vector file
    MUST keep ``cross_language_coverage_gate: "pending"`` so
    ``tools/spec_coverage_gate.py`` (which fails on a second executable
    capability lacking polyglot runners) stays green. This asserts the marker
    is present so a future edit that drops it is caught here rather than in CI.
    """
    assert _CAPABILITY.get("cross_language_coverage_gate") == "pending", (
        "id-token.json must stay opted out of the cross-language coverage gate "
        "until Go/Rust runners land (Epic 23 story 23.2)"
    )
