"""Cross-language conformance for the injectable claims validators (issue #603).

Drives the shared vectors in ``spec/test-fixtures/claims-validation/vectors.json``
against the real Python validators. The Go (#624) and Rust (#625) runners read
the **same** file, so this is the guard that the three implementations behave
identically — the point of formalizing the API in the first place.

Each vector builds a validator from a language-neutral spec and checks one of:
accept (validator returns), reject (raises ``ClaimsValidationError``, optionally
naming the offending ``claim``), or construction_error (building the validator
itself raises). Rejection *reason* wording is language-specific and not asserted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from py_identity_model import (
    ClaimsValidationError,
    combine_claims_validators,
    require_claim_value,
    require_claims,
    require_scopes,
)


pytestmark = pytest.mark.unit


def _find_vectors() -> Path | None:
    """Locate the shared vectors by walking up from this file.

    A fixed ``parents[N]`` breaks when the tree is relocated (e.g. mutmut copies
    sources under ``py/mutants/``), so search upward for the repo root that holds
    the vectors instead.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = (
            parent / "spec" / "test-fixtures" / "claims-validation" / "vectors.json"
        )
        if candidate.is_file():
            return candidate
    return None


_VECTORS = _find_vectors()


def _build(spec: dict[str, Any]):
    """Construct a validator from a language-neutral spec (may raise on bad spec)."""
    kind = spec["type"]
    if kind == "require_claims":
        return require_claims(*spec["names"])
    if kind == "require_claim_value":
        return require_claim_value(spec["name"], spec["value"])
    if kind == "require_scopes":
        return require_scopes(*spec["scopes"])
    if kind == "combine":
        members = [_build(member) for member in spec["of"]]
        return combine_claims_validators(members, require=spec["require"])
    raise AssertionError(f"unknown validator type in vector: {kind!r}")


def _load_cases():
    if _VECTORS is None:
        return [pytest.param(None, id="vectors-not-found")]
    data = json.loads(_VECTORS.read_text())
    return [pytest.param(case, id=case["id"]) for case in data["cases"]]


@pytest.mark.parametrize("case", _load_cases())
def test_claims_validation_vector(case):
    if case is None:
        pytest.skip("shared claims vectors not found on this checkout")
    expect = case["expect"]

    if expect.get("construction_error"):
        with pytest.raises(ValueError, match=r"at least one|'all' or 'any'"):
            _build(case["validator"])
        return

    validator = _build(case["validator"])
    claims = case["claims"]

    if expect.get("accept"):
        validator(claims)  # must not raise
        return

    reject = expect["reject"]
    with pytest.raises(ClaimsValidationError) as excinfo:
        validator(claims)
    if "claim" in reject:
        assert excinfo.value.claim == reject["claim"]


# --------------------------------------------------------------------------- #
# Python-specific edge cases beyond the cross-language vectors                 #
# --------------------------------------------------------------------------- #


def test_combine_all_empty_is_accept():
    # An empty all-of is a no-op that accepts (documented; harmless), whereas an
    # empty any-of is a construction error (covered by CLV-041).
    combine_claims_validators([], require="all")({"sub": "u1"})


def test_require_scopes_from_scp_set_and_ignores_non_strings():
    # The impl accepts list/tuple/set/frozenset and filters non-string members.
    require_scopes("read")({"scp": {"read", "write"}})
    require_scopes("read")({"scp": ["read", 123, "write"]})  # 123 ignored, read granted
    with pytest.raises(ClaimsValidationError):
        require_scopes("admin")({"scp": ["read", 123]})


def test_combine_any_aggregates_all_reasons():
    validator = combine_claims_validators(
        [require_scopes("admin"), require_claims("groups")], require="any"
    )
    with pytest.raises(ClaimsValidationError) as excinfo:
        validator({"scope": "read"})
    # Aggregate rejection carries no single claim but mentions both failures.
    assert excinfo.value.claim is None
    assert "admin" in excinfo.value.reason
    assert "groups" in excinfo.value.reason


def test_require_claim_value_matches_non_string_values():
    require_claim_value("email_verified", True)({"email_verified": True})
    with pytest.raises(ClaimsValidationError):
        require_claim_value("email_verified", True)({"email_verified": False})
