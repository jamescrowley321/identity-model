"""Self-test for the Go/Rust mutation-gate driver (tools/mutation_security_native.py).

The gate is security-critical infrastructure, so its classification logic is
unit-tested here, mirroring ``tests/security/test_mutation_gate.py`` for the
Python gate. The invariants locked in:

* **Fail-closed status classification** — killed is an allowlist (Go:
  ``KILLED``/``NOT VIABLE``; Rust: ``CaughtMutant``/``Unviable``); every other
  status, including statuses future tool versions may invent, is a survivor.
* **Content-keyed waivers** — a waiver matches only when the mutant's identity
  AND its content hash agree; position drift changes nothing, content drift
  invalidates the waiver.
* **Malformed allowlist entries are hard errors**, never silent passes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_DRIVER = Path(__file__).resolve().parents[4] / "tools" / "mutation_security_native.py"
_spec = importlib.util.spec_from_file_location("mutation_security_native", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


# ── changed-line diff parsing ────────────────────────────────────────────────


def test_parse_changed_lines_reads_u0_hunks():
    diff = (
        "--- a/pkg/jwt/claims_validation.go\n"
        "+++ b/pkg/jwt/claims_validation.go\n"
        "@@ -106 +106 @@ func CombineClaimsValidators\n"
        "-\tif mode == CombineAny && len(members) == 0 {\n"
        "+\tif len(members) == 0 && mode == CombineAny {\n"
        "@@ -200,3 +201,2 @@ other hunk\n"
    )
    assert gate.parse_changed_lines(diff) == {106, 201, 202}


def test_parse_changed_lines_pure_deletion_marks_anchor_line():
    # A pure deletion (`+9,0`) has no added lines; the anchor line stays in
    # scope, matching the Python gate's conservative (fail-closed) parsing.
    assert gate.parse_changed_lines("@@ -10,2 +9,0 @@\n") == {9}


# ── allowlist parsing ────────────────────────────────────────────────────────

_GO_ENTRY = "pkg/jwt/claims_validation.go:106:18:CONDITIONALS_NEGATION"
_RS_ENTRY = "src/jwt/claims_validation.rs:combine_claims_validators"
_HASH = "0123456789abcdef"


def test_load_allowlist_go_keys_on_file_type_hash():
    text = f"# comment\n\n{_GO_ENTRY} {_HASH}  # justification\n"
    assert gate.load_allowlist(text, "go", gate.parse_go_waiver_name) == {
        ("pkg/jwt/claims_validation.go", "CONDITIONALS_NEGATION", _HASH)
    }


def test_load_allowlist_rust_keys_on_file_function_hash():
    text = f"{_RS_ENTRY} {_HASH}\n"
    assert gate.load_allowlist(text, "rust", gate.parse_rust_waiver_name) == {
        ("src/jwt/claims_validation.rs", "combine_claims_validators", _HASH)
    }


@pytest.mark.parametrize(
    "entry",
    [
        _GO_ENTRY,  # bare name, no hash
        f"{_GO_ENTRY} deadbeef",  # hash too short
        f"{_GO_ENTRY} {_HASH} extra",  # too many fields
        f"pkg/jwt/x.go:1:2 {_HASH}",  # name missing the TYPE field
        f"not-a-go-name {_HASH}",  # unparseable name
    ],
)
def test_load_allowlist_rejects_malformed_entries(entry):
    with pytest.raises(ValueError, match="malformed entry"):
        gate.load_allowlist(entry, "go", gate.parse_go_waiver_name)


def test_load_allowlist_rust_rejects_unparseable_name():
    with pytest.raises(ValueError, match="malformed entry"):
        gate.load_allowlist(
            f"src/jwt/no_function_part.rs {_HASH}", "rust", gate.parse_rust_waiver_name
        )


# ── Go content hashing ───────────────────────────────────────────────────────

_GO_LINE = "\tif mode == CombineAny && len(members) == 0 {"


def test_go_mutant_hash_stable_under_reindentation():
    original = gate.go_mutant_hash([_GO_LINE], 1, 12, "CONDITIONALS_NEGATION")
    reindented = gate.go_mutant_hash(
        ["        " + _GO_LINE.lstrip()], 1, 19, "CONDITIONALS_NEGATION"
    )
    assert original is not None
    assert original == reindented


def test_go_mutant_hash_changes_with_content_type_and_offset():
    base = gate.go_mutant_hash([_GO_LINE], 1, 12, "CONDITIONALS_NEGATION")
    other_line = gate.go_mutant_hash(
        ["\tif mode != CombineAny && len(members) == 0 {"],
        1,
        12,
        "CONDITIONALS_NEGATION",
    )
    other_type = gate.go_mutant_hash([_GO_LINE], 1, 12, "CONDITIONALS_BOUNDARY")
    other_offset = gate.go_mutant_hash([_GO_LINE], 1, 40, "CONDITIONALS_NEGATION")
    hashes = [base, other_line, other_type, other_offset]
    assert len(set(hashes)) == len(hashes)


def test_go_mutant_hash_unresolvable_positions_return_none():
    assert gate.go_mutant_hash([_GO_LINE], 2, 12, "CONDITIONALS_NEGATION") is None
    assert gate.go_mutant_hash(["   "], 1, 1, "CONDITIONALS_NEGATION") is None


# ── Rust diff hashing ────────────────────────────────────────────────────────

_RS_DIFF = (
    "--- src/jwt/claims_validation.rs\n"
    "+++ replace && with || in combine_claims_validators\n"
    "@@ -251,7 +251,7 @@\n"
    " context line\n"
    "-    if mode == CombineMode::Any && members.is_empty() {\n"
    "+    if mode == CombineMode::Any || members.is_empty() {\n"
)


def test_rust_diff_hash_ignores_headers_and_hunk_numbers():
    renumbered = _RS_DIFF.replace("@@ -251,7 +251,7 @@", "@@ -900,7 +903,7 @@").replace(
        "--- src/jwt/claims_validation.rs", "--- /sandbox/src/jwt/claims_validation.rs"
    )
    assert gate.rust_diff_hash(_RS_DIFF) == gate.rust_diff_hash(renumbered)


def test_rust_diff_hash_tracks_the_transformation():
    other = _RS_DIFF.replace("|| members.is_empty()", "&& !members.is_empty()")
    assert gate.rust_diff_hash(_RS_DIFF) != gate.rust_diff_hash(other)


# ── Go evaluation ────────────────────────────────────────────────────────────

_GO_FILE = "pkg/jwt/claims_validation.go"
_GO_SOURCES = {_GO_FILE: [_GO_LINE]}


def _go_mutant(status: str, column: int = 12, mtype: str = "CONDITIONALS_NEGATION"):
    return (_GO_FILE, {"status": status, "line": 1, "column": column, "type": mtype})


@pytest.mark.parametrize("status", ["KILLED", "NOT VIABLE"])
def test_evaluate_go_killed_statuses_pass(status):
    unwaived, waived = gate.evaluate_go([_go_mutant(status)], set(), _GO_SOURCES)
    assert unwaived == []
    assert waived == []


@pytest.mark.parametrize(
    "status",
    ["LIVED", "NOT COVERED", "TIMED OUT", "SKIPPED", "RUNNABLE", "SOME FUTURE STATUS"],
)
def test_evaluate_go_everything_else_survives(status):
    unwaived, waived = gate.evaluate_go([_go_mutant(status)], set(), _GO_SOURCES)
    assert waived == []
    assert len(unwaived) == 1
    assert unwaived[0].startswith(f"{_GO_FILE}:1:12:CONDITIONALS_NEGATION: {status}")


def test_evaluate_go_skipped_survivor_explains_scoping_drift():
    unwaived, _ = gate.evaluate_go([_go_mutant("SKIPPED")], set(), _GO_SOURCES)
    assert "never tested" in unwaived[0]


def test_evaluate_go_waiver_requires_matching_content_hash():
    digest = gate.go_mutant_hash([_GO_LINE], 1, 12, "CONDITIONALS_NEGATION")
    matching = {(_GO_FILE, "CONDITIONALS_NEGATION", digest)}
    unwaived, waived = gate.evaluate_go([_go_mutant("LIVED")], matching, _GO_SOURCES)
    assert unwaived == []
    assert waived == [f"{_GO_FILE}:1:12:CONDITIONALS_NEGATION: LIVED"]

    stale = {(_GO_FILE, "CONDITIONALS_NEGATION", "f" * 16)}
    unwaived, waived = gate.evaluate_go([_go_mutant("LIVED")], stale, _GO_SOURCES)
    assert waived == []
    assert len(unwaived) == 1
    # The survivor line carries the ready-to-paste waiver entry.
    assert (
        f"[waiver line: {_GO_FILE}:1:12:CONDITIONALS_NEGATION {digest}]"
        in (unwaived[0])
    )


def test_evaluate_go_unresolvable_position_cannot_be_waived():
    # Line 99 does not exist in the source: the hash is None, so no waiver can
    # ever match (fail-closed), and no waiver line is offered.
    mutant = (
        _GO_FILE,
        {"status": "LIVED", "line": 99, "column": 1, "type": "CONDITIONALS_NEGATION"},
    )
    unwaived, waived = gate.evaluate_go([mutant], set(), _GO_SOURCES)
    assert waived == []
    assert len(unwaived) == 1
    assert "waiver line" not in unwaived[0]


# ── Rust scoping + evaluation ────────────────────────────────────────────────

_RS_FILE = "src/jwt/claims_validation.rs"


def _rs_mutant(name: str, start: int, end: int, function: str = "combine"):
    return {
        "name": name,
        "file": _RS_FILE,
        "function": {"function_name": function},
        "span": {"start": {"line": start}, "end": {"line": end}},
        "diff": _RS_DIFF,
    }


def test_rust_in_scope_intersects_spans_with_changed_lines():
    on_line = _rs_mutant("on", 254, 254)
    body_span = _rs_mutant("body", 250, 270)  # whole-fn replacement spanning 254
    elsewhere = _rs_mutant("off", 10, 12)
    scoped = gate.rust_in_scope([on_line, body_span, elsewhere], {_RS_FILE: {254}})
    assert scoped == [on_line, body_span]


@pytest.mark.parametrize("summary", ["CaughtMutant", "Unviable"])
def test_evaluate_rust_killed_summaries_pass(summary):
    info = {"m": _rs_mutant("m", 1, 1)}
    unwaived, waived = gate.evaluate_rust({"m": summary}, info, set())
    assert unwaived == []
    assert waived == []


@pytest.mark.parametrize(
    "summary", ["MissedMutant", "Timeout", "Success", "Failure", "SomeFutureSummary"]
)
def test_evaluate_rust_everything_else_survives(summary):
    info = {"m": _rs_mutant("m", 1, 1)}
    unwaived, waived = gate.evaluate_rust({"m": summary}, info, set())
    assert waived == []
    assert len(unwaived) == 1
    assert unwaived[0].startswith(f"m: {summary}")


def test_evaluate_rust_waiver_requires_matching_diff_hash():
    info = {"m": _rs_mutant("m", 1, 1)}
    digest = gate.rust_diff_hash(_RS_DIFF)
    unwaived, waived = gate.evaluate_rust(
        {"m": "MissedMutant"}, info, {(_RS_FILE, "combine", digest)}
    )
    assert unwaived == []
    assert waived == ["m: MissedMutant"]

    unwaived, waived = gate.evaluate_rust(
        {"m": "MissedMutant"}, info, {(_RS_FILE, "combine", "f" * 16)}
    )
    assert waived == []
    assert f"[waiver line: {_RS_FILE}:combine {digest}]" in unwaived[0]


def test_evaluate_rust_unenumerated_mutant_cannot_be_waived():
    unwaived, waived = gate.evaluate_rust({"ghost": "MissedMutant"}, {}, set())
    assert waived == []
    assert unwaived == [
        "ghost: MissedMutant  [outside the gate's enumeration — cannot be waived]"
    ]
