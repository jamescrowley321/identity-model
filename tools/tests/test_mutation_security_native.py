"""Self-test for the Go/Rust mutation-gate driver (tools/mutation_security_native.py).

The gate is security-critical infrastructure, so its classification logic is
tested here, mirroring ``tools/tests/test_mutation_security.py`` for the Python
gate. Both live in ``tools/tests`` and run via ``make test-tools``, outside the
library suite — ``py/src/tests`` and its coverage gate describe the published
``py-identity-model`` package, not the repo's own machinery. The invariants
locked in:

* **Fail-closed status classification** — killed is an allowlist (Go:
  ``KILLED``/``NOT VIABLE``; Rust: ``CaughtMutant``/``Unviable``); every other
  status, including statuses future tool versions may invent, is a survivor.
* **Content-keyed waivers** — a waiver matches only when the mutant's identity
  AND its content hash agree; position drift changes nothing, content drift
  invalidates the waiver.
* **Malformed allowlist entries are hard errors**, never silent passes.
* **The gate does its own Go scoping** — gremlins is pointed at the changed
  packages and its report paths are re-anchored to module-relative ones before
  the changed-line intersection. If that re-anchoring silently stopped
  matching, every intersection would be empty and the gate would pass
  everything, so it is pinned here.
* **The gate is driven end to end**, not only through its pure helpers. The
  failure mode this gate exists to prevent is *passing everything quietly*, and
  every mechanism that could reintroduce it — an empty report from one package
  of several, a re-anchored path that matches no key, a mutant the gate cannot
  position, a run that killed nothing — is exercised through :func:`gate_go`
  itself with git and gremlins replaced. A gate that had gone vacuous must not
  be able to pass this file.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


_DRIVER = Path(__file__).resolve().parents[1] / "mutation_security_native.py"
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
    # The gate passes gremlins no scoping flag, so nothing in the changed
    # packages should ever come back SKIPPED; if one does it is tool drift, and
    # the message must say so rather than invite a waiver.
    unwaived, _ = gate.evaluate_go([_go_mutant("SKIPPED")], set(), _GO_SOURCES)
    assert "never tested" in unwaived[0]
    assert "no scoping flag" in unwaived[0]
    assert "do NOT waive" in unwaived[0]


def test_evaluate_go_skipped_survivor_cannot_be_waived_away():
    # The message above tells the author a waiver will not help. The allowlist
    # lookup used to run BEFORE that branch, so a SKIPPED mutant with a matching
    # waiver was waived anyway and the promise was decoration. Nothing executed
    # the mutant, so there is no evidence an equivalence claim could rest on:
    # the allowlist is not consulted for SKIPPED at all.
    digest = gate.go_mutant_hash([_GO_LINE], 1, 12, "CONDITIONALS_NEGATION")
    matching = {(_GO_FILE, "CONDITIONALS_NEGATION", digest)}
    unwaived, waived = gate.evaluate_go([_go_mutant("SKIPPED")], matching, _GO_SOURCES)
    assert waived == []
    assert len(unwaived) == 1
    assert "do NOT waive" in unwaived[0]


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


# ── Go package scoping (defect: gremlins' own --diff mis-scoped) ─────────────


def test_go_package_dirs_dedupes_to_the_packages_that_changed():
    changed = [
        "pkg/token/options.go",
        "pkg/token/token.go",
        "pkg/jwt/claims_validation.go",
        "pkg/jwks/cache/store.go",
    ]
    # One entry per package — gremlins takes a single path argument per run,
    # and a PR must not pay for packages it did not touch.
    assert gate.go_package_dirs(changed) == [
        "pkg/jwks/cache",
        "pkg/jwt",
        "pkg/token",
    ]


def test_go_report_mutants_reanchors_paths_to_the_module_root():
    # gremlins reports file_name relative to the PATH ARGUMENT it was given:
    # `gremlins unleash ./pkg/token` says "token.go", while the gate's
    # changed-line map is keyed "pkg/token/token.go". Without this
    # re-anchoring the intersection is always empty — a gate that passes
    # everything.
    report = {
        "files": [
            {
                "file_name": "token.go",
                "mutations": [
                    {
                        "status": "KILLED",
                        "line": 250,
                        "column": 20,
                        "type": "CONDITIONALS_NEGATION",
                    }
                ],
            },
            {"file_name": "sub/helper.go", "mutations": [{"status": "LIVED"}]},
        ]
    }
    assert gate.go_report_mutants(report, "pkg/token") == [
        (
            "pkg/token/token.go",
            {
                "status": "KILLED",
                "line": 250,
                "column": 20,
                "type": "CONDITIONALS_NEGATION",
            },
        ),
        ("pkg/token/sub/helper.go", {"status": "LIVED"}),
    ]


@pytest.mark.parametrize("report", [{}, {"files": None}, {"files": []}])
def test_go_report_mutants_tolerates_empty_reports(report):
    # An empty report is not a crash here — gate_go turns "no mutants at all"
    # into an exit-2 drift failure, which must be reached, not pre-empted.
    assert gate.go_report_mutants(report, "pkg/token") == []


def test_go_package_dirs_drops_a_dir_covered_by_its_own_ancestor():
    # gremlins expands its path argument to `<path>/...`, so ./pkg/jwks already
    # mutates pkg/jwks/cache. Running both would mutate the same code twice
    # under two different timeout baselines; a KILLED-here / TIMED OUT-there
    # split between the two runs would fail the gate on nothing at all.
    changed = ["pkg/jwks/jwks.go", "pkg/jwks/cache/store.go", "pkg/jwt/claims.go"]
    assert gate.go_package_dirs(changed) == ["pkg/jwks", "pkg/jwt"]


def test_go_package_dirs_module_root_file_collapses_to_the_module():
    # A GO_SURFACE entry may name a single file at the module root (RUST_SURFACE
    # already does); PurePosixPath spells its parent ".", which as a path
    # argument is the whole module and therefore covers every other dir.
    assert gate.go_package_dirs(["identity.go", "pkg/jwt/claims.go"]) == ["."]
    assert gate.go_path_prefix(".") == "."
    assert gate.go_path_prefix("pkg/jwt") == "./pkg/jwt"


@pytest.mark.parametrize(
    "relpath",
    [
        "pkg/jwt/testdata/fixture.go",
        "pkg/jwt/_scratch/x.go",
        "pkg/jwt/.hidden/x.go",
    ],
)
def test_go_ignored_path_matches_what_the_go_tool_skips(relpath):
    assert gate.go_ignored_path(relpath)


@pytest.mark.parametrize("relpath", ["pkg/jwt/claims.go", "pkg/jwt/sub/x.go"])
def test_go_ignored_path_leaves_real_packages_alone(relpath):
    assert not gate.go_ignored_path(relpath)


def test_go_report_mutants_normalises_a_dot_parent_instead_of_prefixing_it():
    # The module root is pkg_dir ".": a plain f-string join yields "./x.go",
    # which resolves on disk yet equals no changed-file key ("x.go"), so the
    # intersection would empty out and the gate would report "no mutatable
    # constructs" — a silent pass. The join must normalise.
    report = {"files": [{"file_name": "x.go", "mutations": [{"status": "KILLED"}]}]}
    assert gate.go_report_mutants(report, ".") == [("x.go", {"status": "KILLED"})]
    dotted = {"files": [{"file_name": "./token.go", "mutations": [{"status": "K"}]}]}
    assert gate.go_report_mutants(dotted, "pkg/token") == [
        ("pkg/token/token.go", {"status": "K"})
    ]


@pytest.mark.parametrize(
    "file_name",
    ["/abs/token.go", "../token.go", "sub/../../escape.go", "", None],
)
def test_go_report_mutants_rejects_paths_that_escape_the_package(file_name):
    report = {"files": [{"file_name": file_name, "mutations": [{"status": "LIVED"}]}]}
    with pytest.raises(ValueError, match="file_name|usable"):
        gate.go_report_mutants(report, "pkg/token")


# ── the scoping invariant the gate actually depends on ──────────────────────

_PKG_FILES = {"pkg/jwt/claims.go", "pkg/jwt/doc.go", "pkg/jwt/sub/helper.go"}


def test_go_anchoring_check_passes_when_both_sides_share_one_spelling():
    assert (
        gate.go_anchoring_check(
            "pkg/jwt",
            {"pkg/jwt/claims.go", "pkg/jwt/sub/helper.go"},
            _PKG_FILES,
            {"pkg/jwt/claims.go"},
        )
        is None
    )


def test_go_anchoring_check_allows_a_changed_file_with_no_mutants():
    # doc.go is a real file with nothing mutatable — gremlins never reports it.
    # That is the "no mutatable constructs" pass, and it must stay available.
    assert (
        gate.go_anchoring_check(
            "pkg/jwt", {"pkg/jwt/claims.go"}, _PKG_FILES, {"pkg/jwt/doc.go"}
        )
        is None
    )


@pytest.mark.parametrize(
    "report_paths",
    [
        {"pkg/jwt/./claims.go"},  # resolves identically, matches no key
        {"pkg/jwt/CLAIMS.go"},  # case-differing (macOS devs run this locally)
        {"pkg/jwt/pkg/jwt/claims.go"},  # gremlins started reporting rooted paths
    ],
)
def test_go_anchoring_check_rejects_paths_that_resolve_but_do_not_match(report_paths):
    # Every one of these passes an on-disk existence test and still matches no
    # changed-line key. "The anchoring matched nothing" must never be able to
    # read as "the changed lines have no mutatable constructs".
    error = gate.go_anchoring_check(
        "pkg/jwt", report_paths, _PKG_FILES, {"pkg/jwt/claims.go"}
    )
    assert error is not None
    assert "FAILED" in error


def test_go_anchoring_check_rejects_a_changed_key_the_package_does_not_hold():
    error = gate.go_anchoring_check("pkg/jwt", set(), _PKG_FILES, {"pkg/jwt/ghost.go"})
    assert error is not None
    assert "pkg/jwt/ghost.go" in error


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("line", None),
        ("line", 0),
        ("line", "250"),
        ("line", True),
        ("column", "20"),
        ("status", None),
        ("type", ""),
    ],
)
def test_go_malformed_mutants_flags_anything_the_gate_cannot_position(field, value):
    # `None in {250}` and `"250" in {250}` are both False, so a field rename or
    # type change in gremlins' report would silently drop every in-scope mutant
    # and pass the gate. The intersection is the only scoping step left, so this
    # has to be loud like every other drift mode here.
    mutant = {"status": "LIVED", "line": 250, "column": 20, "type": "COND"}
    mutant[field] = value
    assert gate.go_malformed_mutants([("pkg/jwt/claims.go", mutant)]) == [
        f"pkg/jwt/claims.go: {field}={value!r}"
    ]


def test_go_malformed_mutants_accepts_a_well_formed_report():
    mutant = {"status": "KILLED", "line": 1, "column": 0, "type": "COND"}
    assert gate.go_malformed_mutants([("pkg/jwt/claims.go", mutant)]) == []


# ── gremlins invocation ──────────────────────────────────────────────────────


def _fake_run(returncode: int, payload: str | None):
    calls: dict[str, object] = {}

    def run(cmd, cwd=None, env=None):
        calls["cmd"] = cmd
        calls["cwd"] = cwd
        if payload is not None:
            Path(cmd[cmd.index("--output") + 1]).write_text(payload)
        return subprocess.CompletedProcess(cmd, returncode, "", "boom")

    return run, calls


def test_run_gremlins_argv_passes_no_diff_flag_and_pins_the_coefficient(monkeypatch):
    # gremlins' own --diff scoping is what this gate stopped trusting (it
    # silently SKIPPED a mutant on an added line). If --diff ever came back the
    # intersection would be applied to an already-mis-scoped report, and the
    # coefficient is what keeps a Go recompile from reporting every mutant as
    # TIMED OUT. Both are pinned in argv.
    run, calls = _fake_run(0, json.dumps({"files": []}))
    monkeypatch.setattr(gate, "_run", run)

    assert gate.run_gremlins("pkg/token") == {"files": []}

    cmd = calls["cmd"]
    assert cmd[:2] == ["gremlins", "unleash"]
    assert not [arg for arg in cmd if arg.startswith("--diff")]
    assert cmd[cmd.index("--timeout-coefficient") + 1] == str(
        gate.GO_TIMEOUT_COEFFICIENT
    )
    assert cmd[-1] == "./pkg/token"


def test_run_gremlins_uses_a_complete_report_written_alongside_a_nonzero_exit(
    monkeypatch, capsys
):
    run, _calls = _fake_run(1, json.dumps({"files": [{"file_name": "t.go"}]}))
    monkeypatch.setattr(gate, "_run", run)
    assert gate.run_gremlins("pkg/token") == {"files": [{"file_name": "t.go"}]}
    assert "exited 1" in capsys.readouterr().out


@pytest.mark.parametrize("payload", [None, "{truncated", '["not", "an", "object"]'])
def test_run_gremlins_fails_closed_on_a_missing_or_unusable_report(
    monkeypatch, payload
):
    run, _calls = _fake_run(0, payload)
    monkeypatch.setattr(gate, "_run", run)
    assert gate.run_gremlins("pkg/token") is None


# ── gate_go end to end (git + gremlins replaced) ─────────────────────────────

_GO_BODY = """package jwt

func Check(n int) bool {
	if n > 3 {
		return true
	}
	return false
}
"""


class _GoGateHarness:
    """Drives :func:`gate_go` over a throwaway module with its edges replaced.

    The gate's own guards are what is under test, so only the boundaries move:
    git (``changed_surface_files`` / ``changed_line_numbers``), the ``go list``
    probe, and the gremlins subprocess. Everything in between — the per-package
    floor, the health check, the anchoring proof, the intersection — runs for
    real against files that exist on disk.
    """

    def __init__(self, root: Path, monkeypatch) -> None:
        self.root = root
        self.reports: dict[str, object] = {}
        self.runs: list[str] = []
        self.listed: dict[str, object] = {}
        self._changed: dict[str, set[int]] = {}
        (root / "tools").mkdir()
        monkeypatch.setattr(gate, "REPO_ROOT", root)
        monkeypatch.setattr(gate, "GO_ALLOWLIST", root / "tools" / "go-waivers.txt")
        monkeypatch.setattr(gate, "changed_surface_files", self._changed_files)
        monkeypatch.setattr(gate, "changed_line_numbers", self._changed_lines)
        monkeypatch.setattr(gate, "go_list_packages", self._go_list)
        monkeypatch.setattr(gate, "run_gremlins", self._run_gremlins)

    # -- setup ---------------------------------------------------------------
    def change(self, relpath: str, lines: set[int], body: str = _GO_BODY) -> None:
        path = self.root / "go" / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        self._changed[relpath] = lines

    def report(self, pkg_dir: str, *files: dict) -> None:
        self.reports[pkg_dir] = {"files": list(files)}

    # -- replaced edges ------------------------------------------------------
    def _changed_files(self, *_args, **_kwargs) -> list[str]:
        return sorted(self._changed)

    def _changed_lines(self, _base, _lang_dir, relpath: str) -> set[int]:
        return set(self._changed[relpath])

    def _go_list(self, pkg_dir: str):
        return self.listed.get(pkg_dir, [f"example.com/go/{pkg_dir}"])

    def _run_gremlins(self, pkg_dir: str):
        self.runs.append(pkg_dir)
        return self.reports.get(pkg_dir)

    def run(self) -> int:
        return gate.gate_go("origin/main")


@pytest.fixture
def go_gate(tmp_path, monkeypatch):
    return _GoGateHarness(tmp_path, monkeypatch)


def _mutations(*statuses, line=4, column=6):
    return [
        {"status": s, "line": line, "column": column, "type": "CONDITIONALS_NEGATION"}
        for s in statuses
    ]


def test_gate_go_fails_when_a_reported_path_does_not_resolve(go_gate):
    # (a) The re-anchoring produced a path that is not a .go file of the
    # package. Every intersection would be empty; that must not read as a pass.
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt", {"file_name": "ghost.go", "mutations": _mutations("KILLED")}
    )
    assert go_gate.run() == 2


def test_gate_go_fails_when_one_package_of_several_reports_nothing(go_gate):
    # (b) THE regression this gate exists to prevent. dpop's report is empty at
    # exit 0; jwt's mutants would satisfy any aggregate floor, the intersection
    # would find nothing for dpop, and dpop's changed security lines would be
    # waved through. The floor is per run, so this is exit 2 — not 0.
    go_gate.change("pkg/dpop/proof.go", {4})
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report("pkg/dpop")
    go_gate.report(
        "pkg/jwt", {"file_name": "claims.go", "mutations": _mutations("KILLED")}
    )
    assert go_gate.run() == 2


def test_gate_go_fails_when_the_empty_package_is_mutated_last(go_gate):
    # Same defect, opposite order: aggregation must not be able to hide it
    # whichever run comes back empty.
    go_gate.change("pkg/dpop/proof.go", {4})
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/dpop", {"file_name": "proof.go", "mutations": _mutations("KILLED")}
    )
    go_gate.report("pkg/jwt")
    assert go_gate.run() == 2


@pytest.mark.parametrize("status", ["LIVED", "NOT COVERED"])
def test_gate_go_fails_on_a_survivor_on_a_changed_line(go_gate, status):
    # (c) The end-to-end non-vacuity pin: a survivor on a changed line fails.
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt", {"file_name": "claims.go", "mutations": _mutations(status)}
    )
    assert go_gate.run() == 1


def test_gate_go_passes_when_the_changed_line_mutant_is_killed(go_gate):
    # (d) …and a killed one passes, so the failure above is about the status,
    # not about the harness.
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt", {"file_name": "claims.go", "mutations": _mutations("KILLED")}
    )
    assert go_gate.run() == 0
    assert go_gate.runs == ["pkg/jwt"]


def test_gate_go_ignores_mutants_off_the_changed_lines(go_gate):
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt",
        {"file_name": "claims.go", "mutations": _mutations("LIVED", line=7)},
    )
    assert go_gate.run() == 0


def test_gate_go_fails_a_package_that_tested_mutants_and_killed_none(go_gate):
    # NOT VIABLE only proves the mutant did not COMPILE — it is not evidence
    # that any test ran, so a run that is nothing but NOT VIABLE is exactly as
    # broken as one that is all TIMED OUT, and must not silence the check.
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt",
        {"file_name": "claims.go", "mutations": _mutations(*["NOT VIABLE"] * 6)},
    )
    assert go_gate.run() == 2


def test_gate_go_health_check_is_per_package_not_per_gate(go_gate):
    # jwt kills 6; dpop times out 6 and kills none. On the concatenation jwt's
    # kills silence the check and dpop's timeouts are then offered to the author
    # as ordinary survivors with paste-ready waiver lines — the exact blinding
    # the check exists to prevent. Per package, dpop fails as config drift.
    go_gate.change("pkg/dpop/proof.go", {4})
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/dpop",
        {"file_name": "proof.go", "mutations": _mutations(*["TIMED OUT"] * 6)},
    )
    go_gate.report(
        "pkg/jwt",
        {"file_name": "claims.go", "mutations": _mutations(*["KILLED"] * 6)},
    )
    assert go_gate.run() == 2


def test_gate_go_fails_on_a_mutant_it_cannot_position(go_gate):
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt",
        {
            "file_name": "claims.go",
            "mutations": [
                {"status": "LIVED", "line": "4", "column": 6, "type": "COND"}
            ],
        },
    )
    assert go_gate.run() == 2


def test_gate_go_fails_when_no_package_is_buildable_at_that_path(go_gate):
    # A changed .go file under a directory `go list` cannot build (all files
    # behind build constraints) used to abort the gate from inside gremlins
    # with "failed to gather coverage", naming the tool instead of the path.
    # The report below would otherwise pass, so only the probe can fail this.
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt", {"file_name": "claims.go", "mutations": _mutations("KILLED")}
    )
    go_gate.listed["pkg/jwt"] = None
    assert go_gate.run() == 2
    assert go_gate.runs == []


def test_gate_go_skips_paths_the_go_tool_never_compiles(go_gate, capsys):
    # A changed fixture under testdata/ used to send gremlins at a directory
    # with no package, aborting the WHOLE gate with a gremlins error.
    go_gate.change("pkg/jwt/testdata/fixture.go", {4})
    assert go_gate.run() == 0
    assert go_gate.runs == []
    assert "NOT GATED" in capsys.readouterr().out


def test_gate_go_still_gates_the_real_sibling_of_an_ignored_path(go_gate):
    go_gate.change("pkg/jwt/testdata/fixture.go", {4})
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt", {"file_name": "claims.go", "mutations": _mutations("LIVED")}
    )
    assert go_gate.run() == 1
    assert go_gate.runs == ["pkg/jwt"]


def test_gate_go_waives_a_survivor_only_with_a_matching_content_hash(go_gate):
    # The whole pipeline, including the allowlist read, over a real file.
    go_gate.change("pkg/jwt/claims.go", {4})
    go_gate.report(
        "pkg/jwt", {"file_name": "claims.go", "mutations": _mutations("LIVED")}
    )
    source = (go_gate.root / "go" / "pkg/jwt/claims.go").read_text().splitlines()
    digest = gate.go_mutant_hash(source, 4, 6, "CONDITIONALS_NEGATION")
    (go_gate.root / "tools" / "go-waivers.txt").write_text(
        f"pkg/jwt/claims.go:4:6:CONDITIONALS_NEGATION {digest}\n"
    )
    assert go_gate.run() == 0


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
