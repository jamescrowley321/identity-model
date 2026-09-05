"""Self-test for the mutation-security gate driver (tools/mutation_security.py).

The gate is itself security-critical infrastructure, so its classification logic
is unit-tested here. In particular this locks in the fail-CLOSED inversion: any
mutmut status other than ``killed`` (notably ``no tests`` — a changed line with
zero covering tests) MUST be treated as a survivor. The previous denylist
implementation was fail-open on exactly that status.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_DRIVER = Path(__file__).resolve().parents[3] / "tools" / "mutation_security.py"
_spec = importlib.util.spec_from_file_location("mutation_security", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
mutation_security = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mutation_security)

# One mutant name per mutmut status, to exercise the full classification.
_M = "py_identity_model.core.mtls.x_verify__mutmut_"
_SAMPLE_RESULTS = f"""
To apply a mutant on disk:
    mutmut apply <id>

{_M}1: killed
    {_M}2: survived
    {_M}3: no tests
    {_M}4: skipped
    {_M}5: timeout
    {_M}6: suspicious
    {_M}7: killed
some other summary line that is not a mutant
"""
_EXPECTED_STATUSES = {
    f"{_M}1": "killed",
    f"{_M}2": "survived",
    f"{_M}3": "no tests",
    f"{_M}4": "skipped",
    f"{_M}5": "timeout",
    f"{_M}6": "suspicious",
    f"{_M}7": "killed",
}


def test_parse_results_only_captures_mutant_lines():
    assert mutation_security.parse_results(_SAMPLE_RESULTS) == _EXPECTED_STATUSES


def _show(added: str, *, name: str = "pkg.mod.x_f__mutmut_2", status: str = "survived"):
    """A minimal ``mutmut show``-style diff whose *transformation* is
    ``return a <added> b``. Distinct ``added`` values -> distinct diff hashes; the
    volatile header/paths/hunk-numbers deliberately vary to prove they are ignored.
    """
    return (
        f"# {name}: {status}\n"
        "--- src/mod.py\n"
        "+++ src/mod.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def f(a, b):\n"
        "-    return a and b\n"
        f"+    return a {added} b\n"
    )


def _waiver(added: str, prefix: str) -> tuple[str, str]:
    """The ``(prefix, hash)`` waiver key for the ``_show(added)`` transformation."""
    return (prefix, mutation_security._diff_hash(_show(added)))


def test_only_killed_passes_everything_else_is_a_survivor():
    # Empty waiver set + a stub show (never consulted when there is nothing to
    # waive): every non-killed status is a survivor.
    unwaived, waived = mutation_security.evaluate(
        _EXPECTED_STATUSES, waivers=set(), show=lambda _n: ""
    )
    assert waived == []
    # Every non-killed status is a survivor — including "no tests" (the fail-open
    # the old denylist missed); killed mutants are never reported.
    assert unwaived == [
        f"{_M}2: survived",
        f"{_M}3: no tests",
        f"{_M}4: skipped",
        f"{_M}5: timeout",
        f"{_M}6: suspicious",
    ]


def test_content_verified_waiver_waives_only_the_matching_mutant():
    # Each mutant's show-diff encodes its own name -> a distinct hash. A waiver
    # keyed to _M2's (function, content-hash) waives _M2 and nothing else.
    prefix = mutation_security._mutant_prefix(f"{_M}2")

    def show(name):
        # Vary the diff BODY (not just the stripped header) per mutant so each
        # gets a distinct content hash. _M1.._M7 end in distinct digits.
        return _show(name[-1], name=name)

    waivers = {(prefix, mutation_security._diff_hash(show(f"{_M}2")))}
    unwaived, waived = mutation_security.evaluate(
        _EXPECTED_STATUSES, waivers, show=show
    )
    assert waived == [f"{_M}2: survived"]
    assert unwaived == [
        f"{_M}3: no tests",
        f"{_M}4: skipped",
        f"{_M}5: timeout",
        f"{_M}6: suspicious",
    ]


def test_waiver_keyed_by_content_not_name():
    # Two survivors in the SAME function with DIFFERENT transformations (and one
    # name a substring of the other). A waiver for one transformation must not
    # waive the other, even though they share a function prefix.
    statuses = {
        "pkg.mod.x_f__mutmut_1": "survived",
        "pkg.mod.x_f__mutmut_11": "survived",
    }

    def show(name):
        return _show("or" if name.endswith("_1") else "<", name=name)

    waivers = {
        ("pkg.mod.x_f", mutation_security._diff_hash(show("pkg.mod.x_f__mutmut_1")))
    }
    unwaived, waived = mutation_security.evaluate(statuses, waivers, show=show)
    assert waived == ["pkg.mod.x_f__mutmut_1: survived"]
    assert unwaived == ["pkg.mod.x_f__mutmut_11: survived"]


def test_load_allowlist_parses_name_and_hash():
    text = (
        "# a comment\n\n"
        "pkg.mod.x_a__mutmut_1 0123456789abcdef  # equivalent\n"
        "  \n"
        "pkg.mod.x_b__mutmut_2 fedcba9876543210\n"
    )
    assert mutation_security.load_allowlist(text) == {
        ("pkg.mod.x_a", "0123456789abcdef"),
        ("pkg.mod.x_b", "fedcba9876543210"),
    }


def test_load_allowlist_rejects_bare_name_without_hash():
    # A hash-less waiver cannot be content-verified; it must be a hard error, never
    # a silent (index-keyed, fail-open) pass.
    with pytest.raises(ValueError, match="malformed entry"):
        mutation_security.load_allowlist("pkg.mod.x_a__mutmut_1  # no hash\n")


def test_load_allowlist_rejects_malformed_hash():
    with pytest.raises(ValueError, match="malformed entry"):
        mutation_security.load_allowlist("pkg.mod.x_a__mutmut_1 nothex\n")
    with pytest.raises(ValueError, match="malformed entry"):
        # right charset, wrong length
        mutation_security.load_allowlist("pkg.mod.x_a__mutmut_1 abcdef\n")


# ── #615: index-keyed waivers are fail-open under renumbering ─────────────────
# mutmut numbers a function's mutants densely (``{name}_{i+1}``), so the ``_N``
# index is not stable: an edit — or the changed-line pre-filter compacting the
# generated set — renumbers them. A name-keyed waiver would then silently rebind
# to a DIFFERENT mutant. These tests lock in the content-verified fix.


def test_stale_index_waiver_not_honored_when_transformation_changed():
    """The core #615 fail-open: a waiver authored for transformation A must NOT
    waive a different (killable) transformation B that later inherits the same
    mutant NAME through renumbering."""
    name = "pkg.mod.x_f__mutmut_13"
    prefix = mutation_security._mutant_prefix(name)
    # Allowlist was authored for transformation A (`return a or b`, equivalent).
    waivers = {_waiver("or", prefix)}

    # After a renumber, `..._13` now maps to transformation B (`return a < b`,
    # a real behaviour change). Content verification refuses the stale waiver.
    unwaived, waived = mutation_security.evaluate(
        {name: "survived"}, waivers, show=lambda _n: _show("<")
    )
    assert waived == []  # B is NOT waived...
    assert unwaived == [f"{name}: survived"]  # ...so the gate FAILS closed.

    # Contrast — the OLD index-keyed logic (`name in allowlist`) waived purely by
    # name, so the SAME stale entry would have silently waived B (the fail-open):
    assert name in {name}


def test_equivalent_mutant_still_waived_after_index_renumber():
    """No false-fail: the genuine equivalent keeps its content hash, so its waiver
    still applies even when its index moved (e.g. _13 -> _7 under the pre-filter)."""
    prefix = "pkg.mod.x_f"
    waivers = {_waiver("or", prefix)}  # authored when the equivalent was _13
    renamed = "pkg.mod.x_f__mutmut_7"  # same transformation, new index
    unwaived, waived = mutation_security.evaluate(
        {renamed: "survived"}, waivers, show=lambda _n: _show("or")
    )
    assert waived == [f"{renamed}: survived"]
    assert unwaived == []


def test_killable_survivor_on_changed_line_fails_the_gate():
    """A killable mutant that survives on a changed line must fail the gate even
    under the changed-line pre-filter — proving the speedup did not neuter it. It
    is kept in scope by scope_to_changed_lines (fail-closed) and, with no matching
    waiver, reported as an unwaived survivor (gate exit 1)."""
    name = "pkg.mod.x_g__mutmut_2"
    diff = _show("<")  # a real, killable mutation
    # changed_files=[] -> the mutant's file is unknown -> kept in scope (fail-closed).
    scoped = mutation_security.scope_to_changed_lines(
        {name: "survived"}, changed_files=[], base="X", show=lambda _n: diff
    )
    assert scoped == {name: "survived"}  # survived the pre-filter scoping
    unwaived, waived = mutation_security.evaluate(
        scoped, waivers=set(), show=lambda _n: diff
    )
    assert waived == []
    assert unwaived == [f"{name}: survived"]  # gate fails


# ── Changed-LINE scoping (issue #511) ────────────────────────────────────────
# ``mutmut show`` renders a mutant as a unified diff whose removed line is the
# exact original source line (libcst preserves formatting). The gate maps that
# back to a file line and drops mutants that sit only on unchanged lines.

_SHOW_DIFF = (
    "# mod.x_beta__mutmut_1: survived\n"
    "--- src/mod.py\n"
    "+++ src/mod.py\n"
    "@@ -1,4 +1,4 @@\n"
    " def beta(a, b):\n"
    "-    if a > b:\n"
    "+    if a >= b:\n"
    "         return a - b\n"
    "     return b - a\n"
)

# File the diff above came from (``beta`` spans file lines 7-10).
_MOD_SOURCE = [
    "def alpha(x):",  # 1
    "    y = x + 1",  # 2
    "    z = y * 2",  # 3
    "    return z",  # 4
    "",  # 5
    "",  # 6
    "def beta(a, b):",  # 7
    "    if a > b:",  # 8  <- the mutated line
    "        return a - b",  # 9
    "    return b - a",  # 10
]
_MOD_SPANS = [("alpha", 1, 4), ("beta", 7, 10)]
_MOD_MUTANT = "mod.x_beta__mutmut_1"


def _on_changed_line(changed: set[int], *, source=None, spans=None, show=None):
    return mutation_security._mutant_on_changed_line(
        _MOD_MUTANT,
        {"src/mod.py": changed},
        {"src/mod.py": _MOD_SOURCE if source is None else source},
        {"src/mod.py": _MOD_SPANS if spans is None else spans},
        (lambda _n: _SHOW_DIFF) if show is None else show,
    )


def test_mutant_file_maps_module_to_source_path():
    assert (
        mutation_security._mutant_file(
            "py_identity_model.sync.token_validation.x_validate_token__mutmut_3"
        )
        == "src/py_identity_model/sync/token_validation.py"
    )


def test_removed_source_line_extracts_the_mutated_line():
    assert mutation_security._removed_source_line(_SHOW_DIFF) == "if a > b:"


def test_removed_source_line_none_when_no_removed_line():
    # A ``+``-only hunk (and the ``---`` file header) yields no mutated line.
    diff = "--- a\n+++ b\n@@ -1 +1,2 @@\n context\n+added\n"
    assert mutation_security._removed_source_line(diff) is None


def test_kept_when_mutated_line_is_changed():
    assert _on_changed_line({8}) is True


def test_dropped_when_mutated_line_is_unchanged():
    # The mutant is on line 8; the PR only changed line 9 -> pre-existing debt.
    assert _on_changed_line({9}) is False


def test_failclosed_when_show_diff_unparseable():
    assert _on_changed_line({9}, show=lambda _n: "no diff here") is True


def test_failclosed_when_file_not_in_changed_set():
    # A mutant whose file isn't among the changed files is kept (fail-closed).
    assert (
        mutation_security._mutant_on_changed_line(
            "other.x_f__mutmut_1", {}, {}, {}, lambda _n: _SHOW_DIFF
        )
        is True
    )


def test_failclosed_when_function_span_unknown():
    assert _on_changed_line({9}, spans=[("alpha", 1, 4)]) is True


def test_failclosed_when_content_not_found_libcst_reformat():
    # If the removed text doesn't byte-match any source line (e.g. libcst
    # reformatting), we cannot place it -> keep in scope.
    assert (
        _on_changed_line({9}, show=lambda _n: _SHOW_DIFF.replace("a > b", "a>b"))
        is True
    )


def test_duplicate_content_touching_a_changed_line_is_kept():
    # Same line text appears twice in the function; one occurrence is on a
    # changed line -> conservative keep.
    source = [*_MOD_SOURCE, "    if a > b:"]  # line 11, inside an extended span
    spans = [("alpha", 1, 4), ("beta", 7, 11)]
    assert _on_changed_line({11}, source=source, spans=spans) is True


def test_scope_to_changed_lines_passes_killed_through_without_line_check(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(
        mutation_security,
        "_mutant_on_changed_line",
        lambda name, *_a, **_k: seen.append(name) or True,
    )
    scoped = {"pkg.x_f__mutmut_1": "killed", "pkg.x_f__mutmut_2": "survived"}
    out = mutation_security.scope_to_changed_lines(scoped, changed_files=[], base="X")
    assert out == scoped
    # Only the survivor is line-checked (so ``mutmut show`` never runs for killed).
    assert seen == ["pkg.x_f__mutmut_2"]


def test_scope_to_changed_lines_drops_unchanged_line_survivors(monkeypatch):
    monkeypatch.setattr(
        mutation_security,
        "_mutant_on_changed_line",
        lambda name, *_a, **_k: name.endswith("_2"),
    )
    scoped = {
        "pkg.x_f__mutmut_1": "killed",
        "pkg.x_f__mutmut_2": "survived",
        "pkg.x_f__mutmut_3": "survived",
    }
    out = mutation_security.scope_to_changed_lines(scoped, changed_files=[], base="X")
    assert out == {"pkg.x_f__mutmut_1": "killed", "pkg.x_f__mutmut_2": "survived"}


# ── Changed-line PRE-filter (speed): covered_lines_for_file fail-safe ─────────
# The wrapper monkeypatches mutmut with this; it MUST return None (mutate the
# whole file — slow but correct) on any mismatch, never an empty set (which
# would make mutmut mutate nothing = fail-open).

_REL = "src/py_identity_model/core/jwt_helpers.py"
_CHANGED = {_REL: {80, 81, 82}}


def test_covered_lines_exact_relpath_match():
    assert mutation_security.covered_lines_for_file(_REL, _CHANGED) == {80, 81, 82}


def test_covered_lines_matches_mutants_prefixed_path():
    # mutmut may pass the path prefixed with the sandbox dir.
    assert mutation_security.covered_lines_for_file(f"mutants/{_REL}", _CHANGED) == {
        80,
        81,
        82,
    }


def test_covered_lines_matches_absolute_path():
    assert mutation_security.covered_lines_for_file(
        f"/home/runner/work/repo/py/mutants/{_REL}", _CHANGED
    ) == {80, 81, 82}


def test_covered_lines_unmatched_file_returns_none_not_empty():
    """Fail-safe: an unknown file mutates the whole file (None), never nothing."""
    assert (
        mutation_security.covered_lines_for_file("src/other/thing.py", _CHANGED) is None
    )


def test_covered_lines_empty_map_returns_none():
    assert mutation_security.covered_lines_for_file(_REL, {}) is None


def test_covered_lines_never_returns_empty_set():
    """A substring-but-not-suffix collision must not falsely match to an empty set."""
    # 'jwt_helpers.py' is a suffix of the key; a file merely *containing* the
    # key name mid-path but not as a suffix must not match.
    assert (
        mutation_security.covered_lines_for_file(
            "src/py_identity_model/core/jwt_helpers.py.bak", _CHANGED
        )
        is None
    )


def test_covered_lines_matched_but_no_changed_lines_returns_none():
    """Finding 2: a file that MATCHES but whose diff yielded no line numbers (a
    mode-only change or a hunk-parse miss) must fall back to full mutation (None),
    never an empty set. Returning ``set()`` tells mutmut to mutate *nothing* on
    that file — a silent fail-open the >=1 floor cannot catch when other files
    still produce statuses."""
    assert mutation_security.covered_lines_for_file(_REL, {_REL: set()}) is None
    # Same for a mutants/-prefixed path that matches by suffix.
    assert (
        mutation_security.covered_lines_for_file(f"mutants/{_REL}", {_REL: set()})
        is None
    )


# ── #615 diff-signature: renumbering-stable, transformation-sensitive ─────────


def test_diff_signature_ignores_index_status_path_and_hunk_numbers():
    # Same transformation, but different mutant index, run status, sandbox path,
    # and hunk line numbers -> identical hash (the properties #615 relies on).
    a = (
        "# a.b.x_f__mutmut_3: survived\n"
        "--- /abs/mutants/src/a.py\n"
        "+++ /abs/mutants/src/a.py\n"
        "@@ -34,7 +34,7 @@\n"
        " ctx\n"
        "-    x = 1\n"
        "+    x = 2\n"
    )
    b = (
        "# a.b.x_f__mutmut_99: killed\n"
        "--- src/a.py\n"
        "+++ src/a.py\n"
        "@@ -1,7 +1,7 @@\n"
        " ctx\n"
        "-    x = 1\n"
        "+    x = 2\n"
    )
    assert mutation_security._diff_hash(a) == mutation_security._diff_hash(b)


def test_diff_signature_distinguishes_different_transformations():
    a = "@@ -1,3 +1,3 @@\n ctx\n-    x = 1\n+    x = 2\n"
    b = "@@ -1,3 +1,3 @@\n ctx\n-    x = 1\n+    x = 3\n"
    assert mutation_security._diff_hash(a) != mutation_security._diff_hash(b)


# ── _run_prefiltered: 0-mutant probe disambiguation ──────────────────────────


def test_run_prefiltered_returns_parsed_statuses(monkeypatch):
    monkeypatch.setattr(
        mutation_security, "changed_lines_by_file", lambda _b, _c: {"f": [1]}
    )
    monkeypatch.setattr(mutation_security, "run_mutmut", lambda _j: 0)
    monkeypatch.setattr(mutation_security, "_mutmut_results_text", lambda: "text")
    monkeypatch.setattr(
        mutation_security, "parse_results", lambda _t: {"pkg.x_f__mutmut_1": "survived"}
    )
    statuses, code = mutation_security._run_prefiltered("base", ["f"])
    assert code == 0
    assert statuses == {"pkg.x_f__mutmut_1": "survived"}


def test_run_prefiltered_zero_mutants_then_probe_zero_is_drift_fail(monkeypatch):
    # 0 mutants after the pre-filter AND 0 under the unrestricted probe = genuine
    # config/version drift (the #510 silent-green hole) -> fail closed (exit 2).
    monkeypatch.setattr(mutation_security, "changed_lines_by_file", lambda _b, _c: {})
    monkeypatch.setattr(mutation_security, "run_mutmut", lambda _j: 0)
    monkeypatch.setattr(mutation_security, "_mutmut_results_text", lambda: "")
    monkeypatch.setattr(mutation_security, "parse_results", lambda _t: {})
    statuses, code = mutation_security._run_prefiltered("base", ["f"])
    # exit 2 == the gate's "fail closed on drift" code.
    drift_exit = 2
    assert statuses is None
    assert code == drift_exit


def test_run_prefiltered_zero_mutants_but_probe_healthy_is_legit_pass(monkeypatch):
    # 0 mutants after the pre-filter but the unrestricted probe DOES produce
    # mutants = the changed lines simply have nothing to mutate -> legit pass.
    monkeypatch.setattr(mutation_security, "changed_lines_by_file", lambda _b, _c: {})
    monkeypatch.setattr(mutation_security, "run_mutmut", lambda _j: 0)
    monkeypatch.setattr(mutation_security, "_mutmut_results_text", lambda: "text")
    calls = {"n": 0}

    def parse(_t):
        calls["n"] += 1
        return {} if calls["n"] == 1 else {"pkg.x_f__mutmut_1": "killed"}

    monkeypatch.setattr(mutation_security, "parse_results", parse)
    statuses, code = mutation_security._run_prefiltered("base", ["f"])
    assert statuses is None
    assert code == 0


# ── End-to-end: the shipped allowlist is content-consistent with source ───────


def test_allowlist_hashes_match_current_source(monkeypatch):
    """Every shipped waiver still names a real transformation in the CURRENT
    source with the recorded hash. This is the mechanical guard for #615: if a
    source change renumbers or alters a waived mutant, it fails LOUDLY here
    (fail-closed) instead of silently rebinding the waiver at gate time.

    Uses mutmut's pure-libcst generation (no sandbox, no test run — milliseconds
    per file), so it is deterministic and fast.
    """
    package_root = _DRIVER.parents[1]  # .../py  (so src/... paths resolve)
    monkeypatch.chdir(package_root)
    mutation_security._generate_mutants.cache_clear()

    allowlist_text = (_DRIVER.parent / "mutation_security_allowlist.txt").read_text()
    entries = [
        parts
        for line in allowlist_text.splitlines()
        if (s := line.split("#", 1)[0].strip()) and (parts := s.split())
    ]
    assert entries, "allowlist unexpectedly empty — the migration dropped everything"

    mismatches = {
        name: (recorded, got)
        for name, recorded in entries
        if (got := mutation_security.compute_diff_hash(name)) != recorded
    }
    assert not mismatches, (
        "allowlist entries no longer match current source (renumbered/edited); "
        f"re-author with `--hash`: {mismatches}"
    )
