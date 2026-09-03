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


def test_only_killed_passes_everything_else_is_a_survivor():
    unwaived, waived = mutation_security.evaluate(_EXPECTED_STATUSES, allowlist=set())
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


def test_exact_name_allowlist_waives_only_that_mutant():
    unwaived, waived = mutation_security.evaluate(_EXPECTED_STATUSES, {f"{_M}2"})
    assert waived == [f"{_M}2: survived"]
    assert unwaived == [
        f"{_M}3: no tests",
        f"{_M}4: skipped",
        f"{_M}5: timeout",
        f"{_M}6: suspicious",
    ]


def test_allowlist_is_anchored_not_substring():
    # A waiver for one mutant must NOT waive a different mutant whose name
    # contains it as a substring.
    statuses = {"pkg.x_f__mutmut_1": "survived", "pkg.x_f__mutmut_11": "survived"}
    unwaived, waived = mutation_security.evaluate(statuses, {"pkg.x_f__mutmut_1"})
    assert waived == ["pkg.x_f__mutmut_1: survived"]
    assert unwaived == ["pkg.x_f__mutmut_11: survived"]


def test_load_allowlist_strips_comments_and_blanks():
    text = "# a comment\n\npkg.x_a__mutmut_1  # equivalent\n  \npkg.x_b__mutmut_2\n"
    assert mutation_security.load_allowlist(text) == {
        "pkg.x_a__mutmut_1",
        "pkg.x_b__mutmut_2",
    }


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
