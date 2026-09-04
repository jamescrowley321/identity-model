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
import sys

import pytest


_DRIVER = Path(__file__).resolve().parents[3] / "tools" / "mutation_security.py"
_spec = importlib.util.spec_from_file_location("mutation_security", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
mutation_security = importlib.util.module_from_spec(_spec)
# Register before exec so dataclasses can resolve the module's own (PEP 563,
# string) annotations via sys.modules when it processes ``WaiverSet``.
sys.modules[_spec.name] = mutation_security
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


_EMPTY_WAIVERS = mutation_security.WaiverSet(frozenset(), frozenset())


def test_only_killed_passes_everything_else_is_a_survivor():
    # An empty ``show`` diff has no removed line -> nothing can be waived, so every
    # non-killed status surfaces as a survivor.
    unwaived, waived = mutation_security.evaluate(
        _EXPECTED_STATUSES, _EMPTY_WAIVERS, show=lambda _n: ""
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


# ── Content-addressed waivers (issue #615) ───────────────────────────────────
# A waiver matches a survivor by the CONTENT of its mutation — the function id
# plus the source line it rewrote (from ``mutmut show``) — never the volatile
# ``__mutmut_N`` index. This closes the fail-open where renumbering silently
# rebinds a stale index-name waiver onto a *different, real* survivor.

_PARSERS_FN = "py_identity_model.core.parsers.x_find_key_by_kid"
_GUARD = "if len(signing_keys) > 1 and jwt_alg:"


def _show(original, mutated):
    """A ``mutmut show`` unified diff rewriting ``original`` to ``mutated``."""
    return (
        "--- src/p.py\n+++ src/p.py\n@@ -2,3 +2,3 @@\n"
        " def find_key_by_kid(keys, kid, jwt_alg):\n"
        f"-        {original}\n"
        f"+        {mutated}\n"
        "         return keys\n"
    )


def test_added_source_line_extracts_the_mutated_line():
    assert mutation_security._added_source_line(_SHOW_DIFF) == "if a >= b:"


def test_added_source_line_none_when_no_added_line():
    diff = "--- a\n+++ b\n@@ -1,2 +1 @@\n context\n-removed\n"
    assert mutation_security._added_source_line(diff) is None


def test_mutant_func_id_strips_the_index():
    assert mutation_security._mutant_func_id(f"{_PARSERS_FN}__mutmut_14") == _PARSERS_FN


def test_exact_waiver_waives_only_that_transformation():
    waivers = mutation_security.load_allowlist(
        f"{_PARSERS_FN} | {_GUARD} => if len(signing_keys) > 1 or jwt_alg:"
    )
    unwaived, waived = mutation_security.evaluate(
        {f"{_PARSERS_FN}__mutmut_14": "survived"},
        waivers,
        show=lambda _n: _show(_GUARD, "if len(signing_keys) > 1 or jwt_alg:"),
    )
    assert waived == [f"{_PARSERS_FN}__mutmut_14: survived"]
    assert unwaived == []


def test_exact_waiver_does_not_waive_a_different_mutation_with_the_same_index():
    # THE #615 fail-open, closed: a waiver written for the harmless `or` mutation
    # must NOT waive a *different*, dangerous mutation (`< 1`) that inherited the
    # same __mutmut_14 index after the function was renumbered.
    waivers = mutation_security.load_allowlist(
        f"{_PARSERS_FN} | {_GUARD} => if len(signing_keys) > 1 or jwt_alg:"
    )
    unwaived, waived = mutation_security.evaluate(
        {f"{_PARSERS_FN}__mutmut_14": "survived"},
        waivers,
        show=lambda _n: _show(_GUARD, "if len(signing_keys) < 1 and jwt_alg:"),
    )
    assert waived == []
    assert unwaived == [f"{_PARSERS_FN}__mutmut_14: survived"]


def test_exact_waiver_is_index_independent():
    # Same mutation content, different (renumbered) index -> still waived.
    waivers = mutation_security.load_allowlist(
        f"{_PARSERS_FN} | {_GUARD} => if len(signing_keys) > 1 or jwt_alg:"
    )
    for idx in ("__mutmut_9", "__mutmut_37", "__mutmut_200"):
        unwaived, waived = mutation_security.evaluate(
            {f"{_PARSERS_FN}{idx}": "survived"},
            waivers,
            show=lambda _n: _show(_GUARD, "if len(signing_keys) > 1 or jwt_alg:"),
        )
        assert waived == [f"{_PARSERS_FN}{idx}: survived"], idx
        assert unwaived == []


def test_line_waiver_waives_any_mutation_of_that_line():
    log = 'logger.info("Forcing JWKS refresh for %s", jwks_uri)'
    waivers = mutation_security.load_allowlist(f"{_PARSERS_FN} | {log}")
    for mutated in (
        'logger.info("XXForcing JWKS refresh for %sXX", jwks_uri)',
        'logger.info("", jwks_uri)',
        "logger.info(None, jwks_uri)",
    ):
        unwaived, waived = mutation_security.evaluate(
            {f"{_PARSERS_FN}__mutmut_3": "survived"},
            waivers,
            show=lambda _n, m=mutated: _show(log, m),
        )
        assert waived == [f"{_PARSERS_FN}__mutmut_3: survived"], mutated
        assert unwaived == []


def test_line_waiver_does_not_waive_a_different_line():
    waivers = mutation_security.load_allowlist(f"{_PARSERS_FN} | {_GUARD}")
    unwaived, waived = mutation_security.evaluate(
        {f"{_PARSERS_FN}__mutmut_3": "survived"},
        waivers,
        show=lambda _n: _show("return keys[0]", "return keys[1]"),
    )
    assert waived == []
    assert unwaived == [f"{_PARSERS_FN}__mutmut_3: survived"]


def test_waiver_is_scoped_to_its_function():
    # Identical source line, different function -> not waived (a broad line in one
    # function must never leak a waiver into another).
    waivers = mutation_security.load_allowlist(f"{_PARSERS_FN} | {_GUARD}")
    other = "py_identity_model.core.jwks_logic.x_other"
    unwaived, waived = mutation_security.evaluate(
        {f"{other}__mutmut_1": "survived"},
        waivers,
        show=lambda _n: _show(_GUARD, "if len(signing_keys) >= 1 and jwt_alg:"),
    )
    assert waived == []
    assert unwaived == [f"{other}__mutmut_1: survived"]


def test_unparseable_show_is_never_waived():
    # Fail-closed: a survivor whose diff has no removed line cannot be placed, so
    # even a matching-looking waiver must not apply.
    waivers = mutation_security.load_allowlist(f"{_PARSERS_FN} | {_GUARD}")
    unwaived, waived = mutation_security.evaluate(
        {f"{_PARSERS_FN}__mutmut_1": "survived"},
        waivers,
        show=lambda _n: "no diff here",
    )
    assert waived == []
    assert unwaived == [f"{_PARSERS_FN}__mutmut_1: survived"]


def test_killed_mutants_need_no_show_call():
    called: list[str] = []
    mutation_security.evaluate(
        {f"{_PARSERS_FN}__mutmut_1": "killed"},
        _EMPTY_WAIVERS,
        show=lambda n: called.append(n) or "",
    )
    assert called == []


def test_load_allowlist_parses_line_and_exact_waivers():
    text = (
        "# a comment\n"
        "\n"
        f"{_PARSERS_FN} | {_GUARD}\n"
        f"{_PARSERS_FN} | {_GUARD} => if len(signing_keys) >= 1 and jwt_alg:\n"
    )
    waivers = mutation_security.load_allowlist(text)
    assert waivers.line == frozenset({(_PARSERS_FN, _GUARD)})
    assert waivers.exact == frozenset(
        {(_PARSERS_FN, _GUARD, "if len(signing_keys) >= 1 and jwt_alg:")}
    )


def test_load_allowlist_rejects_a_malformed_line():
    with pytest.raises(ValueError, match="malformed waiver"):
        mutation_security.load_allowlist("this line has no pipe separator\n")


def test_load_allowlist_does_not_strip_hash_inside_a_source_line():
    # A ``#`` inside a waived source line is content, not a comment (whole-line
    # ``#`` is still a comment).
    waivers = mutation_security.load_allowlist(f"{_PARSERS_FN} | count = 0  # noqa\n")
    assert waivers.line == frozenset({(_PARSERS_FN, "count = 0  # noqa")})


def test_repo_allowlist_parses_and_is_index_free():
    # The checked-in allowlist must always parse, and no entry may reference a
    # volatile ``__mutmut_N`` index (that would be the #615 fail-open re-entering).
    text = _DRIVER.with_name("mutation_security_allowlist.txt").read_text()
    waivers = mutation_security.load_allowlist(text)
    assert waivers.line
    assert waivers.exact
    for entry in [*waivers.line, *waivers.exact]:
        assert "__mutmut_" not in entry[0], entry


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
