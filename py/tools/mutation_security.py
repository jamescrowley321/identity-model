#!/usr/bin/env python3
"""Changed-files-scoped mutation gate for the security-critical modules.

Epic 19 G.1 (mutation gate) + G.5 (aggregate ``security-gate``). This driver
runs `mutmut <https://github.com/boxed/mutmut>`_ against **only** the
security-critical modules that changed versus ``BASE`` (default ``origin/main``)
and fails if any mutant that is **not provably killed** survives.

Why "not killed = survivor" (fail-closed), not a denylist
---------------------------------------------------------
An earlier version enumerated a *denylist* of survivor statuses
(``survived``/``timeout``/...). That is **fail-open**: mutmut also emits
``no tests`` (a changed line with zero covering tests), ``skipped``,
``suspicious`` and future statuses — none of which were on the denylist, so a
control with no test at all was silently reported as PASSED. We invert it: the
**only** passing status is ``killed``; every other status is a survivor unless
it is explicitly waived. This is robust to new mutmut statuses by construction.

Guardrails
----------
* **Changed-line scope, not full-file or full-function.** Full mutation of every
  security module is a nightly concern; on a PR we prove the *lines this PR
  touched* are pinned by fail-closed tests. Mutants are first narrowed to the
  functions the PR changed, then — via each surviving mutant's ``mutmut show``
  diff — down to the changed **lines**, so a one-line edit to a large function
  does not drag in that function's pre-existing mutation debt (issue #511). The
  line filter is **fail-closed**: any mutant it cannot positively place on an
  unchanged line stays in scope (see ``scope_to_changed_lines``). Pre-existing
  debt on untouched lines is not this PR's regression surface, so it does not
  gate the PR. Empty intersection -> exit 0 (safe as a required check).
* **Changed-line *pre-filter* (speed).** mutmut's ``only_mutate`` is file-glob
  only, so it would mutate every construct in every changed file (~1500 mutants,
  ~40 min for a multi-file PR) and the changed-line scoping above would then
  discard almost all of them. Instead, ``_mutmut_prefilter_run.py`` restricts
  mutmut to generating mutants **only on the changed lines** up front, so the run
  is proportional to what the PR touched, not to the size of the files it touched.
  Fail-safe: an unmatched file falls back to full mutation (see
  :func:`covered_lines_for_file`), and a 0-mutant result is disambiguated from
  drift by an unrestricted probe run (see ``main``), so neither speed path can
  turn the gate silently green.
* **>=1-mutant floor.** If mutmut produced **zero** mutants for the changed
  files, that is a config/scope/version-drift failure, not a pass — we exit 1.
  (This is the "silent green on output drift" hole the review flagged.)
* **Content-addressed equivalent-mutant allowlist.** Genuinely-equivalent
  mutants (semantically identical, unkillable) are waived in
  ``tools/mutation_security_allowlist.txt`` by the **content of the mutation**
  — the function it lives in plus the source line it rewrote (from
  ``mutmut show``) — **never** its ``__mutmut_N`` index. mutmut numbers mutants
  sequentially and *renumbers* them whenever a function changes, so an
  index-keyed waiver can silently rebind to a *different, real* survivor and pass
  the gate green (issue #615: fail-open). Keying on content makes a waiver track
  the exact mutation it was written for; a survivor whose mutation is not waived
  — or whose ``mutmut show`` diff cannot be parsed — stays gated (fail-closed).

mutmut 3.x is configured via ``setup.cfg [mutmut]``; this driver writes a
**temporary** ``setup.cfg`` for the run (restoring any pre-existing one) so the
scope stays dynamic. ``also_copy = src/tests`` is required because this repo's
tests live under ``src/tests`` (mutmut only auto-copies top-level ``tests/``).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import functools
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


# ── The security-critical surface ────────────────────────────────────────────
# Every module here is mutation-gated when it changes. Keep in sync with
# docs/security/control-matrix.md. Broad on purpose: changed-files scoping means
# only the files a PR *touches* are actually mutated, so listing the whole
# security surface costs nothing until one of them changes.
SECURITY_MODULES: list[str] = [
    # core validation / crypto / protocol
    "src/py_identity_model/core/token_validation_logic.py",
    "src/py_identity_model/core/jwt_helpers.py",
    "src/py_identity_model/core/parsers.py",
    "src/py_identity_model/core/mtls.py",
    "src/py_identity_model/core/dpop.py",
    "src/py_identity_model/core/jarm.py",
    "src/py_identity_model/core/client_auth.py",
    "src/py_identity_model/core/jwks_logic.py",
    "src/py_identity_model/core/jwks_cache.py",
    "src/py_identity_model/core/discovery_logic.py",
    "src/py_identity_model/core/discovery_policy.py",
    "src/py_identity_model/core/state_validation.py",
    "src/py_identity_model/core/validators.py",
    # public entrypoint wrappers (sync + aio) — where controls must be *invoked*
    "src/py_identity_model/sync/token_validation.py",
    "src/py_identity_model/sync/userinfo.py",
    "src/py_identity_model/sync/logout.py",
    "src/py_identity_model/aio/token_validation.py",
    "src/py_identity_model/aio/userinfo.py",
    "src/py_identity_model/aio/logout.py",
]

# Package root copied (and made importable) into mutmut's ``mutants/`` sandbox.
SOURCE_ROOT = "src/py_identity_model"

# Tests mutmut may run to kill mutants. mutmut narrows this per-mutant to the
# covering tests via its stats-collection pass, so listing the suite does not
# mean every test runs for every mutant.
TEST_SELECTION: list[str] = ["src/tests/security", "src/tests/unit"]

ALLOWLIST_FILE = Path("tools/mutation_security_allowlist.txt")

# The ONLY status that counts as a killed mutant. Everything else is a survivor.
KILLED_STATUS = "killed"

# mutmut mutant names always contain this marker.
_MUTANT_LINE = re.compile(
    r"^\s*(?P<name>\S*__mutmut_\S*):\s*(?P<status>[a-z][a-z ]*?)\s*$"
)


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    # Commands are built from module constants and a git ref, never untrusted
    # shell input; shell=False keeps args literal.
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def changed_security_files(base: str) -> list[str]:
    """Security modules whose CONTENT changed on HEAD versus ``base``.

    Uses ``--name-status -M`` so a pure rename — a file that only MOVED with no
    content change, e.g. the CONS-2.1 relocation of the package into ``py/`` —
    is excluded: moving a file changes no security logic, so there is nothing to
    mutation-test (and treating a move as a full-file change would run mutation
    testing over every relocated module). Content changes (``A``/``M`` or a
    rename with <100% similarity) are kept, keyed on the NEW path.

    Paths are normalized to be package-relative: this tool runs from ``py/``
    (the package root, CONS-2.1) where ``SECURITY_MODULES`` are listed
    ``src/py_identity_model/...``, but ``git`` prints repo-root paths, so the
    ``py/`` prefix is stripped. Without that strip the membership test matches
    nothing and passes vacuously — the exact hole PR #510 closed.
    """
    res = _run(["git", "diff", "--name-status", "-M", f"{base}...HEAD"])
    if res.returncode != 0:
        # No common merge-base yet (e.g. a freshly created local base branch):
        # fall back to a direct two-dot diff against the base tip.
        res = _run(["git", "diff", "--name-status", "-M", base])
    if res.returncode != 0:
        print(
            f"error: could not diff against BASE={base!r}:\n{res.stderr}",
            file=sys.stderr,
        )
        sys.exit(2)
    changed: set[str] = set()
    for line in res.stdout.splitlines():
        fields = line.split("\t")
        status = fields[0]
        if status.startswith("R"):
            # "R<similarity>\told\tnew"; a 100%-similar rename is a pure move
            # (no content change) and the new path is the last tab field.
            if status == "R100":
                continue
            newpath = fields[-1]
        elif status[:1] in ("A", "M"):
            newpath = fields[1]
        else:  # D (deleted) etc. — nothing exists on HEAD to test
            continue
        changed.add(newpath.removeprefix("py/"))
    return [m for m in SECURITY_MODULES if m in changed and Path(m).exists()]


def _changed_line_numbers(base: str, path: str) -> set[int]:
    """New-file line numbers that changed on HEAD versus ``base`` for ``path``."""
    res = _run(["git", "diff", "-U0", f"{base}...HEAD", "--", path])
    if res.returncode != 0:
        res = _run(["git", "diff", "-U0", base, "--", path])
    lines: set[int] = set()
    # -U0 hunk header: @@ -old,n +new,m @@ ; m absent means a single line.
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", res.stdout, re.M):
        start = int(m.group(1))
        count = 1 if m.group(2) is None else int(m.group(2))
        lines.update(range(start, start + max(count, 1)))
    return lines


def changed_lines_by_file(base: str, changed_files: list[str]) -> dict[str, list[int]]:
    """``{relpath: sorted changed line numbers}`` for every changed file.

    Serialized to JSON and handed to the mutmut pre-filter wrapper so mutmut
    only mutates the lines this PR touched (see ``_mutmut_prefilter_run.py``).
    """
    return {p: sorted(_changed_line_numbers(base, p)) for p in changed_files}


def covered_lines_for_file(
    filename: str, changed_by_relpath: dict[str, set[int]]
) -> set[int] | None:
    """The changed lines to restrict mutation to for ``filename``, or ``None``.

    Consumed by the pre-filter wrapper's monkeypatch of mutmut's
    ``get_covered_lines_for_file``. mutmut passes a source path (relative,
    possibly ``mutants/``-prefixed or absolute); we match it against the changed
    files by suffix and return that file's changed lines so mutmut mutates **only
    those lines**.

    **Fail-safe:** returns ``None`` on any non-match, which tells mutmut to mutate
    the *whole* file — slow but correct (the pre-#511 behaviour). So a path-keying
    or mutmut-version drift degrades to full mutation, **never** to "mutate
    nothing" (which would be fail-open). Returning an empty set is deliberately
    never done here.
    """
    fn = str(filename).replace(os.sep, "/")
    for rel, lines in changed_by_relpath.items():
        if fn == rel or fn.endswith("/" + rel):
            return set(lines)
    return None


def _function_spans(path: str) -> list[tuple[str, int, int]]:
    """``(name, first_line, last_line)`` for every def/async def in ``path``."""
    tree = ast.parse(Path(path).read_text())
    return [
        (node.name, node.lineno, node.end_lineno or node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def unchanged_functions(base: str, changed_files: list[str]) -> set[str]:
    """Function names in the changed security files that this PR did NOT touch.

    The gate proves the functions a PR *changed* are mutation-pinned — not the
    pre-existing rest of a file that merely shares it. A mutant living in one of
    these untouched functions is therefore out of scope. Fail-closed: module-level
    statements and any mutant we cannot map to a known function stay in scope.
    """
    all_funcs: set[str] = set()
    changed_funcs: set[str] = set()
    for path in changed_files:
        lines = _changed_line_numbers(base, path)
        for name, start, end in _function_spans(path):
            all_funcs.add(name)
            if not set(range(start, end + 1)).isdisjoint(lines):
                changed_funcs.add(name)
    return all_funcs - changed_funcs


def _mutant_function(mutant_name: str) -> str:
    """The source function a mutmut mutant belongs to (``pkg.mod.x_foo__mutmut_3``
    -> ``foo``)."""
    leaf = mutant_name.rpartition("__mutmut_")[0].rpartition(".")[2]
    return leaf[2:] if leaf.startswith("x_") else leaf


def scope_to_changed_functions(
    statuses: dict[str, str], unchanged: set[str]
) -> dict[str, str]:
    """Drop mutants that live in a function the PR did not change (fail-closed:
    module-level / unrecognised mutants are kept)."""
    return {
        name: status
        for name, status in statuses.items()
        if _mutant_function(name) not in unchanged
    }


def _mutant_file(mutant_name: str) -> str:
    """The source file a mutmut mutant belongs to.

    ``py_identity_model.sync.token_validation.x_foo__mutmut_3`` ->
    ``src/py_identity_model/sync/token_validation.py``. mutmut names a module by
    its path relative to ``src`` with ``/`` -> ``.`` (see the ``src.`` guard in
    mutmut's trampoline), so we invert that mapping.
    """
    dotted = mutant_name.rpartition("__mutmut_")[0].rpartition(".")[0]
    return "src/" + dotted.replace(".", "/") + ".py"


def _removed_source_line(show_output: str) -> str | None:
    """The stripped text of the first *removed* (original) line in a
    ``mutmut show`` unified diff — i.e. the exact source line the mutant altered.

    Returns ``None`` when the diff has no removed line (an unexpected/empty
    ``show`` output), which callers treat fail-closed. libcst preserves source
    formatting, so the removed line matches the original file verbatim modulo
    leading indentation (which ``strip`` discards).
    """
    in_hunk = False
    for line in show_output.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        # ``---``/``+++`` are file headers, not hunk content.
        if in_hunk and line.startswith("-") and not line.startswith("---"):
            return line[1:].strip()
    return None


def _added_source_line(show_output: str) -> str | None:
    """The stripped text of the first *added* (mutated) line in a ``mutmut show``
    unified diff — i.e. the source line as mutmut rewrote it.

    Mirror of :func:`_removed_source_line` for the ``+`` side. Returns ``None``
    when the diff has no added line (callers treat that fail-closed). ``+++`` is a
    file header, not hunk content.
    """
    in_hunk = False
    for line in show_output.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_hunk and line.startswith("+") and not line.startswith("+++"):
            return line[1:].strip()
    return None


def _mutant_func_id(mutant_name: str) -> str:
    """The dotted mutmut function id a mutant belongs to — its name minus the
    ``__mutmut_N`` suffix, e.g.
    ``py_identity_model.aio.token_validation.x__refresh_jwks``.

    Only the trailing index changes when mutmut renumbers a function's mutants, so
    this prefix is stable and anchors a content waiver to a specific function
    without pinning a volatile mutant number.
    """
    return mutant_name.rpartition("__mutmut_")[0]


@functools.cache
def _mutmut_show(mutant_name: str) -> str:
    # Cached: the line-scoping pass and the waiver-evaluation pass both call this
    # per survivor within one run, and a mutant's diff is stable for that run.
    return _run([sys.executable, "-m", "mutmut", "show", mutant_name]).stdout


def _mutant_on_changed_line(
    mutant_name: str,
    changed_lines: dict[str, set[int]],
    source_lines: dict[str, list[str]],
    spans: dict[str, list[tuple[str, int, int]]],
    show: Callable[[str], str],
) -> bool:
    """Whether a mutant must stay in scope, gating on the **changed lines**.

    Fail-closed: returns ``True`` (keep in scope) on *any* uncertainty — an
    unknown file, a mutant we cannot map to a function span, an unparseable
    ``show`` diff, or a mutated line whose text is not found in the function.
    Returns ``False`` (drop as pre-existing debt) **only** when the mutated
    source line's content is found within the mutant's function *and every*
    occurrence sits on a line this PR did not change. Duplicate content that
    touches any changed line keeps the mutant (conservative).
    """
    path = _mutant_file(mutant_name)
    if path not in changed_lines:
        return True
    func = _mutant_function(mutant_name)
    fn_spans = [(s, e) for (name, s, e) in spans[path] if name == func]
    if not fn_spans:
        return True
    text = _removed_source_line(show(mutant_name))
    if text is None:
        return True
    lines = source_lines[path]
    candidates = {
        ln
        for (start, end) in fn_spans
        for ln in range(start, end + 1)
        if 1 <= ln <= len(lines) and lines[ln - 1].strip() == text
    }
    if not candidates:
        return True
    return bool(candidates & changed_lines[path])


def scope_to_changed_lines(
    scoped: dict[str, str],
    changed_files: list[str],
    base: str,
    show: Callable[[str], str] = _mutmut_show,
) -> dict[str, str]:
    """Refine function-scoped mutants down to the **lines** this PR changed.

    Function-scoping keeps every mutant in a touched function; a one-line edit to
    a large function still drags in that function's pre-existing mutation debt
    (issue #511). This narrows it: a *surviving* mutant is dropped only when it is
    provably on a line the PR did not change (see ``_mutant_on_changed_line`` —
    fail-closed on any doubt). ``killed`` mutants are passed through untouched
    (they never gate and need no ``show`` call).
    """
    changed_lines = {p: _changed_line_numbers(base, p) for p in changed_files}
    source_lines = {p: Path(p).read_text().splitlines() for p in changed_files}
    spans = {p: _function_spans(p) for p in changed_files}
    # ``killed`` short-circuits before ``_mutant_on_changed_line`` so no
    # ``mutmut show`` subprocess runs for a mutant that never gates.
    return {
        name: status
        for name, status in scoped.items()
        if status == KILLED_STATUS
        or _mutant_on_changed_line(name, changed_lines, source_lines, spans, show)
    }


def _write_setup_cfg(only_mutate: list[str]) -> str | None:
    """Write a temporary ``setup.cfg`` for the run; return backup text if any."""
    cfg = Path("setup.cfg")
    backup = cfg.read_text() if cfg.exists() else None
    only_block = "\n".join(f"    {p}" for p in only_mutate)
    test_block = "\n".join(f"    {p}" for p in TEST_SELECTION)
    cfg.write_text(
        "[mutmut]\n"
        f"source_paths = {SOURCE_ROOT}\n"
        f"only_mutate =\n{only_block}\n"
        # This repo's tests live under src/tests; mutmut only auto-copies
        # top-level tests/, so without this the sandbox has no tests to run.
        # tools/ must also be copied: the gate self-test
        # (src/tests/security/test_mutation_gate.py) loads tools/mutation_security.py
        # relative to the repo root, which is the sandbox root under mutmut. Without
        # it the baseline suite fails to collect and mutmut aborts before mutating.
        "also_copy =\n    src/tests\n    tools\n"
        f"pytest_add_cli_args_test_selection =\n{test_block}\n"
    )
    return backup


def _restore_setup_cfg(backup: str | None) -> None:
    cfg = Path("setup.cfg")
    if backup is None:
        cfg.unlink(missing_ok=True)
    else:
        cfg.write_text(backup)


@dataclass(frozen=True)
class WaiverSet:
    """Content-addressed equivalent-mutant waivers parsed from the allowlist.

    Both kinds key on the mutation's CONTENT — the dotted function id plus the
    source text it changed — never the volatile ``__mutmut_N`` index:

    * ``exact`` — waive one specific ``original -> mutated`` transformation.
    * ``line``  — waive *every* mutation of a certified no-effect source line
      (e.g. a log message, where any mutation is equivalent). Use only for lines
      with no control-flow or security effect.
    """

    line: frozenset[tuple[str, str]]
    exact: frozenset[tuple[str, str, str]]

    def waives(self, func_id: str, original: str | None, mutated: str | None) -> bool:
        """Whether a survivor with this content is waived.

        ``original``/``mutated`` come from the mutant's ``mutmut show`` diff.
        ``original is None`` (an unparseable diff) is never waived — fail-closed.
        """
        if original is None:
            return False
        if (func_id, original) in self.line:
            return True
        if mutated is None:
            return False
        return (func_id, original, mutated) in self.exact


def load_allowlist(text: str) -> WaiverSet:
    """Parse the content-addressed waiver file into a :class:`WaiverSet`.

    Each non-comment, non-blank line is one waiver::

        <func_id> | <original source line>                    # LINE waiver
        <func_id> | <original source line> => <mutated line>   # EXACT waiver

    ``func_id`` is a mutmut function id (a mutant name minus its ``__mutmut_N``
    suffix). Source text is compared stripped, matching ``_removed_source_line``
    / ``_added_source_line``. Justifications go on their own ``#`` comment lines
    above the waiver; a whole-line ``#`` is a comment, but ``#`` is **not**
    stripped mid-line (a source line may legitimately contain one). A line with
    no `` | `` separator raises — a security gate must not silently drop a waiver
    it cannot parse (that would fail-open).
    """
    line_w: set[tuple[str, str]] = set()
    exact_w: set[tuple[str, str, str]] = set()
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        entry = raw.strip()
        if " | " not in entry:
            raise ValueError(
                f"malformed waiver (expected '<func_id> | <source line>'): {entry!r}"
            )
        func_id, _, rest = entry.partition(" | ")
        func_id = func_id.strip()
        if " => " in rest:
            original, _, mutated = rest.partition(" => ")
            exact_w.add((func_id, original.strip(), mutated.strip()))
        else:
            line_w.add((func_id, rest.strip()))
    return WaiverSet(line=frozenset(line_w), exact=frozenset(exact_w))


def parse_results(text: str) -> dict[str, str]:
    """Map ``mutant-name -> status`` from ``mutmut results --all`` output.

    Only lines naming a real mutant (``...__mutmut_N``) are parsed; headers and
    summary lines are ignored.
    """
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        m = _MUTANT_LINE.match(line)
        if m:
            statuses[m.group("name")] = m.group("status")
    return statuses


def evaluate(
    statuses: dict[str, str],
    waivers: WaiverSet,
    show: Callable[[str], str] = _mutmut_show,
) -> tuple[list[str], list[str]]:
    """Return ``(unwaived_survivors, waived_survivors)``.

    A survivor is **any** mutant whose status is not exactly ``killed``. It is
    waived only when the CONTENT of its mutation — its function id plus the source
    line it changed, read from ``mutmut show`` — matches a waiver (see
    :meth:`WaiverSet.waives`). The mutant's ``__mutmut_N`` index plays no part, so
    renumbering can neither silently rebind a waiver to a different real survivor
    (issue #615) nor break a genuine one. A survivor whose diff cannot be parsed
    is unwaivable (fail-closed).
    """
    unwaived, waived = [], []
    for name, status in sorted(statuses.items()):
        if status == KILLED_STATUS:
            continue
        diff = show(name)
        entry = f"{name}: {status}"
        if waivers.waives(
            _mutant_func_id(name),
            _removed_source_line(diff),
            _added_source_line(diff),
        ):
            waived.append(entry)
        else:
            unwaived.append(entry)
    return unwaived, waived


def _mutmut_results_text() -> str:
    # --all so killed mutants are included too (needed for the >=1 floor check).
    return _run([sys.executable, "-m", "mutmut", "results", "--all", "true"]).stdout


_PREFILTER_WRAPPER = str(Path(__file__).with_name("_mutmut_prefilter_run.py"))


def run_mutmut(changed_lines_json: str) -> int:
    """Run ``mutmut run`` restricted to the PR's changed lines; return exit code.

    Invokes the pre-filter wrapper, which monkeypatches mutmut so it only mutates
    lines in ``changed_lines_json`` (``{relpath: [lines]}``). Pass ``"{}"`` to
    mutate everything (the drift-probe fallback). The wrapper propagates mutmut's
    own exit code; a crash (e.g. mutmut-internals drift breaking the monkeypatch)
    surfaces as non-zero and fails the gate closed.
    """
    env = {**os.environ, "MUTATION_CHANGED_LINES": changed_lines_json}
    return subprocess.run(
        [sys.executable, _PREFILTER_WRAPPER], check=False, text=True, env=env
    ).returncode


def _run_prefiltered(
    base: str, changed: list[str]
) -> tuple[dict[str, str] | None, int]:
    """Run mutmut restricted to the changed lines; return ``(statuses, exit)``.

    ``statuses`` is ``None`` when the caller should return ``exit`` directly:
    a crashed run (2), genuine 0-mutant drift (2), or a legit "changed lines have
    no mutatable constructs" pass (0). Otherwise ``(parsed_statuses, 0)``.

    Pre-filtering (issue #511) is the big speedup — mutmut otherwise mutates every
    construct in every changed file (~1500 mutants for a multi-file PR); the
    wrapper restricts it to the changed lines, cutting that to a handful. mutmut
    exits 0 even with survivors, so a non-zero code means the run crashed (bad
    config, import error, or mutmut-internals drift breaking the monkeypatch) —
    fail closed.
    """
    if run_mutmut(json.dumps(changed_lines_by_file(base, changed))) != 0:
        print("mutation-security: mutmut run failed to complete.", file=sys.stderr)
        return None, 2

    statuses = parse_results(_mutmut_results_text())
    if statuses:
        return statuses, 0

    # Zero mutants after the line pre-filter is AMBIGUOUS: either the changed
    # lines have no mutatable constructs (a legit pass — e.g. a comment/docstring/
    # annotation-only change) or config/version drift. Disambiguate with an
    # unrestricted probe: if the FULL file also yields 0 mutants, that is genuine
    # drift (the #510 "silent green" hole) → fail; otherwise mutmut is healthy and
    # the changed lines simply aren't mutatable → pass.
    if run_mutmut("{}") != 0:
        print(
            "mutation-security: mutmut probe run failed to complete.", file=sys.stderr
        )
        return None, 2
    if not parse_results(_mutmut_results_text()):
        print(
            "mutation-security: FAILED — mutmut produced 0 mutants even unrestricted "
            "for the changed security module(s). This is config/scope/version drift, "
            "not a pass.",
            file=sys.stderr,
        )
        return None, 2
    print(
        "mutation-security: PASSED — the changed line(s) contain no mutatable "
        "constructs (mutmut healthy; nothing to gate)."
    )
    return None, 0


def main() -> int:
    base = os.environ.get("BASE", "origin/main")
    changed = changed_security_files(base)

    if not changed:
        print(
            f"mutation-security: no security modules changed vs {base}; gate is a no-op pass."
        )
        return 0

    print(
        f"mutation-security: gating {len(changed)} changed security module(s) vs {base}:"
    )
    for f in changed:
        print(f"  - {f}")

    backup = _write_setup_cfg(changed)
    try:
        statuses, early_exit = _run_prefiltered(base, changed)
        if statuses is None:
            return early_exit

        # Scope to the functions this PR actually changed. Untouched functions in a
        # touched file are pre-existing mutation debt, not this PR's regression
        # surface, so their mutants do not gate the PR (the >=1 floor above still runs
        # against the full mutant set, so config/version drift is still caught).
        unchanged = unchanged_functions(base, changed)
        fn_scoped = scope_to_changed_functions(statuses, unchanged)
        # Narrow further to the changed *lines*: a one-line edit to a large
        # function must not inherit that function's pre-existing mutation debt
        # (issue #511). Fail-closed — see scope_to_changed_lines.
        scoped = scope_to_changed_lines(fn_scoped, changed, base)
        excluded = len(statuses) - len(scoped)
        line_excluded = len(fn_scoped) - len(scoped)
        print(
            f"mutation-security: {len(scoped)}/{len(statuses)} mutant(s) live on the "
            f"changed line(s); {excluded} out of scope "
            f"({line_excluded} on unchanged lines within changed functions)."
        )

        try:
            waivers = load_allowlist(_read_allowlist())
        except ValueError as exc:
            print(f"mutation-security: FAILED — {exc}", file=sys.stderr)
            return 2
        unwaived, waived = evaluate(scoped, waivers)
        for w in waived:
            print(f"mutation-security: WAIVED equivalent mutant {w}")

        if unwaived:
            print(
                "\nmutation-security: FAILED — surviving mutant(s) with no fail-closed test:"
            )
            for s in unwaived:
                print(f"  {s}")
            print(
                "\nAdd a test under src/tests/security/ that kills the mutant "
                "(`mutmut show <name>` shows its diff), or — if it is provably "
                "equivalent — waive it in tools/mutation_security_allowlist.txt by "
                "its CONTENT, with a justification:\n"
                "  <func_id> | <original line> => <mutated line>   (this mutation)\n"
                "  <func_id> | <original line>                     (any mutation of "
                "a no-effect line, e.g. a log message)\n"
                "where <func_id> is the mutant name up to (not including) "
                "'__mutmut_'."
            )
            return 1

        print(
            f"mutation-security: PASSED — {len(scoped)} mutant(s) on the changed "
            "line(s), all killed (or waived-equivalent)."
        )
        return 0
    finally:
        _restore_setup_cfg(backup)


def _read_allowlist() -> str:
    return ALLOWLIST_FILE.read_text() if ALLOWLIST_FILE.exists() else ""


if __name__ == "__main__":
    raise SystemExit(main())
