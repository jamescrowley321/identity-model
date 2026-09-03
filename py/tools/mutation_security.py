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
* **>=1-mutant floor.** If mutmut produced **zero** mutants for the changed
  files, that is a config/scope/version-drift failure, not a pass — we exit 1.
  (This is the "silent green on output drift" hole the review flagged.)
* **Exact-name equivalent-mutant allowlist.** Genuinely-equivalent mutants
  (semantically identical, unkillable) are waived by their **exact mutant name**
  in ``tools/mutation_security_allowlist.txt`` (anchored, not substring-anywhere
  — one broad substring must never silently waive real survivors elsewhere).

mutmut 3.x is configured via ``setup.cfg [mutmut]``; this driver writes a
**temporary** ``setup.cfg`` for the run (restoring any pre-existing one) so the
scope stays dynamic. ``also_copy = src/tests`` is required because this repo's
tests live under ``src/tests`` (mutmut only auto-copies top-level ``tests/``).
"""

from __future__ import annotations

import ast
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


def _mutmut_show(mutant_name: str) -> str:
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


def load_allowlist(text: str) -> set[str]:
    """Exact mutant names to waive (equivalent mutants). One name per line;
    ``#`` comments and blanks ignored."""
    return {
        stripped
        for line in text.splitlines()
        if (stripped := line.split("#", 1)[0].strip())
    }


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
    statuses: dict[str, str], allowlist: set[str]
) -> tuple[list[str], list[str]]:
    """Return ``(unwaived_survivors, waived_survivors)``.

    A survivor is **any** mutant whose status is not exactly ``killed``.
    """
    unwaived, waived = [], []
    for name, status in sorted(statuses.items()):
        if status == KILLED_STATUS:
            continue
        (waived if name in allowlist else unwaived).append(f"{name}: {status}")
    return unwaived, waived


def _mutmut_results_text() -> str:
    # --all so killed mutants are included too (needed for the >=1 floor check).
    return _run([sys.executable, "-m", "mutmut", "results", "--all", "true"]).stdout


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
        # mutmut writes into ./mutants (gitignored) and exits 0 even with survivors;
        # a non-zero code means the run itself crashed (bad config, import error...).
        run = subprocess.run(
            [sys.executable, "-m", "mutmut", "run"], check=False, text=True
        )
        if run.returncode != 0:
            print("mutation-security: mutmut run failed to complete.", file=sys.stderr)
            return 2

        statuses = parse_results(_mutmut_results_text())

        # >=1-mutant floor: zero mutants for changed files == config/version drift,
        # not a pass. Without this, output-format drift would be a silent green.
        if not statuses:
            print(
                "mutation-security: FAILED — mutmut produced 0 mutants for the changed "
                "security module(s). This is config/scope/version drift, not a pass.",
                file=sys.stderr,
            )
            return 2

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

        unwaived, waived = evaluate(scoped, load_allowlist(_read_allowlist()))
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
                "(`mutmut show <name>` to see it), or — if it is provably equivalent — "
                "waive its exact name in tools/mutation_security_allowlist.txt with a justification."
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
