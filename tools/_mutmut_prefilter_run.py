#!/usr/bin/env python3
"""Run ``mutmut run`` restricted to a PR's changed lines.

The mutation gate (``tools/mutation_security.py``) invokes this instead of
``python -m mutmut run``. mutmut's ``only_mutate`` config is file-glob only —
there is no line/function scoping — so a one-line edit to a large security file
otherwise mutates the *whole* file (~hundreds of mutants, ~40 min in CI).

This wrapper monkeypatches mutmut's ``get_covered_lines_for_file`` (which mutmut
already consults to restrict mutation to a set of lines) so it returns the
**changed lines** for each changed file, taken from ``$MUTATION_CHANGED_LINES``
(JSON ``{relpath: [line, ...]}``). mutmut then mutates only those lines.

Fail-safe: :func:`mutation_security.covered_lines_for_file` returns ``None`` for
any file it cannot match, which tells mutmut to mutate the whole file — slow but
correct. So a path-keying or mutmut-version drift degrades to the pre-existing
full-mutation behaviour, never to "mutate nothing" (which would be fail-open).
An empty ``$MUTATION_CHANGED_LINES`` (``{}``) mutates everything — used by the
gate's drift-probe fallback.

The wrapper propagates mutmut's own exit code; if the monkeypatch cannot be
applied (mutmut internals changed), the import/attribute error crashes the
wrapper with a non-zero code and the gate fails closed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_security import covered_lines_for_file
import mutmut.__main__ as _mutmut_main


def main() -> int:
    changed = {
        rel: set(lines)
        for rel, lines in json.loads(
            os.environ.get("MUTATION_CHANGED_LINES", "{}")
        ).items()
    }

    # mutmut calls this (``__main__.py`` ~line 374) once per source file while
    # generating mutants; returning a line set restricts mutation to those lines.
    _mutmut_main.get_covered_lines_for_file = (
        lambda filename, _covered_lines: covered_lines_for_file(filename, changed)
    )

    try:
        _mutmut_main.cli.main(["run"], standalone_mode=False)
    except SystemExit as exc:  # click raises SystemExit with the command's code
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
