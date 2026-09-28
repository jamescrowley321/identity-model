#!/usr/bin/env python3
"""Assert the ci-complete merge gate actually aggregates every CI job.

``ci-complete`` is the one required status check that stands for the whole
matrix, and it stands for exactly the jobs named in three places that have to
agree: its ``needs:`` list, the ``RESULTS`` map it inspects, and the
``SKIP_ALLOWED`` map that says which skips are legitimate.

A job missing from any of them is invisible to the gate. Nothing about that is
noticeable by eye -- the workflow still runs the job, the job still reports its
own green check, and the aggregate check still passes. It simply stops being
able to block a merge. This script makes that drift a CI failure instead, so a
job added without wiring cannot silently become optional.

Keys are not enough; the values are checked too, structurally:

- every ``RESULTS`` entry must be exactly ``${{ needs.<same-key>.result }}``,
  so one job cannot report another job's result;
- no key may appear twice in either map (the bash reader is last-wins, so a
  trailing duplicate would silently override the real entry);
- every ``SKIP_ALLOWED`` entry must be the logical negation of that job's own
  ``if:``. Both expressions are parsed and reduced to negation normal form
  (De Morgan, ``!(a == b)`` -> ``a != b``, flattened and order-insensitive
  ``&&`` / ``||``) and compared as trees, so a hard-coded ``true`` or a
  condition copied from a different job is rejected;
- every change-gated job's paths filter must cover what the job reads: the
  local files and directories its steps name (``working-directory``,
  ``*-file`` / ``work-dir`` / ``manifest-path`` inputs, local actions, paths
  in ``run:`` scripts and in the recipes of the ``make`` targets they call).
  Each is resolved against the checked-out tree. A read the filter misses is a
  PR that could change that input, skip the job, and have ci-complete call the
  skip justified. This is a floor, not a proof: a file reached only
  indirectly (e.g. opened by a script the job runs) is not discovered.

What this CANNOT prove: that the job list is the right one. It reads the same
ci.yml the pull request is editing, so deleting a job from ``needs:``,
``RESULTS`` and ``SKIP_ALLOWED`` together leaves all three agreeing about a
smaller matrix and this script content. A check cannot audit its own baseline.

What stands behind it is branch protection, which names its required contexts
outside the repository, where a pull request cannot reach them. That is the
layer to add a job to when it must be impossible to drop -- not this file. Read
a pass here as "every job this workflow declares is wired into the gate", never
as "every job that ought to exist does".

Exits non-zero with a specific message naming the offending jobs.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import pathlib
import posixpath
import re
import shlex
import sys
from typing import Any

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GATE = "ci-complete"
CHANGES_JOB = "changes"
PATHS_FILTER_ACTION = "dorny/paths-filter"


@dataclass(frozen=True)
class Failure:
    """One reason the gate's wiring is wrong. ``job`` is "" when global.

    ``subject`` names the specific thing at fault beyond the job, when there
    is one (the path a filter misses), so callers can key on it.
    """

    kind: str
    job: str
    detail: str
    subject: str = ""

    def __str__(self) -> str:
        where = f"[{self.job}] " if self.job else ""
        return f"{self.kind}: {where}{self.detail}"


# ── GitHub Actions expression parsing ────────────────────────────────────────
#
# Just enough of the expression grammar for `if:` conditions: literals,
# property references, function calls, `!`, comparisons, `&&`, `||` and
# parentheses. Anything else is a parse error, which fails the gate closed.

_TOKEN = re.compile(
    r"""
    \s*(?:
        (?P<op>\|\||&&|==|!=|<=|>=|<|>|!|\(|\)|,)
      | (?P<str>'(?:[^']|'')*')
      | (?P<num>-?\d+(?:\.\d+)?)
      | (?P<ident>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_*][A-Za-z0-9_-]*)*)
    )
    """,
    re.VERBOSE,
)

_NEGATED_CMP = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}
_SYMMETRIC_CMP = {"==", "!="}

# AST nodes are plain tuples so that equality is structural:
#   ("lit", value)  ("ref", "a.b.c")  ("call", name, (args...))
#   ("not", node)   ("cmp", op, left, right)
#   ("and", frozenset(nodes))  ("or", frozenset(nodes))
Node = tuple[Any, ...]


class ExpressionError(ValueError):
    pass


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if match is None or match.end() == pos:
            raise ExpressionError(f"cannot tokenize {text[pos:]!r}")
        kind = match.lastgroup
        assert kind is not None
        tokens.append((kind, match.group(kind)))
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return tokens


class _Parser:
    def __init__(self, text: str) -> None:
        self.tokens = _tokenize(text)
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self, value: str | None = None) -> tuple[str, str]:
        tok = self._peek()
        if tok is None or (value is not None and tok[1] != value):
            raise ExpressionError(f"expected {value or 'a token'}, got {tok}")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self._or()
        if self._peek() is not None:
            raise ExpressionError(f"trailing tokens from {self._peek()}")
        return node

    def _or(self) -> Node:
        parts = [self._and()]
        while self._peek() == ("op", "||"):
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else ("or", tuple(parts))

    def _and(self) -> Node:
        parts = [self._cmp()]
        while self._peek() == ("op", "&&"):
            self._take()
            parts.append(self._cmp())
        return parts[0] if len(parts) == 1 else ("and", tuple(parts))

    def _cmp(self) -> Node:
        left = self._unary()
        tok = self._peek()
        if tok is not None and tok[0] == "op" and tok[1] in _NEGATED_CMP:
            self._take()
            return ("cmp", tok[1], left, self._unary())
        return left

    def _unary(self) -> Node:
        if self._peek() == ("op", "!"):
            self._take()
            return ("not", self._unary())
        return self._primary()

    def _primary(self) -> Node:
        kind, value = self._take()
        if (kind, value) == ("op", "("):
            node = self._or()
            self._take(")")
            return node
        if kind == "str":
            return ("lit", value[1:-1].replace("''", "'"))
        if kind == "num":
            return ("lit", float(value))
        if kind == "ident":
            lowered = value.lower()
            if lowered in ("true", "false"):
                return ("lit", lowered == "true")
            if lowered == "null":
                return ("lit", None)
            if self._peek() == ("op", "("):
                self._take()
                args: list[Node] = []
                if self._peek() != ("op", ")"):
                    args.append(self._or())
                    while self._peek() == ("op", ","):
                        self._take()
                        args.append(self._or())
                self._take(")")
                return ("call", lowered, tuple(args))
            return ("ref", value)
        raise ExpressionError(f"unexpected {value!r}")


_WRAPPED = re.compile(r"^\s*\$\{\{(?P<body>.*)\}\}\s*$", re.DOTALL)


def parse_expression(text: str, *, require_wrapper: bool) -> Node:
    """Parse an expression, with or without its ``${{ }}`` wrapper.

    ``if:`` accepts a bare expression; an env value is a literal string unless
    the whole of it is one ``${{ }}`` expression, so ``require_wrapper``
    rejects a bare ``true`` there instead of reading it as a condition.
    """
    match = _WRAPPED.match(text)
    if match is not None:
        body = match.group("body")
        if "${{" in body or "}}" in body:
            raise ExpressionError(f"more than one expression in {text!r}")
        return _Parser(body).parse()
    if require_wrapper:
        raise ExpressionError(f"{text!r} is a literal, not a ${{{{ }}}} expression")
    return _Parser(text).parse()


def normalize(node: Node, negate: bool = False) -> Node:
    """Negation normal form: push `!` down to atoms, flatten and/or."""
    kind = node[0]
    if kind == "not":
        return normalize(node[1], not negate)
    if kind in ("and", "or"):
        flipped = {"and": "or", "or": "and"}[kind] if negate else kind
        members: set[Node] = set()
        for child in node[1]:
            norm = normalize(child, negate)
            if norm[0] == flipped:
                members.update(norm[1])
            else:
                members.add(norm)
        if len(members) == 1:
            return next(iter(members))
        return (flipped, frozenset(members))
    if kind == "cmp":
        op = _NEGATED_CMP[node[1]] if negate else node[1]
        left, right = normalize(node[2]), normalize(node[3])
        if op in _SYMMETRIC_CMP and repr(right) < repr(left):
            left, right = right, left
        return ("cmp", op, left, right)
    if kind == "lit" and negate and isinstance(node[1], bool):
        return ("lit", not node[1])
    if kind == "call":
        node = ("call", node[1], tuple(normalize(a) for a in node[2]))
    return ("not", node) if negate else node


def is_negation_of(candidate: Node, condition: Node) -> bool:
    return normalize(candidate) == normalize(condition, negate=True)


def refs(node: Node) -> set[str]:
    kind = node[0]
    if kind == "ref":
        return {node[1]}
    if kind == "not":
        return refs(node[1])
    if kind == "cmp":
        return refs(node[2]) | refs(node[3])
    if kind in ("and", "or"):
        return set().union(*(refs(child) for child in node[1]))
    if kind == "call":
        return set().union(set(), *(refs(arg) for arg in node[2]))
    return set()


# ── ci-complete env maps ─────────────────────────────────────────────────────


def _env_map(
    step: dict[str, Any], name: str, failures: list[Failure]
) -> dict[str, str]:
    """Parse a newline-delimited ``job=value`` env block, rejecting junk."""
    env = step.get("env") or {}
    raw = env.get(name)
    if raw is None:
        return {}
    if not isinstance(raw, str):
        failures.append(Failure(f"malformed-{name}", "", "is not a string block"))
        return {}
    entries: list[tuple[str, str]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if "=" not in line:
            failures.append(
                Failure(f"malformed-{name}", "", f"line has no '=': {line.strip()!r}")
            )
            continue
        key, value = line.split("=", 1)
        entries.append((key.strip(), value.strip()))
    counts = Counter(key for key, _ in entries)
    for key, count in sorted(counts.items()):
        if count > 1:
            failures.append(
                Failure(
                    f"duplicate-{name}",
                    key,
                    f"appears {count} times; the gate's reader is last-wins, "
                    "so the later entry silently overrides the real one",
                )
            )
    return dict(entries)


# ── paths-filter coverage ────────────────────────────────────────────────────


def _glob_regex(glob: str) -> re.Pattern[str]:
    """picomatch-style glob (as dorny/paths-filter uses it, dot: true)."""
    out = []
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _covered(path: str, is_dir: bool, globs: list[str]) -> bool:
    probe = f"{path}/__any_file__" if is_dir else path
    return any(_glob_regex(g).match(probe) for g in globs)


_SHELL_OPERATORS = {"&&", "||", ";", "|", "&"}
_PATH_INPUTS = ("working-directory", "work-dir", "manifest-path")


def _make_recipes(makefile: pathlib.Path) -> dict[str, tuple[list[str], list[str]]]:
    """target -> (prerequisites, recipe lines) for the repo-root Makefile."""
    rules: dict[str, tuple[list[str], list[str]]] = {}
    current: list[str] | None = None
    if not makefile.is_file():
        return rules
    for line in makefile.read_text().splitlines():
        if line.startswith("\t") and current is not None:
            current.append(line.strip())
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:(?![:=])\s*([^#]*)", line)
        if match and not match.group(1).startswith("."):
            current = []
            rules[match.group(1)] = (match.group(2).split(), current)
        elif line and not line.startswith("#"):
            current = None
    return rules


def _shell_tokens(script: str) -> list[list[str]]:
    lines = []
    for line in script.splitlines():
        try:
            lines.append(shlex.split(line, comments=True))
        except ValueError:
            lines.append(line.split())
    return lines


class _ReadCollector:
    def __init__(self, repo_root: pathlib.Path) -> None:
        self.root = repo_root
        self.recipes = _make_recipes(repo_root / "Makefile")
        self.found: dict[str, bool] = {}  # path -> is_dir

    def add(self, token: str, cwd: str = "") -> None:
        token = token.strip()
        if (
            not token
            or "$" in token
            or token.startswith(("-", "/", "~"))
            or "://" in token
            or "=" in token
        ):
            return
        path = posixpath.normpath(posixpath.join(cwd, token))
        if path in (".", "") or path.startswith(".."):
            return
        target = self.root / path
        if target.exists():
            self.found[path] = target.is_dir()

    def add_script(self, script: str, cwd: str = "") -> None:
        for tokens in _shell_tokens(script):
            for index, token in enumerate(tokens):
                self.add(token, cwd)
                if token == "make":
                    self.add("Makefile")
                    for target in tokens[index + 1 :]:
                        if target in _SHELL_OPERATORS:
                            break
                        if not target.startswith("-") and "=" not in target:
                            self.add_make_target(target, set())

    def add_make_target(self, target: str, seen: set[str]) -> None:
        if target in seen or target not in self.recipes:
            return
        seen.add(target)
        prerequisites, recipe = self.recipes[target]
        for dep in prerequisites:
            self.add_make_target(dep, seen)
        for line in recipe:
            for tokens in _shell_tokens(line.lstrip("@-")):
                for token in tokens:
                    self.add(token)

    def add_job(self, job: dict[str, Any]) -> None:
        for step in job.get("steps") or []:
            cwd = str(step.get("working-directory") or "")
            if cwd:
                self.add(cwd)
            uses = str(step.get("uses") or "")
            if uses.startswith("./"):
                self.add(uses)
            for key, value in (step.get("with") or {}).items():
                if isinstance(value, str) and (
                    key.endswith("-file") or key in _PATH_INPUTS
                ):
                    self.add(value)
            run = step.get("run")
            if isinstance(run, str):
                self.add_script(run, cwd)


# Only plain `*`, `**`, `?` and literal characters are modelled. Anything else
# picomatch gives meaning to -- a leading `!` negation (which makes the filter
# order-dependent and can carve a read path OUT of a `**`), brace/extglob
# alternation, character classes, escapes -- is rejected rather than guessed at,
# so a filter this checker cannot evaluate exactly fails the gate closed.
_UNSUPPORTED_GLOB = re.compile(r"^!|[\[\]{}()\\+@]")


def _paths_filters(
    changes: dict[str, Any], failures: list[Failure]
) -> dict[str, list[str]] | None:
    for step in changes.get("steps") or []:
        if not str(step.get("uses") or "").startswith(PATHS_FILTER_ACTION):
            continue
        filters = yaml.safe_load((step.get("with") or {}).get("filters") or "")
        if not isinstance(filters, dict):
            return None
        parsed: dict[str, list[str]] = {}
        for name, globs in filters.items():
            parsed[str(name)] = []
            if not isinstance(globs, list):
                globs = [globs]
            for glob in globs:
                if not isinstance(glob, str) or _UNSUPPORTED_GLOB.search(glob):
                    failures.append(
                        Failure(
                            "unsupported-filter-glob",
                            CHANGES_JOB,
                            f"filter '{name}' entry {glob!r} uses syntax this "
                            "check cannot evaluate exactly (negation, "
                            "alternation, classes, change-type maps); use "
                            "plain `*` / `**` / `?` globs",
                            subject=str(glob),
                        )
                    )
                else:
                    parsed[str(name)].append(glob)
        return parsed
    return None


def _check_filter_coverage(
    jobs: dict[str, Any],
    conditions: dict[str, Node],
    workflow_relpath: str,
    repo_root: pathlib.Path,
) -> list[Failure]:
    failures: list[Failure] = []
    prefix = f"needs.{CHANGES_JOB}.outputs."
    gated = {
        name: sorted(r[len(prefix) :] for r in refs(cond) if r.startswith(prefix))
        for name, cond in conditions.items()
    }
    gated = {name: outputs for name, outputs in gated.items() if outputs}
    if not gated:
        return failures
    filters = _paths_filters(jobs.get(CHANGES_JOB) or {}, failures)
    if filters is None:
        return [
            Failure(
                "no-paths-filter",
                CHANGES_JOB,
                f"jobs gate on {prefix}* but '{CHANGES_JOB}' has no "
                f"{PATHS_FILTER_ACTION} step to read the filters from",
            )
        ]
    for name, outputs in sorted(gated.items()):
        unknown = [o for o in outputs if o not in filters]
        if unknown:
            failures.append(
                Failure(
                    "unknown-filter",
                    name,
                    f"gates on filter output(s) {', '.join(unknown)} that the "
                    f"'{CHANGES_JOB}' paths filter does not define",
                )
            )
        globs = [g for o in outputs if o in filters for g in filters[o]]
        collector = _ReadCollector(repo_root)
        collector.found[workflow_relpath] = False
        collector.add_job(jobs[name])
        for path, is_dir in sorted(collector.found.items()):
            if not _covered(path, is_dir, globs):
                failures.append(
                    Failure(
                        "filter-misses-read",
                        name,
                        f"reads {path}{'/' if is_dir else ''} but none of the "
                        f"filters it is gated on ({', '.join(outputs)}) match "
                        "it: a PR touching only that path skips this job and "
                        "ci-complete calls the skip justified",
                        subject=path,
                    )
                )
    return failures


# ── the check ────────────────────────────────────────────────────────────────


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else [str(n) for n in needs]


def check(workflow: dict[str, Any], repo_root: pathlib.Path) -> list[Failure]:
    """Every reason ``workflow``'s ci-complete wiring is wrong (empty = ok)."""
    jobs = workflow.get("jobs") or {}
    if GATE not in jobs:
        return [Failure("no-gate-job", GATE, "the workflow has no such job")]

    gate = jobs[GATE]
    expected = set(jobs) - {GATE}
    failures: list[Failure] = []

    needs_list = _needs(gate)
    for job, count in sorted(Counter(needs_list).items()):
        if count > 1:
            failures.append(Failure("duplicate-needs", job, f"listed {count} times"))
    needs = set(needs_list)

    check_step = next(
        (s for s in gate.get("steps") or [] if "RESULTS" in (s.get("env") or {})),
        None,
    )
    if check_step is None:
        return [Failure("no-results-step", GATE, "no step carries a RESULTS block")]

    results = _env_map(check_step, "RESULTS", failures)
    skip_allowed = _env_map(check_step, "SKIP_ALLOWED", failures)

    for label, actual in (("needs", needs), ("RESULTS", set(results))):
        for job in sorted(expected - actual):
            failures.append(
                Failure(
                    f"missing-from-{label}",
                    job,
                    f"absent from {label} of '{GATE}', so it cannot block a merge",
                )
            )
        for job in sorted(actual - expected):
            failures.append(
                Failure(f"unknown-in-{label}", job, "names a job that does not exist")
            )

    # A RESULTS entry is only evidence about a job if it reads that job.
    for job, value in sorted(results.items()):
        want: Node = ("ref", f"needs.{job}.result")
        try:
            ok = parse_expression(value, require_wrapper=True) == want
        except ExpressionError:
            ok = False
        if not ok:
            failures.append(
                Failure(
                    "results-wrong-source",
                    job,
                    f"is {value!r}; it must be ${{{{ needs.{job}.result }}}}",
                )
            )

    for job in sorted(set(skip_allowed) - expected):
        failures.append(
            Failure("unknown-in-SKIP_ALLOWED", job, "names a job that does not exist")
        )

    # A job with no `if:` never skips on its own; the only way it skips is a
    # skipped dependency, which is the anomaly this gate is for. Classify on
    # `if:` alone -- `needs:` does not make a skip legitimate.
    conditions: dict[str, Node] = {}
    unconditional: set[str] = set()
    for name in sorted(expected):
        condition = jobs[name].get("if")
        if condition is None:
            unconditional.add(name)
            continue
        try:
            conditions[name] = parse_expression(str(condition), require_wrapper=False)
        except ExpressionError as exc:
            failures.append(Failure("unparseable-if", name, str(exc)))

    for job in sorted(set(skip_allowed) & unconditional):
        failures.append(
            Failure(
                "skip-allowed-on-unconditional",
                job,
                "has no `if:` and so can never legitimately skip",
            )
        )

    for job in sorted(expected - unconditional):
        if job not in skip_allowed:
            failures.append(
                Failure(
                    "missing-from-SKIP_ALLOWED",
                    job,
                    "is conditional but SKIP_ALLOWED does not say when its "
                    "skip is legitimate, so a legitimate skip fails the gate",
                )
            )
            continue
        if job not in conditions:
            continue  # its `if:` did not parse; already reported
        try:
            mirror = parse_expression(skip_allowed[job], require_wrapper=True)
        except ExpressionError as exc:
            failures.append(Failure("skip-allowed-not-negation", job, str(exc)))
            continue
        if not is_negation_of(mirror, conditions[job]):
            failures.append(
                Failure(
                    "skip-allowed-not-negation",
                    job,
                    f"SKIP_ALLOWED is {skip_allowed[job]!r}, which is not the "
                    f"negation of its `if: {jobs[job]['if']}`",
                )
            )

    workflow_relpath = ".github/workflows/ci.yml"
    failures.extend(
        _check_filter_coverage(jobs, conditions, workflow_relpath, repo_root)
    )
    return failures


def main() -> int:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    failures = check(workflow, REPO_ROOT)
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    jobs = set(workflow["jobs"]) - {GATE}
    conditional = {name for name in jobs if "if" in workflow["jobs"][name]}
    print(
        f"{GATE} aggregates all {len(jobs)} jobs "
        f"({len(conditional)} conditional, {len(jobs) - len(conditional)} "
        "unconditional); every RESULTS value reads its own job, every "
        "SKIP_ALLOWED value negates its job's `if:`, and every change-gated "
        "job's filters cover the paths it reads."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
