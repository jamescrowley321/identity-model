#!/usr/bin/env python3
"""Diff-scoped mutation gates for the Go and Rust libraries (issue #638).

Mirrors the Python gate (``py/tools/mutation_security.py``) for the other two
languages: every mutant on a line this PR changed inside the security surface
must be **killed** by tests, or explicitly waived as an equivalent mutant —
anything else fails the gate. A PR that touches no in-scope line passes
vacuously (and fast).

Per-language tooling
--------------------
* **Go** — `go-gremlins <https://github.com/go-gremlins/gremlins>`_ (v0.6.0+,
  which has native changed-line scoping via ``--diff``). The driver runs
  ``gremlins unleash --diff BASE`` from ``go/`` and gates the machine-readable
  report. gremlins invokes ``git diff --merge-base BASE`` itself; its mutant
  positions are Go-module-relative while git prints repo-root paths, so the
  driver exports ``diff.relative=true`` through git's environment-config
  variables for the gremlins subprocess. If that path alignment ever drifts,
  gremlins marks the in-scope mutants ``SKIPPED`` (never tested) — which this
  gate counts as survivors, so drift fails closed instead of green.
* **Rust** — `cargo-mutants <https://mutants.rs>`_ with ``--in-diff`` (native
  changed-line scoping). ``--in-place`` is required: the crate's tests read and
  ``include_str!`` fixtures from ``../spec/``, which cargo-mutants' default
  copied-tree build cannot see (the copy stops at the workspace root), so the
  baseline build fails in a copy. In-place mutation runs serially and restores
  each file after its run.

Fail-closed rules (all mirrored from the Python gate)
-----------------------------------------------------
* **Killed is an allowlist of statuses, not a denylist of survivors.** Go: only
  ``KILLED`` and ``NOT VIABLE`` pass; Rust: only ``CaughtMutant`` and
  ``Unviable``. Every other status — including ones future tool versions may
  add — is a survivor unless waived. ``NOT VIABLE``/``Unviable`` mean the
  mutant does not compile: in a compiled language the build check kills it as
  mechanically as a failing test, which is why they sit in the killed set (the
  Python gate has no analogue — every Python mutant runs).
* **>=1-mutant floor.** Zero mutants enumerated where the tool should have
  produced some is config/scope/version drift, not a pass — exit 2. The
  "changed lines have no mutatable constructs" pass is only taken when an
  *unrestricted* enumeration proves the tool healthy: the gremlins report
  always contains the whole Go module's mutants (scoping only affects which
  are tested), and the Rust gate enumerates the whole crate with
  ``cargo mutants --list --json`` and filters to the changed files itself, so
  no file-pattern argument can silently scope mutants away.
* **Coverage cross-check (Rust).** The driver computes its own changed-line ∩
  mutant-span intersection from ``cargo mutants --list --json`` and requires
  every mutant in that intersection to appear in the run's ``outcomes.json``.
  If cargo-mutants' ``--in-diff`` scoping ever disagrees with the driver's, the
  missing mutants fail the gate (exit 2) rather than silently not being tested.
* **Content-keyed waivers.** Line numbers drift, so a waiver must pin the
  *transformation*, never a position (the Python gate's issue #615). A survivor
  is waived only when its identity AND a 16-hex SHA-256 content hash both match
  an allowlist entry:

  - Go (``tools/mutation_security_go_allowlist.txt``), entry
    ``<file>:<line>:<col>:<TYPE> <hash>``: the key is ``(file, TYPE, hash)``
    where ``hash`` covers the mutated source line's stripped text, the mutator
    type, and the token's offset within the stripped line. The ``line:col`` in
    the entry is a human label only. Re-indenting does not move the hash;
    changing the line's content does — the waiver then dies and must be
    re-authored (fail-closed).
  - Rust (``tools/mutation_security_rust_allowlist.txt``), entry
    ``<file>:<function> <hash>``: the key is ``(file, function, hash)`` where
    ``hash`` covers the mutant's cargo-mutants diff with the volatile
    ``---``/``+++``/``@@`` header lines stripped — the same signature the
    Python gate hashes for mutmut diffs.

  A malformed entry (missing/short hash, unparseable name) is a hard error,
  never a silent pass. Failing runs print each survivor's ready-to-paste
  waiver line, so authoring a waiver never requires computing a hash by hand.

Usage
-----
``python3 tools/mutation_security_native.py {go|rust}`` from the repo root,
with ``BASE`` (default ``origin/main``) naming the ref to diff against —
``make mutation-security-go`` / ``make mutation-security-rust``. Stdlib-only on
purpose: the CI jobs for Go/Rust need no Python environment. Requires
``gremlins`` (Go) or ``cargo-mutants`` (Rust) on PATH:
``go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0`` /
``cargo install cargo-mutants --locked``.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

# ── The security-critical surface ────────────────────────────────────────────
# Go-module-relative (go/...) path prefixes. The analogue of the Python gate's
# SECURITY_MODULES: token/claims validation, key material handling, issuer
# trust, sender-constraining and the client-credential paths. pkg/introspection
# and pkg/revocation are excluded to mirror the Python surface (its
# introspection_logic/revocation_logic are not gated); internal/ and examples/
# are test harnesses and demo binaries, not library controls.
GO_SURFACE: list[str] = [
    "pkg/discovery/",  # issuer match + metadata validation (↔ discovery_logic/policy)
    "pkg/dpop/",  # DPoP keys/proofs/verification (↔ core/dpop.py)
    "pkg/idtoken/",  # ID Token validation (OIDC Core §3.1.3.7)
    "pkg/jwks/",  # JWKS fetch/cache/key selection (↔ jwks_logic/jwks_cache)
    "pkg/jwt/",  # JWT + claims validation (↔ token_validation_logic et al.)
    "pkg/token/",  # token endpoint client auth + PKCE (↔ client_auth/state_validation)
    "pkg/userinfo/",  # UserInfo retrieval/validation (↔ sync/aio userinfo)
]

# Crate-relative (rust/...) path prefixes; a non-slash entry is a single file.
# Same curation rationale as GO_SURFACE; src/introspection is excluded to
# mirror Python, and src/http.rs / src/env.rs / src/error.rs are transport and
# plumbing, not security controls.
RUST_SURFACE: list[str] = [
    "src/client_auth.rs",  # client authentication (↔ core/client_auth.py)
    "src/discovery/",  # issuer match + metadata validation
    "src/jwks/",  # JWKS fetch/cache/key selection
    "src/jwt/",  # JWT + claims + ID Token validation
    "src/token/",  # token endpoint + PKCE
    "src/userinfo/",  # UserInfo retrieval/validation
]

# The ONLY statuses that count as killed; see the module docstring.
GO_KILLED = frozenset({"KILLED", "NOT VIABLE"})
RUST_KILLED = frozenset({"CaughtMutant", "Unviable"})

GO_ALLOWLIST = REPO_ROOT / "tools" / "mutation_security_go_allowlist.txt"
RUST_ALLOWLIST = REPO_ROOT / "tools" / "mutation_security_rust_allowlist.txt"

_HASH_RE = re.compile(r"^[0-9a-f]{16}$")
# -U0 hunk header: @@ -old,n +new,m @@ ; m absent means a single line.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)
# Each allowlist entry is exactly two whitespace-separated fields: name + hash.
_ALLOWLIST_FIELDS = 2
# Go waiver names are ``<file>:<line>:<col>:<TYPE>`` — four colon-joined fields.
_GO_NAME_FIELDS = 4


def _run(
    cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    # Commands are built from module constants and a git ref, never untrusted
    # shell input; shell=False keeps args literal.
    try:
        return subprocess.run(
            cmd, text=True, capture_output=True, check=False, cwd=cwd, env=env
        )
    except FileNotFoundError:
        print(
            f"mutation-security: required tool not found: {cmd[0]!r}. "
            "See tools/mutation_security_native.py for install commands.",
            file=sys.stderr,
        )
        sys.exit(2)


def _git_diff(base: str, extra: list[str], cwd: Path) -> str:
    """``git diff --merge-base base ...`` output, falling back to a plain
    two-dot diff when there is no merge base (parity with the Python gate).

    ``--merge-base`` diffs merge-base(BASE, HEAD) → *working tree*, exactly
    what gremlins diffs internally, so local uncommitted edits are scoped the
    same way everywhere; in CI the two forms are identical.
    """
    res = _run(["git", "diff", "--merge-base", base, *extra], cwd=cwd)
    if res.returncode != 0:
        res = _run(["git", "diff", base, *extra], cwd=cwd)
    if res.returncode != 0:
        print(
            f"error: could not diff against BASE={base!r}:\n{res.stderr}",
            file=sys.stderr,
        )
        sys.exit(2)
    return res.stdout


def changed_surface_files(
    base: str,
    lang_dir: str,
    surface: list[str],
    suffix: str,
    exclude_suffix: str | None = None,
) -> list[str]:
    """Security-surface files whose CONTENT changed versus ``base``.

    Same semantics as the Python gate's ``changed_security_files``: pure
    renames (``R100``) are excluded, content changes are keyed on the new
    path, deletions have nothing on HEAD to test. Paths are returned relative
    to ``lang_dir`` (the Go module / Rust crate root) because that is how the
    mutation tools report positions.
    """
    out = _git_diff(base, ["--name-status", "-M", "--", lang_dir], cwd=REPO_ROOT)
    changed: set[str] = set()
    for line in out.splitlines():
        fields = line.split("\t")
        status = fields[0]
        if status.startswith("R"):
            if status == "R100":
                continue
            newpath = fields[-1]
        elif status[:1] in ("A", "M"):
            newpath = fields[1]
        else:  # D (deleted) etc. — nothing exists on HEAD to test
            continue
        changed.add(newpath.removeprefix(lang_dir + "/"))
    return sorted(
        f
        for f in changed
        if f.endswith(suffix)
        and not (exclude_suffix and f.endswith(exclude_suffix))
        and any(f.startswith(p) if p.endswith("/") else f == p for p in surface)
        and (REPO_ROOT / lang_dir / f).exists()
    )


def parse_changed_lines(diff_text: str) -> set[int]:
    """New-file line numbers added/modified in a ``-U0`` unified diff."""
    lines: set[int] = set()
    for m in _HUNK_RE.finditer(diff_text):
        start = int(m.group(1))
        count = 1 if m.group(2) is None else int(m.group(2))
        lines.update(range(start, start + max(count, 1)))
    return lines


def changed_line_numbers(base: str, lang_dir: str, relpath: str) -> set[int]:
    return parse_changed_lines(
        _git_diff(base, ["-U0", "--", f"{lang_dir}/{relpath}"], cwd=REPO_ROOT)
    )


# ── Waivers ──────────────────────────────────────────────────────────────────


def parse_go_waiver_name(name: str) -> tuple[str, str] | None:
    """``pkg/jwt/x.go:106:18:CONDITIONALS_NEGATION`` → ``(file, TYPE)``.

    The ``line:col`` fields are a human label only — content-hash keying makes
    them irrelevant to matching (and immune to drift).
    """
    parts = name.split(":")
    if len(parts) != _GO_NAME_FIELDS or not parts[0].endswith(".go"):
        return None
    return (parts[0], parts[3])


def parse_rust_waiver_name(name: str) -> tuple[str, str] | None:
    """``src/jwt/claims_validation.rs:boxed`` → ``(file, function)``."""
    file, sep, function = name.partition(".rs:")
    if not sep or not function or "/" in function:
        return None
    return (file + ".rs", function)


def load_allowlist(
    text: str,
    allowlist_name: str,
    parse_name: Callable[[str], tuple[str, str] | None],
) -> set[tuple[str, str, str]]:
    """Parse an equivalent-mutant allowlist into ``{(identity..., hash)}`` keys.

    Each non-comment line is ``<name> <16-hex content hash>`` (trailing ``#``
    comment optional). Any malformed entry raises :class:`ValueError`: an
    un-verifiable waiver must be a hard, loud failure, never a silent pass.
    """
    waivers: set[tuple[str, str, str]] = set()
    for raw in text.splitlines():
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        key = parse_name(parts[0]) if len(parts) == _ALLOWLIST_FIELDS else None
        if key is None or not _HASH_RE.match(parts[1]):
            raise ValueError(
                f"{allowlist_name}: malformed entry {stripped!r}; expected "
                "'<name> <16-hex content hash>'. A failing gate run prints the "
                "exact line to paste for each survivor."
            )
        waivers.add((*key, parts[1]))
    return waivers


def go_mutant_hash(
    source_lines: list[str], line: int, column: int, mtype: str
) -> str | None:
    """Content hash pinning a gremlins mutant to its transformation.

    Covers the mutator type, the mutated source line's stripped text, and the
    token's column offset *within* the stripped text (so two mutatable tokens
    of the same kind on one line stay distinct, while re-indenting the line
    moves nothing). Returns ``None`` when the reported position cannot be
    resolved against the current source — such a mutant can never be waived
    (fail-closed).
    """
    if not 1 <= line <= len(source_lines):
        return None
    raw = source_lines[line - 1]
    stripped = raw.strip()
    if not stripped:
        return None
    offset = column - (len(raw) - len(raw.lstrip()))
    payload = f"{mtype}|{stripped}|{offset}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def rust_diff_signature(diff_text: str) -> str:
    """A cargo-mutants diff stripped of everything that is not the
    transformation: ``---``/``+++`` file headers and ``@@`` hunk headers carry
    paths and line numbers that drift; the context and ``-``/``+`` lines that
    remain identify the transformation uniquely (the same reduction the Python
    gate applies to mutmut diffs)."""
    body = [
        line
        for line in diff_text.splitlines()
        if not line.startswith(("--- ", "+++ ", "@@"))
    ]
    return "\n".join(body).strip()


def rust_diff_hash(diff_text: str) -> str:
    return hashlib.sha256(rust_diff_signature(diff_text).encode()).hexdigest()[:16]


# ── Evaluation (pure; unit-tested in py/src/tests/unit) ──────────────────────


def evaluate_go(
    in_scope: list[tuple[str, dict]],
    waivers: set[tuple[str, str, str]],
    source_lines_by_file: dict[str, list[str]],
) -> tuple[list[str], list[str]]:
    """Return ``(unwaived_survivors, waived_survivors)`` for Go mutants.

    A survivor is any mutant whose status is not in :data:`GO_KILLED` — new or
    unknown statuses included. It is waived only when ``(file, TYPE, content
    hash)`` matches an allowlist entry.
    """
    unwaived: list[str] = []
    waived: list[str] = []
    ordered = sorted(
        in_scope, key=lambda t: (t[0], t[1]["line"], t[1]["column"], t[1]["type"])
    )
    for fname, m in ordered:
        status = m["status"]
        if status in GO_KILLED:
            continue
        digest = go_mutant_hash(
            source_lines_by_file.get(fname, []), m["line"], m["column"], m["type"]
        )
        name = f"{fname}:{m['line']}:{m['column']}:{m['type']}"
        if digest is not None and (fname, m["type"], digest) in waivers:
            waived.append(f"{name}: {status}")
            continue
        entry = f"{name}: {status}"
        if status == "SKIPPED":
            entry += (
                "  [never tested: gremlins' own diff scoping disagreed with the "
                "gate's changed-line computation — path/config drift fails closed]"
            )
        elif digest is not None:
            entry += f"  [waiver line: {name} {digest}]"
        unwaived.append(entry)
    return unwaived, waived


def rust_in_scope(listed: list[dict], lines_by_file: dict[str, set[int]]) -> list[dict]:
    """Mutants whose span intersects a changed line (multi-line spans — e.g.
    whole-function-body replacements — are in scope if ANY spanned line
    changed)."""
    scoped = []
    for m in listed:
        changed = lines_by_file.get(m["file"], set())
        span = range(m["span"]["start"]["line"], m["span"]["end"]["line"] + 1)
        if any(ln in changed for ln in span):
            scoped.append(m)
    return scoped


def evaluate_rust(
    results: dict[str, str],
    info_by_name: dict[str, dict],
    waivers: set[tuple[str, str, str]],
) -> tuple[list[str], list[str]]:
    """Return ``(unwaived_survivors, waived_survivors)`` for Rust outcomes.

    ``results`` maps mutant name → outcome summary for every mutant
    cargo-mutants tested; all of them gate (they are already diff-scoped, and
    anything cargo scoped in beyond the driver's own intersection only adds
    pressure). A survivor is waived only when ``(file, function, diff hash)``
    matches; a tested mutant missing from the enumeration cannot be waived at
    all — that is drift, and it fails.
    """
    unwaived: list[str] = []
    waived: list[str] = []
    for name, summary in sorted(results.items()):
        if summary in RUST_KILLED:
            continue
        m = info_by_name.get(name)
        if m is None:
            unwaived.append(
                f"{name}: {summary}  [outside the gate's enumeration — cannot be waived]"
            )
            continue
        fn_name = (m.get("function") or {}).get("function_name") or "<module>"
        digest = rust_diff_hash(m.get("diff", ""))
        if (m["file"], fn_name, digest) in waivers:
            waived.append(f"{name}: {summary}")
        else:
            unwaived.append(
                f"{name}: {summary}  [waiver line: {m['file']}:{fn_name} {digest}]"
            )
    return unwaived, waived


def _finish(
    lang: str,
    scoped: int,
    unwaived: list[str],
    waived: list[str],
    allowlist: Path,
) -> int:
    for w in waived:
        print(f"mutation-security[{lang}]: WAIVED equivalent mutant {w}")
    if unwaived:
        print(
            f"\nmutation-security[{lang}]: FAILED — surviving mutant(s) with no "
            "fail-closed test:"
        )
        for s in unwaived:
            print(f"  {s}")
        print(
            f"\nAdd a test that kills the mutant, or — if it is provably "
            f"equivalent — waive it in {allowlist.relative_to(REPO_ROOT)} by "
            "pasting the '[waiver line: ...]' shown above with a justification "
            "comment. Waivers are content-keyed, so position drift cannot "
            "rebind them to a different mutant."
        )
        return 1
    print(
        f"mutation-security[{lang}]: PASSED — {scoped} mutant(s) on the changed "
        "line(s), all killed (or waived-equivalent)."
    )
    return 0


# ── Go gate ──────────────────────────────────────────────────────────────────


def _git_env_with_relative_diff() -> dict[str, str]:
    """Environment for the gremlins subprocess with ``diff.relative=true``
    injected via git's environment-config mechanism, so the ``git diff``
    gremlins runs from ``go/`` prints module-relative paths that match its
    mutant positions. Appends after any pre-existing GIT_CONFIG_* entries."""
    env = dict(os.environ)
    count = int(env.get("GIT_CONFIG_COUNT", "0") or "0")
    env[f"GIT_CONFIG_KEY_{count}"] = "diff.relative"
    env[f"GIT_CONFIG_VALUE_{count}"] = "true"
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


def gate_go(base: str) -> int:
    changed = changed_surface_files(base, "go", GO_SURFACE, ".go", "_test.go")
    if not changed:
        print(
            f"mutation-security[go]: no security-surface files changed vs {base}; "
            "gate is a no-op pass."
        )
        return 0
    print(
        f"mutation-security[go]: gating {len(changed)} changed security file(s) "
        f"vs {base}:"
    )
    for f in changed:
        print(f"  - {f}")
    lines_by_file = {f: changed_line_numbers(base, "go", f) for f in changed}

    try:
        waivers = load_allowlist(
            _read(GO_ALLOWLIST), GO_ALLOWLIST.name, parse_go_waiver_name
        )
    except ValueError as exc:
        print(f"mutation-security[go]: FAILED — {exc}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        out_json = Path(tmp) / "gremlins.json"
        res = _run(
            ["gremlins", "unleash", "--diff", base, "--output", str(out_json)],
            cwd=REPO_ROOT / "go",
            env=_git_env_with_relative_diff(),
        )
        sys.stdout.write(res.stdout)
        if res.returncode != 0 or not out_json.exists():
            print(
                f"mutation-security[go]: FAILED — gremlins run did not complete:\n"
                f"{res.stderr}",
                file=sys.stderr,
            )
            return 2
        report = json.loads(out_json.read_text())

    mutants = [
        (f["file_name"], m)
        for f in report.get("files") or []
        for m in f.get("mutations") or []
    ]
    if not mutants:
        # gremlins enumerates the WHOLE module regardless of --diff (scoping
        # only decides which mutants are tested), so an empty report can only
        # be config/scope/version drift — the module demonstrably has mutants.
        print(
            "mutation-security[go]: FAILED — gremlins enumerated 0 mutants "
            "module-wide. This is config/scope/version drift, not a pass.",
            file=sys.stderr,
        )
        return 2

    in_scope = [
        (fname, m)
        for fname, m in mutants
        if fname in lines_by_file and m.get("line") in lines_by_file[fname]
    ]
    if not in_scope:
        print(
            "mutation-security[go]: PASSED — the changed line(s) contain no "
            f"mutatable constructs ({len(mutants)} mutant(s) enumerated "
            "module-wide; gremlins healthy)."
        )
        return 0
    print(
        f"mutation-security[go]: {len(in_scope)}/{len(mutants)} mutant(s) live "
        "on the changed line(s)."
    )

    source_lines = {
        f: (REPO_ROOT / "go" / f).read_text().splitlines() for f in lines_by_file
    }
    unwaived, waived = evaluate_go(in_scope, waivers, source_lines)
    return _finish("go", len(in_scope), unwaived, waived, GO_ALLOWLIST)


# ── Rust gate ────────────────────────────────────────────────────────────────


def gate_rust(base: str) -> int:
    changed = changed_surface_files(base, "rust", RUST_SURFACE, ".rs")
    if not changed:
        print(
            f"mutation-security[rust]: no security-surface files changed vs {base}; "
            "gate is a no-op pass."
        )
        return 0
    print(
        f"mutation-security[rust]: gating {len(changed)} changed security file(s) "
        f"vs {base}:"
    )
    for f in changed:
        print(f"  - {f}")
    lines_by_file = {f: changed_line_numbers(base, "rust", f) for f in changed}

    try:
        waivers = load_allowlist(
            _read(RUST_ALLOWLIST), RUST_ALLOWLIST.name, parse_rust_waiver_name
        )
    except ValueError as exc:
        print(f"mutation-security[rust]: FAILED — {exc}", file=sys.stderr)
        return 1

    # Enumerate the WHOLE crate (a parse-only, sub-second step) and filter to
    # the changed files in the driver, rather than trusting a --file pattern:
    # an unrestricted enumeration means "no mutants on the changed lines" can
    # only be true because the changed files genuinely have none — a filter
    # that silently matched nothing would instead show up here as the crate's
    # mutants with none in the changed files (and an empty crate enumeration
    # is drift outright). Same construction as the Go gate's module-wide report.
    res = _run(["cargo", "mutants", "--list", "--json"], cwd=REPO_ROOT / "rust")
    if res.returncode != 0:
        print(
            f"mutation-security[rust]: FAILED — cargo mutants --list failed:\n"
            f"{res.stderr}",
            file=sys.stderr,
        )
        return 2
    listed = json.loads(res.stdout or "[]")
    if not listed:
        print(
            "mutation-security[rust]: FAILED — cargo-mutants enumerated 0 "
            "mutants crate-wide. This is config/scope/version drift, not a pass.",
            file=sys.stderr,
        )
        return 2
    in_changed_files = [m for m in listed if m["file"] in lines_by_file]

    in_scope = rust_in_scope(in_changed_files, lines_by_file)
    if not in_scope:
        print(
            "mutation-security[rust]: PASSED — the changed line(s) contain no "
            f"mutatable constructs ({len(in_changed_files)} mutant(s) in the "
            f"changed file(s), {len(listed)} crate-wide; cargo-mutants healthy)."
        )
        return 0
    print(
        f"mutation-security[rust]: {len(in_scope)}/{len(in_changed_files)} "
        "mutant(s) in the changed file(s) intersect the changed line(s)."
    )

    with tempfile.TemporaryDirectory() as tmp:
        diff_file = Path(tmp) / "changes.diff"
        diff_file.write_text(
            _git_diff(base, ["--relative", "--", *changed], cwd=REPO_ROOT / "rust")
        )
        res = _run(
            [
                "cargo",
                "mutants",
                "--in-place",
                "--in-diff",
                str(diff_file),
                "-o",
                tmp,
            ],
            cwd=REPO_ROOT / "rust",
        )
        sys.stdout.write(res.stdout)
        outcomes_path = Path(tmp) / "mutants.out" / "outcomes.json"
        if not outcomes_path.exists():
            # cargo-mutants' exit code is not trusted in either direction; a
            # run that produced no outcomes at all is the only fatal shape.
            print(
                "mutation-security[rust]: FAILED — cargo mutants produced no "
                f"outcomes:\n{res.stderr}",
                file=sys.stderr,
            )
            return 2
        outcomes = json.loads(outcomes_path.read_text())

    results: dict[str, str] = {}
    for outcome in outcomes.get("outcomes") or []:
        scenario = outcome.get("scenario")
        if isinstance(scenario, dict) and "Mutant" in scenario:
            results[scenario["Mutant"]["name"]] = outcome.get("summary", "")
        elif scenario == "Baseline" and outcome.get("summary") != "Success":
            print(
                "mutation-security[rust]: FAILED — the unmutated baseline "
                f"build/test failed ({outcome.get('summary')}); fix the tree "
                "before gating mutants.",
                file=sys.stderr,
            )
            return 2

    missing = [m["name"] for m in in_scope if m["name"] not in results]
    if missing:
        print(
            "mutation-security[rust]: FAILED — mutant(s) on changed line(s) were "
            "never tested (drift between the gate's changed-line intersection "
            "and cargo-mutants --in-diff):",
            file=sys.stderr,
        )
        for name in missing:
            print(f"  {name}", file=sys.stderr)
        return 2

    unwaived, waived = evaluate_rust(results, {m["name"]: m for m in listed}, waivers)
    return _finish("rust", len(results), unwaived, waived, RUST_ALLOWLIST)


def _read(path: Path) -> str:
    return path.read_text() if path.exists() else ""


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("go", "rust"):
        print("usage: mutation_security_native.py {go|rust}", file=sys.stderr)
        return 2
    base = os.environ.get("BASE", "origin/main")
    return gate_go(base) if argv[0] == "go" else gate_rust(base)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
