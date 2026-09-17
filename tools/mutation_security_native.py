#!/usr/bin/env python3
"""Diff-scoped mutation gates for the Go and Rust libraries (issue #638).

Mirrors the Python gate (``py/tools/mutation_security.py``) for the other two
languages: every mutant on a line this PR changed inside the security surface
must be **killed** by tests, or explicitly waived as an equivalent mutant —
anything else fails the gate. A PR that touches no in-scope line passes
vacuously (and fast).

Per-language tooling
--------------------
* **Go** — `go-gremlins <https://github.com/go-gremlins/gremlins>`_ (v0.6.0+).
  gremlins has a ``--diff`` flag, and the driver deliberately does **not** use
  it: its changed-line scoping is unreliable. Observed on
  ``fix/go-token-exchange-guards``: gremlins skipped the mutant on a genuinely
  added line (``go/pkg/token/token.go``'s new ``if resp.TokenType == ""``
  guard) while testing and killing mutants on other added lines of the same
  file. A skipped mutant is never executed, and ``SKIPPED`` is (correctly) a
  survivor here, so delegating the scoping made the gate fail a branch whose
  tests were in fact fine — and the only way out would have been waiving a
  well-tested line, i.e. blinding the gate.

  The driver already computes the changed lines itself
  (:func:`changed_surface_files` + :func:`changed_line_numbers`), so it only
  needs gremlins to *execute* mutants: it runs ``gremlins unleash ./<pkg>``
  once per package containing a changed surface file and intersects the
  reported mutants against its own changed-line set. That is stronger on
  scoping — an in-scope mutant cannot be silently descoped — and the one
  remaining path coupling is asserted at runtime instead of assumed. That
  coupling is gremlins' reporting convention: ``file_name`` is relative to the
  path argument it was given (and gremlins expands that argument to
  ``<path>/...``, so a nested package reports ``sub/x.go``), which
  :func:`go_report_mutants` re-anchors to a module-relative path. Because the
  scoping intersection is a *string* membership test, both the re-anchored
  report paths and the gate's own changed-file keys must appear verbatim in one
  third set the gate builds itself — the package's ``.go`` files as listed on
  disk (:func:`go_anchoring_check`). An anchoring that silently matched nothing
  therefore cannot be reported as "the changed line(s) contain no mutatable
  constructs".
  Running the changed packages rather than the whole module keeps the cost
  proportional to the PR (measured on this repo: ~5-11s per security package,
  ~45s for a six-package diff, ~49s module-wide).
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
  produced some is config/scope/version drift, not a pass — exit 2. Go applies
  the floor (and the zero-killed health check below) to **each gremlins run
  individually**, never to the concatenation: gremlins derives its timeout
  budget from the calling package's own baseline, so every package has its own
  health, and one package's mutants must never vouch for another's. On the
  concatenation, a PR touching ``pkg/jwt`` and ``pkg/dpop`` where the dpop run
  returns ``{"files": []}`` at exit 0 would see jwt's mutants, skip the drift
  error, find no dpop mutants to intersect, and pass — with dpop's changed
  security lines never gated.
  The "changed lines have no mutatable constructs" pass is only taken when an
  *unrestricted* enumeration proves the tool healthy: the gremlins reports
  contain every mutant in the changed packages (the driver passes no scoping
  flag, so the run is only narrowed by package, never by line), and the Rust
  gate enumerates the whole crate with
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
from pathlib import Path, PurePosixPath


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
#: gremlins derives each mutant's timeout from the *baseline test* duration, but
#: a Go mutant run also has to recompile the package — a cost the baseline never
#: measures. With gremlins' default coefficient the budget is a small multiple of
#: a sub-second test run, so compilation alone exhausts it and EVERY mutant comes
#: back TIMED OUT. Because TIMED OUT is (correctly) a survivor here, an
#: under-sized budget turns the gate into a wall of bogus survivors that an
#: author can only clear by waiving well-tested lines — the exact way a mutation
#: gate goes vacuous.
#:
#: The coefficient is a *ceiling*, not a sleep: a mutant that dies quickly still
#: dies quickly, so raising it buys correctness at ~no wall-time cost. Measured
#: on pkg/token (tests ~0.2s, 67 covered mutants), same tree, one run each:
#:
#:   =========== ======= ========== ==========
#:   coefficient KILLED  TIMED OUT  wall time
#:   =========== ======= ========== ==========
#:   default           0         67      1.44s
#:   30               65          2      8.16s
#:   300              67          0      7.93s
#:   =========== ======= ========== ==========
#:
#: The default is "fast" only because every mutant exhausts its budget during
#: compilation and is abandoned. 30 was not enough either: a repeat of the same
#: comparison on a busier machine scored 38 KILLED / 30 TIMED OUT at 30, so the
#: bogus-survivor count there is load-dependent — precisely what a shared CI
#: runner is. 300 scored 0 TIMED OUT in both, and cost no wall time at all here.
#: Kept generous on purpose: the only real cost is that a genuinely hanging
#: mutant takes longer to be declared dead, and those are rare.
GO_TIMEOUT_COEFFICIENT = 300

#: Below this many actually-tested mutants, "zero killed" is plausible chance
#: rather than a broken run, so the health check stays quiet. Applied per
#: gremlins run: each package has its own timeout baseline, so a healthy package
#: cannot vouch for a broken one.
GO_MIN_TESTED_FOR_HEALTH_CHECK = 5

GO_KILLED = frozenset({"KILLED", "NOT VIABLE"})
#: The health check below asks "did any test actually run?", and only ``KILLED``
#: answers yes. ``NOT VIABLE`` means the mutant failed to *compile*: it proves
#: the build worked, not that a test executed, so a run that is all NOT VIABLE
#: is exactly as broken as one that is all TIMED OUT. It stays in
#: :data:`GO_KILLED` for the per-mutant verdict (a mutant that cannot compile is
#: dead) and is deliberately excluded here.
GO_HEALTHY_STATUS = "KILLED"
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
        # SKIPPED is deliberately un-waivable: nothing ever executed the mutant,
        # so a waiver would assert equivalence on evidence that does not exist.
        # The allowlist is not consulted for it at all — the message below tells
        # the author a waiver cannot help, so that has to be mechanically true
        # rather than advisory.
        waivable = status != "SKIPPED" and digest is not None
        if waivable and (fname, m["type"], digest) in waivers:
            waived.append(f"{name}: {status}")
            continue
        entry = f"{name}: {status}"
        if status == "SKIPPED":
            entry += (
                "  [never tested: the gate passes gremlins no scoping flag, so a "
                "SKIPPED mutant on a changed line is tool drift — fix the run, do "
                "NOT waive it; the allowlist is not consulted for SKIPPED]"
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


def go_ignored_path(relpath: str) -> bool:
    """True when the go tool never compiles this path, so nothing can mutate it.

    ``go``'s ``...`` expansion skips ``testdata`` directories and any path
    component beginning with ``_`` or ``.``. gremlins expands its path argument
    the same way, so pointing it at such a directory aborts the run with
    ``failed to gather coverage`` — a message that blames the tool for what is
    really a path the gate should never have offered it.
    """
    return any(
        part == "testdata" or part.startswith(("_", "."))
        for part in PurePosixPath(relpath).parts
    )


def go_package_dirs(changed: list[str]) -> list[str]:
    """Module-relative package directories holding the changed files.

    ``["pkg/token/token.go", "pkg/token/options.go", "pkg/jwt/claims.go"]`` →
    ``["pkg/jwt", "pkg/token"]``. These become gremlins' path arguments, so a
    PR pays only for the packages it touched instead of the whole module.

    A directory whose ancestor is also in the list is dropped: gremlins expands
    its path argument to ``<path>/...`` (verified — ``unleash ./pkg/outer``
    mutates and reports ``inner/inner.go``), so the ancestor's run already
    covers it. Keeping both would mutate the same code twice under two
    different timeout baselines, and a KILLED-here / TIMED OUT-there
    disagreement between the two runs would fail the gate spuriously.
    """
    dirs = sorted({str(PurePosixPath(f).parent) for f in changed})
    return [
        d
        for d in dirs
        if not any(o != d and PurePosixPath(d).is_relative_to(o) for o in dirs)
    ]


def go_path_prefix(pkg_dir: str) -> str:
    """The ``./``-anchored path argument for a module-relative package dir.

    ``"pkg/token"`` → ``"./pkg/token"``; the module root (``PurePosixPath``
    spells a root-level file's parent ``"."``) → ``"."``.
    """
    return "." if pkg_dir == "." else f"./{pkg_dir}"


def go_report_mutants(report: dict, pkg_dir: str) -> list[tuple[str, dict]]:
    """``(module-relative file, mutant)`` pairs from one gremlins report.

    gremlins reports ``file_name`` relative to the **path argument** it was
    given — ``gremlins unleash ./pkg/token`` reports ``token.go``, not
    ``pkg/token/token.go`` — so the package directory has to be re-attached
    before the report can meet the gate's module-relative changed-line sets.
    Skipping this step would empty every intersection and turn the gate into an
    unconditional pass, so the join is normalised (``PurePosixPath`` collapses
    ``.`` components, which a plain f-string would leave as a ``./`` prefix that
    no changed-file key matches) and :func:`gate_go` proves the result shares
    one spelling with those keys via :func:`go_anchoring_check`.

    Raises :class:`ValueError` on a ``file_name`` that is absolute or contains
    ``..``: both would silently re-point the path outside the package gremlins
    was asked about, and neither can be normalised into a key the gate owns.
    """
    anchored: list[tuple[str, dict]] = []
    for f in report.get("files") or []:
        name = f.get("file_name")
        if not isinstance(name, str) or not name:
            raise ValueError(
                f"gremlins reported a file with no usable file_name ({name!r}) in "
                f"{pkg_dir}; the gate cannot map its mutants onto changed lines."
            )
        parsed = PurePosixPath(name)
        if parsed.is_absolute() or ".." in parsed.parts:
            raise ValueError(
                f"gremlins reported file_name {name!r} in {pkg_dir}: an absolute "
                "path or a '..' segment escapes the package the run was scoped "
                "to, so it cannot be anchored to a module-relative key."
            )
        module_relative = str(PurePosixPath(pkg_dir, parsed))
        anchored.extend((module_relative, m) for m in f.get("mutations") or [])
    return anchored


def go_malformed_mutants(mutants: list[tuple[str, dict]]) -> list[str]:
    """Descriptions of report entries the gate cannot use, for a loud failure.

    The changed-line intersection is now the gate's SOLE scoping mechanism, and
    it is an ``in``-test against a set of ints: ``None in {250}`` and
    ``"250" in {250}`` are both ``False``. So a gremlins field rename or a type
    change would silently drop every in-scope mutant and pass the gate. Every
    other drift mode in this file is loud; this one is too.
    """
    problems: list[str] = []
    for fname, m in mutants:
        bad = [
            f"{field}={m.get(field)!r}"
            for field, ok in (
                ("line", _is_index(m.get("line"), minimum=1)),
                ("column", _is_index(m.get("column"), minimum=0)),
                ("status", isinstance(m.get("status"), str) and bool(m.get("status"))),
                ("type", isinstance(m.get("type"), str) and bool(m.get("type"))),
            )
            if not ok
        ]
        if bad:
            problems.append(f"{fname}: {', '.join(bad)}")
    return problems


def _is_index(value: object, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def go_anchoring_check(
    pkg_dir: str,
    report_paths: set[str],
    package_files: set[str],
    changed_files: set[str],
) -> str | None:
    """``None`` when the report paths and the changed-file keys provably share
    one spelling, otherwise the error to print before exiting 2.

    The scoping intersection is a **string** membership test
    (``fname in lines_by_file``), so it is sound only if both sides spell the
    same file identically. Checking that a path merely *resolves* on disk does
    not establish that — it tests a different predicate. ``pkg/jwt/./x.go``, a
    ``..`` segment, a symlinked package directory and a case-differing path on
    macOS all resolve fine and still match no key, emptying the intersection
    with no diagnostic; the gate would then print "the changed line(s) contain
    no mutatable constructs", i.e. a silent pass.

    So both sides must appear verbatim in a third set the gate builds itself:
    the package's ``.go`` files as listed on disk. Note the asymmetry — a
    changed file with no mutatable construct simply never appears in
    ``report_paths``, which is why the check is *not* "every changed file was
    reported" (that would fail a PR touching, say, a doc-only ``doc.go``).
    """
    stray = sorted(p for p in report_paths if p not in package_files)
    unkeyed = sorted(f for f in changed_files if f not in package_files)
    if not stray and not unkeyed:
        return None
    detail = []
    if stray:
        detail.append(
            "re-anchored gremlins path(s) that are not a .go file listed under "
            f"{pkg_dir}: {', '.join(stray)}"
        )
    if unkeyed:
        detail.append(
            "changed-file key(s) that are not a .go file listed under "
            f"{pkg_dir}: {', '.join(unkeyed)}"
        )
    return (
        f"mutation-security[go]: FAILED — the gate cannot prove its changed-line "
        f"intersection over {pkg_dir} is sound: " + "; ".join(detail) + ". The "
        "intersection is a string match, so a path that resolves to the right "
        "file under a different spelling would silently match nothing and pass "
        "the gate. Fix the anchoring; do not treat this as 'no mutants'."
    )


def go_list_packages(pkg_dir: str) -> list[str] | None:
    """The buildable Go packages under ``pkg_dir``, or ``None`` when there are
    none (the caller fails closed on that).

    gremlins expands its path argument to ``<path>/...`` — its own warning says
    so — and aborts with ``failed to gather coverage: ... exit status 1`` when
    that matches nothing. Asking ``go list`` the same question first costs
    milliseconds and lets the failure name the *path*, which is the thing that
    is actually wrong, instead of pointing at gremlins. The module-wide
    invocation this gate replaced never hit the case, because the go tool skips
    unbuildable directories during pattern expansion.
    """
    prefix = go_path_prefix(pkg_dir)
    res = _run(["go", "list", f"{prefix}/..."], cwd=REPO_ROOT / "go")
    names = [line for line in res.stdout.splitlines() if line.strip()]
    if res.returncode != 0 or not names:
        print(
            f"mutation-security[go]: FAILED — no buildable Go package under "
            f"{prefix}, which holds changed security-surface file(s): "
            f"`go list {prefix}/...` produced nothing. Mutation cannot be run "
            f"there, so the changed lines would go ungated.\n{res.stderr}",
            file=sys.stderr,
        )
        return None
    return names


def run_gremlins(pkg_dir: str) -> dict | None:
    """Run gremlins over one package and return its report, or ``None`` if the
    run did not complete (the caller fails closed on that).

    No ``--diff``: line scoping is the gate's own job (see the module
    docstring). gremlins enumerates and tests every covered mutant in the
    package; the gate decides which of them are in scope.

    A complete report that was written alongside a non-zero exit is *used*, not
    discarded — gremlins exits non-zero for reasons of its own (an efficacy
    threshold, for one) and throwing away the mutants it did produce would turn
    a judgeable run into an opaque one. Only a missing or unparseable report is
    fatal.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out_json = Path(tmp) / "gremlins.json"
        res = _run(
            [
                "gremlins",
                "unleash",
                "--timeout-coefficient",
                str(GO_TIMEOUT_COEFFICIENT),
                "--output",
                str(out_json),
                go_path_prefix(pkg_dir),
            ],
            cwd=REPO_ROOT / "go",
        )
        sys.stdout.write(res.stdout)
        if not out_json.exists():
            print(
                f"mutation-security[go]: FAILED — gremlins run over {pkg_dir} did "
                f"not complete (no report written, exit {res.returncode}):\n"
                f"{res.stderr}",
                file=sys.stderr,
            )
            return None
        try:
            report = json.loads(out_json.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"mutation-security[go]: FAILED — gremlins wrote an unreadable "
                f"report for {pkg_dir} ({exc}); this is tool drift, not a pass.",
                file=sys.stderr,
            )
            return None
        if not isinstance(report, dict):
            print(
                f"mutation-security[go]: FAILED — gremlins report for {pkg_dir} is "
                f"a {type(report).__name__}, not an object; the gate cannot read "
                "it.",
                file=sys.stderr,
            )
            return None
        if res.returncode != 0:
            print(
                f"mutation-security[go]: note — gremlins exited {res.returncode} "
                f"over {pkg_dir} but wrote a complete report; judging the report. "
                f"stderr:\n{res.stderr}"
            )
        return report


def go_package_go_files(pkg_dir: str) -> set[str]:
    """Module-relative ``.go`` files under ``pkg_dir``, as spelled on disk.

    The third set :func:`go_anchoring_check` measures both the gremlins report
    paths and the gate's changed-file keys against. Recursive, because gremlins'
    path argument is recursive.
    """
    root = REPO_ROOT / "go" / pkg_dir
    return {
        str(PurePosixPath(pkg_dir, path.relative_to(root).as_posix()))
        for path in root.rglob("*.go")
        if path.is_file()
    }


def _gate_go_package(
    pkg_dir: str, lines_by_file: dict[str, set[int]]
) -> tuple[list[tuple[str, dict]], int]:
    """One gremlins run, fully validated before its mutants join the pile.

    Returns ``(mutants, 0)`` or ``([], exit_code)``. Every fail-closed guard the
    gate has about *a run* lives here rather than over the concatenation of all
    runs, because each is per-run in nature: gremlins sizes its timeout budget
    from the calling package's baseline, so a package is healthy or broken on
    its own, and a silently-empty package in a multi-package PR must not be
    hidden by a sibling's mutants.
    """
    if go_list_packages(pkg_dir) is None:
        return [], 2
    report = run_gremlins(pkg_dir)
    if report is None:
        return [], 2
    try:
        mutants = go_report_mutants(report, pkg_dir)
    except ValueError as exc:
        print(f"mutation-security[go]: FAILED — {exc}", file=sys.stderr)
        return [], 2

    print(f"mutation-security[go]:   {pkg_dir}: {len(mutants)} mutant(s) enumerated")

    if not mutants:
        # gremlins enumerates every mutant in the package it is pointed at (no
        # scoping flag is passed), so an empty report can only be
        # config/scope/version drift — a Go package demonstrably has mutants.
        print(
            f"mutation-security[go]: FAILED — gremlins enumerated 0 mutants in "
            f"{pkg_dir}, which holds changed security-surface file(s). This is "
            "config/scope/version drift, not a pass: with no mutants to "
            "intersect, that package's changed lines would go ungated.",
            file=sys.stderr,
        )
        return [], 2

    # Health check on this run, before judging anyone's tests. If gremlins tested
    # a meaningful number of mutants here and killed NONE, the tests did not
    # really run — the overwhelmingly likely cause is a per-mutant timeout too
    # small to cover Go's recompilation (see GO_TIMEOUT_COEFFICIENT), which
    # reports every mutant as TIMED OUT. Without this check that misconfiguration
    # is indistinguishable from "your tests are worthless": the gate fails, every
    # survivor offers a paste-ready waiver, and waiving them all silently blinds
    # the gate on well-tested code. Fail as config drift (exit 2) instead, so it
    # can never be waived away. Only KILLED counts as evidence a test ran; see
    # GO_HEALTHY_STATUS.
    tested = [
        m for _f, m in mutants if m.get("status") not in {"SKIPPED", "NOT COVERED"}
    ]
    killed = [m for m in tested if m.get("status") == GO_HEALTHY_STATUS]
    if len(tested) >= GO_MIN_TESTED_FOR_HEALTH_CHECK and not killed:
        statuses = sorted({str(m.get("status")) for m in tested})
        print(
            f"mutation-security[go]: FAILED — gremlins tested {len(tested)} "
            f"mutant(s) in {pkg_dir} and killed none of them (statuses seen: "
            f"{', '.join(statuses)}). A healthy run always kills some. This is "
            f"a broken mutation run, not a test-quality finding — check the "
            f"per-mutant timeout (--timeout-coefficient, currently "
            f"{GO_TIMEOUT_COEFFICIENT}) and the Go toolchain, and do NOT waive "
            f"the survivors.",
            file=sys.stderr,
        )
        return [], 2

    error = go_anchoring_check(
        pkg_dir,
        {fname for fname, _ in mutants},
        go_package_go_files(pkg_dir),
        {f for f in lines_by_file if PurePosixPath(f).is_relative_to(pkg_dir)},
    )
    if error:
        print(error, file=sys.stderr)
        return [], 2
    return mutants, 0


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

    # Paths the go tool never compiles hold no mutants for anyone, and pointing
    # gremlins at their directory only produces "failed to gather coverage".
    # Drop them by name and say so, instead of aborting the whole gate with a
    # message that blames gremlins for a path.
    gatable = [f for f in changed if not go_ignored_path(f)]
    for f in changed:
        if go_ignored_path(f):
            print(
                f"mutation-security[go]: NOT GATED — {f} sits in a path the go "
                "tool skips (a testdata/ directory, or a '_'/'.'-prefixed "
                "component); it is never compiled, so it has no mutants."
            )
    if not gatable:
        print(
            "mutation-security[go]: PASSED — every changed surface file sits in a "
            "go-ignored path; there is no compiled code to mutate."
        )
        return 0

    lines_by_file = {f: changed_line_numbers(base, "go", f) for f in gatable}

    try:
        waivers = load_allowlist(
            _read(GO_ALLOWLIST), GO_ALLOWLIST.name, parse_go_waiver_name
        )
    except ValueError as exc:
        print(f"mutation-security[go]: FAILED — {exc}", file=sys.stderr)
        return 1

    pkg_dirs = go_package_dirs(gatable)
    print(
        f"mutation-security[go]: mutating {len(pkg_dirs)} changed package(s): "
        f"{', '.join(pkg_dirs)}"
    )

    mutants: list[tuple[str, dict]] = []
    for pkg_dir in pkg_dirs:
        pkg_mutants, code = _gate_go_package(pkg_dir, lines_by_file)
        if code:
            return code
        mutants.extend(pkg_mutants)

    malformed = go_malformed_mutants(mutants)
    if malformed:
        print(
            "mutation-security[go]: FAILED — gremlins reported mutant(s) the gate "
            "cannot position, so they could never match a changed line and would "
            "have been silently dropped from the only scoping step this gate has:",
            file=sys.stderr,
        )
        for entry in malformed:
            print(f"  {entry}", file=sys.stderr)
        return 2

    in_scope = [
        (fname, m)
        for fname, m in mutants
        if fname in lines_by_file and m["line"] in lines_by_file[fname]
    ]
    if not in_scope:
        print(
            "mutation-security[go]: PASSED — the changed line(s) contain no "
            f"mutatable constructs ({len(mutants)} mutant(s) enumerated across "
            f"{len(pkg_dirs)} changed package(s); gremlins healthy, anchoring "
            "proven)."
        )
        return 0
    print(
        f"mutation-security[go]: {len(in_scope)}/{len(mutants)} mutant(s) in the "
        "changed package(s) live on the changed line(s)."
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
