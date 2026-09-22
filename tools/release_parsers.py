"""Scope-filtered commit parsers for the monorepo's release pipelines.

The repo hosts several independently versioned distributions, each released by
its own python-semantic-release config on its own tag cadence:

- the core ``py-identity-model`` library — root config, ``py-v{version}`` tags;
- the ``fastapi-identity-model`` package —
  ``packages/fastapi-identity-model/pyproject.toml``,
  ``fastapi-identity-model-v{version}`` tags;
- the Go library — ``tools/semantic-release-go.toml``, ``go/v{version}`` tags
  (the subdir-module format ``go get`` requires; version comes from the tag,
  there is no version file); and
- the Rust crate ``rs-identity-model`` — ``tools/semantic-release-rust.toml``,
  ``rust-v{version}`` tags, versioning ``rust/Cargo.toml``.

python-semantic-release has no native per-package commit routing — every
parsed ``feat``/``fix``/``perf`` commit drives whichever pipeline parses it.
These parsers split the commit stream by conventional-commit scope so each
pipeline only sees its own history:

- :class:`CoreCommitParser` (the Python ``py-identity-model`` pipeline) drops
  every commit scoped to another release track — the ``fastapi`` package and
  the sibling native libraries ``go`` / ``rust`` / ``node`` and the shared
  ``spec`` / ``infra`` — so e.g. ``feat(go): ...`` or ``feat(fastapi): ...``
  never bumps the Python library.
- :class:`FastapiCommitParser`, :class:`GoCommitParser` and
  :class:`RustCommitParser` (the fastapi / Go / Rust pipelines) each keep ONLY
  their own ``(fastapi)`` / ``(go)`` / ``(rust)`` scope and drop everything
  else, including the core history.

The split is scope-based, not path-based: an unscoped ``fix:`` that touches
only ``go/`` still bumps the core. Scoping cross-track commits (``(fastapi)``,
``(go)``, ``(rust)``, ``(spec)``, ``(infra)``, ``(node)``, ``(conformance)``,
``(tools)``, ``(ci)``) is therefore
load-bearing — see CLAUDE.md "Workspace Packages". The release workflow also
path-guards on those directories as a second line of defence.
"""

from __future__ import annotations

from semantic_release.commit_parser.conventional import ConventionalCommitParser
from semantic_release.commit_parser.token import (
    ParsedCommit,
    ParseError,
    ParseResult,
)


PACKAGE_SCOPE = "fastapi"

#: Scopes that belong to a release track OTHER than the core Python library:
#: the fastapi package, the Go/Rust/Node native libraries, the shared
#: spec/infra, and the repo-only trees that ship nothing — ``conformance/``
#: (the OIDF certification harness) and ``tools/`` (the gates and release
#: machinery). A commit carrying one of these must not bump py-identity-model.
#:
#: ``conformance`` was missing, and it is not a hypothetical: two
#: ``fix(conformance):`` commits about a token-rotation *script* cut
#: py-identity-model 3.18.1, whose changelog then read "Stop the rotation
#: script disclosing the token" under Bug Fixes — in the published changelog
#: of an auth library, where it looks like a token-disclosure fix in the
#: library itself. Nothing in either commit touches shipped code.
#:
#: ``ci`` was missing too, and it repeated the incident verbatim:
#: ``fix(ci): gate the @claude workflow on the acting user`` (#739) cut
#: py-identity-model 4.0.1, whose changelog reads "Bug Fixes — ci: Gate the
#: @claude workflow…" — a GitHub Actions trigger condition published to PyPI
#: as a bug fix in an auth library. ``.github/**`` is deliberately absent from
#: the release workflow's ``paths-ignore`` (the Go and Rust versioners must run
#: on workflow-only pushes), so for a workflow change the scope is the ONLY
#: guard. Workflow changes should carry ``ci:`` as the conventional *type*,
#: which no pipeline versions from; this entry is the backstop for when one
#: carries ``ci`` as the scope instead.
#: Every entry is lower-case; membership is tested against a case-folded scope.
#: `fix(CI):` is the same change as `fix(ci):` and must route the same way —
#: `ci` is an acronym people capitalise, and an exact-match frozenset let
#: `fix(CI):` walk straight past this guard and cut a release.
NON_CORE_SCOPES = frozenset(
    {
        PACKAGE_SCOPE,
        # sibling release tracks
        "go",
        "rust",
        "node",
        # shared, versioned by nobody
        "spec",
        "infra",
        # repo-only trees that ship nothing in any wheel
        "conformance",
        "tools",
        "ci",
        "claude",
        "release",
        "deps",
        "docs",
        "hooks",
        "matrix",
        "harness",
        "test",
        "tests",
        "integration",
        "keycloak",
    }
)


def _is_scope_commit(result: ParseResult, scope: str) -> bool:
    """Whether a parse result is scoped to ``scope``.

    Case-folded for the same reason as :func:`_is_non_core_commit`: a
    `feat(Rust):` must version the Rust crate, not be dropped as unrecognised.
    """
    if not isinstance(result, ParsedCommit):
        return False
    return (result.scope or "").casefold() == scope.casefold()


def _is_non_core_commit(result: ParseResult) -> bool:
    """Whether a parse result is scoped to a non-core release track.

    Case-folded: the upstream ConventionalCommitParser does not normalise the
    scope (verified against 10.6.2), so `fix(CI):` and `fix(Ci):` reach here
    spelled as written. Matching them exactly would leave the guard defeatable
    by the shift key.
    """
    if not isinstance(result, ParsedCommit):
        return False
    return (result.scope or "").casefold() in NON_CORE_SCOPES


class _ScopeRoutedParser(ConventionalCommitParser):
    """Conventional parser that routes commits to one release pipeline."""

    def _keep(self, result: ParseResult) -> bool:
        """Subclasses decide whether to keep a (non-error) parsed commit."""
        raise NotImplementedError

    def _route(self, result: ParseResult) -> ParseResult:
        if isinstance(result, ParseError):
            return result
        if self._keep(result):
            return result
        return ParseError(
            commit=result.commit,
            error="commit belongs to another release pipeline; ignored here",
        )

    def parse(self, commit) -> ParseResult | list[ParseResult]:
        parsed = super().parse(commit)
        if isinstance(parsed, list):
            return [self._route(result) for result in parsed]
        return self._route(parsed)


class CoreCommitParser(_ScopeRoutedParser):
    """Python ``py-identity-model`` pipeline: drops non-core-scoped commits."""

    def _keep(self, result: ParseResult) -> bool:
        return not _is_non_core_commit(result)


class _SingleScopeParser(_ScopeRoutedParser):
    """Pipeline that keeps ONLY commits carrying its own ``SCOPE``.

    Each sibling release track (the fastapi package, the Go library, the Rust
    crate) versions off its own conventional-commit scope, so every other
    commit — including the core ``py-identity-model`` history — is dropped.
    """

    #: The single conventional-commit scope this pipeline versions from.
    SCOPE: str = ""

    def _keep(self, result: ParseResult) -> bool:
        return _is_scope_commit(result, self.SCOPE)


class FastapiCommitParser(_SingleScopeParser):
    """``fastapi-identity-model`` pipeline: keeps ONLY ``(fastapi)`` commits."""

    SCOPE = PACKAGE_SCOPE


class GoCommitParser(_SingleScopeParser):
    """Go ``identity-model/go`` pipeline: keeps ONLY ``(go)`` commits."""

    SCOPE = "go"


class RustCommitParser(_SingleScopeParser):
    """Rust ``rs-identity-model`` pipeline: keeps ONLY ``(rust)`` commits."""

    SCOPE = "rust"
