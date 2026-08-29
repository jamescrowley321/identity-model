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
``(go)``, ``(rust)``, ``(spec)``, ``(infra)``, ``(node)``) is therefore
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
#: the fastapi package, the Go/Rust/Node native libraries, and the shared
#: spec/infra. A commit carrying one of these must not bump py-identity-model.
NON_CORE_SCOPES = frozenset({PACKAGE_SCOPE, "go", "rust", "node", "spec", "infra"})


def _is_scope_commit(result: ParseResult, scope: str) -> bool:
    """Whether a parse result is scoped to ``scope``."""
    return isinstance(result, ParsedCommit) and result.scope == scope


def _is_non_core_commit(result: ParseResult) -> bool:
    """Whether a parse result is scoped to a non-core release track."""
    return isinstance(result, ParsedCommit) and result.scope in NON_CORE_SCOPES


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
