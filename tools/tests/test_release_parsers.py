"""Self-test for the scope-routed commit parsers (tools/release_parsers.py).

These parsers decide which release pipeline a commit belongs to, and nothing
else does: the release workflow path-guards `node/**` `spec/**` `infra/**` as a
second line of defence, but NOT `go/**`, `rust/**`, `conformance/**` or
`tools/**`, so for those the scope is the only guard. A scope missing from
``NON_CORE_SCOPES`` publishes a PyPI release of the core library off a commit
that changed nothing shipped — which is how two ``fix(conformance):`` commits
about a token-rotation script cut py-identity-model 3.18.1 with a changelog
that reads like a token-disclosure fix in the library.

The routing had no test at all until that shipped.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_DRIVER = _REPO_ROOT / "tools" / "release_parsers.py"
_spec = importlib.util.spec_from_file_location("release_parsers", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
release_parsers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_parsers)

from semantic_release.commit_parser.token import ParsedCommit  # noqa: E402


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    """A real git repo: the parser builds ``git.Commit`` objects itself.

    A stub object is not enough. When the parser unwraps a squash-merge body it
    constructs fresh ``git.Commit``s from the original, which needs a real repo
    behind it — and squash bodies are precisely how this repo merges, so the
    path that mis-routed 3.18.1 is the one under test.
    """
    from git import Repo

    path = tmp_path_factory.mktemp("release-parsers-repo")
    repo = Repo.init(path)
    with repo.config_writer() as cw:
        cw.set_value("user", "name", "test")
        cw.set_value("user", "email", "test@example.com")
    (path / "seed").write_text("seed\n")
    repo.index.add(["seed"])
    repo.index.commit("chore: seed")
    return repo


def _commit(repo, message: str):
    """Make a real commit carrying ``message`` and return it."""
    path = Path(repo.working_tree_dir)
    marker = path / "marker"
    marker.write_text(message)
    repo.index.add(["marker"])
    return repo.index.commit(message)


def _parse(parser, repo, message: str):
    result = parser.parse(_commit(repo, message))
    return result[0] if isinstance(result, list) else result


def _kept(parser, repo, message: str) -> bool:
    """Whether this pipeline versions from the commit."""
    return isinstance(_parse(parser, repo, message), ParsedCommit)


#: Every scope that must never bump the core Python library, and the tree it
#: owns. Kept as data so adding a scope to NON_CORE_SCOPES without adding it
#: here is visible in review.
NON_CORE = {
    "fastapi": "the fastapi-identity-model package",
    "go": "the Go library",
    "rust": "the Rust crate",
    "node": "the Node library",
    "spec": "the shared conformance vectors",
    "infra": "the shared IdP fixtures",
    "conformance": "the OIDF certification harness — ships nothing",
    "tools": "the repo gates and release machinery — ships nothing",
}


@pytest.fixture
def core():
    return release_parsers.CoreCommitParser()


@pytest.mark.parametrize("scope", sorted(NON_CORE))
@pytest.mark.parametrize("kind", ["feat", "fix", "perf"])
def test_a_non_core_scope_never_bumps_the_core_library(core, repo, scope, kind) -> None:
    assert not _kept(core, repo, f"{kind}({scope}): something in {NON_CORE[scope]}"), (
        f"{kind}({scope}) would cut a py-identity-model release"
    )


def test_the_declared_non_core_scopes_are_exactly_the_ones_under_test() -> None:
    """A scope added to the constant without a case here fails loudly."""
    assert release_parsers.NON_CORE_SCOPES == frozenset(NON_CORE)


@pytest.mark.parametrize(
    "message",
    [
        "fix(token-validation): reject an unsigned token",
        "feat(discovery): add OAuth 2.0 server metadata support",
        "fix: handle a missing kid",
        "perf(jwks): cache the parsed key set",
    ],
)
def test_a_core_commit_still_bumps_the_core_library(core, repo, message) -> None:
    assert _kept(core, repo, message)


def test_an_unscoped_commit_touching_a_sibling_tree_still_bumps_the_core(
    core, repo
) -> None:
    """The routing is scope-based, not path-based — the docstring's own warning."""
    assert _kept(core, repo, "fix: correct a bounds check in the Go validator")


@pytest.mark.parametrize(
    ("parser_name", "scope"),
    [
        ("FastapiCommitParser", "fastapi"),
        ("GoCommitParser", "go"),
        ("RustCommitParser", "rust"),
    ],
)
def test_a_sibling_pipeline_keeps_only_its_own_scope(repo, parser_name, scope) -> None:
    parser = getattr(release_parsers, parser_name)()
    assert _kept(parser, repo, f"feat({scope}): a change on this track")
    for other in sorted(set(NON_CORE) - {scope}):
        assert not _kept(parser, repo, f"feat({other}): a change on another track")
    assert not _kept(parser, repo, "fix(token-validation): a core change")
    assert not _kept(parser, repo, "fix: an unscoped core change")


def test_conformance_is_routed_away_from_the_core(core, repo) -> None:
    """The exact commits that cut 3.18.1, as a regression case.

    Both changed `conformance/scripts/rotate_conformance_token.py`. Neither
    touches shipped library code, and their subjects — read in the published
    changelog of an auth library — describe a token disclosure.
    """
    assert not _kept(
        core, repo, "fix(conformance): Stop the rotation script disclosing the token"
    )
    assert not _kept(
        core,
        repo,
        "fix(conformance): Restore the no-token-output rule this PR had broken",
    )


def test_the_squash_body_that_cut_3_18_1_is_routed_away_from_the_core(
    core, repo
) -> None:
    """The failure as it actually happened, end to end.

    identity-model squash-merges with COMMIT_MESSAGES, and python-semantic-release
    unwraps the squash *body* into individual commits — so the scope on each
    bullet is what routes it, not the PR title. This body cut py-identity-model
    3.18.1 off a PR that changed only a token-rotation script.
    """
    body = (
        "chore(infra): retire the dead HCP Vault Secrets path and SonarCloud leftovers (#659)\n"
        "\n"
        "* fix(conformance): Stop the rotation script disclosing the token\n"
        "\n"
        "* fix(conformance): Restore the no-token-output rule this PR had broken\n"
    )
    results = core.parse(_commit(repo, body))
    if not isinstance(results, list):
        results = [results]
    kept = [r for r in results if isinstance(r, ParsedCommit)]
    assert kept == [], (
        f"these bullets would cut a py-identity-model release: "
        f"{[r.descriptions[0] for r in kept]}"
    )
