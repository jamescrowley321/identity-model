"""The release tooling's pins must agree everywhere, and bind where tools/ runs.

`python-semantic-release` cuts every release in this repo, and PSR declares a
loose `gitpython~=3.0`, so an unconstrained resolve can land on any GitPython.
GitPython <=3.1.58 carries a critical RCE advisory (GHSA-284h-m62q-gf8w) and two
highs, all first patched in 3.1.59 — hence the `gitpython>=3.1.59` floor on every
`uvx` invocation in `.github/workflows/release.yml`.

That bound used to be the ceiling `<3.1.60`, because PSR 10.6.1 called
`Actor.name_email_regex` and GitPython removed it in 3.1.60. PSR 10.6.2 no longer
references the attribute and GitPython restored it (deprecated) by 3.1.62, so the
ceiling was obsolete — and while it stood it held GitPython inside the vulnerable
range.

The same pins have to bind `make test-tools`, because the drivers under tools/
are *release* code: `tools/tests/test_release_parsers.py` builds real
`git.Commit` objects, so running it against a different GitPython exercises a
resolution the release pipeline does not use. When the Makefile passed the pin
inline per-recipe-line with no GitPython bound at all, it resolved 3.1.62 while
the release jobs were on <=3.1.59, and the version was repeated in eight places
across the repo with nothing tying them together.

The Makefile's `PSR_TOOLING` is now the single definition, and these tests are
what stop the other seven copies drifting from it. It is deliberately not a uv
dependency group: PSR requires `click<8.5.0,~=8.1.0`, so locking it would pull
the whole py/ resolution down to click 8.1.x (CVE-2026-7246) for flask, uvicorn,
mkdocs and mutmut alike.
"""

from __future__ import annotations

import re
from pathlib import Path

import git
import pytest
import yaml
from packaging.specifiers import SpecifierSet
from packaging.version import Version


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MAKEFILE = _REPO_ROOT / "Makefile"
_RELEASE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"
_SR_CONFIGS = (
    _REPO_ROOT / "tools" / "semantic-release-go.toml",
    _REPO_ROOT / "tools" / "semantic-release-rust.toml",
)

# `--from "python-semantic-release==10.6.1"` and the unquoted form both appear.
_PSR_PIN = re.compile(r"""python-semantic-release\s*==\s*([0-9][^"'\s\\]*)""")
_GITPYTHON_PIN = re.compile(
    r"""gitpython\s*(>=|<=|==|<|>)\s*([0-9][^"',\s\\]*)""", re.IGNORECASE
)
#: Matches a `uvx` invocation of PSR inside one shell command, however it is
#: wrapped. A previous line-based regex missed any invocation split across lines
#: with a backslash — and because the bound check only inspects what it matched,
#: a reformatted job would have escaped it silently while the others still
#: matched. Line continuations are folded away before this is applied.
_UVX_PSR = re.compile(r"uvx\s[^;&|]*?python-semantic-release", re.DOTALL)
_LINE_CONTINUATION = re.compile(r"\\\s*\n\s*")


def _run_blocks(workflow_text: str) -> list[str]:
    """Every `run:` script in the workflow, as whole commands.

    Parsed as YAML rather than scanned line by line, so a `run:` block is read
    as the shell script it is. Line continuations are folded, so an invocation
    wrapped across several lines is one command here — which is the point: the
    checks below inspect what they match, so anything they fail to match is
    silently exempt from them.
    """
    doc = yaml.safe_load(workflow_text)
    blocks: list[str] = []
    for job in (doc.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if isinstance(run, str):
                blocks.append(_LINE_CONTINUATION.sub(" ", run))
    return blocks


@pytest.fixture(scope="module")
def psr_tooling() -> str:
    """The Makefile's `PSR_TOOLING` — the single definition of the release tooling."""
    body = _MAKEFILE.read_text()
    match = re.search(r"^PSR_TOOLING\s*:?=\s*(.+)$", body, re.MULTILINE)
    assert match is not None, (
        "Makefile lost its PSR_TOOLING definition. `make test-tools` depends on "
        "it, and it is the single source of truth these tests compare against."
    )
    return match.group(1)


@pytest.fixture(scope="module")
def psr_pin(psr_tooling: str) -> str:
    found = _PSR_PIN.findall(psr_tooling)
    assert len(found) == 1, (
        f"PSR_TOOLING must pin exactly one python-semantic-release version, "
        f"got {found}: the release workflow pins one and these must be comparable."
    )
    return found[0]


@pytest.fixture(scope="module")
def gitpython_specifier(psr_tooling: str) -> SpecifierSet:
    found = _GITPYTHON_PIN.findall(psr_tooling)
    assert found, (
        "PSR_TOOLING must bound GitPython. Unbounded, PSR's loose `gitpython~=3.0` "
        "admits <=3.1.58, which carries a critical RCE advisory."
    )
    return SpecifierSet(",".join(f"{op}{ver}" for op, ver in found))


class TestTheEnvironmentToolsTestsRunIn:
    def test_the_running_gitpython_satisfies_the_pin(self, gitpython_specifier):
        """The interpreter running this suite must match the release job's resolve.

        With a floor rather than a ceiling, this also means the tools suite can
        never run on a GitPython carrying the advisories the floor exists for.
        """
        assert Version(git.__version__) in gitpython_specifier, (
            f"tools/tests/ is running GitPython {git.__version__}, which violates "
            f"the release pipeline's `gitpython{gitpython_specifier}`. Run it via "
            "`make test-tools` (or `uv run --project py --group tools`), not with "
            "an ad-hoc `--with` that resolves GitPython freely."
        )

    def test_the_running_psr_matches_the_pin(self, psr_pin):
        import semantic_release

        assert semantic_release.__version__ == psr_pin, (
            f"tools/tests/ is running python-semantic-release "
            f"{semantic_release.__version__}, but PSR_TOOLING pins {psr_pin}."
        )


class TestTheMakefileUsesTheSingleDefinition:
    @pytest.fixture(scope="class")
    def test_tools_recipe(self) -> str:
        body = _MAKEFILE.read_text()
        match = re.search(r"^test-tools:.*\n((?:\t.*\n)+)", body, re.MULTILINE)
        assert match is not None, "the `test-tools` target vanished from the Makefile"
        return match.group(1)

    def test_every_line_uses_the_shared_definition(self, test_tools_recipe):
        lines = [ln for ln in test_tools_recipe.splitlines() if ln.strip()]
        assert lines, "the `test-tools` recipe is empty"
        for line in lines:
            assert "$(PSR_TOOLING)" in line, (
                f"`test-tools` line does not use $(PSR_TOOLING): {line.strip()}"
            )

    def test_no_second_copy_of_the_pin_is_introduced(self, test_tools_recipe):
        """Two copies drift; that is how the Makefile lost the GitPython bound."""
        assert not _PSR_PIN.search(test_tools_recipe), (
            "the `test-tools` recipe pins python-semantic-release inline again. "
            "PSR_TOOLING is the one definition — use $(PSR_TOOLING)."
        )

    def test_the_makefile_defines_the_pin_exactly_once(self):
        body = _MAKEFILE.read_text()
        assert len(_PSR_PIN.findall(body)) == 1, (
            "python-semantic-release is pinned more than once in the Makefile; "
            "PSR_TOOLING must be the only definition."
        )


class TestTheWorkflowAgreesWithTheMakefile:
    @pytest.fixture(scope="class")
    def workflow(self) -> str:
        return _RELEASE_WORKFLOW.read_text()

    @pytest.fixture(scope="class")
    def psr_commands(self, workflow) -> list[str]:
        """Every shell command in release.yml that runs PSR through uvx."""
        return [b for b in _run_blocks(workflow) if _UVX_PSR.search(b)]

    def test_the_workflow_still_invokes_psr(self, psr_commands):
        """Guards the rest of the class against passing vacuously."""
        assert psr_commands, (
            "release.yml no longer runs python-semantic-release via uvx; these "
            "pin-parity assertions would pass vacuously — update them."
        )

    def test_every_psr_invocation_is_accounted_for(self, workflow, psr_commands):
        """Nothing mentioning PSR may sit outside the set the checks inspect.

        The checks below only constrain `psr_commands`. If a `run:` block names
        PSR but this fixture does not classify it as a uvx invocation, that block
        would be exempt from every assertion without anyone noticing.
        """
        mentions = [b for b in _run_blocks(workflow) if "python-semantic-release" in b]
        unmatched = [b.strip()[:120] for b in mentions if b not in psr_commands]
        assert not unmatched, (
            "these release.yml run-blocks mention python-semantic-release but were "
            f"not recognised as uvx invocations, so nothing checks them: {unmatched}"
        )

    def test_every_psr_pin_matches_the_makefile(self, psr_commands, psr_pin):
        found = [v for cmd in psr_commands for v in _PSR_PIN.findall(cmd)]
        assert found, "release.yml pins no python-semantic-release version"
        drifted = sorted({v for v in found if v != psr_pin})
        assert not drifted, (
            f"release.yml pins python-semantic-release {drifted}, but PSR_TOOLING "
            f"pins {psr_pin}. `make test-tools` would validate the release parsers "
            "against a PSR the release job never runs."
        )

    def test_every_gitpython_pin_matches_the_makefile(
        self, psr_commands, gitpython_specifier
    ):
        found = [v for cmd in psr_commands for v in _GITPYTHON_PIN.findall(cmd)]
        assert found, "release.yml no longer constrains GitPython"
        expected = {(sp.operator, sp.version) for sp in gitpython_specifier}
        drifted = sorted(
            {f"{op}{ver}" for op, ver in found if (op, ver) not in expected}
        )
        assert not drifted, (
            f"release.yml constrains GitPython {drifted}, but PSR_TOOLING says "
            f"{gitpython_specifier}."
        )

    def test_no_psr_invocation_omits_the_gitpython_bound(self, psr_commands):
        """One unconstrained job is enough to resolve a vulnerable GitPython."""
        unconstrained = [
            cmd.strip()[:120] for cmd in psr_commands if not _GITPYTHON_PIN.search(cmd)
        ]
        assert not unconstrained, (
            "these release.yml invocations run python-semantic-release without the "
            f"GitPython bound, so they resolve it freely: {unconstrained}"
        )


class TestTheSemanticReleaseConfigsDocumentTheSamePins:
    """The Go/Rust configs carry the invocation in a header comment; it is what a
    human copies when running a release by hand, so it drifts silently."""

    @pytest.mark.parametrize("config", _SR_CONFIGS, ids=lambda p: p.name)
    def test_the_documented_invocation_matches_the_makefile(
        self, config, psr_pin, gitpython_specifier
    ):
        text = config.read_text()
        psr_found = _PSR_PIN.findall(text)
        assert psr_found, f"{config.name} documents no PSR version to check"
        assert set(psr_found) == {psr_pin}, (
            f"{config.name} documents python-semantic-release {sorted(set(psr_found))}, "
            f"but PSR_TOOLING pins {psr_pin}."
        )
        expected = {(s.operator, s.version) for s in gitpython_specifier}
        gp_found = _GITPYTHON_PIN.findall(text)
        assert gp_found, (
            f"{config.name} documents a PSR invocation with no GitPython bound; "
            "copying it by hand resolves GitPython freely, and <=3.1.58 carries "
            "a critical RCE advisory."
        )
        assert set(gp_found) <= expected, (
            f"{config.name} documents GitPython "
            f"{sorted({f'{o}{v}' for o, v in gp_found})}, but PSR_TOOLING says "
            f"{gitpython_specifier}."
        )
