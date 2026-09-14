"""The release tooling's pins must agree everywhere, and bind where tools/ runs.

`python-semantic-release` cuts every release in this repo, and PSR 10.6.1
declares a loose `gitpython~=3.0`. GitPython 3.1.60 removed an API PSR calls, so
an unconstrained resolve crashes the release job — hence the `gitpython<3.1.60`
ceiling on every `uvx` invocation in `.github/workflows/release.yml`.

The same pins have to bind `make test-tools`, because the drivers under tools/
are *release* code: `tools/tests/test_release_parsers.py` builds real
`git.Commit` objects, so running it against an unconstrained GitPython exercises
a resolution the release pipeline deliberately excludes. That is exactly what
happened when `make test-tools` passed the pin inline with `--with` and no
ceiling: it tested the parsers at GitPython 3.1.62, above the release job's own
limit, with nothing locked and the version repeated in eight places.

These tests are the gate on that. `test_the_running_gitpython_satisfies_the_pin`
is the behavioural one — it reads the interpreter actually running the tools
suite, and fails under the old inline `--with` form.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import git
import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version


_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO_ROOT / "py" / "pyproject.toml"
_MAKEFILE = _REPO_ROOT / "Makefile"
_RELEASE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"
_SR_CONFIGS = (
    _REPO_ROOT / "tools" / "semantic-release-go.toml",
    _REPO_ROOT / "tools" / "semantic-release-rust.toml",
)

# `--from "python-semantic-release==10.6.1"` and the unquoted form both appear.
_PSR_PIN = re.compile(r"""python-semantic-release\s*==\s*([0-9][^"'\s\\]*)""")
_GITPYTHON_PIN = re.compile(
    r"""gitpython\s*(<=?|==)\s*([0-9][^"'\s\\]*)""", re.IGNORECASE
)
# Every uvx line that runs PSR, so each can be checked for the ceiling.
_UVX_PSR_LINE = re.compile(r"^.*uvx\s+.*python-semantic-release.*$", re.MULTILINE)


@pytest.fixture(scope="module")
def tools_group() -> list[Requirement]:
    """The `tools` dependency group — the single source of truth for both pins."""
    groups = tomllib.loads(_PYPROJECT.read_text())["dependency-groups"]
    assert "tools" in groups, (
        "py/pyproject.toml lost its `tools` dependency group. `make test-tools` "
        "depends on it; do not reintroduce an inline `--with` pin in the Makefile."
    )
    return [Requirement(spec) for spec in groups["tools"]]


@pytest.fixture(scope="module")
def psr_pin(tools_group: list[Requirement]) -> str:
    (req,) = [r for r in tools_group if r.name == "python-semantic-release"]
    (spec,) = list(req.specifier)
    assert spec.operator == "==", (
        f"python-semantic-release must be pinned exactly, not {req.specifier}: the "
        "release workflow pins an exact version and these must be comparable."
    )
    return spec.version


@pytest.fixture(scope="module")
def gitpython_specifier(tools_group: list[Requirement]) -> SpecifierSet:
    (req,) = [r for r in tools_group if r.name.lower() == "gitpython"]
    assert str(req.specifier), "GitPython must carry the release job's ceiling."
    return req.specifier


class TestTheEnvironmentToolsTestsRunIn:
    def test_the_running_gitpython_satisfies_the_pin(self, gitpython_specifier):
        """The interpreter running this suite must match the release job's resolve.

        This is the check the inline `--with` form failed: it resolved GitPython
        3.1.62, above the ceiling every release invocation carries.
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
            f"{semantic_release.__version__}, but the `tools` group pins {psr_pin}."
        )


class TestTheMakefileUsesTheLockedGroup:
    @pytest.fixture(scope="class")
    def test_tools_recipe(self) -> str:
        body = _MAKEFILE.read_text()
        match = re.search(r"^test-tools:.*\n((?:\t.*\n)+)", body, re.MULTILINE)
        assert match is not None, "the `test-tools` target vanished from the Makefile"
        return match.group(1)

    def test_every_line_selects_the_tools_group(self, test_tools_recipe):
        lines = [ln for ln in test_tools_recipe.splitlines() if ln.strip()]
        assert lines, "the `test-tools` recipe is empty"
        for line in lines:
            assert "--group tools" in line, (
                f"`test-tools` line does not select the locked group: {line.strip()}"
            )

    def test_no_inline_pin_is_reintroduced(self, test_tools_recipe):
        """An inline `--with` is unlocked, unseen by dependabot, and drifts."""
        assert "--with" not in test_tools_recipe, (
            "`test-tools` passes a dependency inline again. Put it in the `tools` "
            "dependency group in py/pyproject.toml so uv.lock pins its closure."
        )

    def test_the_makefile_pins_no_psr_version_of_its_own(self):
        assert not _PSR_PIN.search(_MAKEFILE.read_text()), (
            "the Makefile carries its own python-semantic-release pin again; the "
            "`tools` dependency group is the only place that version belongs."
        )


class TestTheWorkflowAgreesWithTheGroup:
    @pytest.fixture(scope="class")
    def workflow(self) -> str:
        return _RELEASE_WORKFLOW.read_text()

    def test_the_workflow_still_invokes_psr(self, workflow):
        """Guards the rest of the class against passing vacuously."""
        assert _UVX_PSR_LINE.findall(workflow), (
            "release.yml no longer runs python-semantic-release via uvx; these "
            "pin-parity assertions would pass vacuously — update them."
        )

    def test_every_psr_pin_matches_the_group(self, workflow, psr_pin):
        found = _PSR_PIN.findall(workflow)
        assert found, "release.yml pins no python-semantic-release version"
        drifted = sorted({v for v in found if v != psr_pin})
        assert not drifted, (
            f"release.yml pins python-semantic-release {drifted}, but the `tools` "
            f"group pins {psr_pin}. `make test-tools` would validate the release "
            "parsers against a PSR the release job never runs."
        )

    def test_every_gitpython_pin_matches_the_group(self, workflow, gitpython_specifier):
        found = _GITPYTHON_PIN.findall(workflow)
        assert found, "release.yml no longer constrains GitPython"
        expected = {(s.operator, s.version) for s in gitpython_specifier}
        drifted = sorted(
            {f"{op}{ver}" for op, ver in found if (op, ver) not in expected}
        )
        assert not drifted, (
            f"release.yml constrains GitPython {drifted}, but the `tools` group "
            f"says {gitpython_specifier}."
        )

    def test_no_psr_invocation_omits_the_gitpython_ceiling(self, workflow):
        """A single unconstrained job is enough to break the release."""
        unconstrained = [
            line.strip()
            for line in _UVX_PSR_LINE.findall(workflow)
            if not _GITPYTHON_PIN.search(line)
        ]
        assert not unconstrained, (
            "these release.yml invocations run python-semantic-release without the "
            f"GitPython ceiling, so they resolve it freely: {unconstrained}"
        )


class TestTheSemanticReleaseConfigsDocumentTheSamePins:
    """The Go/Rust configs carry the invocation in a header comment; it is what a
    human copies when running a release by hand, so it drifts silently."""

    @pytest.mark.parametrize("config", _SR_CONFIGS, ids=lambda p: p.name)
    def test_the_documented_invocation_matches_the_group(
        self, config, psr_pin, gitpython_specifier
    ):
        text = config.read_text()
        psr_found = _PSR_PIN.findall(text)
        assert psr_found, f"{config.name} documents no PSR version to check"
        assert set(psr_found) == {psr_pin}, (
            f"{config.name} documents python-semantic-release {sorted(set(psr_found))}, "
            f"but the `tools` group pins {psr_pin}."
        )
        expected = {(s.operator, s.version) for s in gitpython_specifier}
        gp_found = _GITPYTHON_PIN.findall(text)
        assert gp_found, (
            f"{config.name} documents a PSR invocation with no GitPython ceiling; "
            "copying it by hand resolves GitPython freely and breaks the release."
        )
        assert set(gp_found) <= expected, (
            f"{config.name} documents GitPython "
            f"{sorted({f'{o}{v}' for o, v in gp_found})}, but the `tools` group says "
            f"{gitpython_specifier}."
        )
