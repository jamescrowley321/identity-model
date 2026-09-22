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
the whole py/ resolution down to click 8.1.x for flask, uvicorn, mkdocs and
mutmut alike — a range covered by GHSA-47fr-3ffg-hgmw / CVE-2026-7246
(click.edit() command injection, fixed in 8.3.3; disputed by Pallets, still
carried by the advisory databases the scanners read).
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import git
import pytest
import yaml
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MAKEFILE = _REPO_ROOT / "Makefile"
_RELEASE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"
_SR_CONFIGS = (
    _REPO_ROOT / "tools" / "semantic-release-go.toml",
    _REPO_ROOT / "tools" / "semantic-release-rust.toml",
)

#: A pinned PSR version as it appears in raw TEXT. Used only where there is no
#: command to tokenise: counting copies in the Makefile, and reading the
#: invocation the semantic-release TOML headers document for humans to copy.
_PSR_PIN = re.compile(r"""python-semantic-release\s*==\s*([0-9][^"'\s\\]*)""")

#: A `\` line continuation, folded before anything is tokenised.
_LINE_CONTINUATION = re.compile(r"\\\s*\n\s*")

#: Shell operators that end one command and begin the next.
_COMMAND_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "(", ")"})

#: The one GitPython mention in prose that is NOT a claim about this pipeline:
#: PSR's own loose declaration, quoted in several jobs while explaining why the
#: floor exists. Every other `gitpython<op>` in a comment is a statement about
#: what the job below it does, and is checked.
_UPSTREAM_LITERAL = SpecifierSet("~=3.0")


def _commands(script: str) -> list[list[str]]:
    """A shell script as the list of commands a shell would actually run.

    Tokenised with `shlex` rather than scanned with regexes, because every gap
    this replaced came from reading the text instead of the commands:

    * A bound written `gitpython>=3.1.59, <3.1.60` -- legal PEP 508, and the
      conventional spacing -- was captured as `>=3.1.59,` by a character class
      that stopped at whitespace. `packaging` then discarded the empty trailing
      segment, so the truncated bound compared EQUAL to `>=3.1.59` and a
      ceiling vanished from both sides of the parity check at once.
    * `... semantic-release version  # floor gitpython>=3.1.59` counted as a
      bound, because only whole-line comments were stripped. bash discards
      everything from the `#`, so the job ran PSR unbounded while the gate read
      the comment as the constraint -- in a job holding RELEASE_TOKEN.
    * A `run:` block holding two PSR calls passed if EITHER carried the bound,
      because the check searched the whole block. Commands are now individual.

    Continuations are folded first, so a wrapped invocation is one command.
    Newlines then separate commands, and `shlex` in POSIX mode drops comments
    exactly where bash does -- including a `#` that is inside quotes and
    therefore not a comment at all.

    A script that cannot be tokenised raises rather than returning nothing: a
    block this function fails to read would otherwise be exempt from every
    check below it, silently, which is the failure mode the whole module is
    about.
    """
    commands: list[list[str]] = []
    for line in _LINE_CONTINUATION.sub(" ", script).splitlines():
        if not line.strip():
            continue
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError as exc:
            raise AssertionError(
                f"could not tokenise a release.yml command, so nothing would "
                f"check it: {line.strip()[:120]!r} ({exc})"
            ) from exc
        current: list[str] = []
        for token in tokens:
            if token in _COMMAND_SEPARATORS:
                if current:
                    commands.append(current)
                    current = []
            else:
                current.append(token)
        if current:
            commands.append(current)
    return commands


def _run_blocks(workflow_text: str) -> list[str]:
    """Every `run:` script in the workflow, as written."""
    doc = yaml.safe_load(workflow_text)
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        return []
    blocks: list[str] = []
    for job in jobs.values():
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(steps, list):
            continue
        for step in steps:
            run = step.get("run") if isinstance(step, dict) else None
            if isinstance(run, str):
                blocks.append(run)
    return blocks


def _workflow_commands(workflow_text: str) -> list[list[str]]:
    """Every command in every `run:` block."""
    return [cmd for block in _run_blocks(workflow_text) for cmd in _commands(block)]


#: The distribution whose invocations this file polices, as written everywhere.
_PSR_NAME = "python-semantic-release"


def _names_match(left: str, right: str) -> bool:
    """Whether two distribution names are the same distribution (PEP 503).

    Package names are case-insensitive and treat runs of `-`, `_` and `.` as
    equivalent, so `Python-Semantic-Release`, `python_semantic_release` and
    `python-semantic-release` all install the same thing. Comparing them with
    `==` meant a capitalised `--from Python-Semantic-Release` was not classified
    as a PSR invocation, and therefore was never checked for the GitPython
    floor -- while the other, correctly spelled invocations kept the
    "the workflow still invokes PSR" guard green, so nothing looked wrong.

    `_bound_for` already lowercased; only this comparison did not. One of the
    two being normalised is what made it survive review.
    """
    return canonicalize_name(left) == canonicalize_name(right)


#: A shell expansion in a token: `$VAR`, `${VAR}`, `$(cmd)` or a backtick.
#: Any of these means the value this file reads is NOT the value uvx installs.
_SHELL_EXPANSION = re.compile(r"[$`]")


def _is_shell_expanded(token: str) -> bool:
    """Whether `token`'s real value is decided at run time, not written here.

    Every assertion in this file reads the workflow as text. A requirement
    written `--from "$PSR_REQ"` has no pin to read: the token does not parse as
    a requirement, so the command was not recognised as a PSR invocation and
    every check simply skipped it — while the other, literal invocations kept
    the vacuity guard green. Unreadable must fail, not pass.
    """
    return bool(_SHELL_EXPANSION.search(token))


def _mentions_psr(token: str) -> bool:
    """Whether `token` names python-semantic-release, however it is spelled.

    The accounting check is the backstop for everything the tokeniser misses,
    so it must not itself be defeated by capitalisation. It was: a literal
    `"python-semantic-release" in token` let `Python-Semantic-Release` through
    both this check and `_is_uvx_psr`, and an unbounded GitPython alongside it
    then passed the whole suite green.
    """
    parsed = _requirement(token)
    if parsed is not None:
        return _names_match(parsed.name, _PSR_NAME)
    # Not a requirement (a bare `semantic-release` subcommand, a path, a flag
    # value): fall back to a normalised substring so a mention still counts.
    return canonicalize_name(_PSR_NAME) in canonicalize_name(token)


def _requirement(token: str) -> Requirement | None:
    """`token` as a PEP 508 requirement, or None if it is not one."""
    try:
        return Requirement(token)
    except InvalidRequirement:
        return None


#: The uvx flags whose value is a requirement uvx will install.
_REQUIREMENT_FLAGS = ("--from", "--with")


def _uvx_requirement_tokens(command: list[str]) -> list[str]:
    """The values uvx resolves as requirements: `--from` and every `--with`.

    Read positionally from the token list, so a requirement is whatever uvx
    would actually install -- not whatever a regex happened to find somewhere
    in the surrounding text.

    Both spellings count. uvx accepts `--with gitpython>=3.1.59` and
    `--with=gitpython>=3.1.59` identically, but the separated form is two
    tokens and the joined form is one. Reading only the separated form made
    `--from=python-semantic-release==10.6.2` invisible: the command was not
    recognised as a PSR invocation at all, so every assertion below simply
    skipped it. A gate that stops looking when the author changes an equals
    sign is not a gate.
    """
    values: list[str] = []
    for token in command:
        for flag in _REQUIREMENT_FLAGS:
            if token.startswith(f"{flag}="):
                values.append(token[len(flag) + 1 :])
    for flag, value in zip(command, command[1:]):
        if flag in _REQUIREMENT_FLAGS:
            values.append(value)
    return values


def _is_uvx_psr(command: list[str]) -> bool:
    """Whether this command runs python-semantic-release through uvx."""
    if not command or command[0] != "uvx":
        return False
    for token in _uvx_requirement_tokens(command):
        requirement = _requirement(token)
        if requirement is not None and _names_match(requirement.name, _PSR_NAME):
            return True
    return False


def _bound_for(name: str, tokens: list[str], where: str) -> SpecifierSet | None:
    """The specifier `tokens` puts on `name`, or None if it names no bound.

    A mention with no specifier (`--with gitpython`) is not a bound: it
    constrains nothing.
    """
    found: list[SpecifierSet] = []
    for token in tokens:
        requirement = _requirement(token)
        if requirement is None or not _names_match(requirement.name, name):
            continue
        if str(requirement.specifier):
            found.append(requirement.specifier)
    if not found:
        return None
    distinct = {str(spec) for spec in found}
    assert len(distinct) == 1, (
        f"{where} bounds {name} more than one way: {sorted(distinct)}. "
        "Everything here is compared against one definition."
    )
    return found[0]


#: A `gitpython<op>` written in a comment. These are claims about what the
#: command below them does, and they demonstrably rot: the floor was described
#: in three places in release.yml while living in exactly one.
_GITPYTHON_IN_PROSE = re.compile(
    r"""gitpython\s*([<>=!~][^\s\\"',]*(?:\s*,\s*[<>=!~][^\s\\"',]*)*)""",
    re.IGNORECASE,
)


def _comment_bounds(script: str) -> list[SpecifierSet]:
    """Every GitPython bound asserted in a comment in `script`."""
    bounds: list[SpecifierSet] = []
    for line in _LINE_CONTINUATION.sub(" ", script).splitlines():
        comment = _strip_to_comment(line)
        if comment is None:
            continue
        for raw in _GITPYTHON_IN_PROSE.findall(comment):
            try:
                bounds.append(SpecifierSet(raw))
            except Exception:  # noqa: BLE001 - prose need not parse
                continue
    return bounds


def _strip_to_comment(line: str) -> str | None:
    """The comment part of `line`, or None. Quotes are respected."""
    in_single = in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[index:]
    return None


@pytest.fixture(scope="module")
def psr_tooling() -> str:
    r"""The Makefile's `PSR_TOOLING` — the single definition of the release tooling.

    Continuations are folded, so a definition wrapped across lines reads whole.
    Make continues a variable on a trailing `\`, this definition is already
    78 characters, and a single-line capture would have silently compared
    everything against whatever fitted on the first line.
    """
    body = _LINE_CONTINUATION.sub(" ", _MAKEFILE.read_text())
    match = re.search(r"^PSR_TOOLING\s*:?=\s*(.+)$", body, re.MULTILINE)
    assert match is not None, (
        "Makefile lost its PSR_TOOLING definition. `make test-tools` depends on "
        "it, and it is the single source of truth these tests compare against."
    )
    return match.group(1)


@pytest.fixture(scope="module")
def psr_tooling_requirements(psr_tooling: str) -> list[str]:
    """PSR_TOOLING's `--from`/`--with` values, read the way uvx reads them."""
    (command,) = _commands(f"uvx {psr_tooling}")
    return _uvx_requirement_tokens(command)


@pytest.fixture(scope="module")
def psr_pin(psr_tooling_requirements: list[str]) -> str:
    bound = _bound_for(
        "python-semantic-release", psr_tooling_requirements, "PSR_TOOLING"
    )
    assert bound is not None, (
        "PSR_TOOLING must pin a python-semantic-release version: the release "
        "workflow pins one and these must be comparable."
    )
    pinned = [spec.version for spec in bound if spec.operator == "=="]
    assert len(pinned) == 1, (
        f"PSR_TOOLING must pin python-semantic-release exactly, got `{bound}`."
    )
    return pinned[0]


@pytest.fixture(scope="module")
def gitpython_specifier(psr_tooling_requirements: list[str]) -> SpecifierSet:
    bound = _bound_for("gitpython", psr_tooling_requirements, "PSR_TOOLING")
    assert bound is not None, (
        "PSR_TOOLING must bound GitPython. Unbounded, PSR's loose `gitpython~=3.0` "
        "admits <=3.1.58, which carries a critical RCE advisory."
    )
    return bound


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


class TestTheRequirementReader:
    """What the parity checks can see, they can enforce — and nothing else."""

    @pytest.mark.parametrize(
        "raw",
        [">=3.1.59", "==3.1.62", "~=3.1.59", "!=3.1.60", "<3.1.60", ">3.1.58"],
    )
    def test_every_operator_form_is_seen(self, raw):
        (command,) = _commands(f'uvx --with "gitpython{raw}" semantic-release')
        bound = _bound_for("gitpython", _uvx_requirement_tokens(command), "test")
        assert bound == SpecifierSet(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            ">=3.1.59,!=3.1.70",
            # The spacing #706 is about: PEP 508 legal, and what a person types.
            ">=3.1.59, !=3.1.70",
            ">=3.1.59 , <3.1.60",
        ],
    )
    def test_a_multi_constraint_bound_is_read_whole(self, raw):
        """A tail dropped here compares EQUAL to the bound without it."""
        (command,) = _commands(f'uvx --with "gitpython{raw}" semantic-release')
        bound = _bound_for("gitpython", _uvx_requirement_tokens(command), "test")
        assert bound == SpecifierSet(raw)
        assert bound != SpecifierSet(raw.split(",")[0])

    @pytest.mark.parametrize("raw", ["==3.1.62", "~=3.1.59", "!=3.1.60"])
    def test_an_unquoted_bound_without_a_redirection_character_is_seen(self, raw):
        (command,) = _commands(f"uvx --with gitpython{raw} semantic-release")
        bound = _bound_for("gitpython", _uvx_requirement_tokens(command), "test")
        assert bound == SpecifierSet(raw)

    @pytest.mark.parametrize("raw", [">=3.1.59", "<3.1.60"])
    def test_an_unquoted_bound_with_a_redirection_character_is_no_bound(self, raw):
        """Because bash does not see one either — it sees a redirection.

        `uvx --with gitpython>=3.1.59 ...` writes to a file called `=3.1.59`
        and installs an unbounded `gitpython`. The previous regex read the raw
        text and reported a bound the shell would never apply; reading tokens
        agrees with bash instead, and the missing bound then fails
        `test_no_psr_invocation_omits_the_gitpython_bound` loudly.
        """
        (command,) = _commands(f"uvx --with gitpython{raw} semantic-release")
        assert _bound_for("gitpython", _uvx_requirement_tokens(command), "test") is None

    def test_an_unbounded_mention_is_not_a_bound(self):
        (command,) = _commands('uvx --with "gitpython" semantic-release')
        assert _bound_for("gitpython", _uvx_requirement_tokens(command), "test") is None

    def test_a_bound_on_another_package_is_not_gitpython(self):
        (command,) = _commands('uvx --with "click>=8.1" semantic-release')
        assert _bound_for("gitpython", _uvx_requirement_tokens(command), "test") is None

    @pytest.mark.parametrize("flag", ["--from", "--with"])
    def test_the_joined_flag_form_is_read(self, flag):
        """`--with=x` is one token; `--with x` is two. uvx accepts both.

        Reading only the separated form made an invocation spelled with an
        equals sign invisible to every assertion in this file rather than
        failing one of them.
        """
        (command,) = _commands(f'uvx {flag}="gitpython>=3.1.59" semantic-release')
        bound = _bound_for("gitpython", _uvx_requirement_tokens(command), "test")
        assert bound == SpecifierSet(">=3.1.59")

    @pytest.mark.parametrize(
        "spelling",
        [
            "python-semantic-release",
            "Python-Semantic-Release",
            "python_semantic_release",
            "PYTHON.SEMANTIC.RELEASE",
        ],
    )
    def test_every_pep503_spelling_is_the_same_distribution(self, spelling):
        """Names are case-insensitive and `-`/`_`/`.` are equivalent.

        A capitalised `--from Python-Semantic-Release` used to be classified as
        "not a PSR invocation", so the GitPython floor was never checked on it
        while the correctly spelled calls kept the vacuity guard green.
        """
        (command,) = _commands(f"uvx --from {spelling}==10.6.2 semantic-release")
        assert _is_uvx_psr(command)

    @pytest.mark.parametrize("spelling", ["gitpython", "GitPython", "GITPYTHON"])
    def test_a_bound_is_found_under_every_spelling_of_its_name(self, spelling):
        """PyPI serves this one as `GitPython`; the workflows write `gitpython`."""
        (command,) = _commands(f'uvx --with "{spelling}>=3.1.59" semantic-release')
        bound = _bound_for("gitpython", _uvx_requirement_tokens(command), "test")
        assert bound == SpecifierSet(">=3.1.59")

    @pytest.mark.parametrize("spelling", ["git_python", "Git.Python", "git-python"])
    def test_a_separator_makes_it_a_different_distribution(self, spelling):
        """PEP 503 folds runs of `-_.` to `-`; it does not delete them.

        `git_python` normalises to `git-python`, which is not `gitpython`. The
        bound must not be credited to a package the resolver would not install.
        """
        (command,) = _commands(f'uvx --with "{spelling}>=3.1.59" semantic-release')
        assert _bound_for("gitpython", _uvx_requirement_tokens(command), "test") is None

    @pytest.mark.parametrize(
        "spelling",
        [
            "python-semantic-release",
            "Python-Semantic-Release",
            "python_semantic_release",
        ],
    )
    def test_a_mention_is_accounted_for_under_every_spelling(self, spelling):
        """The accounting check is the backstop; it must not be case-defeatable."""
        assert _mentions_psr(f"{spelling}==10.6.2")

    @pytest.mark.parametrize(
        "token",
        ["$PSR_REQ", "${PSR_REQ}", "$(cat pin.txt)", "`cat pin.txt`", "psr==$VER"],
    )
    def test_a_shell_expanded_requirement_is_detected(self, token):
        assert _is_shell_expanded(token)

    @pytest.mark.parametrize(
        "token", ["python-semantic-release==10.6.2", "gitpython>=3.1.59", "psr"]
    )
    def test_a_literal_requirement_is_not_an_expansion(self, token):
        assert not _is_shell_expanded(token)

    def test_a_different_distribution_is_not_a_psr_mention(self):
        assert not _mentions_psr("gitpython>=3.1.59")
        assert not _mentions_psr("semantic-release")

    def test_two_different_bounds_fail_by_name(self):
        (command,) = _commands(
            'uvx --with "gitpython>=3.1.59" --with "gitpython<3.1.60" semantic-release'
        )
        with pytest.raises(AssertionError, match="more than one way"):
            _bound_for("gitpython", _uvx_requirement_tokens(command), "somewhere")

    def test_an_unparseable_requirement_is_not_a_bound(self):
        assert _requirement(">=not.a.version.§") is None


class TestTheCommandReader:
    """`_commands` reads what a shell runs, not what the text looks like."""

    @pytest.mark.parametrize(
        ("shape", "text"),
        [
            ("empty file", ""),
            ("jobs is a scalar", "jobs: release\n"),
            ("jobs is a list", "jobs:\n  - release\n"),
            ("a job is a scalar", "jobs:\n  release: go\n"),
            ("steps is a scalar", "jobs:\n  release:\n    steps: go\n"),
            ("a step is a scalar", "jobs:\n  release:\n    steps:\n      - go\n"),
        ],
        ids=lambda v: v if " " in v else "",
    )
    def test_a_malformed_workflow_yields_no_commands(self, shape, text):
        assert _workflow_commands(text) == [], f"{shape} should read as no commands"

    def test_a_wrapped_invocation_reads_as_one_command(self):
        (command,) = _commands(
            "uvx --from python-semantic-release==10.6.2 \\\n"
            '  --with "gitpython>=3.1.59" \\\n'
            "  semantic-release version"
        )
        assert _is_uvx_psr(command)
        assert _bound_for(
            "gitpython", _uvx_requirement_tokens(command), "test"
        ) == SpecifierSet(">=3.1.59")

    def test_a_whole_line_comment_is_not_a_command(self):
        commands = _commands(
            "# uvx --from python-semantic-release==9.0.0 semantic-release\necho skipped"
        )
        assert not any(_is_uvx_psr(c) for c in commands)

    def test_an_end_of_line_comment_is_not_a_bound(self):
        """bash discards from the `#`; so must the gate, or the job is unbounded."""
        (command,) = _commands(
            "uvx --from python-semantic-release==10.6.2 semantic-release version"
            "  # floor gitpython>=3.1.59"
        )
        assert _is_uvx_psr(command)
        assert _bound_for("gitpython", _uvx_requirement_tokens(command), "test") is None

    def test_a_hash_inside_quotes_is_not_a_comment(self):
        commands = _commands(
            'echo "a # b" && uvx --with "gitpython>=3.1.59" '
            "--from python-semantic-release==10.6.2 semantic-release version"
        )
        assert any(_is_uvx_psr(c) for c in commands)

    def test_commands_joined_by_an_operator_are_separate(self):
        commands = _commands(
            "cd py && uvx --from python-semantic-release==10.6.2 "
            '--with "gitpython>=3.1.59" semantic-release version'
        )
        assert len(commands) == 2
        assert commands[0] == ["cd", "py"]

    def test_two_invocations_on_separate_lines_are_separate(self):
        """A block-wide search passed if EITHER call carried the bound."""
        commands = _commands(
            'uvx --from python-semantic-release==10.6.2 --with "gitpython>=3.1.59" '
            "semantic-release version\n"
            "uvx --from python-semantic-release==10.6.2 semantic-release version --print"
        )
        psr = [c for c in commands if _is_uvx_psr(c)]
        assert len(psr) == 2
        unbounded = [
            c
            for c in psr
            if _bound_for("gitpython", _uvx_requirement_tokens(c), "test") is None
        ]
        assert len(unbounded) == 1

    def test_an_untokenisable_command_fails_loudly(self):
        """Silently yielding nothing would exempt the block from every check."""
        with pytest.raises(AssertionError, match="could not tokenise"):
            _commands('uvx --with "unterminated')


class TestTheParityLogicItself:
    """Drives the comparison on synthetic input, not just on the repo's files.

    Every assertion in the class below reads real repo files, which are correct
    — so none of them proves the comparison *fails* on a drifted bound. That is
    exactly how a parser that truncated at whitespace stayed green: the readers
    were tested, the assertion that consumes them was not.
    """

    MAKEFILE_BOUND = SpecifierSet(">=3.1.59")

    def _drift(self, workflow_text: str) -> list[str]:
        """The comparison `test_every_gitpython_pin_matches_the_makefile` makes."""
        drifted = []
        for command in _workflow_commands(workflow_text):
            if not _is_uvx_psr(command):
                continue
            bound = _bound_for("gitpython", _uvx_requirement_tokens(command), "test")
            if bound != self.MAKEFILE_BOUND:
                drifted.append(str(bound))
        return drifted

    def _workflow(self, run: str) -> str:
        body = "\n".join(f"          {line}" for line in run.splitlines())
        return f"jobs:\n  release:\n    steps:\n      - run: |\n{body}\n"

    def test_a_matching_bound_is_not_drift(self):
        assert (
            self._drift(
                self._workflow(
                    "uvx --from python-semantic-release==10.6.2 "
                    '--with "gitpython>=3.1.59" semantic-release version'
                )
            )
            == []
        )

    def test_an_added_constraint_is_drift(self):
        """A superset bound is drift too: it resolves what tools/ never runs."""
        assert self._drift(
            self._workflow(
                "uvx --from python-semantic-release==10.6.2 "
                '--with "gitpython>=3.1.59,!=3.1.70" semantic-release version'
            )
        ) == ["!=3.1.70,>=3.1.59"]

    def test_a_constraint_written_with_a_space_is_drift(self):
        """#706: the truncating reader compared this EQUAL to `>=3.1.59`."""
        assert self._drift(
            self._workflow(
                "uvx --from python-semantic-release==10.6.2 "
                '--with "gitpython>=3.1.59, <3.1.60" semantic-release version'
            )
        ) == ["<3.1.60,>=3.1.59"]

    def test_a_loosened_bound_is_drift(self):
        assert self._drift(
            self._workflow(
                "uvx --from python-semantic-release==10.6.2 "
                '--with "gitpython>=3.1.0" semantic-release version'
            )
        ) == [">=3.1.0"]

    def test_a_bound_only_in_a_trailing_comment_reads_as_unbounded(self):
        """#710: bash never sees it, so neither may the gate."""
        assert self._drift(
            self._workflow(
                "uvx --from python-semantic-release==10.6.2 semantic-release version"
                "  # floor gitpython>=3.1.59"
            )
        ) == ["None"]

    def test_a_second_unbounded_invocation_in_one_block_is_drift(self):
        """#710: a block-wide search passed on the bounded call alone."""
        assert self._drift(
            self._workflow(
                "uvx --from python-semantic-release==10.6.2 "
                '--with "gitpython>=3.1.59" semantic-release version\n'
                "uvx --from python-semantic-release==10.6.2 semantic-release version "
                "--print"
            )
        ) == ["None"]


class TestTheWorkflowAgreesWithTheMakefile:
    @pytest.fixture(scope="class")
    def workflow(self) -> str:
        return _RELEASE_WORKFLOW.read_text()

    @pytest.fixture(scope="class")
    def psr_commands(self, workflow) -> list[list[str]]:
        """Every command in release.yml that runs PSR through uvx.

        Per invocation, not per `run:` block. A block holding a bounded call and
        an unbounded one used to pass on the strength of the first.
        """
        return [c for c in _workflow_commands(workflow) if _is_uvx_psr(c)]

    def test_the_workflow_still_invokes_psr(self, psr_commands):
        """Guards the rest of the class against passing vacuously."""
        assert psr_commands, (
            "release.yml no longer runs python-semantic-release via uvx; these "
            "pin-parity assertions would pass vacuously — update them."
        )

    def test_every_psr_mention_is_accounted_for(self, workflow, psr_commands):
        """Nothing mentioning PSR may sit outside the set the checks inspect."""
        mentions = [
            c
            for c in _workflow_commands(workflow)
            if any(_mentions_psr(token) for token in c)
        ]
        unmatched = [" ".join(c)[:120] for c in mentions if c not in psr_commands]
        assert not unmatched, (
            "these release.yml commands mention python-semantic-release but were "
            f"not recognised as uvx invocations, so nothing checks them: {unmatched}"
        )

    def test_no_uvx_requirement_is_decided_at_run_time(self, workflow):
        """A requirement this file cannot read is a requirement it cannot gate.

        Checked across every uvx command, not just the ones recognised as PSR:
        a shell-expanded `--from` is exactly what stops a command being
        recognised, so keying this on `psr_commands` would look past the case
        it exists for.
        """
        expanded = [
            f"{' '.join(command)[:120]} -> {token}"
            for command in _workflow_commands(workflow)
            if command and command[0] == "uvx"
            for token in _uvx_requirement_tokens(command)
            if _is_shell_expanded(token)
        ]
        assert not expanded, (
            "these release.yml uvx requirements are shell expansions, so the "
            "pin they resolve to is not written in the workflow and nothing "
            f"here can check it. Write the requirement literally: {expanded}"
        )

    def test_every_psr_pin_matches_the_makefile(self, psr_commands, psr_pin):
        drifted = set()
        for command in psr_commands:
            bound = _bound_for(
                "python-semantic-release",
                _uvx_requirement_tokens(command),
                "release.yml",
            )
            if bound != SpecifierSet(f"=={psr_pin}"):
                drifted.add(str(bound))
        assert not drifted, (
            f"release.yml pins python-semantic-release {sorted(drifted)}, but "
            f"PSR_TOOLING pins {psr_pin}. `make test-tools` would validate the "
            "release parsers against a PSR the release job never runs."
        )

    def test_every_gitpython_pin_matches_the_makefile(
        self, psr_commands, gitpython_specifier
    ):
        drifted = sorted(
            {
                str(_bound_for("gitpython", _uvx_requirement_tokens(c), "release.yml"))
                for c in psr_commands
                if _bound_for("gitpython", _uvx_requirement_tokens(c), "release.yml")
                != gitpython_specifier
            }
        )
        assert not drifted, (
            f"release.yml constrains GitPython {drifted}, but PSR_TOOLING says "
            f"{gitpython_specifier}. A bound that merely *includes* the "
            "Makefile's is still drift: the release job would resolve a "
            "GitPython `make test-tools` never exercises."
        )

    def test_no_psr_invocation_omits_the_gitpython_bound(self, psr_commands):
        """One unconstrained invocation is enough to resolve a vulnerable GitPython."""
        unconstrained = [
            " ".join(c)[:120]
            for c in psr_commands
            if _bound_for("gitpython", _uvx_requirement_tokens(c), "release.yml")
            is None
        ]
        assert not unconstrained, (
            "these release.yml invocations run python-semantic-release without the "
            f"GitPython bound, so they resolve it freely: {unconstrained}"
        )


class TestTheCommentsDescribeTheRealBound:
    """A comment about the floor is a claim, and claims rot.

    These were checked before a blanket comment strip removed them, and they
    demonstrably drift: the floor is explained in three places in release.yml
    and lives in exactly one. The bound checks above deliberately ignore
    comments — bash does — so without this nothing looks at them at all.
    """

    def test_every_gitpython_comment_matches_the_makefile(self, gitpython_specifier):
        workflow = _RELEASE_WORKFLOW.read_text()
        claimed = {
            str(bound)
            for block in _run_blocks(workflow)
            for bound in _comment_bounds(block)
            # PSR's own declaration, quoted while explaining why the floor
            # exists. A fact about upstream, not a claim about this pipeline,
            # and the only such exemption.
            if bound != _UPSTREAM_LITERAL
        }
        drifted = sorted(c for c in claimed if SpecifierSet(c) != gitpython_specifier)
        assert not drifted, (
            f"release.yml comments describe the GitPython floor as {drifted}, but "
            f"PSR_TOOLING says {gitpython_specifier}. The comment is what the next "
            "person raising the floor reads."
        )

    def test_the_upstream_literal_is_the_only_exemption(self):
        """If PSR's declaration changes, the exemption must be revisited."""
        assert _UPSTREAM_LITERAL == SpecifierSet("~=3.0")

    def test_a_stale_floor_comment_is_caught(self):
        """The check above reads real files, which are correct — drive it too."""
        stale = _comment_bounds("# Floor gitpython>=3.1.59 (same as the core job)")
        assert stale == [SpecifierSet(">=3.1.59")]
        assert stale[0] != SpecifierSet(">=3.1.60")

    def test_a_multi_constraint_comment_is_read_whole(self):
        """The same truncation #706 is about, on the prose side."""
        (bound,) = _comment_bounds("# floor gitpython>=3.1.59, !=3.1.70 applies")
        assert bound == SpecifierSet(">=3.1.59,!=3.1.70")

    def test_the_upstream_literal_is_not_read_as_a_claim(self):
        (bound,) = _comment_bounds("# PSR's loose gitpython~=3.0 allows <=3.1.58.")
        assert bound == _UPSTREAM_LITERAL


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
            f"{config.name} documents python-semantic-release "
            f"{sorted(set(psr_found))}, but PSR_TOOLING pins {psr_pin}."
        )
        documented = _comment_bounds(text)
        assert documented, (
            f"{config.name} documents a PSR invocation with no GitPython bound; "
            "copying it by hand resolves GitPython freely, and <=3.1.58 carries "
            "a critical RCE advisory."
        )
        drifted = sorted({str(b) for b in documented if b != gitpython_specifier})
        assert not drifted, (
            f"{config.name} documents GitPython {drifted}, but PSR_TOOLING says "
            f"{gitpython_specifier}. Exact, not a superset: a constraint added to "
            "PSR_TOOLING and left out of the comment means the command a human "
            "copies from here resolves differently from the one CI runs."
        )
