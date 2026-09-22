"""The @claude workflow's trigger surface, pinned.

This workflow spends a shared Max subscription window, and the whole of its
access control is one `if:` expression that nothing evaluates. actionlint
checks that the expression parses and that its `github.event.*` paths exist,
which is worth having and is not the same as checking what it decides.

These assertions pin the four decisions that cost real money or real access
when they regress (#698, #704). They read the workflow as parsed YAML rather
than as text, so reformatting does not break them and deleting a guard does.

They are not a substitute for evaluating the expression — see #700, which asks
for a fixture asserting the gate's result for an OUTSIDE_COLLABORATOR payload.
That remains open.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "claude.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    # `on` is the YAML 1.1 boolean True, not the string "on".
    return yaml.safe_load(_WORKFLOW.read_text())


@pytest.fixture(scope="module")
def triggers(workflow) -> dict:
    return workflow[True]


@pytest.fixture(scope="module")
def gate(workflow) -> str:
    return " ".join(workflow["jobs"]["claude"]["if"].split())


def test_issues_does_not_trigger_on_assignment(triggers):
    """`assigned` fires on an act by someone the association test never checks.

    The issues branch tests the ISSUE AUTHOR's association. On `assigned` the
    actor is whoever assigned — triage permission is enough — so a stale
    OWNER-authored issue mentioning @claude bought a 30-minute session per
    re-assign. With `opened`, author and actor are the same person.
    """
    assert triggers["issues"]["types"] == ["opened"]


def test_the_issues_gate_requires_the_mention_to_be_a_command(gate):
    """CONTRIBUTING.md tells people to write `@claude review this PR`.

    Any issue quoting those docs contains the substring, so `contains` made the
    documentation itself a trigger. Anchoring it makes the mention deliberate.
    """
    assert "startsWith(github.event.issue.body, '@claude')" in gate
    assert "contains(github.event.issue.body, '@claude')" not in gate


def test_a_draft_pull_request_does_not_trigger_a_review(gate):
    """`opened` fires for drafts, so without this the normal
    open-as-draft-then-ready flow billed two reviews, the first on
    deliberately incomplete work."""
    assert "github.event.pull_request.draft == false" in gate


def test_a_retrigger_supersedes_rather_than_queues(workflow):
    """Stacking was the cost: each toggle bought another sequential session."""
    assert workflow["concurrency"]["cancel-in-progress"] is True


def test_every_branch_of_the_gate_checks_an_association(gate):
    """No trigger may reach the model without an association test.

    Counted rather than named: a branch added later without one would leave the
    counts unequal, which is the failure this catches.
    """
    assert gate.count("github.event_name ==") == gate.count("author_association")


def test_no_push_or_schedule_trigger_is_added(triggers):
    """#667 removed the unconditional auto-review on purpose."""
    assert set(triggers) <= {
        "pull_request",
        "issue_comment",
        "pull_request_review_comment",
        "pull_request_review",
        "issues",
    }
