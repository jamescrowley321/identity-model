"""TEST_REQUIRE_LIVE must not fail open on an unrecognised spelling.

Every value this parser does not recognise would otherwise mean *off*, and off
is the setting that restores the green-skip #708 removes. spec/config.md
CFG-107 (spec/test-fixtures/config/strict-bool-parsing.json) settles which
spellings are legal; this keeps the harness honest to it.
"""

from __future__ import annotations

import pytest

from tests.integration.test_utils import _strict_bool


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("", False),
    ],
)
def test_accepts_the_spellings_cfg_107_allows(raw, expected):
    assert _strict_bool("TEST_REQUIRE_LIVE", raw) is expected


@pytest.mark.unit
@pytest.mark.parametrize("raw", ["yes", "no", "on", "off", "y", "ture", "enabled"])
def test_rejects_everything_else_loudly(raw):
    """CFG-107 rejects `yes`; silently reading it as False disarms the gate."""
    with pytest.raises(RuntimeError, match="CFG-003"):
        _strict_bool("TEST_REQUIRE_LIVE", raw)
