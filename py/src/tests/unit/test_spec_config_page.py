"""The settings table in ``spec/config.md`` matches Python's ``Config``.

Python defines the settings; the spec page states them for Go and Rust to
match. This test keeps the page honest: every ``Config`` field has exactly one
row, and each row's default and valid range are the ones ``Config`` enforces.
"""

from dataclasses import fields
from pathlib import Path
import re
from typing import Any

import pytest

from py_identity_model import Config, ConfigError


pytestmark = pytest.mark.unit


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "config.md").is_file():
            return parent
    raise RuntimeError("spec/config.md not found above this file")


_PAGE = _find_repo_root() / "spec" / "config.md"
_HEADER = "| Python | Go option | Rust builder method | Unit | Default | Valid |"


def _settings_rows() -> dict[str, dict[str, str]]:
    lines = _PAGE.read_text(encoding="utf-8").splitlines()
    start = lines.index(_HEADER) + 2  # skip the header and the |---| line
    rows: dict[str, dict[str, str]] = {}
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        python, go, rust, unit, default, valid = cells
        assert python not in rows, f"{python} has two rows"
        rows[python] = {
            "go": go,
            "rust": rust,
            "unit": unit,
            "default": default,
            "valid": valid,
        }
    return rows


ROWS = _settings_rows()


def _number(text: str) -> float:
    return float(text.replace(" ", ""))


def test_one_row_per_config_field() -> None:
    assert sorted(ROWS) == sorted(f.name for f in fields(Config))


def test_every_row_names_go_and_rust() -> None:
    for name, row in ROWS.items():
        assert row["go"], name
        assert row["rust"], name


@pytest.mark.parametrize("name", sorted(ROWS))
def test_default_matches_config(name: str) -> None:
    expected = getattr(Config(), name)
    default = ROWS[name]["default"]
    if expected is None:
        assert default == "none"
    else:
        assert _number(default) == expected


def _accepts(name: str, value: float) -> bool:
    if isinstance(getattr(Config(), name), int):
        if value != int(value):
            return True  # not representable; the integer neighbours decide
        value = int(value)
    kwargs: dict[str, Any] = {name: value}
    try:
        Config(**kwargs)
    except ConfigError:
        return False
    return True


_STEP: dict[str, float] = {"seconds": 1e-6}


@pytest.mark.parametrize("name", sorted(ROWS))
def test_valid_range_matches_config(name: str) -> None:
    row = ROWS[name]
    valid = row["valid"]
    step = _STEP.get(row["unit"], 1)
    if valid == "readable file":
        assert getattr(Config(), name) is None
        return
    if m := re.fullmatch(r"> ([\d ]+)", valid):
        lo = _number(m[1])
        assert not _accepts(name, lo)
        assert _accepts(name, lo + step)
    elif m := re.fullmatch(r"≥ ([\d ]+)", valid):
        lo = _number(m[1])
        assert _accepts(name, lo)
        assert not _accepts(name, lo - step)
    elif m := re.fullmatch(r"([\d ]+) \u2013 ([\d ]+)", valid):
        lo, hi = _number(m[1]), _number(m[2])
        assert _accepts(name, lo)
        assert _accepts(name, hi)
        assert not _accepts(name, lo - step)
        assert not _accepts(name, hi + step)
    else:
        pytest.fail(f"{name}: unrecognised range {valid!r}")
