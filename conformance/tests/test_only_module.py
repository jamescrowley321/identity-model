"""Tests for the ``--only-module`` filter in conformance/run_tests.py (#906)."""

from __future__ import annotations

import pytest
from run_tests import _select_modules


FAPI2_MODULES = [
    "fapi2-security-profile-final-client-test-happy-path",
    "fapi2-security-profile-final-client-test-invalid-alternate-alg",
    "fapi2-security-profile-final-client-test-invalid-aud",
]


def test_no_filter_keeps_every_module():
    assert _select_modules(FAPI2_MODULES, None) == FAPI2_MODULES


def test_filter_keeps_only_matching_modules():
    assert _select_modules(FAPI2_MODULES, "invalid-alternate-alg") == [
        "fapi2-security-profile-final-client-test-invalid-alternate-alg"
    ]


def test_filter_matches_substring_in_plan_order():
    assert _select_modules(FAPI2_MODULES, "invalid-a") == [
        "fapi2-security-profile-final-client-test-invalid-alternate-alg",
        "fapi2-security-profile-final-client-test-invalid-aud",
    ]


def test_filter_matching_nothing_raises():
    with pytest.raises(ValueError, match="no-such-module"):
        _select_modules(FAPI2_MODULES, "no-such-module")


def test_empty_filter_raises():
    with pytest.raises(ValueError, match="empty"):
        _select_modules(FAPI2_MODULES, "")
