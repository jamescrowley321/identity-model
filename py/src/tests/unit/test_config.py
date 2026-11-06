"""Unit tests for the plain typed ``Config``.

``Config`` is a frozen, keyword-only value with the library's defaults. It is
validated on creation, and one ``ConfigError`` names every invalid setting.
It has no loaders and parses no strings.
"""

import dataclasses
import math
import os
from pathlib import Path

import pytest

import py_identity_model
from py_identity_model import Config, ConfigError, ConfigIssue
from py_identity_model.core import config as config_module
from py_identity_model.core.http_utils import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_JWKS_KEYS,
    DEFAULT_MAX_JWKS_SIZE,
    DEFAULT_RETRY_BASE_DELAY,
    DEFAULT_RETRY_MAX_ATTEMPTS,
)
from py_identity_model.core.jwks_cache import (
    DEFAULT_DISCO_CACHE_TTL_SECONDS,
    DEFAULT_JWKS_CACHE_TTL_SECONDS,
    DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    DEFAULT_MAX_CACHE_ENTRIES,
)


pytestmark = pytest.mark.unit


EXPECTED_DEFAULTS = {
    "http_timeout": 30.0,
    "http_retry_max_attempts": 3,
    "http_retry_base_delay": 1.0,
    "ca_bundle": None,
    "jwks_max_size": 524288,
    "jwks_max_keys": 100,
    "jwks_cache_ttl": 86400.0,
    "jwks_kid_miss_cooldown": 5.0,
    "discovery_cache_ttl": 3600.0,
    "cache_max_entries": 64,
}


def _issues(exc: ConfigError) -> dict[str, ConfigIssue]:
    return {issue.setting: issue for issue in exc.issues}


# --------------------------------------------------------------------------- #
# Defaults                                                                     #
# --------------------------------------------------------------------------- #


def test_defaults_match_the_settings_table():
    assert dataclasses.asdict(Config()) == EXPECTED_DEFAULTS


def test_defaults_match_the_current_readers():
    # The defaults the env readers fall back to today; Config must not drift.
    assert dataclasses.asdict(Config()) == {
        "http_timeout": DEFAULT_HTTP_TIMEOUT,
        "http_retry_max_attempts": DEFAULT_RETRY_MAX_ATTEMPTS,
        "http_retry_base_delay": DEFAULT_RETRY_BASE_DELAY,
        "ca_bundle": None,
        "jwks_max_size": DEFAULT_MAX_JWKS_SIZE,
        "jwks_max_keys": DEFAULT_MAX_JWKS_KEYS,
        "jwks_cache_ttl": DEFAULT_JWKS_CACHE_TTL_SECONDS,
        "jwks_kid_miss_cooldown": DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
        "discovery_cache_ttl": DEFAULT_DISCO_CACHE_TTL_SECONDS,
        "cache_max_entries": DEFAULT_MAX_CACHE_ENTRIES,
    }


def test_typed_values_override_defaults(tmp_path: Path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    cfg = Config(
        http_timeout=5,
        http_retry_max_attempts=0,
        http_retry_base_delay=0.5,
        ca_bundle=str(bundle),
        jwks_max_size=1,
        jwks_max_keys=1,
        jwks_cache_ttl=60,
        jwks_kid_miss_cooldown=0,
        discovery_cache_ttl=86400,
        cache_max_entries=1,
    )
    assert dataclasses.asdict(cfg) == {
        "http_timeout": 5,
        "http_retry_max_attempts": 0,
        "http_retry_base_delay": 0.5,
        "ca_bundle": str(bundle),
        "jwks_max_size": 1,
        "jwks_max_keys": 1,
        "jwks_cache_ttl": 60,
        "jwks_kid_miss_cooldown": 0,
        "discovery_cache_ttl": 86400,
        "cache_max_entries": 1,
    }


def test_upper_bounds_are_inclusive():
    cfg = Config(
        jwks_cache_ttl=86400.0,
        discovery_cache_ttl=86400.0,
        jwks_kid_miss_cooldown=3600.0,
    )
    assert dataclasses.asdict(cfg) == {
        **EXPECTED_DEFAULTS,
        "jwks_cache_ttl": 86400.0,
        "discovery_cache_ttl": 86400.0,
        "jwks_kid_miss_cooldown": 3600.0,
    }


# --------------------------------------------------------------------------- #
# Validation                                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("http_timeout", 0, "must be greater than 0"),
        ("http_timeout", -1.0, "must be greater than 0"),
        ("http_retry_max_attempts", -1, "must be at least 0"),
        ("http_retry_base_delay", -0.1, "must be at least 0"),
        ("jwks_max_size", 0, "must be at least 1"),
        ("jwks_max_keys", 0, "must be at least 1"),
        ("jwks_cache_ttl", 59.9, "must be at least 60"),
        ("jwks_cache_ttl", 86400.1, "must be at most 86400"),
        ("jwks_kid_miss_cooldown", -0.1, "must be at least 0"),
        ("jwks_kid_miss_cooldown", 3600.1, "must be at most 3600"),
        ("discovery_cache_ttl", 59, "must be at least 60"),
        ("discovery_cache_ttl", 86401, "must be at most 86400"),
        ("cache_max_entries", 0, "must be at least 1"),
        ("cache_max_entries", -5, "must be at least 1"),
    ],
)
def test_out_of_range_value_is_rejected(setting, value, message):
    with pytest.raises(ConfigError) as ei:
        Config(**{setting: value})
    assert ei.value.issues == (ConfigIssue(setting, message),)


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        # No string parsing on the type: "5" is not a number.
        ("http_timeout", "5", "must be a number"),
        ("http_retry_max_attempts", "3", "must be an integer"),
        # bool is an int subclass; it is still not a count.
        ("http_retry_max_attempts", True, "must be an integer"),
        ("http_timeout", False, "must be a number"),
        # A float is not an integer setting.
        ("jwks_max_keys", 2.0, "must be an integer"),
        ("cache_max_entries", 64.0, "must be an integer"),
        ("http_timeout", math.nan, "must be a finite number"),
        ("jwks_cache_ttl", math.inf, "must be a finite number"),
        ("http_retry_base_delay", None, "must be a number"),
        ("ca_bundle", 1, "must be a path to a readable file"),
    ],
)
def test_wrong_type_is_rejected(setting, value, message):
    with pytest.raises(ConfigError) as ei:
        Config(**{setting: value})
    assert ei.value.issues == (ConfigIssue(setting, message),)


def test_every_invalid_setting_is_reported_in_one_error_in_field_order(
    tmp_path: Path,
):
    with pytest.raises(ConfigError) as ei:
        Config(
            cache_max_entries=0,
            http_timeout=0,
            http_retry_max_attempts=-1,
            ca_bundle=str(tmp_path / "missing.pem"),
            jwks_cache_ttl=1,
        )
    assert ei.value.issues == (
        ConfigIssue("http_timeout", "must be greater than 0"),
        ConfigIssue("http_retry_max_attempts", "must be at least 0"),
        ConfigIssue("ca_bundle", "must be a path to a readable file"),
        ConfigIssue("jwks_cache_ttl", "must be at least 60"),
        ConfigIssue("cache_max_entries", "must be at least 1"),
    )
    assert str(ei.value) == (
        "configuration is invalid:\n"
        "  - http_timeout: must be greater than 0\n"
        "  - http_retry_max_attempts: must be at least 0\n"
        "  - ca_bundle: must be a path to a readable file\n"
        "  - jwks_cache_ttl: must be at least 60\n"
        "  - cache_max_entries: must be at least 1"
    )


def test_invalid_value_is_never_replaced_by_its_default():
    with pytest.raises(ConfigError) as ei:
        Config(cache_max_entries=0)
    assert set(_issues(ei.value)) == {"cache_max_entries"}


def test_error_message_does_not_echo_the_value(tmp_path: Path):
    path = str(tmp_path / "secret-name.pem")
    with pytest.raises(ConfigError) as ei:
        Config(ca_bundle=path, http_timeout=-12345.5)
    assert path not in str(ei.value)
    assert "12345" not in str(ei.value)


def test_ca_bundle_directory_is_rejected(tmp_path: Path):
    with pytest.raises(ConfigError) as ei:
        Config(ca_bundle=str(tmp_path))
    assert ei.value.issues == (
        ConfigIssue("ca_bundle", "must be a path to a readable file"),
    )


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads any file"
)
def test_ca_bundle_unreadable_file_is_rejected(tmp_path: Path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    bundle.chmod(0)
    try:
        with pytest.raises(ConfigError) as ei:
            Config(ca_bundle=str(bundle))
    finally:
        bundle.chmod(0o600)
    assert ei.value.issues == (
        ConfigIssue("ca_bundle", "must be a path to a readable file"),
    )


def test_ca_bundle_empty_string_is_rejected():
    with pytest.raises(ConfigError) as ei:
        Config(ca_bundle="")
    assert ei.value.issues == (
        ConfigIssue("ca_bundle", "must be a path to a readable file"),
    )


# An int too large for a float: math.isfinite() overflows on it.
HUGE_INT = 10**400
# A file name longer than any filesystem's NAME_MAX: stat() fails ENAMETOOLONG.
OVERSIZED_NAME = "x" * 300


def test_int_too_large_for_a_float_is_reported_with_the_other_issues():
    with pytest.raises(ConfigError) as ei:
        Config(http_timeout=HUGE_INT, cache_max_entries=0)
    assert ei.value.issues == (
        ConfigIssue("http_timeout", "must be a finite number"),
        ConfigIssue("cache_max_entries", "must be at least 1"),
    )


@pytest.mark.parametrize(
    "name", [OVERSIZED_NAME, "ca\0.pem"], ids=["name-too-long", "embedded-nul"]
)
def test_ca_bundle_path_the_os_cannot_stat_is_reported_with_the_other_issues(
    name: str,
):
    with pytest.raises(ConfigError) as ei:
        Config(ca_bundle=name, cache_max_entries=0)
    assert ei.value.issues == (
        ConfigIssue("ca_bundle", "must be a path to a readable file"),
        ConfigIssue("cache_max_entries", "must be at least 1"),
    )


def test_config_error_is_a_value_error():
    # Callers catching ValueError around construction still catch it.
    with pytest.raises(ValueError, match="http_timeout"):
        Config(http_timeout=0)


# --------------------------------------------------------------------------- #
# Shape                                                                        #
# --------------------------------------------------------------------------- #


def test_config_is_frozen():
    cfg = Config()
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.http_timeout = 1.0  # type: ignore[misc]


def test_config_is_keyword_only():
    with pytest.raises(TypeError):
        Config(10.0)  # type: ignore[misc]


def test_config_has_no_loaders():
    assert {name for name in ("from_env", "build") if hasattr(Config, name)} == set()


def test_config_equality_is_by_value():
    assert Config(http_timeout=5.0) == Config(http_timeout=5.0)
    assert Config(http_timeout=5.0) != Config()


def test_source_and_registry_api_is_gone():
    removed = {
        "ConfigSource",
        "EnvSource",
        "MappingSource",
        "Secret",
        "_REGISTRY",
        "_KeySpec",
    }
    assert {name for name in removed if hasattr(config_module, name)} == set()
    assert {name for name in removed if hasattr(py_identity_model, name)} == set()
    assert removed.isdisjoint(py_identity_model.__all__)
