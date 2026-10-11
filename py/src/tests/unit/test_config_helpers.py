"""Unit tests for the optional config helpers.

``config_from_mapping`` converts string settings (today's environment variable
names) to typed values and returns a validated ``Config``. ``config_from_env``
does the same with ``os.environ``. The library itself never imports the module.
"""

import ast
import dataclasses
from pathlib import Path
import subprocess
import sys

import pytest

import py_identity_model
from py_identity_model import Config, ConfigError, ConfigIssue
from py_identity_model.config_helpers import config_from_env, config_from_mapping


pytestmark = pytest.mark.unit


# Every key the helpers read, and the field it sets.
KEYS = {
    "HTTP_TIMEOUT": "http_timeout",
    "HTTP_RETRY_MAX_ATTEMPTS": "http_retry_max_attempts",
    "HTTP_RETRY_COUNT": "http_retry_max_attempts",
    "HTTP_RETRY_BASE_DELAY": "http_retry_base_delay",
    "SSL_CERT_FILE": "ca_bundle",
    "CURL_CA_BUNDLE": "ca_bundle",
    "REQUESTS_CA_BUNDLE": "ca_bundle",
    "MAX_JWKS_SIZE": "jwks_max_size",
    "MAX_JWKS_KEYS": "jwks_max_keys",
    "JWKS_CACHE_TTL": "jwks_cache_ttl",
    "KID_MISS_REFRESH_COOLDOWN": "jwks_kid_miss_cooldown",
    "DISCO_CACHE_TTL": "discovery_cache_ttl",
    "JWKS_CACHE_MAX_ENTRIES": "cache_max_entries",
}


@pytest.fixture
def ca_file(tmp_path: Path) -> str:
    path = tmp_path / "ca.pem"
    path.write_text("not checked\n")
    return str(path)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """An environment holding none of the keys, with or without a prefix."""
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(f"APP_{key}", raising=False)
    return monkeypatch


def _issues(exc: pytest.ExceptionInfo[ConfigError]) -> dict[str, ConfigIssue]:
    return {issue.setting: issue for issue in exc.value.issues}


# --------------------------------------------------------------------------- #
# config_from_mapping                                                          #
# --------------------------------------------------------------------------- #


def test_empty_mapping_gives_the_defaults():
    assert config_from_mapping({}) == Config()


def test_every_setting_is_converted_to_its_type(ca_file):
    values = {
        "HTTP_TIMEOUT": "12.5",
        "HTTP_RETRY_MAX_ATTEMPTS": "5",
        "HTTP_RETRY_BASE_DELAY": "0.25",
        "SSL_CERT_FILE": ca_file,
        "MAX_JWKS_SIZE": "2048",
        "MAX_JWKS_KEYS": "7",
        "JWKS_CACHE_TTL": "600",
        "KID_MISS_REFRESH_COOLDOWN": "0",
        "DISCO_CACHE_TTL": "120",
        "JWKS_CACHE_MAX_ENTRIES": "8",
    }
    assert config_from_mapping(values) == Config(
        http_timeout=12.5,
        http_retry_max_attempts=5,
        http_retry_base_delay=0.25,
        ca_bundle=ca_file,
        jwks_max_size=2048,
        jwks_max_keys=7,
        jwks_cache_ttl=600.0,
        jwks_kid_miss_cooldown=0.0,
        discovery_cache_ttl=120.0,
        cache_max_entries=8,
    )


def test_converted_values_have_the_field_types():
    config = config_from_mapping({"HTTP_TIMEOUT": "10", "MAX_JWKS_KEYS": "3"})
    assert (type(config.http_timeout), type(config.jwks_max_keys)) == (float, int)


def test_unknown_keys_are_ignored():
    assert config_from_mapping({"PATH": "/usr/bin", "http_timeout": "x"}) == Config()


@pytest.mark.parametrize("unset", ["", None])
def test_empty_or_none_value_counts_as_unset(unset):
    # dotenv_values() gives None for a bare ``KEY`` line and "" for ``KEY=``.
    values = dict.fromkeys(KEYS, unset)
    assert config_from_mapping(values) == Config()


def test_retry_alias_is_read():
    config = config_from_mapping({"HTTP_RETRY_COUNT": "0"})
    assert config == Config(http_retry_max_attempts=0)


def test_primary_retry_key_wins_over_the_alias():
    config = config_from_mapping(
        {"HTTP_RETRY_MAX_ATTEMPTS": "1", "HTTP_RETRY_COUNT": "9"}
    )
    assert config == Config(http_retry_max_attempts=1)


def test_empty_primary_falls_through_to_the_alias():
    config = config_from_mapping(
        {"HTTP_RETRY_MAX_ATTEMPTS": "", "HTTP_RETRY_COUNT": "9"}
    )
    assert config == Config(http_retry_max_attempts=9)


@pytest.mark.parametrize(
    ("winner", "losers"),
    [
        ("SSL_CERT_FILE", ("CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE")),
        ("CURL_CA_BUNDLE", ("REQUESTS_CA_BUNDLE",)),
        ("REQUESTS_CA_BUNDLE", ()),
    ],
)
def test_ca_bundle_keys_in_priority_order(winner, losers, ca_file, tmp_path):
    other = tmp_path / "other.pem"
    other.write_text("x\n")
    values = {winner: ca_file, **dict.fromkeys(losers, str(other))}
    assert config_from_mapping(values).ca_bundle == ca_file


def test_prefix_applies_to_every_key_and_alias(ca_file):
    values = {
        "APP_HTTP_TIMEOUT": "7",
        "APP_HTTP_RETRY_COUNT": "2",
        "APP_REQUESTS_CA_BUNDLE": ca_file,
        "HTTP_TIMEOUT": "99",  # unprefixed: not read
    }
    assert config_from_mapping(values, prefix="APP_") == Config(
        http_timeout=7.0, http_retry_max_attempts=2, ca_bundle=ca_file
    )


@pytest.mark.parametrize(
    ("key", "raw", "message"),
    [
        ("HTTP_TIMEOUT", "fast", "must be a number"),
        ("HTTP_RETRY_MAX_ATTEMPTS", "2.5", "must be an integer"),
        ("MAX_JWKS_SIZE", "1e3", "must be an integer"),
        pytest.param(
            "JWKS_CACHE_MAX_ENTRIES",
            "9" * 5000,  # past int()'s digit limit
            "must be an integer",
            id="int-too-long",
        ),
        ("DISCO_CACHE_TTL", "60s", "must be a number"),
    ],
)
def test_unconvertible_value_is_a_config_error(key, raw, message):
    with pytest.raises(ConfigError) as exc:
        config_from_mapping({key: raw})
    assert exc.value.issues == (ConfigIssue(key, message),)


@pytest.mark.parametrize(
    ("key", "raw", "message"),
    [
        ("HTTP_TIMEOUT", "0", "must be greater than 0"),
        ("HTTP_TIMEOUT", "nan", "must be a finite number"),
        ("JWKS_CACHE_TTL", "1e400", "must be a finite number"),
        ("KID_MISS_REFRESH_COOLDOWN", "3601", "must be at most 3600"),
        ("JWKS_CACHE_MAX_ENTRIES", "0", "must be at least 1"),
        ("SSL_CERT_FILE", "/no/such/ca.pem", "must be a path to a readable file"),
    ],
)
def test_range_issue_names_the_key_it_came_from(key, raw, message):
    with pytest.raises(ConfigError) as exc:
        config_from_mapping({key: raw})
    assert exc.value.issues == (ConfigIssue(key, message),)


def test_alias_issue_names_the_alias_that_was_read():
    with pytest.raises(ConfigError) as exc:
        config_from_mapping({"APP_HTTP_RETRY_COUNT": "-1"}, prefix="APP_")
    assert exc.value.issues == (
        ConfigIssue("APP_HTTP_RETRY_COUNT", "must be at least 0"),
    )


def test_every_problem_is_reported_at_once_in_field_order():
    values = {
        "JWKS_CACHE_MAX_ENTRIES": "lots",  # conversion
        "DISCO_CACHE_TTL": "5",  # range
        "HTTP_TIMEOUT": "-1",  # range
        "MAX_JWKS_KEYS": "many",  # conversion
    }
    with pytest.raises(ConfigError) as exc:
        config_from_mapping(values)
    assert exc.value.issues == (
        ConfigIssue("HTTP_TIMEOUT", "must be greater than 0"),
        ConfigIssue("MAX_JWKS_KEYS", "must be an integer"),
        ConfigIssue("DISCO_CACHE_TTL", "must be at least 60"),
        ConfigIssue("JWKS_CACHE_MAX_ENTRIES", "must be an integer"),
    )


def test_error_never_contains_the_value():
    secretish = "s3cr3t-not-a-number"
    with pytest.raises(ConfigError) as exc:
        config_from_mapping(
            {"HTTP_TIMEOUT": secretish, "SSL_CERT_FILE": f"/{secretish}"}
        )
    assert secretish not in str(exc.value)
    assert set(_issues(exc)) == {"HTTP_TIMEOUT", "SSL_CERT_FILE"}


def test_dotenv_values_shape_is_accepted():
    # What python-dotenv's dotenv_values() returns: dict[str, str | None].
    values: dict[str, str | None] = {"HTTP_TIMEOUT": "4", "MAX_JWKS_KEYS": None}
    assert config_from_mapping(values) == Config(http_timeout=4.0)


# --------------------------------------------------------------------------- #
# config_from_env                                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("clean_env")
def test_env_without_keys_gives_the_defaults():
    assert config_from_env() == Config()


def test_env_is_read_with_todays_names(clean_env):
    clean_env.setenv("HTTP_TIMEOUT", "3")
    clean_env.setenv("HTTP_RETRY_COUNT", "1")
    clean_env.setenv("JWKS_CACHE_MAX_ENTRIES", "16")
    assert config_from_env() == Config(
        http_timeout=3.0, http_retry_max_attempts=1, cache_max_entries=16
    )


def test_env_prefix(clean_env):
    clean_env.setenv("APP_DISCO_CACHE_TTL", "300")
    clean_env.setenv("DISCO_CACHE_TTL", "900")
    assert config_from_env("APP_") == Config(discovery_cache_ttl=300.0)


def test_env_error_names_the_variable(clean_env):
    clean_env.setenv("APP_MAX_JWKS_SIZE", "0")
    with pytest.raises(ConfigError) as exc:
        config_from_env(prefix="APP_")
    assert exc.value.issues == (ConfigIssue("APP_MAX_JWKS_SIZE", "must be at least 1"),)


def test_every_config_field_has_a_key():
    assert set(KEYS.values()) == {f.name for f in dataclasses.fields(Config)}


# --------------------------------------------------------------------------- #
# The library never uses the helpers                                           #
# --------------------------------------------------------------------------- #


def _imported_modules(source: Path) -> set[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


def test_no_library_module_imports_the_helpers():
    package = Path(py_identity_model.__file__).parent
    importers = {
        str(path.relative_to(package))
        for path in package.rglob("*.py")
        if path.name != "config_helpers.py"
        and any(
            name.split(".")[-1] == "config_helpers" for name in _imported_modules(path)
        )
    }
    assert importers == set()


def test_importing_the_library_does_not_load_the_helpers():
    code = (
        "import sys, py_identity_model, py_identity_model.aio;"
        "print('py_identity_model.config_helpers' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"


def test_helpers_are_not_re_exported_at_the_top_level():
    exported = set(py_identity_model.__all__)
    assert {"config_from_env", "config_from_mapping"} & exported == set()
