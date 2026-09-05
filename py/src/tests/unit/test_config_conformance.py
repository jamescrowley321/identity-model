"""Behavior-proving configuration conformance.

Unlike ``test_config.py`` (hand-authored cases that *mirror* the spec by
convention), this runner **loads the canonical cross-language vectors** in
``spec/test-fixtures/config/*.json`` (merged in #637) and executes each one
against the real :class:`Config`. It is the drift guard: the Python
implementation is asserted to conform to the same fixtures the Go/Rust runners
key to, so the impl and the contract in ``spec/config.md`` cannot silently
diverge.

Coverage split:

* ``strict``-mode fixtures — executed here. ``type: "env"`` sources are driven
  through the **real process environment** (``monkeypatch.setenv`` + a real
  :class:`EnvSource`), so this also exercises the ``from_env`` reading path the
  unit tests skip (they pass ``env=False`` with ``MappingSource`` fakes).
* ``legacy``-mode fixtures — behavior-preservation of pre-Config reads (TLS CA
  chain, cache-entry divergence, kid-miss cooldown). The strict typed Config in
  #605 does not implement these, so they are **skipped as n/a** rather than
  faked. When a legacy-mode resolver lands, drop the skip.
* Fixtures referencing a logical key not (yet) in the registry (e.g. CFG-107
  uniform bool parsing, declared out of scope in ``config.py``) are skipped.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from py_identity_model import (
    ClientAuthMethod,
    Config,
    ConfigError,
    EnvSource,
    MappingSource,
    Secret,
)
from py_identity_model.core.config import _REGISTRY


pytestmark = pytest.mark.unit

# ── fixture discovery ─────────────────────────────────────────────────────── #
# repo root = <root>/py/src/tests/unit/this_file.py -> parents[4]
_FIXTURE_DIR = Path(__file__).resolve().parents[4] / "spec" / "test-fixtures" / "config"

# logical key id -> Config dataclass attribute (the contract's own mapping).
_LOGICAL_TO_ATTR = {spec.logical: spec.attr for spec in _REGISTRY}
_DEFAULT_PREFIX = "OIDC_"


class _RaisingSource:
    """A source whose ``resolve`` errors — drives the CFG-004 fail-closed path."""

    def __init__(self, name: str) -> None:
        self.name = name

    def resolve(self, keys):
        raise RuntimeError(f"source is intentionally broken (requested {list(keys)})")


def _clear_registry_env(monkeypatch: pytest.MonkeyPatch, prefixes: set[str]) -> None:
    """Isolate the process env: unset every name any registry key could read."""
    for spec in _REGISTRY:
        for name in spec.env:
            monkeypatch.delenv(name, raising=False)
            if spec.prefixed:
                for prefix in prefixes:
                    monkeypatch.delenv(f"{prefix}{name}", raising=False)


def _expand() -> list:
    """Flatten each fixture into one (id, scenario) per executable case."""
    if not _FIXTURE_DIR.is_dir():
        return [pytest.param(None, id="no-fixtures-present")]
    params = []
    for path in sorted(_FIXTURE_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        base = {k: v for k, v in data.items() if k != "cases"}
        if "cases" in data:
            for i, case in enumerate(data["cases"]):
                params.append(pytest.param({**base, **case}, id=f"{path.stem}[{i}]"))
        else:
            params.append(pytest.param(data, id=path.stem))
    return params


def _make_chain(scenario: dict, monkeypatch: pytest.MonkeyPatch, prefix: str) -> list:
    """Build the source chain (highest precedence first) from a scenario."""
    chain: list = []
    for src in scenario.get("sources", []):
        name = src.get("name", "src")
        if src.get("raises"):
            chain.append(_RaisingSource(name))
        elif src.get("type") == "env":
            for env_name, value in (src.get("values") or {}).items():
                monkeypatch.setenv(env_name, value)
            chain.append(EnvSource(prefix=prefix, name=name))
        else:
            chain.append(MappingSource(src.get("values") or {}, name=name))
    if "env" in scenario:  # shorthand: a single env source
        for env_name, value in scenario["env"].items():
            monkeypatch.setenv(env_name, value)
        chain.append(EnvSource(prefix=prefix, name="env"))
    if scenario.get("raw") is not None and scenario.get("key"):  # shorthand map source
        chain.append(MappingSource({scenario["key"]: scenario["raw"]}, name="raw"))
    return chain


def _build(scenario: dict, monkeypatch: pytest.MonkeyPatch) -> Config:
    prefix = scenario.get("client_prefix") or _DEFAULT_PREFIX
    _clear_registry_env(monkeypatch, {_DEFAULT_PREFIX, prefix})
    chain = _make_chain(scenario, monkeypatch, prefix)
    return Config.build(
        sources=chain,
        overrides=scenario.get("overrides"),
        env=False,  # only the fixture's own sources apply
        group=scenario.get("group"),
        client_auth_method=ClientAuthMethod(scenario.get("client_auth_method", "none")),
    )


def _assert_config(
    scenario: dict, monkeypatch: pytest.MonkeyPatch, expected: dict
) -> None:
    cfg = _build(scenario, monkeypatch)
    actual: dict[str, object] = {}
    for logical in expected:
        value = getattr(cfg, _LOGICAL_TO_ATTR[logical])
        if isinstance(value, Secret):
            value = value.expose()
        elif isinstance(value, tuple):
            value = list(value)
        actual[logical] = value
    assert actual == expected


def _assert_error(scenario: dict, monkeypatch: pytest.MonkeyPatch, err: dict) -> None:
    with pytest.raises(ConfigError) as excinfo:
        _build(scenario, monkeypatch)
    issues = excinfo.value.issues
    if "errors" in err:  # atomic multi-error collection
        got = {(i.code, tuple(sorted(i.keys))) for i in issues}
        want = {(e["code"], tuple(sorted(e["keys"]))) for e in err["errors"]}
        assert got == want
    elif "source" in err:  # CFG-004 names the failing source
        assert any(
            i.code == err["code"] and f"source:{err['source']}" in i.keys
            for i in issues
        ), f"no {err['code']} issue naming source {err['source']!r}: {issues}"
    else:  # single code + keys
        assert err["code"] in {i.code for i in issues}
        keys_for_code = {k for i in issues if i.code == err["code"] for k in i.keys}
        assert keys_for_code == set(err["keys"])


def _assert_rendered(
    scenario: dict, monkeypatch: pytest.MonkeyPatch, expect: dict
) -> None:
    try:
        cfg = _build(scenario, monkeypatch)
        surfaces = [repr(cfg), str(cfg)]
        for field in dataclasses.fields(cfg):
            value = getattr(cfg, field.name)
            surfaces += [repr(value), str(value)]
        blob = "\n".join(surfaces)
    except ConfigError as exc:  # CFG-403: redaction in the error message too
        blob = str(exc)
    for needle in expect.get("rendered_includes", []):
        assert needle in blob
    for sentinel in expect.get("rendered_excludes", []):
        assert sentinel not in blob


@pytest.mark.parametrize("scenario", _expand())
def test_config_vector(scenario, monkeypatch):
    if scenario is None:
        pytest.skip("config vectors absent on this checkout (pre-merge branch)")
    if scenario.get("mode") == "legacy":
        pytest.skip(
            "legacy-mode behavior-preservation not implemented by strict Config"
        )

    expect = scenario["expect"]

    # Skip cases that reference a logical key the strict registry doesn't carry
    # (e.g. CFG-107 test.require_live bool parsing, declared out of scope).
    referenced: set[str] = set(expect.get("config", {}))
    err = expect.get("error", {})
    referenced |= set(err.get("keys", []))
    referenced |= {k for e in err.get("errors", []) for k in e["keys"]}
    if scenario.get("key"):
        referenced.add(scenario["key"])
    unknown = {k for k in referenced if "." in k and k not in _LOGICAL_TO_ATTR}
    if unknown:
        pytest.skip(f"references out-of-registry key(s): {sorted(unknown)}")

    # Two real EnvSources can't hold isolated views of the single process env,
    # so multi-env-source precedence fixtures aren't faithfully representable
    # here; that behavior is covered by test_env_alias_resolves_and_primary_wins
    # and the precedence-source-order fixture.
    env_sources = [
        s
        for s in scenario.get("sources", [])
        if s.get("type") == "env" and not s.get("raises")
    ]
    if len(env_sources) > 1:
        pytest.skip(
            "multiple isolated env sources not representable over one process env"
        )

    if "config" in expect:
        _assert_config(scenario, monkeypatch, expect["config"])
    elif "error" in expect:
        _assert_error(scenario, monkeypatch, expect["error"])
    elif "rendered_includes" in expect or "rendered_excludes" in expect:
        _assert_rendered(scenario, monkeypatch, expect)
    else:
        pytest.skip(f"unrecognized expect shape: {sorted(expect)}")


# --------------------------------------------------------------------------- #
# Real-environment path (the from_env / EnvSource reads unit tests never run)  #
# --------------------------------------------------------------------------- #

_DISCOVERY_URL = "https://issuer.example.com/.well-known/openid-configuration"


@pytest.fixture
def clean_env(monkeypatch):
    _clear_registry_env(monkeypatch, {_DEFAULT_PREFIX, "APP_"})
    return monkeypatch


def test_from_env_reads_real_process_environment(clean_env):
    clean_env.setenv("OIDC_DISCOVERY_URL", _DISCOVERY_URL)
    clean_env.setenv("OIDC_CLIENT_ID", "spa-client")

    cfg = Config.from_env(group="client")

    assert cfg.client_id == "spa-client"
    assert cfg.client_discovery_url == _DISCOVERY_URL


def test_from_env_honors_custom_client_prefix(clean_env):
    clean_env.setenv("APP_DISCOVERY_URL", _DISCOVERY_URL)
    clean_env.setenv("APP_CLIENT_ID", "spa-client")
    # Default OIDC_ names are unset, so a default-prefix read would fail closed.
    cfg = Config.from_env(prefix="APP_", group="client")
    assert cfg.client_id == "spa-client"


def test_env_alias_resolves_and_primary_wins(clean_env):
    # http.retry.max_attempts reads ("HTTP_RETRY_MAX_ATTEMPTS", "HTTP_RETRY_COUNT").
    from_alias = 7
    clean_env.setenv("HTTP_RETRY_COUNT", str(from_alias))  # alias only
    assert Config.from_env().http_retry_max_attempts == from_alias

    from_primary = 9
    clean_env.setenv("HTTP_RETRY_MAX_ATTEMPTS", str(from_primary))  # primary set too
    assert Config.from_env().http_retry_max_attempts == from_primary


def test_client_group_env_names_require_the_prefix(clean_env):
    # Unprefixed CLIENT_ID must NOT satisfy the prefixed client.id key.
    clean_env.setenv("CLIENT_ID", "should-be-ignored")
    clean_env.setenv("OIDC_DISCOVERY_URL", _DISCOVERY_URL)
    with pytest.raises(ConfigError) as excinfo:
        Config.from_env(group="client")
    assert "CFG-001" in {i.code for i in excinfo.value.issues}


def test_secret_from_real_env_is_redacted_everywhere(clean_env):
    clean_env.setenv("OIDC_DISCOVERY_URL", _DISCOVERY_URL)
    clean_env.setenv("OIDC_CLIENT_ID", "confidential-client")
    clean_env.setenv("OIDC_CLIENT_SECRET", "s3cr3t-sentinel-VALUE")

    cfg = Config.from_env(
        group="client", client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC
    )

    assert isinstance(cfg.client_secret, Secret)
    assert cfg.client_secret.expose() == "s3cr3t-sentinel-VALUE"
    rendered = "\n".join(
        [repr(cfg), str(cfg), repr(cfg.client_secret), str(cfg.client_secret)]
    )
    assert "<redacted>" in rendered
    assert "s3cr3t-sentinel-VALUE" not in rendered
