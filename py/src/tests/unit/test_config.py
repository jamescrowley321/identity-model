"""Unit tests for the typed configuration surface (spec/config.md).

Test ids reference the configuration conformance cases in
``spec/vectors/config.json`` (CFG-1xx strict, 3xx precedence, 4xx redaction,
5xx source).
"""

import dataclasses
from typing import cast

import pytest

from py_identity_model import (
    ClientAuthMethod,
    Config,
    ConfigError,
    EnvSource,
    MappingSource,
    Secret,
)


pytestmark = pytest.mark.unit


def _src(**values):
    return MappingSource(values)


def _codes(exc: ConfigError) -> set[str]:
    return {issue.code for issue in exc.issues}


def _keys(exc: ConfigError) -> set[str]:
    return {k for issue in exc.issues for k in issue.keys}


def _full(cfg: Config) -> dict:
    """Every resolved field as a plain dict (secret exposed) for deep-equality.

    Per the repo test-assertion standard we compare the *whole* resolved value
    against an expected dict rather than spot-checking individual fields.
    """
    out: dict[str, object] = {}
    for field in dataclasses.fields(cfg):
        value = getattr(cfg, field.name)
        out[field.name] = value.expose() if isinstance(value, Secret) else value
    return out


# --------------------------------------------------------------------------- #
# CFG-1xx: strict validation                                                   #
# --------------------------------------------------------------------------- #


def test_cfg101_missing_required_fails_closed():
    with pytest.raises(ConfigError) as ei:
        Config.build(env=False, group="client")
    assert _codes(ei.value) == {"CFG-001"}
    assert {"client.discovery_url", "client.id"} <= _keys(ei.value)


def test_cfg102_stray_client_fragment_without_group():
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{"client.id": "spa"})], env=False, group=None)
    assert "CFG-002" in _codes(ei.value)
    assert "client.discovery_url" in _keys(ei.value)


def test_cfg103_missing_secret_for_secret_requiring_method():
    with pytest.raises(ConfigError) as ei:
        Config.build(
            sources=[
                _src(
                    **{
                        "client.discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
                        "client.id": "confidential",
                    }
                )
            ],
            env=False,
            group="client",
            client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        )
    assert "CFG-002" in _codes(ei.value)
    assert "client.secret" in _keys(ei.value)


def test_cfg104_invalid_value_never_defaults():
    with pytest.raises(ConfigError) as ei:
        Config.build(
            sources=[_src(**{"http.timeout": "soon", "http.retry.max_attempts": "-2"})],
            env=False,
        )
    assert _codes(ei.value) == {"CFG-003"}
    assert {"http.timeout", "http.retry.max_attempts"} <= _keys(ei.value)


def test_cfg105_empty_string_is_present_but_invalid():
    with pytest.raises(ConfigError) as ei:
        Config.build(
            sources=[_src(**{"http.timeout": "", "jwks.max_keys": "   "})], env=False
        )
    assert _codes(ei.value) == {"CFG-003"}
    assert {"http.timeout", "jwks.max_keys"} <= _keys(ei.value)


def test_cfg106_all_errors_collected_atomically():
    with pytest.raises(ConfigError) as ei:
        Config.build(
            sources=[_src(**{"http.timeout": "nope", "client.id": "spa"})],
            env=False,
            group="client",
        )
    # invalid http.timeout (CFG-003) AND missing client.discovery_url (CFG-001)
    assert _codes(ei.value) == {"CFG-003", "CFG-001"}
    # registry order: http.timeout comes before client.discovery_url
    ordered = [k for issue in ei.value.issues for k in issue.keys]
    assert ordered.index("http.timeout") < ordered.index("client.discovery_url")


def test_cfg108_absent_optional_keys_take_defaults():
    # Mirrors spec/test-fixtures/config/strict-defaults.json, deep-equality
    # over the *entire* resolved value so a mutated default cannot survive.
    cfg = Config.build(
        sources=[
            _src(
                **{
                    "client.discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
                    "client.id": "spa-client",
                }
            )
        ],
        env=False,
        group="client",
    )
    assert _full(cfg) == {
        "http_timeout": 30.0,
        "http_retry_max_attempts": 3,
        "http_retry_base_delay": 1.0,
        "jwks_max_size": 524288,
        "jwks_max_keys": 100,
        "jwks_cache_ttl": 86400.0,
        "discovery_cache_ttl": 3600.0,
        "jwks_kid_miss_cooldown": 5.0,
        "jwks_cache_max_entries": 64,
        "discovery_cache_max_entries": 64,
        "client_discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
        "client_id": "spa-client",
        "client_secret": None,
        "client_scope": "openid profile email",
        "client_audience": "spa-client",  # defaults to client id
        "client_redirect_uri": "",
        "client_post_login_redirect": "/",
        "client_post_logout_redirect": "/",
        "client_excluded_paths": ("/docs", "/openapi.json", "/health"),
    }


def test_cfg109_config_is_immutable():
    cfg = Config.build(env=False)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.http_timeout = 5.0  # type: ignore[misc]


def test_cfg110_zero_cache_entries_is_unbounded():
    cfg = Config.build(sources=[_src(**{"jwks.cache.max_entries": "0"})], env=False)
    assert cfg.jwks_cache_max_entries == 0


def test_cfg111_url_must_be_absolute():
    with pytest.raises(ConfigError) as ei:
        Config.build(
            sources=[
                _src(
                    **{
                        "client.discovery_url": "issuer.example.com/x",
                        "client.id": "spa",
                    }
                )
            ],
            env=False,
            group="client",
        )
    assert "CFG-003" in _codes(ei.value)
    assert "client.discovery_url" in _keys(ei.value)


def test_ttl_clamp_below_min_is_rejected_in_strict_mode():
    # strict mode does not silently clamp — below the [60, 86400] floor is CFG-003
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{"jwks.cache.ttl": "5"})], env=False)
    assert "CFG-003" in _codes(ei.value)
    assert "jwks.cache.ttl" in _keys(ei.value)


def test_ttl_clamp_above_max_is_rejected_in_strict_mode():
    # strict mode does not silently clamp — above the [60, 86400] ceiling is CFG-003
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{"jwks.cache.ttl": "999999"})], env=False)
    assert _codes(ei.value) == {"CFG-003"}
    assert "jwks.cache.ttl" in _keys(ei.value)


def test_ttl_at_max_boundary_is_accepted():
    # the upper bound is inclusive: exactly the ceiling constructs (kills a
    # `>` -> `>=` mutation of the clamp check)
    cfg = Config.build(sources=[_src(**{"jwks.cache.ttl": "86400"})], env=False)
    assert cfg.jwks_cache_ttl == 86400.0


def test_http_timeout_zero_is_rejected_exclusive_lower_bound():
    # Contract (spec/config.md HTTP transport row) mandates http.timeout > 0.
    # Zero is a footgun and must NOT construct — kills a `<=` -> `<` bound mutation.
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{"http.timeout": "0"})], env=False)
    assert _codes(ei.value) == {"CFG-003"}
    assert "http.timeout" in _keys(ei.value)


def test_http_timeout_negative_is_rejected():
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{"http.timeout": "-1"})], env=False)
    assert _codes(ei.value) == {"CFG-003"}
    assert "http.timeout" in _keys(ei.value)


def test_http_timeout_small_positive_is_accepted():
    # the bound is exactly 0 (exclusive), not a wholesale reject: a tiny
    # positive value constructs — kills an over-rejection mutation.
    cfg = Config.build(sources=[_src(**{"http.timeout": "0.001"})], env=False)
    assert cfg.http_timeout == 0.001


@pytest.mark.parametrize(
    ("key", "raw"),
    [
        ("http.timeout", "nan"),
        ("http.timeout", "inf"),
        ("http.retry.base_delay", "nan"),
        ("http.retry.base_delay", "-inf"),
        ("jwks.cache.ttl", "inf"),
    ],
)
def test_non_finite_floats_are_rejected(key, raw):
    # NaN/Inf parse as floats but are not finite -> CFG-003 (never accepted,
    # never silently defaulted). NaN also slips past every range comparison,
    # so the finiteness gate is the only thing rejecting it.
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{key: raw})], env=False)
    assert _codes(ei.value) == {"CFG-003"}
    assert key in _keys(ei.value)


# NOTE (CFG-107, uniform bool parsing): out of scope for the Python typed
# surface. The only boolean-typed keys in the contract are the test-tier
# TEST_REQUIRE_LIVE / TEST_REQUIRE_HTTPS harness keys (spec/config.md §Test
# tier), which this registry does not implement, so there is no bool key to
# exercise and no bool parser to test. The strict-bool-parsing.json fixture is
# proven by the languages that implement the test tier.


# --------------------------------------------------------------------------- #
# CFG-3xx: precedence & composition                                            #
# --------------------------------------------------------------------------- #


def test_cfg301_override_beats_every_source():
    cfg = Config.build(
        overrides={"http.timeout": "12"},
        sources=[_src(**{"http.timeout": "45"})],
        env=False,
    )
    assert cfg.http_timeout == 12.0


def test_cfg302_earlier_source_wins():
    cfg = Config.build(
        sources=[_src(**{"http.timeout": "20"}), _src(**{"http.timeout": "80"})],
        env=False,
    )
    assert cfg.http_timeout == 20.0


def test_cfg303_env_is_implicitly_last(monkeypatch):
    monkeypatch.setenv("HTTP_TIMEOUT", "80")
    cfg = Config.build(sources=[_src(**{"http.timeout": "20"})], env=True)
    assert cfg.http_timeout == 20.0  # custom source beats env


def test_cfg304_default_only_when_unyielded():
    cfg = Config.build(sources=[_src(**{"http.retry.max_attempts": "7"})], env=False)
    assert cfg.http_retry_max_attempts == 7
    assert cfg.http_timeout == 30.0  # unyielded -> registry default


def test_cfg305_alias_resolves_within_env_source(monkeypatch):
    monkeypatch.delenv("HTTP_RETRY_MAX_ATTEMPTS", raising=False)
    monkeypatch.setenv("HTTP_RETRY_COUNT", "2")
    cfg = Config.build(env=True)
    assert cfg.http_retry_max_attempts == 2  # alias honored
    monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "5")
    cfg2 = Config.build(env=True)
    assert cfg2.http_retry_max_attempts == 5  # primary wins over alias


def test_cfg305_alias_in_higher_source_beats_primary_in_lower_source(monkeypatch):
    # Cross-source case (spec/test-fixtures/config/precedence-alias-within-source
    # .json, first case): a higher-precedence source that resolves the value via
    # its alias env name wins over a lower-precedence source supplying the
    # primary. Alias resolution happens *within* the higher source before it
    # falls through to the next.
    monkeypatch.delenv("HTTP_RETRY_MAX_ATTEMPTS", raising=False)
    monkeypatch.setenv("HTTP_RETRY_COUNT", "2")  # alias only, in the env source
    cfg = Config.build(
        # higher-precedence EnvSource yields 2 via the alias; the lower source's
        # primary value (9) must lose.
        sources=[EnvSource(), _src(**{"http.retry.max_attempts": "9"})],
        env=False,
    )
    assert cfg.http_retry_max_attempts == 2


def test_cfg305_lower_source_wins_when_higher_source_silent():
    # Control for the cross-source case: with no alias/primary in the higher
    # (empty) source, the lower source's value is used — proves the win above is
    # the alias resolving, not the ordering alone.
    cfg = Config.build(
        sources=[_src(), _src(**{"http.retry.max_attempts": "9"})],
        env=False,
    )
    assert cfg.http_retry_max_attempts == 9


# --------------------------------------------------------------------------- #
# CFG-4xx: redaction                                                           #
# --------------------------------------------------------------------------- #


def _client_with_secret() -> Config:
    return Config.build(
        sources=[
            _src(
                **{
                    "client.discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
                    "client.id": "confidential",
                    "client.secret": "s3cr3t-sentinel-VALUE",
                }
            )
        ],
        env=False,
        group="client",
        client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
    )


def test_cfg401_repr_and_str_redact_secret():
    cfg = _client_with_secret()
    assert "s3cr3t-sentinel-VALUE" not in repr(cfg)
    assert "<redacted>" in repr(cfg)
    assert str(cfg.client_secret) == "<redacted>"
    assert "s3cr3t-sentinel-VALUE" not in repr(cfg.client_secret)


def test_cfg403_errors_name_keys_not_values():
    with pytest.raises(ConfigError) as ei:
        Config.build(
            sources=[
                _src(
                    **{
                        "client.discovery_url": "not-a-url-SENTINEL",
                        "client.id": "id-SENTINEL",
                        "client.secret": "secret-SENTINEL",
                    }
                )
            ],
            env=False,
            group="client",
            client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        )
    rendered = str(ei.value)
    assert "client.discovery_url" in rendered
    assert "not-a-url-SENTINEL" not in rendered
    assert "secret-SENTINEL" not in rendered


def test_cfg404_secret_access_is_explicit():
    cfg = _client_with_secret()
    assert isinstance(cfg.client_secret, Secret)
    assert cfg.client_secret.expose() == "s3cr3t-sentinel-VALUE"


# --------------------------------------------------------------------------- #
# CFG-5xx: source behavior                                                     #
# --------------------------------------------------------------------------- #


def test_cfg501_unknown_keys_discarded():
    cfg = Config.build(
        sources=[MappingSource({"http.timeout": "25", "totally.unknown": "ignore"})],
        env=False,
    )
    assert cfg.http_timeout == 25.0


def test_cfg502_failing_source_fails_closed():
    class Boom:
        name = "broken"

        def resolve(self, keys):
            raise RuntimeError("backend down")

    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[Boom()], env=False)
    assert "CFG-004" in _codes(ei.value)
    assert any("broken" in k for k in _keys(ei.value))


@pytest.mark.parametrize("bad_value", [None, 5, 3.14, ["not", "a", "string"], object()])
def test_source_returning_non_string_is_contained_not_crashing(bad_value):
    # Sources supply raw strings only (spec/config.md §Sources). A source that
    # misbehaves by returning a non-string MUST be contained as a controlled
    # CFG-004 collected into ConfigError — never an uncontained AttributeError
    # out of build() from the downstream .strip()/.split(). pytest.raises here
    # would fail loudly if an AttributeError leaked instead.
    class NonString:
        name = "non-string-source"

        def resolve(self, keys):
            # cast launders the deliberate contract violation past the type
            # checker: the source claims a str value but returns a non-str.
            return {"http.timeout": cast("str", bad_value)}

    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[NonString()], env=False)
    assert "CFG-004" in _codes(ei.value)
    assert any("non-string-source" in k for k in _keys(ei.value))
    assert "http.timeout" in _keys(ei.value)


def test_non_string_source_value_does_not_fall_through_to_default():
    # A misbehaving source that "supplies" a key with a non-string does not get
    # silently ignored so the registry default sneaks in — construction fails
    # closed with the CFG-004 issue, so no Config is produced at all.
    class NonString:
        name = "bad"

        def resolve(self, keys):
            return {"http.timeout": cast("str", 123)}

    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[NonString()], env=False)
    assert _codes(ei.value) == {"CFG-004"}


def test_cfg503_source_consulted_once_with_key_list():
    calls: list[tuple[str, ...]] = []

    class Counting:
        name = "counting"

        def resolve(self, keys):
            calls.append(tuple(keys))
            return {}

    Config.build(sources=[Counting()], env=False)
    assert len(calls) == 1
    assert "http.timeout" in calls[0]  # received the registry key list


# --------------------------------------------------------------------------- #
# No import-time / hidden env reads                                            #
# --------------------------------------------------------------------------- #


def test_env_free_construction_ignores_environment(monkeypatch):
    monkeypatch.setenv("HTTP_TIMEOUT", "999")
    cfg = Config.build(env=False)
    assert cfg.http_timeout == 30.0  # env=False must not read the environment


def test_from_env_reads_environment(monkeypatch):
    monkeypatch.setenv("HTTP_TIMEOUT", "42")
    cfg = Config.from_env()
    assert cfg.http_timeout == 42.0


def test_client_prefix_is_applied(monkeypatch):
    monkeypatch.setenv(
        "OIDC_DISCOVERY_URL",
        "https://issuer.example.com/.well-known/openid-configuration",
    )
    monkeypatch.setenv("OIDC_CLIENT_ID", "spa")
    cfg = Config.from_env(group="client")
    assert cfg.client_id == "spa"
    assert (
        cfg.client_discovery_url
        == "https://issuer.example.com/.well-known/openid-configuration"
    )
