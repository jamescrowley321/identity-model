"""Unit tests for the typed configuration surface (spec/config.md).

Test ids reference the configuration conformance cases in
``spec/conformance/config.json`` (CFG-1xx strict, 3xx precedence, 4xx redaction,
5xx source).
"""

import dataclasses

import pytest

from py_identity_model import (
    ClientAuthMethod,
    Config,
    ConfigError,
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
    cfg = Config.build(
        sources=[
            _src(
                **{
                    "client.discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
                    "client.id": "spa",
                }
            )
        ],
        env=False,
        group="client",
    )
    assert cfg.client_scope == "openid profile email"
    assert cfg.client_audience == "spa"  # defaults to client id
    assert cfg.client_post_login_redirect == "/"
    assert cfg.client_excluded_paths == ("/docs", "/openapi.json", "/health")
    assert cfg.http_timeout == 30.0
    assert cfg.jwks_cache_ttl == 86400.0
    assert cfg.discovery_cache_ttl == 3600.0


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


def test_ttl_clamp_is_rejected_in_strict_mode():
    # strict mode does not silently clamp — out of range is CFG-003
    with pytest.raises(ConfigError) as ei:
        Config.build(sources=[_src(**{"jwks.cache.ttl": "5"})], env=False)
    assert "CFG-003" in _codes(ei.value)


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
