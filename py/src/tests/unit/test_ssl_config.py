"""Tests for TLS verification settings resolved from an injected Config."""

import json
import os
import subprocess
import sys
import textwrap

import pytest

from py_identity_model import Config, ConfigError
from py_identity_model.ssl_config import get_ssl_verify


# Environment variables the library used to read for its CA bundle. They must
# now have no effect on the library's own TLS settings.
LEGACY_CA_BUNDLE_ENV_VARS = ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE")


@pytest.fixture
def ca_bundle(tmp_path) -> str:
    """A readable file usable as Config.ca_bundle."""
    path = tmp_path / "ca-bundle.crt"
    path.write_text("placeholder CA bundle\n")
    return str(path)


class TestGetSSLVerify:
    """Test get_ssl_verify(config) for httpx integration."""

    def test_get_ssl_verify_returns_config_ca_bundle(self, ca_bundle):
        """Test that get_ssl_verify returns Config.ca_bundle when set."""
        assert get_ssl_verify(Config(ca_bundle=ca_bundle)) == ca_bundle

    def test_get_ssl_verify_default_true(self):
        """Test that get_ssl_verify returns True when no CA bundle is configured."""
        assert get_ssl_verify(Config()) is True

    def test_empty_ca_bundle_is_rejected(self):
        """Test that an empty CA bundle path is an invalid Config, not 'unset'."""
        with pytest.raises(ConfigError) as exc_info:
            Config(ca_bundle="")

        assert [issue.setting for issue in exc_info.value.issues] == ["ca_bundle"]

    @pytest.mark.parametrize("env_var", LEGACY_CA_BUNDLE_ENV_VARS)
    def test_get_ssl_verify_ignores_ca_bundle_env_vars(
        self, monkeypatch, ca_bundle, env_var
    ):
        """Regression: the legacy CA-bundle env vars are not read by the library."""
        for name in LEGACY_CA_BUNDLE_ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv(env_var, ca_bundle)

        assert get_ssl_verify(Config()) is True

    def test_get_ssl_verify_prefers_config_over_env_vars(
        self, monkeypatch, ca_bundle, tmp_path
    ):
        """Test that Config.ca_bundle is used even when legacy env vars are set."""
        env_bundle = tmp_path / "env-bundle.crt"
        env_bundle.write_text("other CA bundle\n")
        for name in LEGACY_CA_BUNDLE_ENV_VARS:
            monkeypatch.setenv(name, str(env_bundle))

        assert get_ssl_verify(Config(ca_bundle=ca_bundle)) == ca_bundle


class TestImportHasNoEnvironmentSideEffect:
    """Importing the library must not mutate the host process environment.

    ``SSL_CERT_FILE`` is honoured by ``ssl``, ``requests``, ``urllib3``, ``boto3``
    and anything else in the process. Writing it from an import changes the TLS
    trust store of code that never asked this library for anything, with no
    opt-out and no way to restore the prior value.

    These assertions must run in a fresh interpreter: the parent process has
    already imported the package, so an in-process re-import is a no-op that
    would pass without testing anything.
    """

    @staticmethod
    def _env_changed_by_importing(module: str) -> dict[str, list[str | None]]:
        """Import ``module`` in a subprocess; return every env var it changed.

        The returned mapping is ``{name: [before, after]}`` and is empty when the
        import left the environment untouched.
        """
        code = textwrap.dedent(
            """
            import importlib
            import json
            import os
            import sys

            before = dict(os.environ)
            importlib.import_module(sys.argv[1])
            after = dict(os.environ)

            print(
                json.dumps(
                    {
                        key: [before.get(key), after.get(key)]
                        for key in before.keys() | after.keys()
                        if before.get(key) != after.get(key)
                    }
                )
            )
            """
        )

        # Inherit the parent environment so the child can find the interpreter's
        # packages, but pin the three variables whose interaction drives the
        # legacy REQUESTS_CA_BUNDLE -> SSL_CERT_FILE write: only REQUESTS_CA_BUNDLE
        # set is exactly the state that triggers it.
        child_env = dict(os.environ)
        child_env.pop("SSL_CERT_FILE", None)
        child_env.pop("CURL_CA_BUNDLE", None)
        child_env["REQUESTS_CA_BUNDLE"] = "/path/to/legacy-ca-bundle.crt"

        # timeout: an import that deadlocks would otherwise hang forever — the
        # unit-test job sets no timeout-minutes, so a stuck child burns the
        # six-hour default instead of failing.
        result = subprocess.run(
            [sys.executable, "-c", code, module],
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        # check=True would raise CalledProcessError without the captured stderr,
        # reporting a child-side ImportError as a bare exit status.
        assert result.returncode == 0, (
            f"importing {module} in a subprocess failed "
            f"(exit {result.returncode}):\n{result.stderr}"
        )
        # Parse only the last non-empty line: a dependency banner or a
        # sitecustomize print on the child's stdout would otherwise surface as an
        # unrelated JSONDecodeError.
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        assert lines, f"subprocess produced no output; stderr:\n{result.stderr}"
        return json.loads(lines[-1])

    @pytest.mark.parametrize(
        "module",
        ["py_identity_model", "py_identity_model.sync", "py_identity_model.aio"],
    )
    def test_import_does_not_write_ssl_cert_file(self, module):
        """Test that importing an entry point leaves SSL_CERT_FILE unset."""
        changed = self._env_changed_by_importing(module)

        assert "SSL_CERT_FILE" not in changed, (
            f"importing {module} set SSL_CERT_FILE to "
            f"{changed.get('SSL_CERT_FILE', [None, None])[1]!r}, silently "
            "changing the TLS trust store for every other library in the process"
        )

    @pytest.mark.parametrize(
        "module",
        ["py_identity_model", "py_identity_model.sync", "py_identity_model.aio"],
    )
    def test_import_leaves_environment_unchanged(self, module):
        """Test that importing an entry point changes no environment variable."""
        changed = self._env_changed_by_importing(module)

        assert changed == {}, f"importing {module} mutated os.environ: {changed}"
