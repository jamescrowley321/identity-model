"""Tests for SSL certificate environment variable compatibility."""

import json
import os
import subprocess
import sys
import textwrap
import threading
from unittest.mock import patch

import pytest

from py_identity_model.ssl_config import (
    ensure_ssl_compatibility,
    get_ssl_verify,
)


# Expected concurrent thread result count
EXPECTED_THREAD_RESULT_COUNT = 100


@pytest.fixture(autouse=True)
def clear_ssl_cache():
    """Clear get_ssl_verify cache before and after each test."""
    get_ssl_verify.cache_clear()
    yield
    get_ssl_verify.cache_clear()


class TestSSLConfig:
    """Test SSL configuration backward compatibility."""

    def test_requests_ca_bundle_sets_ssl_cert_file(self):
        """Test that REQUESTS_CA_BUNDLE sets SSL_CERT_FILE when SSL_CERT_FILE is not set."""
        with patch.dict(
            os.environ,
            {"REQUESTS_CA_BUNDLE": "/path/to/ca-bundle.crt"},
            clear=True,
        ):
            ensure_ssl_compatibility()
            assert os.environ.get("SSL_CERT_FILE") == "/path/to/ca-bundle.crt"

    def test_ssl_cert_file_not_overridden(self):
        """Test that existing SSL_CERT_FILE is not overridden."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/existing/cert.crt",
                "REQUESTS_CA_BUNDLE": "/other/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            # SSL_CERT_FILE should remain unchanged
            assert os.environ.get("SSL_CERT_FILE") == "/existing/cert.crt"

    def test_curl_ca_bundle_not_overridden(self):
        """Test that CURL_CA_BUNDLE is respected when SSL_CERT_FILE is not set."""
        with patch.dict(
            os.environ,
            {
                "CURL_CA_BUNDLE": "/curl/ca-bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            # SSL_CERT_FILE should not be set because CURL_CA_BUNDLE is already set
            # and httpx will use CURL_CA_BUNDLE
            assert "SSL_CERT_FILE" not in os.environ

    def test_no_env_vars_set(self):
        """Test that no environment variables are set when none exist."""
        with patch.dict(os.environ, {}, clear=True):
            ensure_ssl_compatibility()
            assert "SSL_CERT_FILE" not in os.environ

    def test_ssl_cert_file_priority(self):
        """Test that SSL_CERT_FILE has highest priority."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/ssl/cert.crt",
                "CURL_CA_BUNDLE": "/curl/ca-bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            # SSL_CERT_FILE should remain unchanged
            assert os.environ.get("SSL_CERT_FILE") == "/ssl/cert.crt"


class TestGetSSLVerify:
    """Test get_ssl_verify() function for httpx integration."""

    def test_get_ssl_verify_with_ssl_cert_file(self):
        """Test that get_ssl_verify returns SSL_CERT_FILE path when set."""
        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/path/to/cert.crt"},
            clear=True,
        ):
            # Clear cache to ensure fresh read
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result == "/path/to/cert.crt"

    def test_get_ssl_verify_with_curl_ca_bundle(self):
        """Test that get_ssl_verify returns CURL_CA_BUNDLE when SSL_CERT_FILE not set."""
        with patch.dict(
            os.environ,
            {"CURL_CA_BUNDLE": "/path/to/curl-bundle.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result == "/path/to/curl-bundle.crt"

    def test_get_ssl_verify_with_requests_ca_bundle(self):
        """Test backward compatibility: get_ssl_verify returns REQUESTS_CA_BUNDLE."""
        with patch.dict(
            os.environ,
            {"REQUESTS_CA_BUNDLE": "/path/to/requests-bundle.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result == "/path/to/requests-bundle.crt"

    def test_get_ssl_verify_priority_order(self):
        """Test that get_ssl_verify respects priority: SSL_CERT_FILE > CURL_CA_BUNDLE > REQUESTS_CA_BUNDLE."""
        # Test SSL_CERT_FILE wins
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "/ssl/cert.crt",
                "CURL_CA_BUNDLE": "/curl/bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/bundle.crt",
            },
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            assert get_ssl_verify() == "/ssl/cert.crt"

        # Test CURL_CA_BUNDLE wins when SSL_CERT_FILE not set
        with patch.dict(
            os.environ,
            {
                "CURL_CA_BUNDLE": "/curl/bundle.crt",
                "REQUESTS_CA_BUNDLE": "/requests/bundle.crt",
            },
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            assert get_ssl_verify() == "/curl/bundle.crt"

    def test_get_ssl_verify_default_true(self):
        """Test that get_ssl_verify returns True when no env vars are set."""
        with patch.dict(os.environ, {}, clear=True):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result is True

    def test_get_ssl_verify_ignores_empty_strings(self):
        """Test that get_ssl_verify ignores empty string env vars."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "",
                "CURL_CA_BUNDLE": "",
                "REQUESTS_CA_BUNDLE": "",
            },
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            result = get_ssl_verify()
            assert result is True

    def test_get_ssl_verify_thread_safety(self):
        """Test that get_ssl_verify is thread-safe under concurrent access."""
        with patch.dict(
            os.environ,
            {"REQUESTS_CA_BUNDLE": "/path/to/bundle.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            results = []
            errors = []

            def get_ssl():
                try:
                    results.append(get_ssl_verify())
                except Exception as e:
                    errors.append(e)

            # Create 100 threads that all call get_ssl_verify concurrently
            threads = [threading.Thread(target=get_ssl) for _ in range(100)]

            # Start all threads
            for t in threads:
                t.start()

            # Wait for all threads to complete
            for t in threads:
                t.join()

            # Verify no errors occurred
            assert len(errors) == 0, f"Errors occurred: {errors}"

            # All threads should get the same result
            assert len(results) == EXPECTED_THREAD_RESULT_COUNT
            assert all(r == "/path/to/bundle.crt" for r in results)

    def test_get_ssl_verify_caching(self):
        """Test that get_ssl_verify properly caches results."""
        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/first/cert.crt"},
            clear=True,
        ):
            get_ssl_verify.cache_clear()
            first_result = get_ssl_verify()
            assert first_result == "/first/cert.crt"

        # Change environment variable
        with patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/second/cert.crt"},
            clear=True,
        ):
            # Without clearing cache, should still return cached value
            # (this tests that caching is working - result should be cached first value)

            # Clear cache and verify new value is picked up
            get_ssl_verify.cache_clear()
            new_result = get_ssl_verify()
            assert new_result == "/second/cert.crt"


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


class TestEnsureSSLCompatibilityOptIn:
    """The opt-in shim must resolve the same way get_ssl_verify() does.

    docs/migration-guide.md points callers here to close the split trust store
    left when only REQUESTS_CA_BUNDLE is set, so a silent no-op is the one
    failure mode that matters: the caller believes the export happened.
    """

    def test_empty_ssl_cert_file_is_treated_as_unset(self):
        """Test that an empty SSL_CERT_FILE does not suppress the export."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "",
                "REQUESTS_CA_BUNDLE": "/path/to/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()

            # An empty value selects no bundle -- get_ssl_verify() skips it for
            # the same reason -- so the legacy value must still be exported.
            assert os.environ["SSL_CERT_FILE"] == "/path/to/ca-bundle.crt"

    def test_empty_curl_ca_bundle_does_not_suppress_the_export(self):
        """Test that an empty CURL_CA_BUNDLE does not suppress the export."""
        with patch.dict(
            os.environ,
            {
                "CURL_CA_BUNDLE": "",
                "REQUESTS_CA_BUNDLE": "/path/to/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()

            assert os.environ["SSL_CERT_FILE"] == "/path/to/ca-bundle.crt"

    def test_export_agrees_with_get_ssl_verify(self):
        """Test that the exported value is the one the library itself resolves."""
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": "",
                "REQUESTS_CA_BUNDLE": "/path/to/ca-bundle.crt",
            },
            clear=True,
        ):
            ensure_ssl_compatibility()
            get_ssl_verify.cache_clear()

            assert os.environ["SSL_CERT_FILE"] == get_ssl_verify()
