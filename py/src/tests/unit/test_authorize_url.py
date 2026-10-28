"""Unit tests for authorization URL builder."""

from urllib.parse import parse_qs, urlparse

import pytest

from py_identity_model import build_par_authorization_url as top_level_helper
from py_identity_model.aio import build_par_authorization_url as aio_helper
from py_identity_model.core.authorize_url import (
    build_authorization_url,
    build_par_authorization_url,
)
from py_identity_model.sync import build_par_authorization_url as sync_helper


AUTHZ_ENDPOINT = "https://auth.example.com/authorize"


@pytest.mark.unit
class TestBuildAuthorizationUrl:
    def test_basic_url(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT, client_id="app1", redirect_uri="https://app.com/cb"
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        assert parsed.scheme == "https"
        assert params["client_id"] == ["app1"]
        assert params["redirect_uri"] == ["https://app.com/cb"]
        assert params["response_type"] == ["code"]
        assert params["scope"] == ["openid"]

    def test_pkce_params(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            code_challenge="challenge123",
            code_challenge_method="S256",
        )
        params = parse_qs(urlparse(url).query)

        assert params["code_challenge"] == ["challenge123"]
        assert params["code_challenge_method"] == ["S256"]

    def test_state_and_nonce(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            state="csrf_token",
            nonce="replay_nonce",
        )
        params = parse_qs(urlparse(url).query)

        assert params["state"] == ["csrf_token"]
        assert params["nonce"] == ["replay_nonce"]

    def test_custom_scope(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            scope="openid profile email",
        )
        params = parse_qs(urlparse(url).query)
        assert params["scope"] == ["openid profile email"]

    def test_extra_params(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            login_hint="user@example.com",
        )
        params = parse_qs(urlparse(url).query)
        assert params["login_hint"] == ["user@example.com"]

    def test_endpoint_with_existing_query(self):
        url = build_authorization_url(
            "https://auth.example.com/authorize?tenant=abc",
            client_id="app1",
            redirect_uri="https://app.com/cb",
        )
        assert "?tenant=abc&" in url

    def test_omitted_optional_params(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
        )
        params = parse_qs(urlparse(url).query)
        assert "state" not in params
        assert "nonce" not in params
        assert "code_challenge" not in params

    def test_extra_params_do_not_clobber_required_params(self):
        """MF-1: extra_params are additive, required params always present."""
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            login_hint="user@example.com",
            prompt="consent",
        )
        params = parse_qs(urlparse(url).query)
        # Required params intact
        assert params["client_id"] == ["app1"]
        assert params["redirect_uri"] == ["https://app.com/cb"]
        assert params["response_type"] == ["code"]
        # Extra params present
        assert params["login_hint"] == ["user@example.com"]
        assert params["prompt"] == ["consent"]

    def test_code_challenge_without_method_rejected(self):
        """SF-2: code_challenge without code_challenge_method raises ValueError."""
        with pytest.raises(ValueError, match="RFC 7636"):
            build_authorization_url(
                AUTHZ_ENDPOINT,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="challenge123",
            )

    def test_code_challenge_method_without_challenge_rejected(self):
        """SF-2: code_challenge_method without code_challenge raises ValueError."""
        with pytest.raises(ValueError, match="RFC 7636"):
            build_authorization_url(
                AUTHZ_ENDPOINT,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge_method="S256",
            )

    def test_endpoint_fragment_stripped(self):
        """SF-7: URI fragment on authorization_endpoint is stripped."""
        url = build_authorization_url(
            "https://auth.example.com/authorize#fragment",
            client_id="app1",
            redirect_uri="https://app.com/cb",
        )
        assert "#fragment" not in url
        params = parse_qs(urlparse(url).query)
        assert params["client_id"] == ["app1"]

    def test_empty_endpoint_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_authorization_url(
                "",
                client_id="app1",
                redirect_uri="https://app.com/cb",
            )

    def test_whitespace_endpoint_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_authorization_url(
                "   ",
                client_id="app1",
                redirect_uri="https://app.com/cb",
            )

    def test_invalid_code_challenge_method_raises(self):
        with pytest.raises(ValueError, match=r"S256.*plain"):
            build_authorization_url(
                AUTHZ_ENDPOINT,
                client_id="app1",
                redirect_uri="https://app.com/cb",
                code_challenge="challenge123",
                code_challenge_method="foo",
            )

    def test_plain_code_challenge_method_accepted(self):
        url = build_authorization_url(
            AUTHZ_ENDPOINT,
            client_id="app1",
            redirect_uri="https://app.com/cb",
            code_challenge="challenge123",
            code_challenge_method="plain",
        )
        params = parse_qs(urlparse(url).query)
        assert params["code_challenge_method"] == ["plain"]


REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc"


@pytest.mark.unit
class TestBuildParAuthorizationUrl:
    """FAPI 2.0 Security Profile §5.3.3.2, RFC 9126 §4."""

    def test_only_client_id_and_request_uri(self):
        url = build_par_authorization_url(AUTHZ_ENDPOINT, "app1", REQUEST_URI)
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == AUTHZ_ENDPOINT
        assert parse_qs(parsed.query) == {
            "client_id": ["app1"],
            "request_uri": [REQUEST_URI],
        }

    def test_exact_encoding(self):
        assert build_par_authorization_url(AUTHZ_ENDPOINT, "app 1", "urn:x") == (
            f"{AUTHZ_ENDPOINT}?client_id=app+1&request_uri=urn%3Ax"
        )

    def test_endpoint_query_kept(self):
        url = build_par_authorization_url(f"{AUTHZ_ENDPOINT}?tenant=a", "app1", "urn:x")
        assert url == f"{AUTHZ_ENDPOINT}?tenant=a&client_id=app1&request_uri=urn%3Ax"

    @pytest.mark.parametrize("suffix", ["?", "?tenant=a&"])
    def test_trailing_delimiter_not_doubled(self, suffix):
        url = build_par_authorization_url(f"{AUTHZ_ENDPOINT}{suffix}", "app1", "urn:x")
        assert url == f"{AUTHZ_ENDPOINT}{suffix}client_id=app1&request_uri=urn%3Ax"

    def test_trailing_ampersand_without_query_starts_query(self):
        url = build_par_authorization_url(f"{AUTHZ_ENDPOINT}&", "app1", "urn:x")
        assert url == f"{AUTHZ_ENDPOINT}&?client_id=app1&request_uri=urn%3Ax"

    def test_fragment_stripped(self):
        url = build_par_authorization_url(f"{AUTHZ_ENDPOINT}#frag", "app1", "urn:x")
        assert url == f"{AUTHZ_ENDPOINT}?client_id=app1&request_uri=urn%3Ax"

    @pytest.mark.parametrize(
        ("endpoint", "client_id", "request_uri", "name"),
        [
            ("", "app1", REQUEST_URI, "authorization_endpoint"),
            ("   ", "app1", REQUEST_URI, "authorization_endpoint"),
            (AUTHZ_ENDPOINT, "", REQUEST_URI, "client_id"),
            (AUTHZ_ENDPOINT, "app1", "", "request_uri"),
            (AUTHZ_ENDPOINT, "app1", "   ", "request_uri"),
        ],
    )
    def test_empty_argument_raises(self, endpoint, client_id, request_uri, name):
        with pytest.raises(ValueError, match=f"^{name} must not be empty$"):
            build_par_authorization_url(endpoint, client_id, request_uri)

    @pytest.mark.parametrize(
        ("endpoint", "client_id", "request_uri", "name"),
        [
            (None, "app1", REQUEST_URI, "authorization_endpoint"),
            (AUTHZ_ENDPOINT, 1, REQUEST_URI, "client_id"),
            (AUTHZ_ENDPOINT, "app1", None, "request_uri"),
            (AUTHZ_ENDPOINT, "app1", {"uri": "urn:x"}, "request_uri"),
        ],
    )
    def test_non_string_argument_raises(self, endpoint, client_id, request_uri, name):
        with pytest.raises(ValueError, match=f"^{name} must be a string$"):
            build_par_authorization_url(endpoint, client_id, request_uri)

    def test_exported_from_every_api_surface(self):
        assert top_level_helper is build_par_authorization_url
        assert sync_helper is build_par_authorization_url
        assert aio_helper is build_par_authorization_url
