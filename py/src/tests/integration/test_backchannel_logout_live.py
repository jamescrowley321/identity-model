"""Live integration test for OpenID Connect Back-Channel Logout 1.0.

Confirms the library validates a *real* logout token pushed by a running OP.
The flow: register a client whose ``backchannel_logout_uri`` points at a local
HTTP receiver, complete an auth-code login, trigger RP-Initiated Logout, and
capture the ``logout_token`` the OP pushes to the receiver — then validate it
with ``validate_logout_token``.

This end-to-end push requires the OP to reach a host-side receiver. The shipped
fixtures bind loopback-only (no container->host route), so the test is opt-in:
it runs only when ``TEST_BACKCHANNEL_LOGOUT_RECEIVER_URL`` names a
provider-reachable URL whose port this receiver binds. Otherwise it skips
cleanly. Full container->host wiring is deferred to KC.6; the structural
validation rules are already covered by the unit suite (LOGOUT-004..010).
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from py_identity_model import (
    ClientDeleteRequest,
    ClientRegistrationRequest,
    TokenValidationConfig,
    build_end_session_url,
    delete_client,
    register_client,
    validate_logout_token,
)
from py_identity_model.core.logout_logic import BACKCHANNEL_LOGOUT_EVENT

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow
from .test_dynamic_registration_live import _obtain_initial_access_token


CAPTURE_TIMEOUT_SECONDS = 15.0
POLL_INTERVAL_SECONDS = 0.25
DEFAULT_HTTP_PORT = 80


class _LogoutTokenReceiver(BaseHTTPRequestHandler):
    """Captures the ``logout_token`` from an OP's back-channel POST."""

    def do_POST(self):  # http.server dispatch name
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        body = self.rfile.read(length).decode() if length else ""
        token = parse_qs(body).get("logout_token", [None])[0]
        if token:
            self.server.captured_tokens.append(token)  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002, ARG002  silence logging
        return


def _start_receiver(port: int) -> HTTPServer:
    server = HTTPServer(("0.0.0.0", port), _LogoutTokenReceiver)  # noqa: S104
    server.captured_tokens = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.mark.integration
class TestBackChannelLogoutLive:
    """Validate a real OP-pushed logout token (opt-in, receiver-gated)."""

    def test_validate_pushed_logout_token(
        self,
        provider_capabilities,
        discovery_document,
        raw_discovery,
        test_config,
    ):
        """A logout token pushed by the OP passes ``validate_logout_token``.

        Covers the live half of LOGOUT-004..010: signature/iss/aud/exp plus the
        ``events`` back-channel member on a genuine OP-minted token.
        """
        if "backchannel_logout" not in provider_capabilities:
            pytest.skip("Provider does not advertise backchannel_logout_supported")
        if "registration" not in provider_capabilities:
            pytest.skip("Registration required to wire a receiver URL")

        receiver_url = test_config.get("TEST_BACKCHANNEL_LOGOUT_RECEIVER_URL")
        if not receiver_url:
            pytest.skip(
                "TEST_BACKCHANNEL_LOGOUT_RECEIVER_URL not set — no "
                "provider-reachable back-channel receiver wired (see KC.6)"
            )
        port = urlparse(receiver_url).port or DEFAULT_HTTP_PORT
        redirect_uri = test_config["TEST_AUTH_CODE_REDIRECT_URI"]

        # Binding can fail (privileged default port, or port already in use).
        # Skip cleanly rather than error before the try/finally is entered.
        try:
            server = _start_receiver(port)
        except OSError as exc:
            pytest.skip(f"receiver port {port} unbindable: {exc}")
        client_uri: str | None = None
        mgmt_token: str | None = None
        try:
            initial_access_token = _obtain_initial_access_token(
                raw_discovery, test_config
            )
            registered = register_client(
                ClientRegistrationRequest(
                    address=discovery_document.registration_endpoint,
                    redirect_uris=[redirect_uri],
                    client_name="kc5-bcl-receiver",
                    token_endpoint_auth_method="client_secret_basic",
                    initial_access_token=initial_access_token,
                    extra_metadata={
                        "backchannel_logout_uri": receiver_url,
                        "backchannel_logout_session_required": True,
                    },
                )
            )
            if not registered.is_successful:
                pytest.skip(f"Could not register receiver client: {registered.error}")
            assert registered.client_id
            assert registered.client_secret
            assert registered.registration_client_uri
            assert registered.registration_access_token
            client_uri = registered.registration_client_uri
            mgmt_token = registered.registration_access_token

            # Log in so the OP has a session to terminate.
            flow = perform_auth_code_flow(
                discovery=discovery_document,
                client_id=registered.client_id,
                redirect_uri=redirect_uri,
                config=AuthCodeFlowConfig(
                    client_secret=registered.client_secret,
                    scope="openid profile email",
                ),
            )
            id_token = (flow["token_response"].token or {}).get("id_token")
            if not id_token:
                pytest.skip("Auth-code token response carried no id_token")

            # Trigger RP-Initiated Logout → OP pushes logout_token to receiver.
            logout_url = build_end_session_url(
                end_session_endpoint=discovery_document.end_session_endpoint,
                id_token_hint=id_token,
                client_id=registered.client_id,
            )
            try:
                with httpx.Client(follow_redirects=True, timeout=10.0) as client:
                    client.get(logout_url)
            except httpx.RequestError:
                # The OP processes the logout (and fires the back-channel push)
                # before it 302s to the post-logout redirect; that redirect
                # target may have no live listener. Swallow the unreachable
                # redirect and let the poll below decide on the actual push.
                pass

            logout_token = _await_token(server)
            if logout_token is None:
                pytest.skip(
                    "OP did not push a logout_token to the receiver within "
                    f"{CAPTURE_TIMEOUT_SECONDS}s (reachability not wired)"
                )

            claims = validate_logout_token(
                logout_token,
                TokenValidationConfig(
                    perform_disco=True,
                    audience=registered.client_id,
                    issuer=raw_discovery["issuer"],
                ),
                issuer=test_config["TEST_ISSUER"],
            )
            assert isinstance(claims, dict)
            assert BACKCHANNEL_LOGOUT_EVENT in claims.get("events", {})
            assert claims.get("sub") or claims.get("sid")
        finally:
            server.shutdown()
            server.server_close()
            if client_uri and mgmt_token:
                delete_client(
                    ClientDeleteRequest(
                        address=client_uri,
                        registration_access_token=mgmt_token,
                    )
                )


def _await_token(server: HTTPServer) -> str | None:
    """Poll the receiver up to the capture timeout for a logout token."""
    deadline = time.monotonic() + CAPTURE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if server.captured_tokens:  # type: ignore[attr-defined]
            return server.captured_tokens[0]  # type: ignore[attr-defined]
        time.sleep(POLL_INTERVAL_SECONDS)
    return None
