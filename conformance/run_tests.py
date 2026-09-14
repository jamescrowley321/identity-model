#!/usr/bin/env python3
"""OIDF conformance suite test runner.

Automates test plan creation and execution against the OpenID Foundation
conformance suite, driving the RP harness through each test module.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import textwrap
import time
from urllib.parse import urljoin, urlparse
import zipfile

from cryptography.hazmat.primitives.asymmetric import ec
import httpx


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("conformance-runner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUITE_BASE_URL = "https://localhost.emobix.co.uk:8443"
RP_BASE_URL = "http://localhost:8888"
POLL_INTERVAL = 2  # seconds
MAX_POLL_ATTEMPTS = 60  # 2 minutes max per test

LOCAL_HOSTNAMES = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "localhost.emobix.co.uk",
    }
)


def _is_local_suite(url: str) -> bool:
    """Check if the suite URL points to a local conformance instance."""
    hostname = urlparse(url).hostname or ""
    return hostname in LOCAL_HOSTNAMES


def _parse_content_disposition_filename(disposition: str) -> str | None:
    """Extract the filename from a ``Content-Disposition`` header.

    Uses the stdlib ``email`` parser so quoted, token, and RFC 5987/2231
    extended (``filename*=``) forms are all handled correctly, rather than a
    greedy regex that over-captures multi-parameter headers and ignores
    ``filename*``. Returns ``None`` when no filename is present.
    """
    if not disposition:
        return None
    msg = Message()
    msg["content-disposition"] = disposition
    return msg.get_filename()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TestResult:
    """Result of a single conformance test module."""

    test_name: str
    test_id: str
    status: str  # PASSED, WARNING, FAILED, REVIEW, SKIPPED, INTERRUPTED
    log_url: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# Suite API client
# ---------------------------------------------------------------------------


class ConformanceSuiteClient:
    """REST API client for the OIDF conformance suite."""

    def __init__(self, base_url: str, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(
            verify=not _is_local_suite(base_url),
            timeout=30.0,
            headers=headers,
        )

    def create_plan(
        self,
        plan_name: str,
        variant: dict,
        alias: str,
        rp_base_url: str = RP_BASE_URL,
        publish: str = "",
        client_overrides: dict | None = None,
        server_jwks: dict | None = None,
    ) -> dict:
        """Create a test plan.

        ``publish`` controls whether the suite makes the plan's results publicly
        visible on the published-tests list: "" (default) keeps it private,
        "summary" / "everything" publish it. The downloadable plan export is
        available regardless of this setting.

        ``client_overrides`` is the config file's ``client`` block, merged over
        the default client registration. The logout profiles use it to register a
        ``backchannel_logout_uri`` / ``post_logout_redirect_uris`` (without which
        the OP cannot post a Back-Channel Logout Token or accept an RP-Initiated
        Logout redirect); FAPI 2.0 uses it to register the RP's public ``jwks``
        (for ``private_key_jwt`` assertion verification) and set
        ``token_endpoint_auth_method``. For the certified OIDC-client profiles the
        block is just ``{client_id, client_secret}``, so the merge is a no-op.

        ``server_jwks`` supplies the OP's own signing key set — required by the
        FAPI 2.0 client plan's ``LoadServerJWKs`` step (the certified OIDC-client
        plans auto-generate theirs, so they pass ``None``).

        Returns the plan response including plan ID and list of test modules.
        """
        # Build the plan configuration
        client_config = {
            "client_id": "conformance-rp",
            "client_secret": "conformance-rp-secret",
            "redirect_uri": f"{rp_base_url}/callback",
        }
        if client_overrides:
            client_config.update(client_overrides)
        server_config: dict = {"discoveryUrl": ""}
        if server_jwks:
            server_config["jwks"] = server_jwks
        plan_config = {
            "alias": alias,
            "description": f"py-identity-model conformance: {alias}",
            "publish": publish,
            "server": server_config,
            "client": client_config,
            "client2": {
                "client_id": "conformance-rp-2",
                "client_secret": "conformance-rp-2-secret",
            },
        }

        # Variant is a single JSON-encoded query parameter (per official conformance.py)
        params: dict[str, str] = {"planName": plan_name}
        if variant:
            params["variant"] = json.dumps(variant)

        response = self.client.post(
            f"{self.base_url}/api/plan",
            params=params,
            json=plan_config,
        )
        response.raise_for_status()
        return response.json()

    def create_test_module(self, test_name: str, plan_id: str) -> dict:
        """Create a test module instance within a plan."""
        response = self.client.post(
            f"{self.base_url}/api/runner",
            params={"test": test_name, "plan": plan_id},
        )
        response.raise_for_status()
        return response.json()

    def start_test(self, module_id: str) -> dict:
        """Start a test module and return the response with exposed issuer info."""
        response = self.client.post(
            f"{self.base_url}/api/runner/{module_id}",
        )
        response.raise_for_status()
        return response.json()

    def get_test_info(self, module_id: str) -> dict:
        """Get current status of a test module."""
        response = self.client.get(
            f"{self.base_url}/api/info/{module_id}",
        )
        response.raise_for_status()
        return response.json()

    def get_test_log(self, module_id: str) -> list:
        """Get detailed log entries for a test module."""
        response = self.client.get(
            f"{self.base_url}/api/log/{module_id}",
        )
        response.raise_for_status()
        return response.json()

    def poll_until_done(self, module_id: str) -> dict:
        """Poll a test module until it reaches a terminal state."""
        for _ in range(MAX_POLL_ATTEMPTS):
            info = self.get_test_info(module_id)
            status = info.get("status", "UNKNOWN")
            if status in ("FINISHED", "INTERRUPTED"):
                return info
            logger.debug("Test %s status: %s", module_id, status)
            time.sleep(POLL_INTERVAL)
        return {"status": "TIMEOUT", "id": module_id}

    def download_plan_export(
        self, plan_id: str, kind: str = "export"
    ) -> tuple[str, bytes]:
        """Download a plan-results export zip for a completed plan.

        ``kind`` is "export" (JSON + RSA signature — cheap, tamper-evident, the
        suite's recommended CI artifact) or "exporthtml" (human-readable HTML).
        The endpoint shape mirrors the suite's own ``scripts/conformance.py``
        client: ``GET /api/plan/{kind}/{plan_id}``. Returns
        ``(filename, zip_bytes)`` where ``filename`` comes from the
        Content-Disposition header. Uses a longer read timeout than the default
        client because the suite generates the archive on demand.

        NOTE: this is NOT the OIDF certification package. The certification
        package (``POST /api/plan/{plan_id}/certificationpackage``) additionally
        requires a signed Certification of Conformance PDF and the RP
        client-side logs zip, and it publishes and permanently freezes the plan.
        That is the manual submission step (see #331) and is deliberately not
        automated here.
        """
        response = self.client.get(
            f"{self.base_url}/api/plan/{kind}/{plan_id}",
            timeout=120.0,
        )
        response.raise_for_status()
        content = response.content
        # The export is a zip; a 200 carrying an HTML proxy-error page or an
        # empty body would otherwise be written out as worthless "evidence".
        if not content.startswith(b"PK"):
            raise ValueError(
                f"plan export for {plan_id!r} is not a zip "
                f"(got {len(content)} bytes, content-type "
                f"{response.headers.get('content-type', 'unknown')!r})"
            )
        filename = (
            _parse_content_disposition_filename(
                response.headers.get("content-disposition", "")
            )
            or f"{plan_id}-{kind}.zip"
        )
        return filename, content


# ---------------------------------------------------------------------------
# RP driver
# ---------------------------------------------------------------------------


# Test type determines how the runner drives the RP for each test module.
# - "discovery_only": Just fetch discovery document (no auth flow)
# - "auth_no_userinfo": Full auth flow but skip UserInfo fetch
# - "auth_full": Full auth flow including UserInfo
# - "auth_double": Two sequential full auth flows (key rotation between flows)
DISCOVERY_ONLY_TESTS = frozenset(
    {
        "oidcc-client-test-discovery-openid-config",
    }
)
AUTH_NO_USERINFO_TESTS = frozenset(
    {
        "oidcc-client-test-discovery-jwks-uri-keys",
    }
)
DOUBLE_FLOW_TESTS = frozenset(
    {
        "oidcc-client-test-signing-key-rotation",
    }
)
# Dynamic RP: modules whose auth flow needs a dynamically-registered client
# (the plan has no pre-configured client_id).
DYNAMIC_AUTH_TESTS = frozenset(
    {
        "oidcc-client-test-discovery-jwks-uri-keys",
        "oidcc-client-test-idtoken-sig-none",
        "oidcc-client-test-signing-key-rotation",
        "oidcc-client-test-signing-key-rotation-just-before-signing",
        "oidcc-client-test-userinfo-signed",
        "oidcc-client-test-request-uri-signed-rs256",
        "oidcc-client-test-request-uri-signed-none",
    }
)
# Dynamic RP: modules satisfied by the registration step alone (no auth flow),
# so driving an auth flow afterwards would be an illegal FINISHED -> RUNNING.
DYNAMIC_REGISTER_ONLY_TESTS = frozenset(
    {
        "oidcc-client-test-dynamic-registration",
    }
)

# Logout profiles (the RP-side certification plans oidcc-client-rp-initiated-
# logout-rp-basic and oidcc-client-back-channel-logout-rp-basic). Every module
# in these plans is driven the same way: a normal login, then an RP-Initiated
# Logout. For RP-Initiated Logout the OP redirects to /post-logout-callback; for
# Back-Channel Logout the OP additionally posts a Logout Token to the RP's
# registered /backchannel-logout while it processes the end-session request.
LOGOUT_PROFILES = frozenset(
    {
        "rpinitiated-logout-rp",
        "backchannel-logout-rp",
    }
)

# RP-Initiated Logout modules that must be driven WITHOUT a ``state`` on the
# logout request (state is optional per RP-Initiated Logout 1.0 §2). The rest
# send a state and verify the OP echoes it back unchanged.
NO_STATE_LOGOUT_TESTS = frozenset(
    {
        "oidcc-client-test-rp-init-logout-no-state",
    }
)

# Modules for an OPTIONAL feature the library deliberately does not support, so
# the RP declares non-support rather than driving a doomed flow.
# request-uri-signed-none requires an UNSIGNED (alg=none) request object, but
# py-identity-model excludes ``none`` from SUPPORTED_SIGNING_ALGORITHMS by design
# (unsigned request objects are a security downgrade). This is a legitimate
# declared non-support for OIDF certification, not a masked failure — recorded
# SKIPPED with the reason and never sent to the suite.
DECLARED_UNSUPPORTED_TESTS = frozenset(
    {
        "oidcc-client-test-request-uri-signed-none",
    }
)


def _get_test_type(test_name: str) -> str:
    """Determine the flow type for a given test module."""
    if test_name in DISCOVERY_ONLY_TESTS:
        return "discovery_only"
    if test_name in AUTH_NO_USERINFO_TESTS:
        return "auth_no_userinfo"
    if test_name in DOUBLE_FLOW_TESTS:
        return "auth_double"
    logger.info(
        "Test '%s' not in any special category, using auth_full flow", test_name
    )
    return "auth_full"


def drive_rp_discover(
    rp_base_url: str,
    issuer: str,
    test_id: str,
    test_name: str = "",
    profile: str = "",
) -> None:
    """Hit the RP's /discover endpoint to fetch discovery without starting an auth flow.

    Used for Config RP discovery-only tests where the suite only needs to
    observe the RP fetching the openid-configuration document.
    """
    params = {
        "issuer": issuer,
        "test_id": test_id,
        "test_name": test_name,
        "profile": profile,
    }

    with httpx.Client(verify=False, timeout=30.0) as client:
        try:
            response = client.get(f"{rp_base_url}/discover", params=params)
            logger.info(
                "RP discover completed: status=%d",
                response.status_code,
            )
        except httpx.HTTPError as exc:
            logger.warning("RP discover HTTP error (may be expected): %s", exc)


def drive_rp_register(
    rp_base_url: str,
    issuer: str,
    test_name: str = "",
    profile: str = "",
) -> str | None:
    """Register the RP dynamically (RFC 7591) for a Dynamic RP test module.

    The Dynamic RP plan has no pre-configured client, so the RP must register
    itself with each per-test OP before the auth flow. Returns the issued
    client_id (which the runner passes to /authorize; the RP fills the matching
    secret from its remembered registration), or None if registration did not
    complete.
    """
    params = {"issuer": issuer, "test_name": test_name, "profile": profile}
    with httpx.Client(verify=False, timeout=30.0) as client:
        try:
            response = client.get(f"{rp_base_url}/register", params=params)
            if response.is_success:
                client_id = response.json().get("client_id")
                logger.info("RP registered dynamically: client_id=%s", client_id)
                return client_id
            logger.warning("RP register returned status=%d", response.status_code)
        except httpx.HTTPError as exc:
            logger.warning("RP register HTTP error (may be expected): %s", exc)
    return None


class _FormPostParser(HTMLParser):
    """Parse an HTML form_post response to extract the action URL and fields."""

    def __init__(self) -> None:
        super().__init__()
        self.action: str = ""
        self.method: str = ""
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "form":
            self.action = attr_dict.get("action", "") or ""
            self.method = (attr_dict.get("method", "") or "").upper()
            self.fields = {}
        elif tag == "input" and (attr_dict.get("type") or "").lower() == "hidden":
            name = attr_dict.get("name") or ""
            value = attr_dict.get("value") or ""
            if name:
                self.fields[name] = value


def _parse_form_post(html: str) -> tuple[str, dict[str, str]] | None:
    """Extract action URL and hidden fields from a form_post HTML response.

    Returns (action_url, fields) or None if no POST form found.
    """
    parser = _FormPostParser()
    parser.feed(html)
    if parser.method == "POST" and parser.action:
        return parser.action, parser.fields
    return None


def drive_rp_authorize(
    rp_base_url: str,
    issuer: str,
    client_id: str,
    client_secret: str,
    test_id: str,
    use_pkce: bool = False,
    skip_userinfo: bool = False,
    use_request_uri: bool = False,
    test_name: str = "",
    profile: str = "",
    fapi2: bool = False,
    jarm: bool = False,
    mtls: bool = False,
) -> None:
    """Hit the RP's /authorize endpoint to start an auth flow.

    The RP will redirect to the conformance suite's OP, which handles
    the entire flow and redirects back to /callback. We just need to
    follow the redirects.

    In form_post mode, the OP returns an HTML page with a self-submitting
    form instead of a redirect. We detect this and POST the form data
    to the callback URL ourselves.
    """
    params = {
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": client_secret,
        "test_id": test_id,
        "test_name": test_name,
        "profile": profile,
        "use_pkce": str(use_pkce).lower(),
        "skip_userinfo": str(skip_userinfo).lower(),
        "use_request_uri": str(use_request_uri).lower(),
        "fapi2": str(fapi2).lower(),
        "jarm": str(jarm).lower(),
        "mtls": str(mtls).lower(),
    }

    # Follow all redirects through the full auth flow
    with httpx.Client(verify=False, timeout=30.0, follow_redirects=True) as client:
        try:
            response = client.get(f"{rp_base_url}/authorize", params=params)
            logger.info(
                "RP flow completed: status=%d, url=%s",
                response.status_code,
                response.url,
            )

            # Handle form_post: OP returns HTML with a self-submitting form
            content_type = response.headers.get("content-type", "")
            if response.status_code == httpx.codes.OK and "text/html" in content_type:
                form_data = _parse_form_post(response.text)
                if form_data:
                    action_url, fields = form_data
                    # The form's action attribute may be a relative URL
                    # (e.g. "/test/a/alias/callback"). httpx rejects
                    # relative URLs with httpx.InvalidURL, which does NOT
                    # inherit from httpx.HTTPError and would escape the
                    # exception handler below. Resolve the action URL
                    # against the current response URL first so the POST
                    # target is always absolute.
                    resolved_action = urljoin(str(response.url), action_url)
                    logger.info(
                        "Form post detected, submitting to %s with %d fields",
                        resolved_action,
                        len(fields),
                    )
                    post_response = client.post(resolved_action, data=fields)
                    if post_response.is_error:
                        logger.warning(
                            "Form post callback failed: status=%d, url=%s",
                            post_response.status_code,
                            post_response.url,
                        )
                    else:
                        logger.info(
                            "Form post submitted: status=%d, url=%s",
                            post_response.status_code,
                            post_response.url,
                        )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # httpx.InvalidURL is caught defensively here even though the
            # urljoin above should prevent it — if a future edit to the
            # form_post handler regresses the resolution, we'd rather log
            # and continue than crash the runner process uncaught.
            logger.warning("RP flow HTTP error (may be expected): %s", exc)


def drive_rp_logout(
    rp_base_url: str,
    issuer: str,
    client_id: str,
    client_secret: str,
    test_id: str,
    send_state: bool = True,
    test_name: str = "",
    profile: str = "",
) -> None:
    """Drive a login followed by an RP-Initiated Logout for a logout profile.

    Both logout profiles (RP-Initiated and Back-Channel) start the same way: the
    RP must have a live login before it can log out, so this first drives a full
    auth flow (which the RP records as ``_last_logout_context``), then hits the
    RP's ``/logout`` endpoint. ``/logout`` redirects the user agent to the OP's
    end-session endpoint; following the redirects carries the flow through the
    OP back to ``/post-logout-callback`` (RP-Initiated Logout state round-trip).

    For the Back-Channel profile the OP additionally posts a Logout Token to the
    RP's registered ``backchannel_logout_uri`` while it processes the end-session
    request — that is a server-to-server call the RP handles on its own, so no
    extra driving is needed here.

    ``send_state=False`` tells the RP to omit ``state`` from the logout request
    (the -no-state module); the default sends a state and expects it echoed.
    """
    # Step 1: log in so the RP has an id_token_hint + end_session endpoint.
    drive_rp_authorize(
        rp_base_url=rp_base_url,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        test_id=test_id,
        test_name=test_name,
        profile=profile,
    )

    # Step 2: initiate RP-Initiated Logout and follow the redirect chain.
    params = {
        "test_name": test_name,
        "profile": profile,
        "send_state": str(send_state).lower(),
    }
    with httpx.Client(verify=False, timeout=30.0, follow_redirects=True) as client:
        try:
            response = client.get(f"{rp_base_url}/logout", params=params)
            logger.info(
                "RP logout flow completed: status=%d, url=%s",
                response.status_code,
                response.url,
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.warning("RP logout HTTP error (may be expected): %s", exc)


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------


def _clear_rp_cache(rp_base_url: str) -> None:
    """Clear the RP's library caches before each test module.

    The conformance suite reconfigures the OP between tests. Stale
    discovery/JWKS caches cause signature verification failures and
    30s-per-retry backoff timeouts.
    """
    try:
        with httpx.Client(verify=False, timeout=5.0) as client:
            response = client.post(f"{rp_base_url}/clear-cache")
            response.raise_for_status()
            logger.info("Cleared RP caches: %s", response.json())
    except httpx.HTTPError as exc:
        logger.warning("Failed to clear RP caches (continuing): %s", exc)


def _fetch_rp_jwks(rp_base_url: str, path: str = "/fapi2-jwks") -> dict:
    """Fetch one of the RP's public JWKS endpoints from the harness.

    The harness generates its client key material at startup and exposes the
    public half at ``/fapi2-jwks`` (private_key_jwt signing key) and
    ``/fapi2-mtls-jwks`` (the mTLS client certificate, with x5c). Registering the
    right one with the suite lets the OP verify the RP's ``private_key_jwt``
    assertions or match its TLS-presented certificate. Raises if unreachable —
    a FAPI2 plan without a registered client key cannot pass.
    """
    with httpx.Client(verify=False, timeout=10.0) as client:
        response = client.get(f"{rp_base_url}{path}")
        response.raise_for_status()
        jwks = response.json()
    logger.info("Fetched RP JWKS from %s (%d key(s))", path, len(jwks.get("keys", [])))
    return jwks


def _b64u_uint(value: int) -> str:
    """base64url-encode an unsigned integer as a JWK field (RFC 7518 §6)."""
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _generate_server_signing_jwks() -> dict:
    """Generate an ephemeral server signing JWKS for the FAPI 2.0 client plan.

    Unlike the certified OIDC-client plans (whose ``GenerateServerConfiguration``
    step auto-mints the OP's keys), the FAPI 2.0 client plan uses
    ``GenerateServerConfigurationMTLS`` + ``LoadServerJWKs``, which require the
    plan config to *supply* the OP's own signing key set under ``server.jwks``.
    The suite then adds decoy keys, so the set must contain exactly one signing
    key of a supported variant — a single ES256 (P-256) key satisfies the FAPI
    2.0 PS256/ES256 allow-list. These keys are the *test OP's*, ephemeral per run;
    the RP never holds their private half.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.private_numbers()
    public = numbers.public_numbers
    private_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": "py-idm-conformance-server-es256",
        "x": _b64u_uint(public.x),
        "y": _b64u_uint(public.y),
        "d": _b64u_uint(numbers.private_value),
    }
    return {"keys": [private_jwk]}


def run_test_module(
    suite: ConformanceSuiteClient,
    test_name: str,
    plan_id: str,
    rp_base_url: str,
    client_id: str,
    client_secret: str,
    profile: str = "",
    dynamic: bool = False,
    fapi2: bool = False,
    jarm: bool = False,
    mtls: bool = False,
) -> TestResult:
    """Execute a single conformance test module."""
    logger.info("=" * 60)
    logger.info("Running test: %s", test_name)
    logger.info("=" * 60)

    # Declared non-support: record SKIPPED without touching the suite.
    if test_name in DECLARED_UNSUPPORTED_TESTS:
        reason = (
            "declared unsupported: py-identity-model does not create unsigned "
            "(alg=none) request objects (SUPPORTED_SIGNING_ALGORITHMS excludes "
            "'none' by design)"
        )
        logger.info("[SKIP] %s — %s", test_name, reason)
        return TestResult(
            test_name=test_name,
            test_id="",
            status="SKIPPED",
            detail=reason,
        )

    # Clear RP caches before each test to avoid stale JWKS/discovery
    _clear_rp_cache(rp_base_url)

    # Create the test module instance
    try:
        module_info = suite.create_test_module(test_name, plan_id)
    except httpx.HTTPStatusError as exc:
        logger.error("Failed to create test module %s: %s", test_name, exc)
        return TestResult(
            test_name=test_name,
            test_id="",
            status="FAILED",
            detail=f"Failed to create test module: {exc}",
        )

    module_id: str = module_info.get("id", module_info.get("name", "")) or ""
    logger.info("Test module created: %s", module_id)

    # Wait for the test module to finish setup (CREATED -> WAITING)
    # The conformance suite sets up the OP in a background thread after creation.
    # Do NOT call start_test — the test transitions to RUNNING when the RP connects.
    for _ in range(10):
        info = suite.get_test_info(module_id)
        if info.get("status") != "CREATED":
            break
        time.sleep(0.5)

    logger.info("Test ready, driving RP authorize flow...")

    # Extract the issuer from the module creation response URL
    issuer = module_info.get("url", "")
    if not issuer:
        logger.error("Could not determine issuer for test %s", test_name)
        return TestResult(
            test_name=test_name,
            test_id=module_id,
            status="FAILED",
            detail="Could not determine issuer URL from suite API",
        )
    # Ensure issuer has trailing slash (conformance suite expects it)
    if not issuer.endswith("/"):
        issuer += "/"

    # Drive the RP based on the test type
    test_type = _get_test_type(test_name)
    logger.info("Test type: %s", test_type)

    if profile in LOGOUT_PROFILES:
        # Logout profiles: log in, then drive an RP-Initiated Logout. For the
        # Back-Channel profile the OP posts a Logout Token to the RP's
        # /backchannel-logout on its own while processing the end-session.
        drive_rp_logout(
            rp_base_url=rp_base_url,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            test_id=module_id,
            send_state=test_name not in NO_STATE_LOGOUT_TESTS,
            test_name=test_name,
            profile=profile,
        )
    else:
        # Dynamic RP plan: the OP has no pre-configured client, so the RP
        # registers (RFC 7591) before it can authenticate. Some modules are
        # satisfied by the registration alone; the rest register, then run their
        # auth flow with the freshly issued client_id (the RP fills the secret
        # from its registration). Discovery/webfinger modules need neither and
        # keep their normal flow.
        register_only = dynamic and test_name in DYNAMIC_REGISTER_ONLY_TESTS
        if dynamic and (register_only or test_name in DYNAMIC_AUTH_TESTS):
            registered_id = drive_rp_register(
                rp_base_url=rp_base_url,
                issuer=issuer,
                test_name=test_name,
                profile=profile,
            )
            if registered_id:
                client_id = registered_id
                client_secret = ""

        # Dynamic auth modules use request_type=request_uri (JAR): the RP must
        # authorize with a signed request object referenced by request_uri.
        use_request_uri = dynamic and test_name in DYNAMIC_AUTH_TESTS

        if register_only:
            # Registration is the whole test — no auth flow to drive.
            pass
        elif test_type == "discovery_only":
            # Discovery-only tests: just fetch discovery, no auth flow
            drive_rp_discover(
                rp_base_url=rp_base_url,
                issuer=issuer,
                test_id=module_id,
                test_name=test_name,
                profile=profile,
            )
        elif test_type == "auth_double":
            # Double-flow tests (key rotation): drive two sequential auth flows.
            # The client is registered once (above) and reused across both flows;
            # the OP rotates its signing keys between them.
            logger.info("Driving first auth flow...")
            drive_rp_authorize(
                rp_base_url=rp_base_url,
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                test_id=module_id,
                use_request_uri=use_request_uri,
                test_name=test_name,
                profile=profile,
                fapi2=fapi2,
                jarm=jarm,
                mtls=mtls,
            )
            # Wait briefly for the suite to rotate keys
            time.sleep(1)
            logger.info("Driving second auth flow...")
            drive_rp_authorize(
                rp_base_url=rp_base_url,
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                test_id=module_id,
                use_request_uri=use_request_uri,
                test_name=test_name,
                profile=profile,
                fapi2=fapi2,
                jarm=jarm,
                mtls=mtls,
            )
        else:
            # Standard auth flow (with optional userinfo skip)
            drive_rp_authorize(
                rp_base_url=rp_base_url,
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                test_id=module_id,
                skip_userinfo=(test_type == "auth_no_userinfo"),
                use_request_uri=use_request_uri,
                test_name=test_name,
                profile=profile,
                fapi2=fapi2,
                jarm=jarm,
                mtls=mtls,
            )

    # Poll until the test finishes
    logger.info("Polling test status...")
    result_info = suite.poll_until_done(module_id)
    status = result_info.get("status", "UNKNOWN")
    result = result_info.get("result", status)

    # Map status to final result
    final_status = (result if result else "PASSED") if status == "FINISHED" else status

    log_url = f"{suite.base_url}/log-detail.html?log={module_id}"
    detail = ""

    # Fetch logs for failed tests
    if final_status in ("FAILED", "WARNING", "REVIEW"):
        try:
            logs = suite.get_test_log(module_id)
            # Extract failure messages
            failures = [
                entry
                for entry in logs
                if entry.get("result", "") in ("FAILURE", "WARNING")
            ]
            if failures:
                detail = "; ".join(
                    f"{f.get('src', '')}: {f.get('msg', '')}" for f in failures[:5]
                )
        except httpx.HTTPStatusError:
            pass

    log_symbol = {
        "PASSED": "PASS",
        "WARNING": "WARN",
        "FAILED": "FAIL",
        "REVIEW": "REVIEW",
        "SKIPPED": "SKIP",
    }.get(final_status, "????")
    logger.info("[%s] %s — %s", log_symbol, test_name, log_url)
    if detail:
        logger.info("  Detail: %s", detail)

    return TestResult(
        test_name=test_name,
        test_id=module_id,
        status=final_status,
        log_url=log_url,
        detail=detail,
    )


def run_plan(
    config_path: str,
    suite_base_url: str = SUITE_BASE_URL,
    rp_base_url: str = RP_BASE_URL,
    token: str | None = None,
    publish: str = "",
    profile: str = "",
) -> tuple[str, list[TestResult]]:
    """Run all tests in a conformance test plan.

    Returns a tuple of (plan_id, results).
    """
    # Load plan config
    config = json.loads(Path(config_path).read_text())
    plan_name = config["plan_name"]
    variant = config["variant"]
    alias = config["alias"]
    fapi2 = bool(config.get("fapi2", False))
    jarm = bool(config.get("jarm", False))
    mtls = bool(config.get("mtls", False))

    logger.info("Plan: %s (%s)", plan_name, alias)
    logger.info("Variant: %s", variant)
    logger.info("Suite: %s", suite_base_url)
    logger.info("RP: %s", rp_base_url)

    suite = ConformanceSuiteClient(suite_base_url, token=token)

    # Create the test plan. The config's client block is merged into the plan's
    # client registration so logout profiles register their backchannel_logout_uri
    # / post_logout_redirect_uris (and Dynamic its jwks) with the OP. FAPI 2.0
    # instead registers the RP's public JWKS (served at /fapi2-jwks) so the suite
    # can verify its private_key_jwt assertions, and supplies the OP's own signing
    # keys (LoadServerJWKs). The private half never leaves the RP.
    client_overrides: dict | None = config.get("client")
    server_jwks: dict | None = None
    if fapi2:
        if mtls:
            # mTLS: register the RP's client certificate for
            # self_signed_tls_client_auth and request cert-bound access tokens.
            # The suite's EnsureClientCertificateMatches compares the presented
            # TLS cert against a registered PEM ``certificate``, so supply that
            # (reconstructed from the jwks x5c) alongside the jwks.
            mtls_jwks = _fetch_rp_jwks(rp_base_url, "/fapi2-mtls-jwks")
            x5c = mtls_jwks["keys"][0]["x5c"][0]
            cert_pem = (
                "-----BEGIN CERTIFICATE-----\n"
                + "\n".join(textwrap.wrap(x5c, 64))
                + "\n-----END CERTIFICATE-----\n"
            )
            client_overrides = {
                "jwks": mtls_jwks,
                "certificate": cert_pem,
                "token_endpoint_auth_method": "self_signed_tls_client_auth",
                "tls_client_certificate_bound_access_tokens": True,
                "scope": "openid",
            }
        else:
            client_overrides = {
                "jwks": _fetch_rp_jwks(rp_base_url),
                "token_endpoint_auth_method": "private_key_jwt",
                # The RP requests the minimal ``openid`` scope; the suite requires
                # the registered client scope to match it exactly
                # (EnsureRequestedScopeIsEqualToConfiguredScope).
                "scope": "openid",
            }
        if jarm:
            # JARM: register the alg the OP must sign the authorization response
            # with. It must match the OP's supplied signing key (ES256, see
            # _generate_server_signing_jwks) so the RP can verify the response.
            client_overrides["authorization_signed_response_alg"] = "ES256"
        # The FAPI 2.0 client plan requires the OP's own signing key set
        # (LoadServerJWKs); mint an ephemeral one for this run.
        server_jwks = _generate_server_signing_jwks()

    logger.info("Creating test plan...")
    plan_response = suite.create_plan(
        plan_name,
        variant,
        alias,
        rp_base_url=rp_base_url,
        publish=publish,
        client_overrides=client_overrides,
        server_jwks=server_jwks,
    )
    plan_id = plan_response.get("id", "")
    modules = plan_response.get("modules", [])

    if not plan_id:
        logger.error("Failed to create plan: %s", plan_response)
        sys.exit(1)

    logger.info("Plan created: %s with %d test modules", plan_id, len(modules))

    # Extract test names from modules
    test_names = []
    for module in modules:
        if isinstance(module, dict):
            test_names.append(module.get("testModule", ""))
        else:
            test_names.append(str(module))

    if not test_names:
        logger.error("No test modules found in plan")
        sys.exit(1)

    logger.info("Tests to run: %s", ", ".join(test_names))

    # Client credentials from plan config
    client_config = config.get("client", {})
    client_id = client_config.get("client_id", "conformance-rp")
    client_secret = client_config.get("client_secret", "conformance-rp-secret")

    # Dynamic RP plans register a client per test module (no pre-configured
    # client_id); flag it so run_test_module drives /register first.
    is_dynamic = "dynamic" in plan_name

    # Run each test
    results: list[TestResult] = []
    for test_name in test_names:
        result = run_test_module(
            suite=suite,
            test_name=test_name,
            plan_id=plan_id,
            rp_base_url=rp_base_url,
            client_id=client_id,
            client_secret=client_secret,
            profile=profile,
            dynamic=is_dynamic,
            fapi2=fapi2,
            jarm=jarm,
            mtls=mtls,
        )
        results.append(result)

    return plan_id, results


# Statuses that count as a clean, submission-worthy outcome. Everything else —
# FAILED/INTERRUPTED/TIMEOUT, REVIEW (needs a human), and any unknown status —
# must keep an export from being treated as passing evidence. SKIPPED is fine
# (e.g. the expected idtoken-sig-none skip); WARNING is an accepted pass.
PASSING_STATUSES = frozenset({"PASSED", "WARNING", "SKIPPED"})


def print_summary(results: list[TestResult]) -> bool:
    """Print a summary table and return True only if the run is evidence-worthy.

    Returns True when there is at least one result and every result is in
    :data:`PASSING_STATUSES`. An empty run (no test ran) and any REVIEW/unknown
    status both return False — "nothing ran" and "needs review" are not "all
    passed", and neither should gate a certification export open.
    """
    print("\n" + "=" * 70)
    print("CONFORMANCE TEST RESULTS")
    print("=" * 70)
    print(f"{'Test':<50} {'Result':<10}")
    print("-" * 70)

    for r in results:
        symbol = {
            "PASSED": "PASS",
            "WARNING": "WARN",
            "FAILED": "FAIL",
            "REVIEW": "REVIEW",
            "SKIPPED": "SKIP",
        }.get(r.status, "????")
        print(f"{r.test_name:<50} [{symbol}]")
        if r.detail:
            print(f"  {r.detail}")

    all_ok = bool(results) and all(r.status in PASSING_STATUSES for r in results)

    print("-" * 70)
    passed = sum(1 for r in results if r.status == "PASSED")
    warned = sum(1 for r in results if r.status == "WARNING")
    failed = sum(1 for r in results if r.status in ("FAILED", "INTERRUPTED", "TIMEOUT"))
    skipped = sum(1 for r in results if r.status == "SKIPPED")
    review = sum(1 for r in results if r.status == "REVIEW")
    print(
        f"Total: {len(results)} | Passed: {passed} | Warnings: {warned} | "
        f"Failed: {failed} | Review: {review} | Skipped: {skipped}"
    )
    if not results:
        print("No tests ran — not treating this as a passing run.")
    print("=" * 70)

    return all_ok


# ---------------------------------------------------------------------------
# Plan export gating
# ---------------------------------------------------------------------------


def _should_download_export(
    export_zip: str | None, suite_url: str, all_ok: bool
) -> tuple[bool, str | None]:
    """Decide whether to download a plan-results export zip.

    Returns ``(do_download, skip_reason)``. ``skip_reason`` is ``None`` when
    ``do_download`` is True. An export is only worth keeping when a real
    (hosted) suite ran every test to a passing/warning state — the local
    conformance instance is a throwaway regression shield, and a run with
    failures is not evidence-worthy.
    """
    if not export_zip:
        return False, None
    if _is_local_suite(suite_url):
        return (
            False,
            "local suite export is not useful evidence; run against a hosted "
            "suite (CONFORMANCE_SERVER) to capture a signed plan export",
        )
    if not all_ok:
        return False, "not all tests passed"
    return True, None


# ---------------------------------------------------------------------------
# RP client-side logs (clientSideData)
# ---------------------------------------------------------------------------


def _rp_log_dir() -> Path:
    """Base directory for per-test RP logs the harness writes.

    Defaults to an absolute path derived from this file's location so it matches
    the harness default (``app.py`` computes the same path from its own
    ``__file__``) regardless of working directory. Env-overridable via
    ``RP_LOG_DIR`` — set the same value for both processes if you override it.
    """
    return Path(
        os.environ.get("RP_LOG_DIR")
        or (Path(__file__).parent / "results" / "hosted" / "rp-logs")
    )


def _reset_dir(path: Path) -> None:
    """Remove ``path`` and recreate it empty (so stale logs never leak in)."""
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _zip_directory(src_dir: Path, output: Path) -> int:
    """Zip the files directly under ``src_dir`` (flat) into ``output``.

    Returns the number of files written. Used to assemble the per-profile RP
    log bundle submitted to OIDF as ``clientSideData``.
    """
    files = sorted(p for p in src_dir.glob("*") if p.is_file())
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            zf.write(p, arcname=p.name)
    return len(files)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    # Environment variable overrides
    env_server = os.environ.get("CONFORMANCE_SERVER", "")
    env_token = os.environ.get("CONFORMANCE_TOKEN", "").strip()

    parser = argparse.ArgumentParser(
        description="Run OIDF conformance tests against py-identity-model"
    )
    parser.add_argument(
        "--plan",
        required=True,
        choices=[
            "basic-rp",
            "config-rp",
            "form-post-basic-rp",
            # New RP certification profiles being driven to green locally before
            # a hosted run (Dynamic #216, RP-Initiated Logout #214,
            # Back-Channel Logout #442). See conformance/README.md.
            "dynamic-rp",
            "rpinitiated-logout-rp",
            "backchannel-logout-rp",
            # FAPI 2.0 Security Profile RP plan (PAR + PKCE S256 +
            # private_key_jwt + DPoP-bound tokens + RFC 9207 iss)
            "fapi2-rp",
            # FAPI 2.0 Message Signing RP plan (adds JARM signed authorization
            # responses on top of the security profile)
            "fapi2-message-signing-rp",
            # FAPI 2.0 Security Profile RP, mTLS variant (client_auth_type=mtls +
            # sender_constrain=mtls: cert-bound tokens over RFC 8705 mutual TLS)
            "fapi2-mtls-rp",
            # fastapi-identity-model package regression plans (same suite
            # plans, driven against the rp-fastapi harness on :8889)
            "fastapi-basic-rp",
            "fastapi-config-rp",
            "fastapi-form-post-basic-rp",
        ],
        help="Test plan to run",
    )
    parser.add_argument(
        "--suite-url",
        default=env_server or SUITE_BASE_URL,
        help=f"Conformance suite base URL (env: CONFORMANCE_SERVER, default: {SUITE_BASE_URL})",
    )
    parser.add_argument(
        "--rp-url",
        default=RP_BASE_URL,
        help=f"RP harness base URL (default: {RP_BASE_URL})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Path to write JSON results file",
    )
    parser.add_argument(
        "--export-zip",
        default=None,
        help=(
            "Path to write the signed plan-results export (.zip) after a passing "
            "hosted run. This is the suite's CI evidence artifact, NOT the OIDF "
            "certification package (which is a manual, publish-and-freeze step "
            "requiring a signed PDF — see conformance/README.md). Only honoured "
            "for a hosted suite when every test passes; ignored for local runs."
        ),
    )
    parser.add_argument(
        "--export-kind",
        choices=["export", "exporthtml"],
        default="export",
        help=(
            "Plan export format: 'export' (JSON + RSA signature, default) or "
            "'exporthtml' (human-readable HTML)."
        ),
    )
    parser.add_argument(
        "--rp-logs-zip",
        default=None,
        help=(
            "Path to write the per-test RP client-side logs (.zip) the harness "
            "captured for this plan — one log file per test, the 'clientSideData' "
            "uploaded with an OIDF certification submission (see #331). The "
            "per-profile log dir is reset before the run and zipped after."
        ),
    )
    parser.add_argument(
        "--publish",
        choices=["none", "summary", "everything"],
        default="none",
        help=(
            "Publish results on the suite's public published-tests list "
            "(default: none — keep private). The certification package is "
            "produced regardless."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Token guard: require CONFORMANCE_TOKEN for non-local suites
    if not _is_local_suite(args.suite_url) and not env_token:
        logger.error(
            "CONFORMANCE_TOKEN is required when targeting a hosted suite (%s).\n\n"
            "To rotate the token CI uses:\n"
            "  make conformance-token              # create + push to the repo secret\n\n"
            "That secret cannot be read back — GitHub does not allow it — so for a\n"
            "local run mint your own token in the suite UI and set it:\n"
            "  export CONFORMANCE_TOKEN=<your-token>",
            args.suite_url,
        )
        sys.exit(1)

    config_path = Path(__file__).parent / "configs" / f"{args.plan}.json"
    if not config_path.exists():
        logger.error("Config not found: %s", config_path)
        sys.exit(1)

    publish_value = "" if args.publish == "none" else args.publish

    # Reset this profile's RP-log directory so the zip only contains this run's
    # per-test logs (the harness appends, so stale files would otherwise leak in).
    # Confine the rmtree target to the log base before deleting — args.plan is
    # already constrained by argparse choices, but _reset_dir removes a tree, so
    # a mistuned RP_LOG_DIR must never let it escape the intended directory.
    rp_log_base = _rp_log_dir().resolve()
    rp_log_profile_dir = (rp_log_base / args.plan).resolve()
    if not rp_log_profile_dir.is_relative_to(rp_log_base):
        logger.error(
            "Refusing to use RP log dir outside base: %s not under %s",
            rp_log_profile_dir,
            rp_log_base,
        )
        sys.exit(1)
    if args.rp_logs_zip:
        _reset_dir(rp_log_profile_dir)

    plan_id, results = run_plan(
        config_path=str(config_path),
        suite_base_url=args.suite_url,
        rp_base_url=args.rp_url,
        token=env_token or None,
        publish=publish_value,
        profile=args.plan,
    )

    all_ok = print_summary(results)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        results_json = {
            "plan": args.plan,
            "plan_id": plan_id,
            "suite_url": args.suite_url,
            "results": [
                {
                    "test": r.test_name,
                    "status": r.status,
                    "test_id": r.test_id,
                    "log_url": r.log_url,
                    "detail": r.detail,
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "passed": sum(1 for r in results if r.status == "PASSED"),
                "warning": sum(1 for r in results if r.status == "WARNING"),
                "failed": sum(
                    1
                    for r in results
                    if r.status in ("FAILED", "INTERRUPTED", "TIMEOUT")
                ),
                "review": sum(1 for r in results if r.status == "REVIEW"),
                "skipped": sum(1 for r in results if r.status == "SKIPPED"),
            },
            "all_passed": all_ok,
        }
        output_path.write_text(json.dumps(results_json, indent=2) + "\n")
        logger.info("Results written to %s", output_path)

    # Download the signed plan export as evidence for submission-worthy hosted
    # runs. This is NOT the OIDF certification package — see download_plan_export.
    do_download, skip_reason = _should_download_export(
        args.export_zip, args.suite_url, all_ok
    )
    artifact_failed = False
    if args.export_zip and not do_download:
        logger.warning("Plan export skipped: %s", skip_reason)
    elif do_download:
        logger.info("Downloading %s for plan %s...", args.export_kind, plan_id)
        download_client = ConformanceSuiteClient(
            args.suite_url, token=env_token or None
        )
        try:
            filename, content = download_client.download_plan_export(
                plan_id, kind=args.export_kind
            )
            export_path = Path(args.export_zip)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_bytes(content)
            logger.info(
                "Plan export (%s) written to %s (%d bytes)",
                filename,
                export_path,
                len(content),
            )
        except (httpx.HTTPError, ValueError, OSError) as exc:
            # The run passed but we could not capture its evidence — fail loudly
            # rather than exit 0 with a missing/corrupt export.
            logger.error("Plan export failed for plan %s: %s", plan_id, exc)
            artifact_failed = True
        finally:
            download_client.client.close()

    # Assemble the per-test RP client-side logs zip (clientSideData). Captured
    # regardless of pass/fail — the logs for failed tests are exactly what you'd
    # inspect — so this is gated only on the flag, not on all_ok.
    if args.rp_logs_zip:
        count = _zip_directory(rp_log_profile_dir, Path(args.rp_logs_zip))
        if count == 0:
            # An empty clientSideData bundle is worthless as a submission
            # artifact, so an explicit --rp-logs-zip that captured nothing is a
            # hard failure, not a warning that exits 0.
            logger.error(
                "No RP logs captured in %s — is the harness running this build "
                "(it must receive test_name/profile and share RP_LOG_DIR)?",
                rp_log_profile_dir,
            )
            artifact_failed = True
        else:
            logger.info(
                "RP client-side logs (%d files) written to %s",
                count,
                args.rp_logs_zip,
            )

    sys.exit(0 if (all_ok and not artifact_failed) else 1)


if __name__ == "__main__":
    main()
