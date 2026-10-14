"""OIDC RP conformance test harness.

Thin FastAPI application that acts as an OpenID Connect Relying Party,
using py-identity-model's public API to exercise all RP conformance tests.
"""

from __future__ import annotations

import base64
import contextvars
from dataclasses import dataclass, field
import datetime
import html
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError
from starlette.concurrency import run_in_threadpool

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    AuthorizeCallbackResponse,
    ClientRegistrationRequest,
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    DiscoveryPolicy,
    DPoPKey,
    HTTPClient,
    JwksRequest,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    TokenValidationConfig,
    UserInfoRequest,
    build_authorization_url,
    build_end_session_url,
    clear_jwks_cache,
    create_request_object,
    generate_dpop_key,
    generate_pkce_pair,
    get_discovery_document,
    get_jwks,
    get_userinfo,
    is_jarm_response,
    parse_authorize_callback_response,
    parse_discovery_url,
    process_jarm_response,
    push_authorization_request,
    register_client,
    request_authorization_code_token,
    resolve_mtls_endpoint,
    validate_authorize_callback_issuer,
    validate_authorize_callback_state,
    validate_logout_token,
    validate_id_token,
    validate_post_logout_state,
    validate_token,
)
from py_identity_model.core.parsers import (
    extract_jwt_header_fields,
    find_key_by_kid,
)
from py_identity_model.core.userinfo_logic import validate_userinfo_sub
from py_identity_model.exceptions import (
    ConfigurationException,
    JarmValidationException,
    LogoutStateValidationException,
    LogoutTokenValidationException,
    PyIdentityModelException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("conformance-rp")

app = FastAPI(title="py-identity-model Conformance RP")

# ---------------------------------------------------------------------------
# Per-test RP log capture (clientSideData for OIDF RP certification)
# ---------------------------------------------------------------------------
#
# OIDF RP certification requires one log file per test (named by the suite test
# module name), demonstrating the RP's behaviour — in particular that negative
# tests are rejected (https://openid.net/certification/connect_rp_submission/).
# The conformance suite only logs the OP side, so the RP must produce these.
#
# The runner tells the harness which test is active via /authorize, /discover
# and /callback, and a logging handler routes records to the active test's file.
# The active-test pointer is a ContextVar rather than a plain global: every
# request (and the threadpool call FastAPI runs sync endpoints in) gets its own
# context copy, so concurrent or overlapping requests can never route a record
# to the wrong test's file, and a request's pointer cannot leak into the next
# one. RP_LOG_DIR defaults to an absolute path derived from this file's location
# so the harness and the (separately-launched) runner agree on it regardless of
# working directory.

_active_test: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "rp_active_test", default=None
)


def _rp_log_base() -> Path:
    """Base directory for per-test RP logs (env-overridable)."""
    return Path(
        os.environ.get("RP_LOG_DIR")
        or (Path(__file__).parent / "results" / "hosted" / "rp-logs")
    )


def _sanitize_path_component(value: str, fallback: str) -> str:
    """Reduce ``value`` to a single safe path segment.

    Every character outside ``[A-Za-z0-9._-]`` is replaced (removing path
    separators), and a result that is empty or consists only of dots (``""``,
    ``"."``, ``".."``, ...) — which the character class alone would let through
    and which would walk out of the log base — collapses to ``fallback``.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    if not safe or set(safe) == {"."}:
        return fallback
    return safe


def _rp_log_path(profile: str, test_name: str) -> Path:
    """Path to the log file for ``test_name`` within ``profile`` (dir created).

    ``profile`` and ``test_name`` arrive as request parameters, so the path is
    hardened two ways: each is reduced to a single sanitised path segment via
    :func:`_sanitize_path_component` (no separators, no dot-only escapes), and
    the resolved path is verified to stay inside the log base — a value that
    somehow escaped raises rather than writing outside the base directory.
    """
    base = _rp_log_base().resolve()
    safe_profile = _sanitize_path_component(profile, "default")
    safe_test = _sanitize_path_component(test_name, "unknown")
    candidate = (base / safe_profile / f"{safe_test}.log").resolve()
    if not candidate.is_relative_to(base):
        raise ValueError(
            f"refusing unsafe RP log path (profile={profile!r}, test={test_name!r})"
        )
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def _set_active_test(profile: str | None, test_name: str | None) -> None:
    """Point per-test logging at ``test_name`` (or clear it when no test)."""
    _active_test.set((profile or "", test_name) if test_name else None)


def _get_active_test() -> tuple[str, str] | None:
    """Current ``(profile, test_name)`` for log routing, or ``None``."""
    return _active_test.get()


class _PerTestLogRouter(logging.Handler):
    """Appends harness + library log records to the active test's log file."""

    _warned_on_failure = False

    def emit(self, record: logging.LogRecord) -> None:
        test = _get_active_test()
        if not test or not test[1]:
            return
        try:
            with _rp_log_path(test[0], test[1]).open("a", encoding="utf-8") as fh:
                fh.write(self.format(record) + "\n")
        except (OSError, ValueError) as exc:
            # Never let log capture break the flow under test, but a silently
            # empty clientSideData bundle is a worthless submission artifact, so
            # surface the first failure on stderr (bypassing logging to avoid
            # recursing back into this handler).
            if not _PerTestLogRouter._warned_on_failure:
                _PerTestLogRouter._warned_on_failure = True
                sys.stderr.write(
                    f"WARNING: RP per-test log capture failing for "
                    f"profile={test[0]!r} test={test[1]!r}: {exc}\n"
                )


def _install_rp_log_router() -> None:
    router = _PerTestLogRouter()
    router.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    for name in ("conformance-rp", "py_identity_model"):
        logging.getLogger(name).addHandler(router)
    # Capture the library's own validation detail in the per-test logs.
    logging.getLogger("py_identity_model").setLevel(logging.DEBUG)


_install_rp_log_router()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUITE_BASE_URL = os.environ.get(
    "CONFORMANCE_SUITE_BASE_URL", "https://localhost.emobix.co.uk:8443"
)
# Browser-facing base URL: used for redirect_uri / post_logout_redirect_uri,
# which the user agent (the runner, on the host) follows.
RP_BASE_URL = os.environ.get("RP_BASE_URL", "http://localhost:8888")
# OP-facing base URL: used for request_uri, which the OP fetches server-to-server.
# Inside docker the OP reaches the RP by its compose service name, not localhost;
# defaults to RP_BASE_URL for non-docker runs.
RP_INTERNAL_BASE_URL = os.environ.get("RP_INTERNAL_BASE_URL", RP_BASE_URL)

# ---------------------------------------------------------------------------
# RP signing key for JWT Secured Authorization Requests (JAR, RFC 9101)
# ---------------------------------------------------------------------------
#
# The Dynamic RP plan bakes in request_type=request_uri: the RP must send a
# signed request object referenced by a request_uri the OP fetches. We generate
# one RSA key at startup, register its public half as the client's ``jwks`` (so
# the OP can verify the request object), and sign request objects with RS256 via
# the library's create_request_object.


def _generate_rp_signing_key() -> tuple[bytes, dict, str]:
    """Generate an RSA signing key and its public JWK set (with a kid)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    kid = secrets.token_hex(8)
    public_jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return private_pem, {"keys": [public_jwk]}, kid


_rp_private_key_pem, _rp_jwks, _rp_kid = _generate_rp_signing_key()

# Signed request objects the OP will fetch by request_uri, keyed by a random id.
request_objects: dict[str, str] = {}

# ---------------------------------------------------------------------------
# Session store — in-memory, keyed by state parameter
# ---------------------------------------------------------------------------


@dataclass
class AuthSession:
    """Tracks per-flow state between /authorize and /callback."""

    issuer: str
    state: str
    nonce: str
    code_verifier: str | None = None
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    skip_userinfo: bool = False
    # RP-Initiated Logout: the id_token issued to this session (used as
    # id_token_hint) and the OP's end-session endpoint, captured in /callback.
    id_token: str = ""
    end_session_endpoint: str = ""
    # Per-test RP-log routing (recovered in /callback via the session)
    test_name: str = ""
    profile: str = ""
    # FAPI 2.0 flow: when set, the callback exchanges the code with
    # private_key_jwt + a DPoP-bound token request (RFC 9449) and validates the
    # RFC 9207 ``iss`` authorization-response parameter. ``dpop_key`` is the
    # per-flow key the PAR + token + userinfo requests are bound to.
    fapi2: bool = False
    dpop_key: DPoPKey | None = None
    # mTLS (RFC 8705): when set, client authentication + sender constraining use a
    # client certificate (presented at the TLS layer) instead of private_key_jwt +
    # DPoP, and requests target the OP's mtls_endpoint_aliases.
    mtls: bool = False
    # JARM (JWT-Secured Authorization Response Mode): when set, the OP returns a
    # signed authorization response JWT, decoded in /callback via the library's
    # process_jarm_response instead of plain query-string parsing.
    jarm: bool = False
    # The OP's discovery address, kept so /callback can verify a JARM response
    # (its signature is checked against the OP's published JWKS).
    disco_address: str = ""
    # Results populated after callback
    result: dict = field(default_factory=dict)


# state -> AuthSession
sessions: dict[str, AuthSession] = {}

# test_id -> AuthSession (for the runner to retrieve results)
test_results: dict[str, AuthSession] = {}

# Shared HTTP client that skips TLS verification (conformance suite uses self-signed certs)
_http_client: HTTPClient | None = None

# Most recent auth-flow context (issuer / client_id / discovery address), captured
# in /authorize. The OP posts a Back-Channel Logout Token to a fixed URI that
# carries no flow parameters, so the receiver recovers the issuer (for signature
# + iss validation) and client_id (audience) from the last flow it drove.
_last_flow_context: dict[str, str] | None = None

# Most recent completed-login context for RP-Initiated Logout: the OP's
# end-session endpoint, the issued id_token (used as ``id_token_hint``), and the
# client_id. Captured in /callback on a successful login; consumed by /logout,
# which carries no flow parameters of its own.
_last_logout_context: dict[str, str] | None = None

# The ``state`` the harness sent to the end-session endpoint on the most recent
# /logout redirect. Checked against the value the OP returns to
# /post-logout-callback (RP-Initiated Logout 1.0 §2 state round-trip).
_expected_logout_state: str | None = None

# Most recent dynamically-registered client (RFC 7591): the issued client_id
# and, for confidential clients, client_secret. Populated by /register so a
# subsequent /authorize flow can use the freshly registered client.
_registered_client: dict[str, str] | None = None


def _get_http_client() -> HTTPClient:
    global _http_client
    if _http_client is None:
        _http_client = HTTPClient(verify=False)
    return _http_client


# ---------------------------------------------------------------------------
# FAPI 2.0 client authentication key (private_key_jwt, RFC 7523)
# ---------------------------------------------------------------------------
#
# FAPI 2.0 requires an asymmetric client-authentication method. The RP holds one
# long-lived ES256 signing key for its ``private_key_jwt`` assertions; the public
# half is served at ``/fapi2-jwks`` so the runner can register it with the suite
# as the client's JWKS before creating the plan (the suite verifies the assertion
# signature against it). ES256 satisfies the FAPI 2.0 PS256/ES256 allow-list.
# The DPoP key is separate and minted per-flow in /authorize.

_FAPI2_CLIENT_KID = "fapi2-rp-key-1"
_FAPI2_CLIENT_KEY: DPoPKey = generate_dpop_key("ES256")

# FAPI 2.0 requests a minimal scope: the profile's OP only advertises ``openid``
# and the conformance client is registered for exactly that, so the requested
# scope must equal it (EnsureRequestedScopeIsEqualToConfiguredScope).
_FAPI2_SCOPE = "openid"

# FAPI 2.0 permits only strong asymmetric ID token signing algorithms; RS256 in
# particular is forbidden. Restricting the RP's accepted set here makes the
# library reject an ID token signed with a disallowed alg (the OIDF
# ``invalid-alternate-alg`` module forces RS256 and expects rejection).
_FAPI2_ID_TOKEN_ALGS = ["PS256", "ES256", "EdDSA"]

# For the ``plain_fapi`` profile the OIDF client test treats a dedicated resource
# ("accounts") endpoint — NOT userinfo — as the resource server; the happy-path
# module only transitions to FINISHED once the RP makes a (DPoP-bound) resource
# request there (AbstractFAPI2SPFinalClientTest#userinfoEndpoint leaves the test
# WAITING because PlainFAPIClientProfileBehavior.userInfoIsResourceEndpoint()
# is false, whereas accountsEndpoint() calls resourceEndpointCallComplete()).
# The path is fixed by the suite (AbstractFAPI2SPFinalClientTest.ACCOUNTS_PATH).
_FAPI2_RESOURCE_PATH = "open-banking/v1.1/accounts"


def _fapi2_public_jwk() -> dict:
    """Public JWK for the RP's private_key_jwt signing key (with kid/use/alg)."""
    jwk = dict(_FAPI2_CLIENT_KEY.public_jwk)
    jwk.update({"kid": _FAPI2_CLIENT_KID, "use": "sig", "alg": "ES256"})
    return jwk


def _fapi2_private_key_jwt(audience: str) -> PrivateKeyJwt:
    """Build the private_key_jwt assertion params for ``audience`` (RFC 7523)."""
    return PrivateKeyJwt(
        private_key=_FAPI2_CLIENT_KEY.private_key_pem,
        algorithm="ES256",
        kid=_FAPI2_CLIENT_KID,
        audience=audience,
    )


# ---------------------------------------------------------------------------
# mTLS client certificate (FAPI 2.0 client_auth_type=mtls / sender_constrain=mtls)
# ---------------------------------------------------------------------------
#
# For the mTLS variant the RP authenticates + sender-constrains with a client
# certificate (RFC 8705) instead of private_key_jwt + DPoP. We mint one
# self-signed cert at startup, write it to PEM files (the library's MtlsClientAuth
# takes file paths for httpx's cert=), and publish its public half as the client
# JWKS (with x5c) at /fapi2-mtls-jwks so the runner registers it for
# self_signed_tls_client_auth — the OP then matches the presented TLS cert
# against that registered key.

_FAPI2_MTLS_KID = "fapi2-mtls-rp-key"


def _b64u_uint32(value: int) -> str:
    """Base64url-encode a P-256 coordinate (fixed 32-byte width, no padding)."""
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()


def _generate_mtls_client_cert() -> tuple[str, str, dict]:
    """Mint a self-signed EC client cert; return ``(cert_path, key_path, jwks)``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "py-identity-model-mtls-rp")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    cert_dir = Path(tempfile.mkdtemp(prefix="rp-mtls-"))
    cert_path = cert_dir / "client.crt"
    key_path = cert_dir / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    pub = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "kid": _FAPI2_MTLS_KID,
        "x": _b64u_uint32(pub.x),
        "y": _b64u_uint32(pub.y),
        "x5c": [base64.b64encode(der).decode()],
    }
    return str(cert_path), str(key_path), {"keys": [jwk]}


_FAPI2_MTLS_CERT_PATH, _FAPI2_MTLS_KEY_PATH, _FAPI2_MTLS_JWKS = (
    _generate_mtls_client_cert()
)


def _fapi2_mtls_auth() -> MtlsClientAuth:
    """mTLS client-auth config presenting the RP's self-signed client cert."""
    return MtlsClientAuth(
        certificate=_FAPI2_MTLS_CERT_PATH,
        private_key=_FAPI2_MTLS_KEY_PATH,
        auth_method="self_signed_tls_client_auth",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
@app.get("/health")
def health() -> dict:
    """Health check."""
    return {"status": "ok", "service": "conformance-rp"}


@app.post("/clear-cache")
def clear_cache() -> dict:
    """Clear library discovery and JWKS caches between conformance tests.

    The conformance suite reconfigures the OP's JWKS between test modules.
    Without clearing caches, validate_token uses stale keys and hangs on
    retry backoff (3 retries x 30s timeout = ~2 min timeout per test).
    """
    _set_active_test(None, None)
    clear_discovery_cache()
    clear_jwks_cache()
    logger.info("Cleared discovery and JWKS caches")
    return {"status": "ok", "cleared": ["discovery", "jwks"]}


@app.get("/fapi2-jwks", response_model=None)
def fapi2_jwks() -> JSONResponse:
    """Public JWKS for the RP's private_key_jwt signing key (FAPI 2.0).

    The runner fetches this and registers it as the client's ``jwks`` with the
    conformance suite so the suite can verify the RP's ``private_key_jwt`` client
    assertions. Only public key material is exposed.
    """
    return JSONResponse(content={"keys": [_fapi2_public_jwk()]})


@app.get("/fapi2-mtls-jwks", response_model=None)
def fapi2_mtls_jwks() -> JSONResponse:
    """Public JWKS (with x5c) for the RP's mTLS client certificate (FAPI 2.0).

    The runner registers this as the client's ``jwks`` so the OP can match the
    TLS-presented certificate under ``self_signed_tls_client_auth`` (RFC 8705).
    Only public key material + the certificate are exposed.
    """
    return JSONResponse(content=_FAPI2_MTLS_JWKS)


@app.get("/discover", response_model=None)
def discover(
    issuer: str = Query(..., description="Issuer URL for this test"),
    test_id: str = Query("", description="Test module ID for result tracking"),
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
) -> JSONResponse:
    """Fetch discovery document (and JWKS) without starting an auth flow.

    Used for Config RP discovery-only tests where the suite just needs to
    observe the RP fetching the openid-configuration endpoint.
    """
    _set_active_test(profile, test_name)
    http_client = _get_http_client()
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        error_msg = f"invalid_issuer: {exc}"
        logger.error("REJECTED: invalid issuer URL: %s", exc)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": error_msg,
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
        )
    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )

    if not disco.is_successful:
        logger.error("REJECTED: discovery fetch failed: %s", disco.error)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"discovery_failed: {disco.error}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "discovery_failed", "detail": disco.error},
        )

    if test_id:
        session = AuthSession(issuer=issuer, state="", nonce="")
        session.result = {
            "test_id": test_id,
            "status": "success",
            "issuer": disco.issuer,
        }
        test_results[test_id] = session

    logger.info(
        "ACCEPTED: discovery document fetched and validated for issuer '%s'",
        disco.issuer,
    )
    return JSONResponse(content={"status": "ok", "issuer": disco.issuer})


@app.get("/register", response_model=None)
def register(
    issuer: str = Query(..., description="Issuer URL for this test"),
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
) -> JSONResponse:
    """Dynamically register this RP with the OP (RFC 7591, Dynamic RP profile).

    Discovers the OP's ``registration_endpoint`` and registers a client with
    minimal metadata (this RP's redirect URI) via the library's
    ``register_client``. The issued ``client_id`` (and, for confidential
    clients, ``client_secret``) are remembered so a subsequent /authorize flow
    can use the freshly registered client.
    """
    _set_active_test(profile, test_name)
    http_client = _get_http_client()
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        logger.error("REJECTED: invalid issuer URL: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
        )

    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )
    if not disco.is_successful:
        logger.error("REJECTED: discovery fetch failed: %s", disco.error)
        return JSONResponse(
            status_code=502,
            content={"error": "discovery_failed", "detail": disco.error},
        )
    if not disco.registration_endpoint:
        logger.error("REJECTED: OP does not advertise a registration_endpoint")
        return JSONResponse(
            status_code=400,
            content={
                "error": "registration_not_supported",
                "detail": "OP discovery has no registration_endpoint",
            },
        )

    response = register_client(
        ClientRegistrationRequest(
            address=disco.registration_endpoint,
            redirect_uris=[f"{RP_BASE_URL}/callback"],
            client_name="py-identity-model-dynamic-rp",
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_basic",
            # The Dynamic plan authorizes via request_uri (JAR): register the
            # RP's public key and RS256 as the request-object signing alg so the
            # OP can verify the signed request objects it fetches.
            extra_metadata={
                "jwks": _rp_jwks,
                "request_object_signing_alg": "RS256",
            },
        ),
        http_client=http_client,
    )
    if not response.is_successful:
        logger.error("REJECTED: dynamic registration failed: %s", response.error)
        return JSONResponse(
            status_code=400,
            content={"error": "registration_failed", "detail": response.error},
        )

    global _registered_client
    _registered_client = {
        "client_id": response.client_id or "",
        "client_secret": response.client_secret or "",
    }
    logger.info(
        "ACCEPTED: client registered dynamically, client_id=%s",
        response.client_id,
    )
    # Never return client_secret in the body; only confirm registration.
    return JSONResponse(content={"status": "ok", "client_id": response.client_id})


@app.get("/request-object/{obj_id}", response_model=None)
def request_object(obj_id: str) -> Response:
    """Serve a signed request object for the OP to fetch via request_uri (JAR).

    /authorize stores the signed JWT under a random id and points the OP here
    with ``request_uri``. RFC 9101 §10.3 defines the media type
    ``application/oauth-authz-req+jwt`` for the fetched request object.
    """
    jwt_str = request_objects.get(obj_id)
    if not jwt_str:
        return Response(status_code=404, content="not found")
    return Response(content=jwt_str, media_type="application/oauth-authz-req+jwt")


@app.get("/authorize", response_model=None)
def authorize(
    issuer: str = Query(..., description="Issuer URL for this test"),
    client_id: str = Query(..., description="Client ID registered with the suite"),
    client_secret: str = Query("", description="Client secret"),
    test_id: str = Query("", description="Test module ID for result tracking"),
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
    use_pkce: str = Query("false", description="Whether to use PKCE"),
    skip_userinfo: str = Query(
        "false", description="Skip UserInfo fetch after token validation"
    ),
    use_request_uri: str = Query(
        "false",
        description="Send authorization params as a signed request object via "
        "request_uri (JAR, RFC 9101) instead of plain query params",
    ),
    scope: str = Query(
        "openid profile email address phone", description="Requested scopes"
    ),
    fapi2: str = Query(
        "false",
        description=(
            "Drive the FAPI 2.0 flow: PAR + PKCE S256 + private_key_jwt + "
            "DPoP-bound token request, with RFC 9207 iss validation in /callback"
        ),
    ),
    jarm: str = Query(
        "false",
        description=(
            "Request a JARM (JWT-Secured Authorization Response Mode) response: "
            "pushes response_mode=jwt so the OP returns a signed response JWT, "
            "decoded in /callback via process_jarm_response. Implies FAPI 2.0."
        ),
    ),
    mtls: str = Query(
        "false",
        description=(
            "Drive the FAPI 2.0 mTLS variant: authenticate + sender-constrain "
            "with a client certificate (RFC 8705) at the OP's mtls_endpoint_"
            "aliases instead of private_key_jwt + DPoP. Implies FAPI 2.0."
        ),
    ),
) -> RedirectResponse | JSONResponse:
    """Build an authorization URL and redirect to the OP.

    The conformance test runner calls this to start an authorization flow.
    """
    _set_active_test(profile, test_name)
    http_client = _get_http_client()

    # Dynamic RP: the runner registers a client (RFC 7591) and passes back its
    # client_id, but cannot know the secret (/register never returns it). Fill
    # the secret from the remembered registration when the client_id matches.
    if _registered_client and client_id == _registered_client.get("client_id"):
        client_secret = _registered_client.get("client_secret", "") or client_secret

    # Fetch discovery document for this issuer
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        error_msg = f"invalid_issuer: {exc}"
        logger.error("REJECTED: invalid issuer URL: %s", exc)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": error_msg,
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_issuer", "detail": "Invalid issuer URL"},
        )
    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )

    if not disco.is_successful:
        # Discovery failure includes format/validation errors — store as test result
        logger.error("REJECTED: discovery fetch failed: %s", disco.error)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"discovery_failed: {disco.error}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "discovery_failed", "detail": disco.error},
        )

    # OIDC Discovery 1.0 §4.3: issuer in document MUST match the URL used to retrieve it
    if not disco.issuer:
        error_msg = "Discovery document missing required 'issuer' field"
        logger.error("REJECTED: %s", error_msg)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"missing_issuer: {error_msg}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "missing_issuer", "detail": error_msg},
        )
    if disco.issuer != issuer:
        error_msg = (
            f"Issuer mismatch: discovery document issuer '{disco.issuer}' "
            f"does not match expected '{issuer}'"
        )
        logger.error("REJECTED: %s", error_msg)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"issuer_mismatch: {error_msg}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=502,
            content={"error": "issuer_mismatch", "detail": error_msg},
        )

    if fapi2.lower() == "true" or jarm.lower() == "true" or mtls.lower() == "true":
        return _authorize_fapi2(
            disco=disco,
            disco_address=disco_endpoint.url,
            issuer=issuer,
            client_id=client_id,
            scope=_FAPI2_SCOPE,
            test_id=test_id,
            test_name=test_name,
            profile=profile,
            skip_userinfo=skip_userinfo.lower() == "true",
            jarm=jarm.lower() == "true",
            mtls=mtls.lower() == "true",
            http_client=http_client,
        )

    # Generate per-flow state and nonce
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    redirect_uri = f"{RP_BASE_URL}/callback"

    # Optional PKCE
    code_verifier: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    if use_pkce.lower() == "true":
        code_verifier, code_challenge = generate_pkce_pair()
        code_challenge_method = "S256"

    # Build the authorization URL
    if disco.authorization_endpoint is None:
        return JSONResponse(
            status_code=502,
            content={
                "error": "missing_endpoint",
                "detail": "Discovery document missing authorization_endpoint",
            },
        )
    if use_request_uri.lower() == "true":
        # JAR (RFC 9101): sign the authorization params into a request object,
        # host it, and reference it by request_uri the OP fetches and verifies
        # against the RP's registered jwks. The library's create_request_object
        # produces the signed JWT; we build the request_uri form of the auth URL
        # ourselves (build_jar_authorization_url uses the inline ``request``
        # param, but the Dynamic plan requires request_uri).
        request_object = create_request_object(
            private_key=_rp_private_key_pem,
            algorithm="RS256",
            client_id=client_id,
            audience=disco.issuer,
            redirect_uri=redirect_uri,
            scope=scope,
            response_type="code",
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            kid=_rp_kid,
        )
        obj_id = secrets.token_urlsafe(16)
        request_objects[obj_id] = request_object
        request_uri = f"{RP_INTERNAL_BASE_URL}/request-object/{obj_id}"
        auth_params = {
            "client_id": client_id,
            "request_uri": request_uri,
            "scope": scope,
            "response_type": "code",
        }
        separator = "&" if "?" in disco.authorization_endpoint else "?"
        auth_url = f"{disco.authorization_endpoint}{separator}{urlencode(auth_params)}"
    else:
        auth_url = build_authorization_url(
            authorization_endpoint=disco.authorization_endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            response_type="code",
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

    # Store session
    session = AuthSession(
        issuer=issuer,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        skip_userinfo=skip_userinfo.lower() == "true",
        test_name=test_name,
        profile=profile,
    )
    sessions[state] = session
    if test_id:
        session.result["test_id"] = test_id

    # Record the flow context so the Back-Channel Logout receiver can validate a
    # Logout Token the OP later posts to /backchannel-logout (no flow params ride
    # along on that request).
    global _last_flow_context
    _last_flow_context = {
        "issuer": issuer,
        "client_id": client_id,
        "disco_address": disco_endpoint.url,
    }

    logger.info(
        "ACCEPTED: discovery issuer '%s' matches expected; redirecting to OP", issuer
    )
    logger.info("Redirecting to OP: %s", auth_url)
    return RedirectResponse(url=auth_url, status_code=302)


def _authorize_fapi2(
    disco: DiscoveryDocumentResponse,
    disco_address: str,
    issuer: str,
    client_id: str,
    scope: str,
    test_id: str,
    test_name: str,
    profile: str,
    skip_userinfo: bool,
    http_client: HTTPClient,
    jarm: bool = False,
    mtls: bool = False,
) -> RedirectResponse | JSONResponse:
    """Drive the FAPI 2.0 authorization request via PAR.

    Pushes the authorization parameters to the PAR endpoint with PKCE ``S256``
    then redirects to the authorization endpoint with only ``client_id`` +
    ``request_uri`` (RFC 9126 §4). Client authentication + sender constraining
    are either ``private_key_jwt`` (RFC 7523) + a per-flow DPoP proof (RFC 9449),
    or — when ``mtls`` — a client certificate presented at the TLS layer against
    the OP's ``mtls_endpoint_aliases`` (RFC 8705). The chosen mode is persisted on
    the session so /callback completes the flow the same way, with RFC 9207
    ``iss`` checks throughout.
    """
    # mTLS drives the OP's mtls_endpoint_aliases (a distinct host/port); the
    # library resolves the alias, falling back to the standard endpoint.
    par_endpoint = (
        resolve_mtls_endpoint(disco, "pushed_authorization_request_endpoint")
        if mtls
        else disco.pushed_authorization_request_endpoint
    )
    if not par_endpoint:
        error_msg = "OP does not advertise a pushed_authorization_request_endpoint"
        logger.error("REJECTED: %s", error_msg)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"par_not_supported: {error_msg}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=400,
            content={"error": "par_not_supported", "detail": error_msg},
        )
    if disco.authorization_endpoint is None:
        return JSONResponse(
            status_code=502,
            content={
                "error": "missing_endpoint",
                "detail": "Discovery document missing authorization_endpoint",
            },
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    # mTLS sender-constrains via the client certificate, so no DPoP key; the
    # cert-configured client is built by the library (http_client must be None).
    dpop_key = None if mtls else generate_dpop_key("ES256")
    mtls_auth = _fapi2_mtls_auth() if mtls else None
    redirect_uri = f"{RP_BASE_URL}/callback"

    par_response = push_authorization_request(
        PushedAuthorizationRequest(
            address=par_endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            private_key_jwt=None
            if mtls
            else _fapi2_private_key_jwt(disco.issuer or issuer),
            dpop_key=dpop_key,
            mtls=mtls_auth,
            # JARM: ask the OP to return a signed authorization response JWT.
            response_mode="jwt" if jarm else None,
        ),
        http_client=None if mtls else http_client,
    )
    if not par_response.is_successful or not par_response.request_uri:
        logger.error("REJECTED: PAR request failed: %s", par_response.error)
        if test_id:
            error_session = AuthSession(issuer=issuer, state="", nonce="")
            error_session.result = {
                "test_id": test_id,
                "status": "error",
                "error": f"par_failed: {par_response.error}",
            }
            test_results[test_id] = error_session
        return JSONResponse(
            status_code=400,
            content={"error": "par_failed", "detail": par_response.error},
        )

    # RFC 9126 §4: the authorization request carries ONLY client_id + request_uri;
    # every other parameter was pushed and MUST NOT be repeated on the front channel.
    auth_url = f"{disco.authorization_endpoint}?" + urlencode(
        {"client_id": client_id, "request_uri": par_response.request_uri}
    )

    # Persist the OP's canonical discovery issuer (FAPI 2.0 requires the
    # private_key_jwt ``aud`` at BOTH PAR and token endpoints to be the issuer
    # URL as a string, not the endpoint URL — ValidateClientAssertionAudClaimIs
    # IssuerAsString).
    session = AuthSession(
        issuer=disco.issuer or issuer,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        client_id=client_id,
        redirect_uri=redirect_uri,
        skip_userinfo=skip_userinfo,
        test_name=test_name,
        profile=profile,
        fapi2=True,
        dpop_key=dpop_key,
        jarm=jarm,
        mtls=mtls,
        disco_address=disco_address,
    )
    sessions[state] = session
    if test_id:
        session.result["test_id"] = test_id

    global _last_flow_context
    _last_flow_context = {
        "issuer": issuer,
        "client_id": client_id,
        "disco_address": disco_address,
    }

    logger.info(
        "ACCEPTED: FAPI2 PAR pushed (%s + PKCE S256); redirecting to OP with "
        "request_uri",
        "mTLS" if mtls else "private_key_jwt + DPoP",
    )
    return RedirectResponse(url=auth_url, status_code=302)


def _fetch_and_validate_discovery(
    issuer: str, http_client: HTTPClient, session: AuthSession
) -> HTMLResponse | tuple:
    """Fetch discovery document and validate issuer for a callback flow.

    Returns an HTMLResponse on error, or a (disco, disco_endpoint) tuple on success.
    """
    try:
        disco_endpoint = parse_discovery_url(issuer)
    except ConfigurationException as exc:
        error_msg = f"invalid_issuer: {exc}"
        logger.error("REJECTED: invalid issuer URL in callback: %s", exc)
        session.result["status"] = "error"
        session.result["error"] = error_msg
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Invalid Issuer</h1><p>Discovery URL is invalid</p>",
            status_code=400,
        )
    policy = DiscoveryPolicy(require_https=False, validate_issuer=True)
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=disco_endpoint.url, policy=policy),
        http_client=http_client,
    )

    if not disco.is_successful:
        logger.error("REJECTED: discovery fetch failed in callback: %s", disco.error)
        session.result["status"] = "error"
        session.result["error"] = f"discovery_failed: {disco.error}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Discovery Failed</h1><p>{html.escape(str(disco.error))}</p>",
            status_code=502,
        )

    # OIDC Discovery 1.0 §4.3: issuer in document MUST match the URL used to retrieve it
    if not disco.issuer:
        error_msg = "Discovery document missing required 'issuer' field"
        logger.error("REJECTED: %s", error_msg)
        session.result["status"] = "error"
        session.result["error"] = f"missing_issuer: {error_msg}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Missing Issuer</h1><p>{html.escape(error_msg)}</p>",
            status_code=502,
        )
    if disco.issuer != issuer:
        error_msg = (
            f"Issuer mismatch: discovery document issuer '{disco.issuer}' "
            f"does not match expected '{issuer}'"
        )
        logger.error("REJECTED: %s", error_msg)
        session.result["status"] = "error"
        session.result["error"] = f"issuer_mismatch: {error_msg}"
        _store_test_result(session)
        return HTMLResponse(
            content=f"<h1>Issuer Mismatch</h1><p>{html.escape(error_msg)}</p>",
            status_code=502,
        )

    return disco, disco_endpoint


def _validate_fapi2_callback_issuer(
    cb_response: AuthorizeCallbackResponse,
    disco: DiscoveryDocumentResponse,
    session: AuthSession,
) -> HTMLResponse | None:
    """RFC 9207 ``iss`` validation for a FAPI 2.0 callback (mix-up defense).

    FAPI 2.0 mandates the ``iss`` authorization-response parameter, so it is
    required regardless of advertised metadata support. Returns an error
    ``HTMLResponse`` on failure, or ``None`` when the flow may proceed (including
    for non-FAPI2 sessions, which skip the check).
    """
    if not session.fapi2:
        return None
    iss_result = validate_authorize_callback_issuer(
        cb_response, disco.issuer, require=True
    )
    if iss_result.is_valid:
        return None
    session.result["status"] = "error"
    session.result["error"] = f"iss_validation: {iss_result.result.value}"
    logger.error(
        "REJECTED: RFC 9207 iss validation failed: %s", iss_result.result.value
    )
    _store_test_result(session)
    return HTMLResponse(
        content=(
            "<h1>Issuer (RFC 9207) Validation Failed</h1>"
            f"<p>{html.escape(iss_result.result.value)}</p>"
        ),
        status_code=400,
    )


def _client_for_session(
    session: AuthSession, http_client: HTTPClient
) -> HTTPClient | None:
    """The HTTP client to pass a client-authenticating request.

    mTLS sessions must let the library build a short-lived cert-configured client
    (``resolve_http_client`` rejects a managed client alongside ``mtls``), so pass
    ``None``; every other session reuses the shared verify-disabled client.
    """
    return None if session.mtls else http_client


def _build_auth_code_token_request(
    session: AuthSession, disco: DiscoveryDocumentResponse, code: str
) -> AuthorizationCodeTokenRequest:
    """Build the auth-code token exchange request for a session.

    mTLS sessions authenticate + sender-constrain with the client certificate at
    the OP's mtls token endpoint; other FAPI 2.0 sessions use ``private_key_jwt``
    + DPoP; the rest use the (optional) client secret.
    """
    if session.mtls:
        token_endpoint = resolve_mtls_endpoint(disco, "token_endpoint") or ""
        return AuthorizationCodeTokenRequest(
            address=token_endpoint,
            client_id=session.client_id,
            code=code,
            redirect_uri=session.redirect_uri,
            code_verifier=session.code_verifier,
            mtls=_fapi2_mtls_auth(),
        )
    if session.fapi2:
        return AuthorizationCodeTokenRequest(
            address=disco.token_endpoint,
            client_id=session.client_id,
            code=code,
            redirect_uri=session.redirect_uri,
            code_verifier=session.code_verifier,
            private_key_jwt=_fapi2_private_key_jwt(session.issuer),
            dpop_key=session.dpop_key,
        )
    return AuthorizationCodeTokenRequest(
        address=disco.token_endpoint,
        client_id=session.client_id,
        code=code,
        redirect_uri=session.redirect_uri,
        code_verifier=session.code_verifier,
        client_secret=session.client_secret if session.client_secret else None,
    )


def _fetch_userinfo(
    session: AuthSession,
    disco: DiscoveryDocumentResponse,
    access_token: str | None,
    expected_sub: str | None,
    http_client: HTTPClient,
) -> dict | HTMLResponse:
    """Fetch + validate UserInfo, returning claims or an error ``HTMLResponse``.

    Skipped (returns ``{}``) when there is no access token, no userinfo endpoint,
    or the flow opted out. FAPI 2.0 sessions present the DPoP-bound access token
    with a DPoP proof (RFC 9449); a ``sub`` mismatch is fatal (OIDC Core §5.3.4).
    A signed (``application/jwt``) response is verified against the OP's JWKS
    with ``iss`` and ``aud`` checked (§5.3.2) before its ``sub`` is compared.
    The JWKS is fetched before UserInfo: the OIDF module finishes once it has
    served UserInfo and rejects any later request.
    """
    if not (access_token and disco.userinfo_endpoint and not session.skip_userinfo):
        return {}
    # mTLS presents the cert-bound token at the mtls userinfo endpoint; DPoP
    # sessions present the DPoP-bound token with a proof at the standard endpoint.
    userinfo_endpoint = (
        resolve_mtls_endpoint(disco, "userinfo_endpoint")
        if session.mtls
        else disco.userinfo_endpoint
    )
    jwks_response = get_jwks(
        JwksRequest(
            address=disco.jwks_uri, policy=DiscoveryPolicy(require_https=False)
        ),
        http_client=http_client,
    )
    try:
        userinfo_response = get_userinfo(
            UserInfoRequest(
                address=userinfo_endpoint,
                token=access_token,
                dpop_key=(
                    session.dpop_key if (session.fapi2 and not session.mtls) else None
                ),
                mtls=_fapi2_mtls_auth() if session.mtls else None,
            ),
            http_client=_client_for_session(session, http_client),
        )
    except PyIdentityModelException as exc:
        logger.warning("UserInfo exception: %s", exc)
        session.result["userinfo_error"] = str(exc)
        return {}

    error_msg: str | None
    if userinfo_response.is_successful and userinfo_response.raw is not None:
        try:
            if not jwks_response.is_successful:
                raise TokenValidationException(
                    f"OP JWKS unavailable: {jwks_response.error}"
                )
            kid, jwt_alg = extract_jwt_header_fields(userinfo_response.raw)
            key, alg = find_key_by_kid(kid, jwks_response.keys or [], jwt_alg=jwt_alg)
            return validate_token(
                userinfo_response.raw,
                token_validation_config=TokenValidationConfig(
                    perform_disco=False,
                    key=key,
                    algorithms=[alg],
                    audience=session.client_id,
                    issuer=disco.issuer,
                    subject=expected_sub,
                    options={"require": ["iss", "aud", "sub"]},
                ),
            )
        except PyIdentityModelException as exc:
            error_msg = exc.message
        except PyJWTError as exc:
            error_msg = f"malformed signed UserInfo: {exc}"
    else:
        userinfo_response = validate_userinfo_sub(userinfo_response, expected_sub)
        if userinfo_response.is_successful:
            return userinfo_response.claims or {}
        error_msg = userinfo_response.error

    # OIDC Core 1.0 §5.3.2/§5.3.4: an unverifiable signed response or a sub
    # mismatch is fatal.
    logger.error("REJECTED: UserInfo validation failed: %s", error_msg)
    session.result["status"] = "error"
    session.result["error"] = f"userinfo_validation: {error_msg}"
    _store_test_result(session)
    return HTMLResponse(
        content=(
            f"<h1>UserInfo Validation Failed</h1><p>{html.escape(str(error_msg))}</p>"
        ),
        status_code=400,
    )


def _id_token_validation_params(
    session: AuthSession,
) -> tuple[dict, list[str] | None]:
    """Return ``(options, algorithms)`` for ID token validation.

    FAPI 2.0 hardens validation: require ``exp``/``aud`` and restrict the
    accepted signature algorithms to the strong asymmetric set (rejecting
    RS256), so the library fails closed on the OIDF negative modules
    (invalid-alternate-alg, invalid-missing-exp) instead of accepting the token
    and calling userinfo. Basic/Config/Form-Post profiles keep the looser
    OIDC-Core defaults.
    """
    if session.fapi2:
        return (
            {"verify_exp": True, "require": ["sub", "iat", "exp", "aud"]},
            _FAPI2_ID_TOKEN_ALGS,
        )
    return {"verify_exp": True, "require": ["sub", "iat"]}, None


def _fetch_fapi2_resource(
    session: AuthSession,
    disco: DiscoveryDocumentResponse,
    access_token: str | None,
    http_client: HTTPClient,
) -> None:
    """Make the FAPI 2.0 sender-constrained resource ("accounts") request.

    For the ``plain_fapi`` profile the OIDF client test treats a dedicated
    resource endpoint — not userinfo — as the resource server, and the
    happy-path module only reaches FINISHED once the RP calls it (see
    ``_FAPI2_RESOURCE_PATH``). We reuse ``get_userinfo`` (``expected_sub=None`` so
    no OIDC sub check runs) purely as a sender-constrained GET presenting the
    cnf-bound access token: DPoP sessions attach a resource proof (``ath``) with
    the RFC 9449 §8 nonce retry; mTLS sessions present the client certificate at
    the mtls resource host (derived from the mtls token endpoint). Best-effort —
    the suite fires ``resourceEndpointCallComplete`` when the request arrives.
    """
    if not (session.fapi2 and access_token):
        return
    if session.mtls:
        # The mtls resource endpoint shares the mtls token endpoint's base host
        # (port 8444) so nginx requests + forwards the client certificate.
        mtls_token = resolve_mtls_endpoint(disco, "token_endpoint") or ""
        base = mtls_token.rsplit("/token", 1)[0]
        request = UserInfoRequest(
            address=f"{base.rstrip('/')}/{_FAPI2_RESOURCE_PATH}",
            token=access_token,
            expected_sub=None,
            mtls=_fapi2_mtls_auth(),
        )
    elif session.dpop_key:
        request = UserInfoRequest(
            address=session.issuer.rstrip("/") + "/" + _FAPI2_RESOURCE_PATH,
            token=access_token,
            expected_sub=None,
            dpop_key=session.dpop_key,
        )
    else:
        return
    try:
        resource_response = get_userinfo(
            request, http_client=_client_for_session(session, http_client)
        )
    except PyIdentityModelException as exc:
        logger.info("FAPI2 accounts request completed with exception: %s", exc)
        return
    logger.info(
        "FAPI2 resource (accounts) request done: success=%s",
        resource_response.is_successful,
    )


def _parse_callback(
    request_url: str, http_client: HTTPClient
) -> AuthorizeCallbackResponse | HTMLResponse:
    """Parse a callback URL, decoding a JARM ``response`` JWT when present.

    A JARM (JWT-Secured Authorization Response Mode) response carries the
    parameters inside a signed ``response`` JWT rather than plain query params;
    decode + verify it via the library's ``process_jarm_response``. The flow's
    client_id / discovery address come from ``_last_flow_context`` because the
    ``state`` (the session key) is inside the JWT. Returns the parsed callback,
    or an error ``HTMLResponse`` when parsing or JARM validation fails.
    """
    try:
        if is_jarm_response(request_url):
            ctx = _last_flow_context or {}
            return process_jarm_response(
                request_url,
                client_id=ctx.get("client_id", ""),
                disco_doc_address=ctx.get("disco_address"),
                require_https=False,
                http_client=http_client,
            )
        return parse_authorize_callback_response(request_url)
    except (JarmValidationException, TokenValidationException) as exc:
        # A JARM response failing signature / iss / aud / exp / alg validation
        # MUST be rejected (the negative message-signing modules). There is no
        # verified state yet, so respond 400 without completing the flow.
        logger.error("REJECTED: JARM response validation failed: %s", exc.message)
        return HTMLResponse(
            content=(
                f"<h1>JARM Validation Failed</h1><p>{html.escape(str(exc.message))}</p>"
            ),
            status_code=400,
        )
    except PyIdentityModelException as exc:
        logger.error("Callback parse error: %s", exc)
        return HTMLResponse(
            content="<h1>Callback Error</h1><p>Failed to parse callback</p>",
            status_code=400,
        )


def _handle_callback(request_url: str) -> HTMLResponse | JSONResponse:
    """Common callback handler for GET and POST response modes."""
    http_client = _get_http_client()

    cb_response = _parse_callback(str(request_url), http_client)
    if isinstance(cb_response, HTMLResponse):
        return cb_response

    # Look up session by state
    state_value = cb_response.state
    if state_value is None or state_value not in sessions:
        logger.error("Unknown state: %s", state_value)
        return HTMLResponse(
            content="<h1>Error</h1><p>Unknown or missing state parameter</p>",
            status_code=400,
        )

    session = sessions.pop(state_value)
    # Route this flow's logs to the test that started it (recovered via state).
    _set_active_test(session.profile, session.test_name)

    # Validate state
    state_result = validate_authorize_callback_state(cb_response, session.state)
    if not state_result.is_valid:
        session.result["status"] = "error"
        session.result["error"] = f"state_validation: {state_result.result.value}"
        logger.error("REJECTED: state validation failed: %s", state_result.result.value)
        _store_test_result(session)
        return HTMLResponse(
            content=(
                "<h1>State Validation Failed</h1>"
                f"<p>{html.escape(state_result.result.value)}</p>"
            ),
            status_code=400,
        )

    # Check for error response from OP
    if not cb_response.is_successful:
        session.result["status"] = "error"
        session.result["error"] = cb_response.error
        session.result["error_description"] = cb_response.error_description
        logger.error(
            "REJECTED: OP returned error response: %s (%s)",
            cb_response.error,
            cb_response.error_description,
        )
        _store_test_result(session)
        return HTMLResponse(
            content=(
                "<h1>OP Error</h1>"
                f"<p>{html.escape(str(cb_response.error))}: "
                f"{html.escape(str(cb_response.error_description))}</p>"
            ),
            status_code=400,
        )

    # Fetch discovery document (not cached in harness, each test may use different OP)
    disco_result = _fetch_and_validate_discovery(session.issuer, http_client, session)
    if isinstance(disco_result, HTMLResponse):
        return disco_result
    disco, disco_endpoint = disco_result

    # FAPI 2.0: validate the RFC 9207 ``iss`` authorization-response parameter.
    fapi2_iss_error = _validate_fapi2_callback_issuer(cb_response, disco, session)
    if fapi2_iss_error is not None:
        return fapi2_iss_error

    # Exchange authorization code for tokens
    if disco.token_endpoint is None:
        session.result["status"] = "error"
        session.result["error"] = "missing_token_endpoint"
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Discovery Error</h1><p>Discovery document missing token_endpoint</p>",
            status_code=502,
        )
    if cb_response.code is None:
        session.result["status"] = "error"
        session.result["error"] = "missing_code"
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Callback Error</h1><p>Authorization callback missing code parameter</p>",
            status_code=400,
        )
    token_response = request_authorization_code_token(
        _build_auth_code_token_request(session, disco, cb_response.code),
        http_client=_client_for_session(session, http_client),
    )

    if not token_response.is_successful:
        session.result["status"] = "error"
        session.result["error"] = f"token_exchange: {token_response.error}"
        logger.error("REJECTED: token exchange failed: %s", token_response.error)
        _store_test_result(session)
        return HTMLResponse(
            content=(
                "<h1>Token Exchange Failed</h1>"
                f"<p>{html.escape(str(token_response.error))}</p>"
            ),
            status_code=400,
        )

    if token_response.token is None:
        session.result["status"] = "error"
        session.result["error"] = "missing_token_data"
        _store_test_result(session)
        return HTMLResponse(
            content="<h1>Token Error</h1><p>Token response missing token data</p>",
            status_code=502,
        )
    token_data = token_response.token
    id_token_jwt = token_data.get("id_token")
    access_token = token_data.get("access_token")

    # Validate the ID token.
    #
    # CRITICAL: do NOT pass http_client= to validate_token here.
    #
    # When http_client is provided, sync/token_validation._discover_and_resolve_key
    # takes the non-cached branch (calling get_jwks directly) and the library's
    # JWKS cache — and therefore its cache-miss-triggered retry path — is
    # structurally bypassed. That makes the retry-on-signature-failure logic
    # from PR #310 unreachable from the harness, and the rp-key-rotation-*
    # conformance tests pass for the wrong reason (fresh JWKS on every call,
    # never triggering the sig-fail → refresh → retry sequence the tests exist
    # to exercise). See #327 for the full analysis.
    #
    # Letting validate_token use its default (thread-local) HTTPClient routes
    # through _get_cached_jwks → first validation uses cached keys → sig failure
    # triggers _retry_with_refreshed_jwks → retry succeeds with rotated keys.
    # That is the behavior the rp-key-rotation conformance tests are designed
    # to verify, and it only works if we let the library own the HTTP client.
    claims: dict = {}
    if id_token_jwt:
        id_token_options, id_token_algorithms = _id_token_validation_params(session)
        try:
            # validate_id_token adds the ID-Token profile on top of the base
            # checks, including the rejection of audiences other than this
            # client (OIDC Core §3.1.3.7 step 3) that the FAPI 2.0
            # invalid-secondary-aud module exercises.
            claims = validate_id_token(
                id_token_jwt,
                token_validation_config=TokenValidationConfig(
                    perform_disco=True,
                    audience=session.client_id,
                    issuer=disco.issuer,
                    algorithms=id_token_algorithms,
                    options=id_token_options,
                    require_https=False,
                ),
                disco_doc_address=disco_endpoint.url,
            )
        except TokenValidationException as exc:
            session.result["status"] = "error"
            session.result["error"] = f"id_token_validation: {exc.message}"
            logger.error("REJECTED: id_token validation failed: %s", exc.message)
            _store_test_result(session)
            return HTMLResponse(
                content=(
                    "<h1>ID Token Validation Failed</h1>"
                    f"<p>{html.escape(str(exc.message))}</p>"
                ),
                status_code=400,
            )

        logger.info(
            "ACCEPTED: id_token validated by py-identity-model "
            "(signature, issuer, audience, expiry, ID-Token profile)"
        )

        # Validate nonce
        token_nonce = claims.get("nonce")
        if token_nonce != session.nonce:
            session.result["status"] = "error"
            session.result["error"] = (
                f"nonce_mismatch: expected={session.nonce}, got={token_nonce}"
            )
            logger.error(
                "REJECTED: nonce mismatch (expected=%s, got=%s)",
                session.nonce,
                token_nonce,
            )
            _store_test_result(session)
            return HTMLResponse(
                content=(
                    "<h1>Nonce Mismatch</h1>"
                    f"<p>Expected: {html.escape(str(session.nonce))}, "
                    f"Got: {html.escape(str(token_nonce))}</p>"
                ),
                status_code=400,
            )

    # Fetch UserInfo (if endpoint is available and we have an access token)
    userinfo_result = _fetch_userinfo(
        session, disco, access_token, claims.get("sub"), http_client
    )
    if isinstance(userinfo_result, HTMLResponse):
        return userinfo_result
    userinfo_claims = userinfo_result

    # FAPI 2.0 (plain_fapi): drive the dedicated resource endpoint so the OIDF
    # happy-path module transitions to FINISHED (userinfo alone leaves it
    # WAITING for this profile).
    _fetch_fapi2_resource(session, disco, access_token, http_client)

    # Record the id_token + end-session endpoint so a later /logout can build the
    # RP-Initiated Logout URL. /logout carries no flow parameters of its own, so
    # (like the back-channel receiver) it recovers them from the last flow driven.
    session.id_token = id_token_jwt or ""
    session.end_session_endpoint = disco.end_session_endpoint or ""
    global _last_logout_context
    _last_logout_context = {
        "end_session_endpoint": session.end_session_endpoint,
        "id_token": session.id_token,
        "client_id": session.client_id,
    }

    # Store successful result
    session.result["status"] = "success"
    session.result["id_token_claims"] = claims
    session.result["userinfo_claims"] = userinfo_claims
    session.result["access_token"] = access_token
    _store_test_result(session)

    logger.info(
        "ACCEPTED: authentication successful for issuer=%s, sub=%s",
        session.issuer,
        claims.get("sub"),
    )

    # Build response body with ID token and UserInfo claims so the conformance
    # suite can verify the RP fetched and displayed them. All interpolated
    # values originate from the IdP (claims, error messages) and must be
    # HTML-escaped before rendering — see #381.
    claim_lines = [
        f"<p>Subject: {html.escape(str(claims.get('sub', 'N/A')))}</p>",
        f"<p>Issuer: {html.escape(str(claims.get('iss', 'N/A')))}</p>",
    ]
    if userinfo_claims:
        claim_lines.append("<h2>UserInfo Claims</h2>")
        for key, value in userinfo_claims.items():
            claim_lines.append(
                f"<p>{html.escape(str(key))}: {html.escape(str(value))}</p>"
            )

    return HTMLResponse(
        content="<h1>Authentication Successful</h1>" + "\n".join(claim_lines),
        status_code=200,
    )


@app.get("/callback", response_model=None)
def callback_get(request: Request) -> HTMLResponse | JSONResponse:
    """Handle authorization callback (query string mode)."""
    return _handle_callback(str(request.url))


@app.post("/callback", response_model=None)
async def callback_post(request: Request) -> HTMLResponse | JSONResponse:
    """Handle authorization callback (form_post mode).

    Async to support ``await request.form()``, with the blocking
    ``_handle_callback`` offloaded to a threadpool.

    Starlette's ``FormData`` is a multi-dict — a single form key can
    carry multiple values. ``dict(form_data)`` silently drops all but
    the first value for such keys, which would corrupt any response
    that legitimately submits a repeated field. Use ``multi_items()``
    so every (key, value) pair survives the urlencode round-trip.
    """
    form_data = await request.form()
    params = urlencode(list(form_data.multi_items()))
    callback_url = f"{RP_BASE_URL}/callback?{params}"
    return await run_in_threadpool(_handle_callback, callback_url)


def _receive_backchannel_logout(logout_token: str | None) -> JSONResponse:
    """Validate a Back-Channel Logout Token posted by the OP (sync worker).

    OpenID Connect Back-Channel Logout 1.0 §2.4/§2.5: the OP POSTs a
    ``logout_token`` to the RP's ``backchannel_logout_uri``. The RP validates it
    and responds 200 on success or 400 on failure. Validation is delegated to
    ``validate_logout_token`` so the harness exercises the library's public API.
    """
    if not logout_token:
        logger.error("REJECTED: back-channel logout request missing logout_token")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "detail": "missing logout_token"},
        )

    # Snapshot the process-global flow context once. A concurrent ``/authorize``
    # can replace ``_last_flow_context`` between the None-check and the field
    # reads; binding the reference once ensures issuer/client_id/disco all come
    # from a single, self-consistent flow rather than a spliced mix.
    flow_context = _last_flow_context
    if flow_context is None:
        logger.error("REJECTED: back-channel logout received before any auth flow")
        return JSONResponse(
            status_code=400,
            content={"error": "no_flow_context", "detail": "no prior auth flow"},
        )

    try:
        claims = validate_logout_token(
            logout_token,
            TokenValidationConfig(
                perform_disco=True,
                audience=flow_context["client_id"],
                issuer=flow_context["issuer"],
                require_https=False,
            ),
            disco_doc_address=flow_context["disco_address"],
        )
    except LogoutTokenValidationException as exc:
        logger.error("REJECTED: logout token failed logout rules: %s", exc.message)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_logout_token", "detail": exc.message},
        )
    except TokenValidationException as exc:
        logger.error("REJECTED: logout token failed JWT validation: %s", exc.message)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_logout_token", "detail": exc.message},
        )
    except PyIdentityModelException as exc:
        logger.error("REJECTED: logout token validation error: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_logout_token", "detail": exc.message},
        )
    except PyJWTError as exc:
        # A non-empty but malformed ``logout_token`` (not a well-formed JWT)
        # trips PyJWT's header decode inside ``validate_token`` and raises a
        # ``PyJWTError`` — which is NOT a ``PyIdentityModelException``. Spec
        # §2.5 mandates 400 (not an uncaught 500) for an invalid token.
        logger.error("REJECTED: logout token is not a well-formed JWT: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_logout_token", "detail": "malformed token"},
        )

    logger.info(
        "ACCEPTED: back-channel logout token validated (sub=%s, sid=%s)",
        claims.get("sub"),
        claims.get("sid"),
    )
    return JSONResponse(content={"status": "ok"})


@app.post("/backchannel-logout", response_model=None)
async def backchannel_logout(request: Request) -> JSONResponse:
    """Back-Channel Logout receiver (OpenID Connect Back-Channel Logout 1.0 §2.5).

    Async to support ``await request.form()``; the blocking validation is
    offloaded to a threadpool so the library owns its (thread-local) HTTP client.
    """
    form_data = await request.form()
    logout_token = form_data.get("logout_token")
    if not isinstance(logout_token, str):
        logout_token = None
    response = await run_in_threadpool(_receive_backchannel_logout, logout_token)
    # Back-Channel Logout 1.0 §2.8: the RP's response SHOULD carry no-store cache
    # headers so a logout is never served from cache. Set on every response
    # (success and error) since the OP posts to this fixed URI.
    response.headers["Cache-Control"] = "no-cache, no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/logout", response_model=None)
def logout(
    test_name: str = Query("", description="Test module name for RP log capture"),
    profile: str = Query("", description="Profile/plan name for RP log capture"),
    send_state: str = Query(
        "true", description="Whether to include a state on the logout request"
    ),
) -> RedirectResponse | JSONResponse:
    """Initiate RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0 §2).

    Builds the OP's end-session URL with the ``id_token_hint``, ``client_id``,
    ``post_logout_redirect_uri`` and (optionally) a fresh ``state`` via the
    library's ``build_end_session_url``, remembers the ``state`` for the
    round-trip check, and redirects the user agent to the OP. Returns 400 if no
    login flow has completed yet (no end-session endpoint / id_token to log out
    with).

    ``state`` is OPTIONAL in RP-Initiated Logout 1.0 §2. ``send_state=false``
    omits it (the -no-state module); the round-trip check then expects the OP to
    return no state either.
    """
    _set_active_test(profile, test_name)
    logout_context = _last_logout_context
    if logout_context is None or not logout_context.get("end_session_endpoint"):
        logger.error("REJECTED: /logout called before a successful login flow")
        return JSONResponse(
            status_code=400,
            content={
                "error": "no_logout_context",
                "detail": "no completed login flow with an end_session_endpoint",
            },
        )

    global _expected_logout_state
    _expected_logout_state = (
        secrets.token_urlsafe(32) if send_state.lower() == "true" else None
    )

    end_session_url = build_end_session_url(
        logout_context["end_session_endpoint"],
        id_token_hint=logout_context["id_token"] or None,
        client_id=logout_context["client_id"] or None,
        post_logout_redirect_uri=f"{RP_BASE_URL}/post-logout-callback",
        state=_expected_logout_state,
    )

    # Log only the endpoint, never the full URL: it carries id_token_hint (a
    # complete ID Token with PII/subject claims) which must not land in logs.
    logger.info(
        "Redirecting to OP end-session endpoint: %s",
        logout_context["end_session_endpoint"],
    )
    return RedirectResponse(url=end_session_url, status_code=302)


@app.get("/post-logout-callback", response_model=None)
def post_logout_callback(state: str | None = Query(default=None)) -> HTMLResponse:
    """Post-logout redirect target (RP-Initiated Logout 1.0 §2 state round-trip).

    Validates the ``state`` the OP returns against the value sent to the
    end-session endpoint using the library's ``validate_post_logout_state``.
    Responds 200 on a matching round-trip and 400 on a missing/mismatched state.
    """
    try:
        validate_post_logout_state(_expected_logout_state, state)
    except LogoutStateValidationException as exc:
        logger.error("REJECTED: post-logout state validation failed: %s", exc.message)
        return HTMLResponse(
            content=(
                "<h1>Logout State Validation Failed</h1>"
                f"<p>{html.escape(str(exc.message))}</p>"
            ),
            status_code=400,
        )

    logger.info("ACCEPTED: post-logout state validated by py-identity-model")
    return HTMLResponse(
        content="<h1>Logout Successful</h1><p>State validated.</p>",
        status_code=200,
    )


@app.get("/results/{test_id}")
def get_result(test_id: str) -> JSONResponse:
    """Retrieve the result of a completed test flow."""
    if test_id in test_results:
        session = test_results[test_id]
        return JSONResponse(content=session.result)
    return JSONResponse(status_code=404, content={"error": "not_found"})


def _store_test_result(session: AuthSession) -> None:
    """Store session result indexed by test_id if available."""
    test_id = session.result.get("test_id")
    if test_id:
        test_results[test_id] = session
