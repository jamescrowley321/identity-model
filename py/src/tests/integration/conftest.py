"""Shared fixtures for integration tests.

Includes:
- Generic provider fixtures with retry/caching logic
- Discovery-driven capability detection (RFC 8414)
- Auth code flow helpers for providers with devInteractions
"""

from contextlib import suppress
from dataclasses import dataclass
import getpass
from html.parser import HTMLParser
import json
from pathlib import Path
import secrets
import tempfile
import time
from types import MappingProxyType
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from filelock import FileLock
import httpx
import pytest
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentRequest,
    JsonWebKey,
    JwksRequest,
    JwksResponse,
    PrivateKeyJwt,
    get_discovery_document,
    get_jwks,
    parse_authorize_callback_response,
    request_authorization_code_token,
    request_client_credentials_token,
    validate_authorize_callback_state,
)
from py_identity_model.aio.http_client import _reset_async_http_client
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.jwks_cache import is_uncacheable
from py_identity_model.core.models import DiscoveryDocumentResponse
from py_identity_model.core.parsers import (
    extract_kid_from_jwt,
    find_key_by_kid,
)
from py_identity_model.core.pkce import generate_pkce_pair
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.http_client import close_http_client

from ..harness import (
    HarnessError,
    Provider,
    ProviderConfig,
    TokenSource,
)
from .test_utils import get_config


@pytest.hookimpl(trylast=True)
def pytest_configure(config: pytest.Config) -> None:
    """Clear stale cross-run integration cache before the run starts.

    The session fixtures below cache discovery/JWKS/tokens to JSON at
    ``tmp_path_factory.getbasetemp().parent`` — a path kept stable so
    ``pytest -n auto`` workers share one fetch, but which therefore also
    persists across *separate* runs. Every integration run starts a FRESH
    provider container with new ephemeral signing keys and mints new tokens,
    so a cache left over from a prior run is always stale: cached access /
    opaque tokens have expired ("Token has expired" / introspection inactive)
    and the cached JWKS no longer matches the new keys ("Invalid signature" /
    "refresh cooldown active"). That produced ~22 spurious failures on any
    re-run more than a token TTL after the previous one.

    Clear it once, on the xdist controller only (before workers spawn and
    before any fixture reads it). The in-run FileLock + JSON cache still
    prevents the N-worker discovery/JWKS stampede the cache exists to avoid.
    """
    if hasattr(config, "workerinput"):  # xdist worker: controller already cleared
        return
    factory = getattr(config, "_tmp_path_factory", None)
    if factory is not None:
        cache_dir = factory.getbasetemp().parent
    else:  # fallback to pytest's default basetemp location
        cache_dir = Path(tempfile.gettempdir()) / f"pytest-of-{getpass.getuser()}"
    if not cache_dir.is_dir():
        return
    stale_cache_stems = (
        "discovery_document",
        "raw_discovery",
        "jwks_response",
        "client_credentials_token",
        "opaque_access_token",
    )
    for stem in stale_cache_stems:
        for ext in ("json", "lock"):
            for stale in cache_dir.glob(f"*_{stem}.{ext}"):
                stale.unlink(missing_ok=True)


# HTTP status codes
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_TOO_MANY_REQUESTS = 429

# JWT format: three dot-separated segments
JWT_SEGMENT_SEPARATOR_COUNT = 2

# Shared token validation options — audience validation disabled for
# integration tests because provider-issued tokens may not include an
# audience matching the test client.
DEFAULT_VALIDATION_OPTIONS: dict[str, bool] = {
    "verify_aud": False,
    "require_aud": False,
}


# ============================================================================
# Generic provider fixtures
# ============================================================================

RATE_LIMIT_ERROR_MESSAGE = "Rate limited"
MAX_REDIRECTS = 20


def retry_with_backoff():
    """Retry decorator that handles HTTP 429 rate limiting."""
    return retry(
        retry=retry_if_exception_type(httpx.HTTPStatusError),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )


@pytest.fixture(scope="session")
def provider_slug(env_file) -> str:
    """Stable per-provider slug used to namespace cross-worker cache files.

    Session cache/lock files live at a stable path
    (``tmp_path_factory.getbasetemp().parent``) that is *not* keyed by
    provider. Running two providers against the same base tmp dir — e.g.
    ``make test-integration-node-oidc`` then ``...-keycloak`` — would
    otherwise reuse the first provider's cached discovery document, JWKS and
    tokens, pointing the second run at a dead endpoint (Errno 111) and the
    wrong signing keys. Deriving the slug from the env file
    (``.env.keycloak`` -> ``keycloak``) isolates each provider's caches.
    """
    if not env_file:
        return "default"
    # Strip any directory component without importing os
    name = env_file.replace("\\", "/").rsplit("/", 1)[-1]
    if name.startswith(".env."):
        return name[len(".env.") :] or "default"
    return "default"


@pytest.fixture(scope="session")
def test_config(env_file, provider_slug, tmp_path_factory):
    """Session-scoped test configuration with file-lock for xdist safety."""
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    lock_file = root_tmp_dir / f"{provider_slug}_test_config.lock"
    with FileLock(str(lock_file)):
        return get_config(env_file)


@pytest.fixture(scope="session")
def discovery_document(test_config, provider_slug, tmp_path_factory):
    """Cached discovery document, shared across xdist workers.

    See ``client_credentials_token`` for the cross-worker FileLock +
    JSON cache rationale: without it, ``pytest -n auto`` fans out N
    simultaneous discovery requests at session start and trips upstream
    rate limits.
    """
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    cache_file = root_tmp_dir / f"{provider_slug}_discovery_document.json"
    lock_file = root_tmp_dir / f"{provider_slug}_discovery_document.lock"

    with FileLock(str(lock_file)):
        if cache_file.exists():
            return DiscoveryDocumentResponse(**json.loads(cache_file.read_text()))

        require_https = test_config.get("TEST_REQUIRE_HTTPS", True)
        policy = DiscoveryPolicy(require_https=require_https)
        disco_doc_req = DiscoveryDocumentRequest(
            address=test_config["TEST_DISCO_ADDRESS"],
            policy=policy,
        )
        response = get_discovery_document(disco_doc_req)
        if not response.is_successful:
            pytest.fail(f"Failed to fetch discovery document: {response.error}")
        # ``asdict()`` trips the BaseResponse field-access guards; use vars()
        # to read the underlying storage. See models.BaseResponse docstring.
        cache_file.write_text(json.dumps(vars(response)))
        return response


@pytest.fixture(scope="session")
def raw_discovery(test_config, provider_slug, tmp_path_factory):
    """Raw discovery JSON for capability detection.

    Provides access to all RFC 8414 fields, including those not yet
    in the typed DiscoveryDocumentResponse model. Shared across xdist
    workers via FileLock + JSON cache; see ``client_credentials_token``
    for the rationale.
    """
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    cache_file = root_tmp_dir / f"{provider_slug}_raw_discovery.json"
    lock_file = root_tmp_dir / f"{provider_slug}_raw_discovery.lock"

    with FileLock(str(lock_file)):
        if cache_file.exists():
            return json.loads(cache_file.read_text())

        address = test_config["TEST_DISCO_ADDRESS"]

        @retry_with_backoff()
        def fetch_raw():
            resp = httpx.get(address, timeout=10.0)
            if resp.status_code == HTTP_TOO_MANY_REQUESTS:
                raise httpx.HTTPStatusError(
                    RATE_LIMIT_ERROR_MESSAGE,
                    request=resp.request,
                    response=resp,
                )
            return resp

        try:
            resp = fetch_raw()
        except httpx.TransportError as exc:
            pytest.fail(f"raw_discovery: cannot reach {address}: {exc}")
        if resp.status_code != HTTP_OK:
            pytest.fail(f"raw_discovery: HTTP {resp.status_code} from {address}")
        try:
            data = resp.json()
        except ValueError as exc:
            pytest.fail(f"raw_discovery: invalid JSON from {address}: {exc}")
        cache_file.write_text(json.dumps(data))
        return data


def _detect_grant_capabilities(raw_discovery: dict, grants: set) -> set[str]:
    """Detect grant type and endpoint capabilities."""
    caps = set()
    if raw_discovery.get("authorization_endpoint"):
        caps.add("authorization_code")
    if "client_credentials" in grants:
        caps.add("client_credentials")
    if "refresh_token" in grants:
        caps.add("refresh_token")
    if "urn:ietf:params:oauth:grant-type:device_code" in grants:
        caps.add("device_authorization")
    if "urn:ietf:params:oauth:grant-type:token-exchange" in grants:
        caps.add("token_exchange")
    for endpoint, cap in (
        ("introspection_endpoint", "introspection"),
        ("revocation_endpoint", "revocation"),
        ("userinfo_endpoint", "userinfo"),
        ("device_authorization_endpoint", "device_authorization_endpoint"),
        ("pushed_authorization_request_endpoint", "par"),
        ("end_session_endpoint", "end_session"),
        ("registration_endpoint", "registration"),
    ):
        if raw_discovery.get(endpoint):
            caps.add(cap)
    return caps


def _detect_feature_capabilities(raw_discovery: dict) -> set[str]:
    """Detect feature capabilities from discovery metadata."""
    caps = set()
    challenge_methods = raw_discovery.get("code_challenge_methods_supported", [])
    if "S256" in challenge_methods:
        caps.add("pkce")
    if raw_discovery.get("dpop_signing_alg_values_supported"):
        caps.add("dpop")
    if raw_discovery.get("request_parameter_supported"):
        caps.add("jar")
    if raw_discovery.get("backchannel_logout_supported"):
        caps.add("backchannel_logout")
    # JARM (JWT-Secured Authorization Response Mode): the AS advertises the
    # signing algs and/or the *.jwt response modes when it can return a signed
    # authorization response.
    response_modes = raw_discovery.get("response_modes_supported", [])
    if raw_discovery.get("authorization_signing_alg_values_supported") or any(
        mode.endswith(".jwt") or mode == "jwt" for mode in response_modes
    ):
        caps.add("jarm")

    # mTLS (RFC 8705): the AS must both terminate TLS with client-cert
    # verification and advertise an mTLS client-auth method / mtls_endpoint_aliases.
    auth_methods = raw_discovery.get("token_endpoint_auth_methods_supported", []) or []
    if (
        {"tls_client_auth", "self_signed_tls_client_auth"} & set(auth_methods)
        or raw_discovery.get("mtls_endpoint_aliases")
        or raw_discovery.get("tls_client_certificate_bound_access_tokens")
    ):
        caps.add("mtls")

    # devInteractions: only local fixtures support automated
    # browser-like auth code flows
    issuer = raw_discovery.get("issuer", "")
    if issuer.startswith(("http://localhost", "http://127.0.0.1")):
        caps.add("dev_interactions")

    return caps


@pytest.fixture(scope="session")
def provider_capabilities(raw_discovery):
    """Detect provider capabilities from discovery document (RFC 8414).

    Capabilities are derived entirely from the discovery document —
    no TEST_PROVIDER env var needed.
    """
    grants = set(raw_discovery.get("grant_types_supported", []))
    caps = _detect_grant_capabilities(raw_discovery, grants)
    caps |= _detect_feature_capabilities(raw_discovery)
    return caps


@pytest.fixture(scope="session")
def jwks_response(test_config, provider_slug, tmp_path_factory):
    """Cached JWKS response, shared across xdist workers.

    See ``client_credentials_token`` for the cross-worker FileLock +
    JSON cache rationale.
    """
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    cache_file = root_tmp_dir / f"{provider_slug}_jwks_response.json"
    lock_file = root_tmp_dir / f"{provider_slug}_jwks_response.lock"

    with FileLock(str(lock_file)):
        if cache_file.exists():
            cached = json.loads(cache_file.read_text())
            keys = [JsonWebKey(**k) for k in cached.pop("keys") or []]
            return JwksResponse(keys=keys, **cached)

        jwks_req = JwksRequest(address=test_config["TEST_JWKS_ADDRESS"])
        response = get_jwks(jwks_req)
        if not response.is_successful:
            pytest.fail(f"Failed to fetch JWKS: {response.error}")
        # vars() bypasses BaseResponse field-access guards; manually expand
        # the nested JsonWebKey list since vars() doesn't recurse.
        data = vars(response).copy()
        data["keys"] = [vars(k) for k in response.keys or []]
        cache_file.write_text(json.dumps(data))
        return response


@pytest.fixture(scope="session")
def provider_caches_responses(discovery_document, jwks_response):
    """Whether the provider's Cache-Control allows the library to cache.

    Discovery still honors strict ``no-store``/``no-cache`` semantics
    (sensitive metadata). JWKS, per
    :func:`py_identity_model.core.jwks_cache.is_uncacheable_for_jwks`
    and issue #396, is always cached regardless of provider directives
    — JWKS contains public keys, and strict honoring self-DoSes the
    upstream at scale. ``jwks_response`` is therefore unused here but
    retained as a fixture dep so its session-scoped cache stays
    populated for downstream tests.
    """
    del jwks_response  # see docstring
    return not is_uncacheable(discovery_document.cache_control)


@pytest.fixture(autouse=True)
async def _clear_async_caches():
    """Override the root fixture: reset the async HTTP client but keep caches.

    The root conftest's ``_clear_async_caches`` wipes the library's
    discovery/JWKS caches before *every* test. For integration tests that
    defeats the library's own per-process caching, so each test would refetch
    discovery + JWKS live and trip provider rate limits (429). Instead we want
    integration tests to exercise the *real* fetch once per worker and then
    reuse the genuine cache — exactly how a real application behaves.

    We still reset the singleton async HTTP client so it is recreated on each
    test's event loop (pytest-asyncio uses a fresh loop per test); only the
    cache clears are dropped. Cache-behavior tests that need a cold cache clear
    it explicitly via the local ``clear_validation_caches`` fixture.
    """
    _reset_async_http_client()


@pytest.fixture(autouse=True)
def _integration_retry_backoff(monkeypatch):
    """Give the library a real retry backoff for integration tests.

    The root conftest zeroes ``HTTP_RETRY_BASE_DELAY`` so unit tests that
    exercise retry paths don't sleep. Integration tests hit live, rate-limited
    providers, so a genuine discovery/JWKS fetch that draws a transient 429
    must actually back off (and honor ``Retry-After``) to recover instead of
    hammering the endpoint with zero delay.
    """
    monkeypatch.setenv("HTTP_RETRY_BASE_DELAY", "1.0")


@pytest.fixture(scope="session")
def token_endpoint(discovery_document):
    """Provide the token endpoint from cached discovery document."""
    return discovery_document.token_endpoint


@pytest.fixture(scope="session")
def jwks_uri(discovery_document):
    """Provide the JWKS URI from cached discovery document."""
    return discovery_document.jwks_uri


@pytest.fixture(scope="session")
def issuer(discovery_document):
    """Provide the issuer from cached discovery document."""
    return discovery_document.issuer


@pytest.fixture(scope="session")
def userinfo_endpoint(discovery_document):
    """Provide the UserInfo endpoint from cached discovery document."""
    return discovery_document.userinfo_endpoint


@pytest.fixture(scope="session")
def require_https(test_config):
    """Provide whether HTTPS is required for the current provider."""
    return test_config.get("TEST_REQUIRE_HTTPS", True)


def _fetch_token_with_extended_backoff(
    token_request: ClientCredentialsTokenRequest,
    label: str,
) -> ClientCredentialsTokenResponse:
    """Fetch a client-credentials token with longer 429 backoff than the
    library's internal retry budget.

    The library retries 3x with 1s/2s/4s backoff (~7s total). Provider
    rate-limit recovery can exceed that, especially when several pytest
    xdist workers race the same upstream at session start. Extends the
    budget to 5+10+20+40s on 429 specifically; other failures are
    returned immediately.
    """
    max_attempts = 5
    last_error: str | None = None
    for attempt in range(max_attempts):
        response = request_client_credentials_token(token_request)
        if response.is_successful:
            return response
        last_error = str(response.error or "unknown error")
        is_rate_limited = "429" in last_error
        if not is_rate_limited or attempt == max_attempts - 1:
            break
        sleep_for = 5 * (2**attempt)
        print(
            f"[{label}] token endpoint rate-limited "
            f"(attempt {attempt + 1}/{max_attempts}); sleeping {sleep_for}s",
            flush=True,
        )
        time.sleep(sleep_for)
    pytest.fail(f"Failed to obtain {label} after extended retries: {last_error}")


@pytest.fixture(scope="session")
def client_credentials_token(
    test_config,
    token_endpoint,
    provider_slug,
    tmp_path_factory,
):
    """Client credentials token, shared across xdist workers.

    Without cross-worker coordination, ``pytest -n auto`` fans out N
    simultaneous token requests at session start. With N=4 workers and a
    typical upstream rate limit, the cluster trips HTTP 429 and the
    session-scoped fixture (which is actually per-worker under xdist)
    fails for everyone downstream.

    Serialize the fetch with a ``FileLock`` and persist the response to
    a JSON cache under the xdist tmp root. The first worker to acquire
    the lock fetches; subsequent workers see the cache and reconstruct
    the response object instead of re-fetching.
    """
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    cache_file = root_tmp_dir / f"{provider_slug}_client_credentials_token.json"
    lock_file = root_tmp_dir / f"{provider_slug}_client_credentials_token.lock"

    with FileLock(str(lock_file)):
        if cache_file.exists():
            cached = json.loads(cache_file.read_text())
            return ClientCredentialsTokenResponse(
                is_successful=True, token=cached["token"]
            )

        response = _fetch_token_with_extended_backoff(
            ClientCredentialsTokenRequest(
                client_id=test_config["TEST_CLIENT_ID"],
                client_secret=test_config["TEST_CLIENT_SECRET"],
                address=token_endpoint,
                scope=test_config["TEST_SCOPE"],
            ),
            label="client_credentials_token",
        )
        cache_file.write_text(json.dumps({"token": response.token}))
        return response


@pytest.fixture(scope="session")
def jwt_access_token(client_credentials_token, test_config, token_endpoint):
    """JWT-format access token for manual key validation tests.

    Uses the standard client_credentials token if it's already a JWT.
    Falls back to requesting with resource param for providers that
    need it for JWT format (e.g., node-oidc without defaultResource).
    Skips if no JWT token can be obtained.
    """
    # Check if standard token is already JWT
    token = client_credentials_token.token
    access_token = token.get("access_token", "")
    if access_token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT:
        return token

    # Fallback: request with resource param to force JWT format
    @retry_with_backoff()
    def fetch_jwt_with_resource():
        r = httpx.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "scope": test_config.get("TEST_SCOPE", "openid"),
                "resource": "urn:test:api",
            },
            auth=(
                test_config["TEST_CLIENT_ID"],
                test_config["TEST_CLIENT_SECRET"],
            ),
            timeout=10.0,
        )
        if r.status_code == HTTP_TOO_MANY_REQUESTS:
            raise httpx.HTTPStatusError(
                RATE_LIMIT_ERROR_MESSAGE,
                request=r.request,
                response=r,
            )
        return r

    resp = fetch_jwt_with_resource()
    if resp.status_code == HTTP_OK:
        data = resp.json()
        if data.get("access_token", "").count(".") == JWT_SEGMENT_SEPARATOR_COUNT:
            return data

    pytest.skip("Provider does not return JWT-format access tokens")


@pytest.fixture(scope="session")
def jwt_signing_key(jwks_response, jwt_access_token):
    """Extract the signing key and algorithm for a JWT from JWKS."""
    jwt_token = jwt_access_token["access_token"]
    kid = extract_kid_from_jwt(jwt_token)
    try:
        return find_key_by_kid(kid, jwks_response.keys or [])
    except TokenValidationException:
        pytest.skip(f"Key {kid} not found in JWKS")


@pytest.fixture(scope="session")
def opaque_access_token(
    test_config,
    token_endpoint,
    provider_slug,
    tmp_path_factory,
):
    """Opaque access token for introspection/revocation tests.

    Some providers (e.g. node-oidc-provider) cannot introspect or revoke
    JWT-format tokens.  This fixture uses a dedicated client that receives
    opaque tokens.  Skips when the opaque client is not configured.

    Shared across xdist workers via FileLock + JSON cache; see
    ``client_credentials_token`` for the rationale.
    """
    opaque_id = test_config.get("TEST_OPAQUE_CLIENT_ID")
    opaque_secret = test_config.get("TEST_OPAQUE_CLIENT_SECRET")
    if not opaque_id or not opaque_secret:
        pytest.skip("TEST_OPAQUE_CLIENT_ID not configured")

    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    cache_file = root_tmp_dir / f"{provider_slug}_opaque_access_token.json"
    lock_file = root_tmp_dir / f"{provider_slug}_opaque_access_token.lock"

    with FileLock(str(lock_file)):
        if cache_file.exists():
            cached = json.loads(cache_file.read_text())
            return cached["access_token"]

        response = _fetch_token_with_extended_backoff(
            ClientCredentialsTokenRequest(
                client_id=opaque_id,
                client_secret=opaque_secret,
                address=token_endpoint,
                scope=test_config["TEST_SCOPE"],
            ),
            label="opaque_access_token",
        )
        assert response.token is not None, "Token response has no token dict"
        access_token = response.token["access_token"]
        cache_file.write_text(json.dumps({"access_token": access_token}))
        return access_token


# ============================================================================
# Unified token-source harness (TH-1.1, #463)
# ============================================================================

# The provider slug (derived from the ``.env.<slug>`` file) maps onto the
# harness ``Provider`` enum. An unrecognised slug (e.g. ``.env.local``) leaves
# the real provider unwired, so only the always-available MOCK provider is
# offered and the real-IdP tests skip cleanly.
_SLUG_TO_PROVIDER: dict[str, Provider] = {
    "node-oidc": Provider.NODE_OIDC,
    "keycloak": Provider.KEYCLOAK,
    "ory": Provider.ORY,
    "descope": Provider.DESCOPE,
}


@pytest.fixture(scope="session")
def harness_provider(provider_slug) -> Provider | None:
    """The real :class:`Provider` under test, or ``None`` for an unknown slug."""
    return _SLUG_TO_PROVIDER.get(provider_slug)


@pytest.fixture(scope="session")
def token_source(
    harness_provider,
    raw_discovery,
    discovery_document,
    provider_capabilities,
    test_config,
) -> TokenSource:
    """Session-scoped unified minter (:class:`TokenSource`) for the harness.

    Wires the real provider under test — capabilities derived from live
    discovery via ``provider_matrix.detect_capabilities`` (so the harness and
    the capability matrix never drift), credentials from the env file — plus
    the always-available MOCK provider. When the provider supports automated
    auth-code flows (devInteractions) and the auth-code client is configured,
    an ``auth_code_minter`` wrapping :func:`perform_auth_code_flow` is injected
    so ``Grant.AUTHORIZATION_CODE`` mints end-to-end.

    Tests translate the typed gating errors
    (:class:`HarnessCapabilityError` / :class:`HarnessCredentialError`) to
    ``pytest.skip`` so secret-gated providers (Ory/Descope) skip cleanly while
    MOCK is always mintable.
    """
    if harness_provider is None:
        return TokenSource.with_mock()

    auth_code_minter = None
    if "dev_interactions" in provider_capabilities:
        client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID")
        redirect_uri = test_config.get("TEST_AUTH_CODE_REDIRECT_URI")
        client_secret = test_config.get("TEST_AUTH_CODE_CLIENT_SECRET")
        if client_id and redirect_uri:

            def auth_code_minter(
                tenant: str | None,
                scopes: str | None,
                *,
                _client_id: str = client_id,
                _redirect_uri: str = redirect_uri,
                _client_secret: str | None = client_secret,
            ) -> dict[str, Any]:
                del tenant  # single-tenant local fixtures ignore tenant shaping
                result = perform_auth_code_flow(
                    discovery=discovery_document,
                    client_id=_client_id,
                    redirect_uri=_redirect_uri,
                    config=AuthCodeFlowConfig(
                        client_secret=_client_secret,
                        scope=scopes or "openid profile email offline_access",
                        resource="urn:test:api",
                    ),
                )
                token_response = result["token_response"]
                if not token_response.is_successful or token_response.token is None:
                    raise HarnessError(f"auth-code mint failed: {token_response.error}")
                return dict(token_response.token)

    real_cfg = ProviderConfig.from_discovery(
        harness_provider,
        raw_discovery,
        token_endpoint=discovery_document.token_endpoint,
        client_id=test_config.get("TEST_CLIENT_ID"),
        client_secret=test_config.get("TEST_CLIENT_SECRET"),
        scope=test_config.get("TEST_SCOPE"),
        auth_code_minter=auth_code_minter,
        # Descope multi-tenant access-key exchange (AC-3); absent -> skip.
        descope_project_id=test_config.get("DESCOPE_PROJECT_ID"),
        descope_management_key=test_config.get("DESCOPE_MANAGEMENT_KEY"),
        descope_base_url=test_config.get("DESCOPE_BASE_URL"),
    )
    return TokenSource.with_mock(extra=[real_cfg])


@pytest.fixture(autouse=True)
def _cleanup_http_client_per_test():
    """Close the persistent HTTP client after each integration test.

    httpx.Client keeps connections pooled in the thread-local singleton.
    Python 3.13's stricter ``__del__`` raises ``ResourceWarning`` when
    pooled transports are garbage-collected with open sockets.  Closing
    the client after every test ensures no connections leak between
    tests and prevents ``PytestUnraisableExceptionWarning`` failures.
    """
    yield
    with suppress(Exception):
        close_http_client()


# ============================================================================
# Auth code flow helpers (capability-gated)
# ============================================================================


def _resolve_location(resp: httpx.Response) -> str | None:
    """Extract and resolve the Location header from a redirect.

    Handles absolute URLs, protocol-relative (//), absolute paths (/),
    and bare relative paths per RFC 7231 section 7.1.2.
    """
    location = resp.headers.get("location")
    if location is None:
        return None
    if not location.startswith("http"):
        parsed = urlparse(str(resp.url))
        base = f"{parsed.scheme}://{parsed.netloc}"
        if location.startswith("//"):
            location = f"{parsed.scheme}:{location}"
        elif location.startswith("/"):
            location = f"{base}{location}"
        else:
            # Bare relative path (no leading slash) — resolve
            # against the current URL's directory
            parent = parsed.path.rsplit("/", 1)[0]
            location = f"{base}{parent}/{location}"
    return location


def is_redirect(status_code: int) -> bool:
    return status_code in (301, 302, 303, 307, 308)


def _matches_redirect_uri(location: str, redirect_uri: str) -> bool:
    """Check if location matches the redirect_uri."""
    return location == redirect_uri or location.startswith(
        (redirect_uri + "?", redirect_uri + "#")
    )


def follow_redirects_to_callback(
    client: httpx.Client,
    resp: httpx.Response,
    redirect_uri: str,
) -> tuple[str | None, httpx.Response]:
    """Follow redirects until we reach the redirect_uri."""
    redirects = 0
    while is_redirect(resp.status_code):
        location = _resolve_location(resp)
        if location is None:
            return None, resp

        if _matches_redirect_uri(location, redirect_uri):
            return location, resp

        redirects += 1
        if redirects > MAX_REDIRECTS:
            pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")

        resp = client.get(location)

    return None, resp


def _follow_redirects_counted(
    client: httpx.Client,
    resp: httpx.Response,
    redirect_uri: str,
    prior_redirects: int,
) -> tuple[str | None, httpx.Response]:
    """Follow redirects with a shared counter across the flow."""
    total = prior_redirects
    while is_redirect(resp.status_code):
        location = _resolve_location(resp)
        if location is None:
            return None, resp

        if _matches_redirect_uri(location, redirect_uri):
            return location, resp

        total += 1
        if total > MAX_REDIRECTS:
            pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")

        resp = client.get(location)

    return None, resp


class _LoginFormParser(HTMLParser):
    """Extract the HTML login ``<form>`` — the one carrying a password input.

    Providers that render a server-side login page (e.g. Keycloak) return an
    HTML ``<form action=".../login-actions/authenticate?...">`` with
    ``username``/``password`` inputs rather than node-oidc's devInteractions
    JSON-ish endpoint. This captures that form's action plus every input
    name/value so hidden fields (Keycloak's ``credentialId`` etc.) round-trip.
    """

    def __init__(self) -> None:
        super().__init__()
        # Depth counter (not a bool) so a nested <form> (invalid HTML, but
        # defensive) neither resets the outer form on its start tag nor closes
        # it early on its end tag — only the outermost boundary opens/commits.
        self._form_depth = 0
        self._current_action: str | None = None
        self._current_inputs: dict[str, str] = {}
        self._current_has_password = False
        self.action: str | None = None
        self.inputs: dict[str, str] = {}
        self.field_names: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attrs_d = {k: (v or "") for k, v in attrs}
        if tag == "form":
            if self._form_depth == 0:
                self._current_action = attrs_d.get("action")
                self._current_inputs = {}
                self._current_has_password = False
            self._form_depth += 1
        elif tag == "input" and self._form_depth > 0:
            name = attrs_d.get("name")
            if not name:
                return
            self._current_inputs[name] = attrs_d.get("value", "")
            if attrs_d.get("type", "").lower() == "password":
                self._current_has_password = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form_depth > 0:
            self._form_depth -= 1
            if self._form_depth != 0:
                return
            # Outermost </form> closed: keep the first form that collects a password
            if self._current_has_password and self.action is None:
                self.action = self._current_action
                self.inputs = dict(self._current_inputs)
                self.field_names = set(self._current_inputs)


def _parse_login_form(html_text: str, base_url: str):
    """Parse an HTML login form.

    Returns ``(action_url, field_names, hidden)`` where ``action_url`` is the
    absolute, HTML-entity-unescaped POST target (``&amp;`` -> ``&``), or
    ``None`` when no password-bearing form is present. ``hidden`` holds every
    input except the credential fields the caller fills.
    """
    parser = _LoginFormParser()
    parser.feed(html_text)
    if not parser.field_names:
        return None
    # ``HTMLParser`` already unescapes character references in attribute
    # values (``&amp;`` -> ``&``), so the action is used as-is; a second
    # ``unescape`` here would double-decode (e.g. ``&amp;amp;`` -> ``&``).
    action = parser.action if parser.action else base_url
    action_url = urljoin(base_url, action)
    hidden = {
        k: v
        for k, v in parser.inputs.items()
        if k not in {"username", "login", "password"}
    }
    return action_url, parser.field_names, hidden


def _iter_set_cookies(response: httpx.Response):
    """Yield ``(name, value)`` for every ``Set-Cookie`` on ``response``."""
    for header in response.headers.get_list("set-cookie"):
        name, sep, rest = header.partition("=")
        if not sep:
            continue
        yield name.strip(), rest.split(";", 1)[0].strip()


class _AuthFlowClient(httpx.Client):
    """``httpx.Client`` that echoes cookies back over plain ``http``.

    httpx rebuilds the cookie jar with the *default* stdlib policy on every
    outgoing request (``BaseClient._merge_cookies`` wraps the client jar in a
    fresh ``Cookies``, and ``Request.__init__`` wraps it again before calling
    ``set_cookie_header``), so a custom ``CookiePolicy`` cannot survive to the
    send path. That default policy refuses to send ``Secure`` cookies over an
    ``http://`` connection. Keycloak marks its ``AUTH_SESSION_ID`` /
    ``KC_RESTART`` auth-session cookies ``Secure; SameSite=None``
    unconditionally, so a plain-http auth-code flow never gets them back and
    every login POST fails with "Restart login cookie not found".

    This client keeps its own ``name -> value`` store, captures every
    ``Set-Cookie`` (``Secure`` included), and writes the ``Cookie`` header
    itself. node-oidc's non-``Secure`` cookies round-trip identically through
    the same store, so both providers share one code path.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._flow_cookies: dict[str, str] = {}

    def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        if self._flow_cookies:
            request.headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self._flow_cookies.items()
            )
        response = super().send(request, **kwargs)
        for name, value in _iter_set_cookies(response):
            # An empty value is a deletion (Max-Age=0 / expired) — drop it.
            if value:
                self._flow_cookies[name] = value
            else:
                self._flow_cookies.pop(name, None)
        return response


def _submit_login(client, resp, interaction_url, config):
    """Submit login credentials, handling both provider login styles.

    node-oidc exposes a devInteractions endpoint that dispatches on a
    ``prompt`` field; server-rendered providers (e.g. Keycloak) return an HTML
    ``<form>`` that must be parsed for its action and field names. Returns the
    post-login response for the caller's redirect-following loop.
    """
    if "/interaction/" in interaction_url:
        # node-oidc devInteractions: a single endpoint dispatches on the
        # `prompt` field. Left byte-for-byte identical to preserve the
        # existing (passing) node-oidc flow.
        return client.post(
            interaction_url,
            data={
                "prompt": "login",
                "login": config.login_hint,
                "password": config.login_password,
            },
        )
    # Generic server-rendered HTML login form (e.g. Keycloak). Parse the
    # returned form for its action + field names, echo back any hidden
    # fields, and fill whichever username field the form uses.
    form = _parse_login_form(resp.text, interaction_url)
    if form is None:
        pytest.fail(f"Could not locate a login form at {interaction_url}")
    action_url, field_names, hidden = form
    data = dict(hidden)
    if "username" in field_names:
        data["username"] = config.login_hint
    if "login" in field_names:
        data["login"] = config.login_hint
    if "username" not in field_names and "login" not in field_names:
        # Provider names its identifier field something else (not
        # username/login). Fall back to the sole non-password field so the
        # identifier is still sent rather than silently dropped; if more than
        # one non-password field exists it is ambiguous, so fail loudly.
        identifier_fields = field_names - {"password"}
        if len(identifier_fields) == 1:
            data[next(iter(identifier_fields))] = config.login_hint
        else:
            pytest.fail(
                f"Could not identify the username field in the login form at "
                f"{action_url}; fields={sorted(field_names)}"
            )
    data["password"] = config.login_password
    return client.post(action_url, data=data)


@dataclass(frozen=True)
class AuthCodeFlowConfig:
    """Optional configuration for :func:`perform_auth_code_flow`."""

    client_secret: str | None = None
    scope: str = "openid profile email offline_access"
    resource: str | None = None
    login_hint: str = "test-user"
    login_password: str = "test"
    private_key_jwt: PrivateKeyJwt | None = None
    # When set, sent on the authorization request so the OP echoes them into
    # the ID Token — letting live tests exercise the OIDC §3.1.3.7 nonce
    # binding (step 11) and auth_time/max_age freshness (step 12) on a real
    # minted token rather than only synthetic claim sets.
    nonce: str | None = None
    max_age: int | None = None


def perform_auth_code_flow(
    discovery: DiscoveryDocumentResponse,
    client_id: str,
    redirect_uri: str,
    config: AuthCodeFlowConfig | None = None,
) -> MappingProxyType:
    """Perform a full auth code + PKCE flow using devInteractions.

    Args:
        discovery: Discovery document response.
        client_id: OAuth client identifier.
        redirect_uri: Registered redirect URI.
        config: Optional flow configuration (scope, credentials, etc.).
            Defaults to ``AuthCodeFlowConfig()`` when ``None``.

    Returns dict with token_response, state, callback,
    state_result, code_verifier.
    """
    if config is None:
        config = AuthCodeFlowConfig()
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    assert discovery.authorization_endpoint, (
        "Missing authorization_endpoint in discovery"
    )

    auth_params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": config.scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    # Optional authorization-request params. nonce/max_age are echoed by the OP
    # into the ID Token (nonce claim, auth_time), letting live tests exercise
    # the §3.1.3.7 nonce and max_age bindings on a real minted token.
    optional_params = {
        "resource": config.resource,
        "nonce": config.nonce,
        "max_age": config.max_age,
    }
    auth_params.update(
        {key: str(value) for key, value in optional_params.items() if value is not None}
    )

    auth_url = f"{discovery.authorization_endpoint}?{urlencode(auth_params)}"

    # Use a single redirect counter across the entire flow
    total_redirects = 0

    with _AuthFlowClient(follow_redirects=False, timeout=10.0) as client:
        resp = client.get(auth_url)
        while is_redirect(resp.status_code):
            location = _resolve_location(resp)
            if location is None:
                pytest.fail(f"Redirect without Location header at {resp.url}")
            if _matches_redirect_uri(location, redirect_uri):
                break
            total_redirects += 1
            if total_redirects > MAX_REDIRECTS:
                pytest.fail(f"Too many redirects (>{MAX_REDIRECTS})")
            resp = client.get(location)

        if resp.status_code >= HTTP_BAD_REQUEST:
            pytest.fail(f"Auth request failed: {resp.status_code} at {resp.url}")

        interaction_url = str(resp.url)
        resp = _submit_login(client, resp, interaction_url, config)

        callback_url, resp = _follow_redirects_counted(
            client, resp, redirect_uri, total_redirects
        )

        if callback_url is None:
            consent_url = str(resp.url)
            if "/interaction/" in consent_url:
                resp = client.post(consent_url, data={"prompt": "consent"})
                callback_url, resp = _follow_redirects_counted(
                    client, resp, redirect_uri, total_redirects
                )

        if callback_url is None:
            pytest.fail(
                "Auth code flow did not reach redirect_uri. "
                f"Last: {resp.status_code} at {resp.url}"
            )

    callback = parse_authorize_callback_response(callback_url)
    if not callback.is_successful:
        pytest.fail(f"Auth callback error: {callback.error}")

    state_result = validate_authorize_callback_state(callback, state)
    if not state_result.is_valid:
        pytest.fail(f"State validation failed: {state_result.result}")

    assert callback.code is not None
    assert discovery.token_endpoint is not None
    token_request = AuthorizationCodeTokenRequest(
        address=discovery.token_endpoint,
        client_id=client_id,
        code=callback.code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        client_secret=config.client_secret,
        private_key_jwt=config.private_key_jwt,
    )
    token_response = request_authorization_code_token(token_request)

    return MappingProxyType(
        {
            "token_response": token_response,
            "state": state,
            "callback": callback,
            "state_result": state_result,
            "code_verifier": code_verifier,
        }
    )


@pytest.fixture(scope="session")
def auth_code_result(provider_capabilities, discovery_document, test_config):
    """Perform auth code + PKCE flow with confidential client.

    Skips if provider lacks dev_interactions or authorization_code.
    """
    if "dev_interactions" not in provider_capabilities:
        pytest.skip(
            "Provider does not support automated auth code flow (no devInteractions)"
        )
    if "authorization_code" not in provider_capabilities:
        pytest.skip("Provider does not advertise authorization_endpoint")

    client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID")
    redirect_uri = test_config.get("TEST_AUTH_CODE_REDIRECT_URI")
    client_secret = test_config.get("TEST_AUTH_CODE_CLIENT_SECRET")
    if not client_id or not redirect_uri:
        pytest.skip(
            "TEST_AUTH_CODE_CLIENT_ID and "
            "TEST_AUTH_CODE_REDIRECT_URI required "
            "for auth code flow tests"
        )

    return perform_auth_code_flow(
        discovery=discovery_document,
        client_id=client_id,
        redirect_uri=redirect_uri,
        config=AuthCodeFlowConfig(
            client_secret=client_secret,
            scope="openid profile email offline_access",
            resource="urn:test:api",
        ),
    )


@pytest.fixture(scope="session")
def logout_id_token(auth_code_result):
    """The ID Token minted by the confidential auth-code flow.

    Used as the ``id_token_hint`` for RP-Initiated Logout end-session
    round-trips. Skips cleanly if the provider issued no ID Token (e.g.
    the ``openid`` scope was not honoured).
    """
    token_response = auth_code_result["token_response"]
    id_token = (token_response.token or {}).get("id_token")
    if not id_token:
        pytest.skip("Auth-code token response carried no id_token")
    return id_token


@pytest.fixture(scope="session")
def public_auth_code_result(provider_capabilities, discovery_document, test_config):
    """Perform auth code + PKCE flow with public client.

    Skips if provider lacks dev_interactions or authorization_code.
    """
    if "dev_interactions" not in provider_capabilities:
        pytest.skip(
            "Provider does not support automated auth code flow (no devInteractions)"
        )
    if "authorization_code" not in provider_capabilities:
        pytest.skip("Provider does not advertise authorization_endpoint")

    client_id = test_config.get("TEST_PKCE_PUBLIC_CLIENT_ID")
    redirect_uri = test_config.get("TEST_PKCE_PUBLIC_REDIRECT_URI")
    if not client_id or not redirect_uri:
        pytest.skip(
            "TEST_PKCE_PUBLIC_CLIENT_ID and "
            "TEST_PKCE_PUBLIC_REDIRECT_URI required "
            "for public client auth code flow tests"
        )

    return perform_auth_code_flow(
        discovery=discovery_document,
        client_id=client_id,
        redirect_uri=redirect_uri,
        config=AuthCodeFlowConfig(
            scope="openid profile email offline_access",
            resource="urn:test:api",
        ),
    )
