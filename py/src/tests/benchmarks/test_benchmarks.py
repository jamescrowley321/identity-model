"""Performance benchmark tests for py-identity-model.

Run with: make test-benchmark
"""

import asyncio
import base64
import time

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    validate_fapi_authorization_request,
    validate_fapi_client_config,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as aio_validate_token,
)
from py_identity_model.core.discovery_policy import (
    DiscoveryPolicy,
    parse_discovery_url,
    validate_url_scheme,
)
from py_identity_model.core.dpop import (
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.core.jar import create_request_object
from py_identity_model.core.models import (
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    TokenValidationConfig,
)
from py_identity_model.core.parsers import jwks_from_dict
from py_identity_model.core.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
)
from py_identity_model.identity import to_principal


# Test constants
PKCE_PAIR_LENGTH = 2

# ============================================================================
# PKCE Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_pkce_pair(benchmark):
    result = benchmark(generate_pkce_pair)
    assert result is not None
    assert len(result) == PKCE_PAIR_LENGTH


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_code_verifier(benchmark):
    result = benchmark(generate_code_verifier)
    assert isinstance(result, str)


@pytest.mark.benchmark(group="pkce")
def test_bench_generate_code_challenge(benchmark):
    verifier = generate_code_verifier()
    result = benchmark(generate_code_challenge, verifier)
    assert isinstance(result, str)


# ============================================================================
# DPoP Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="dpop")
def test_bench_generate_dpop_key_ec(benchmark):
    result = benchmark(generate_dpop_key, "ES256")
    assert result is not None


@pytest.mark.benchmark(group="dpop")
def test_bench_generate_dpop_key_rsa(benchmark):
    result = benchmark(generate_dpop_key, "RS256")
    assert result is not None


@pytest.mark.benchmark(group="dpop")
def test_bench_create_dpop_proof(benchmark):
    key = generate_dpop_key()
    result = benchmark(create_dpop_proof, key, "POST", "https://auth.example.com/token")
    assert isinstance(result, str)


# ============================================================================
# JAR Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="jar")
def test_bench_create_request_object_ec(benchmark, ec_private_pem):
    result = benchmark(
        create_request_object,
        private_key=ec_private_pem,
        algorithm="ES256",
        client_id="bench-app",
        audience="https://auth.example.com",
        redirect_uri="https://app.example.com/cb",
    )
    assert isinstance(result, str)


@pytest.mark.benchmark(group="jar")
def test_bench_create_request_object_rsa(benchmark, rsa_private_pem):
    result = benchmark(
        create_request_object,
        private_key=rsa_private_pem,
        algorithm="RS256",
        client_id="bench-app",
        audience="https://auth.example.com",
        redirect_uri="https://app.example.com/cb",
    )
    assert isinstance(result, str)


# ============================================================================
# FAPI Validation Benchmarks
# ============================================================================


_FAPI_DPOP_KEY = generate_dpop_key("ES256")
_FAPI_PKJ = PrivateKeyJwt(
    private_key=_FAPI_DPOP_KEY.private_key_pem,
    algorithm="ES256",
    issuer="https://auth.example.com",
)


@pytest.mark.benchmark(group="fapi")
def test_bench_validate_fapi_request(benchmark):
    request = PushedAuthorizationRequest(
        address="https://auth.example.com/par",
        client_id="client",
        redirect_uri="https://app.example.com/cb",
        code_challenge="challenge_value",
        code_challenge_method="S256",
        private_key_jwt=_FAPI_PKJ,
        dpop_key=_FAPI_DPOP_KEY,
    )
    result = benchmark(validate_fapi_authorization_request, request)
    assert result is not None


@pytest.mark.benchmark(group="fapi")
def test_bench_validate_fapi_client(benchmark):
    result = benchmark(
        validate_fapi_client_config,
        issuer="https://auth.example.com",
        private_key_jwt=_FAPI_PKJ,
        dpop_key=_FAPI_DPOP_KEY,
    )
    assert result is not None


# ============================================================================
# Discovery Policy Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="discovery")
def test_bench_parse_discovery_url(benchmark):
    result = benchmark(parse_discovery_url, "https://auth.example.com")
    assert result is not None


@pytest.mark.benchmark(group="discovery")
def test_bench_validate_url_scheme(benchmark):
    policy = DiscoveryPolicy()
    benchmark(validate_url_scheme, "https://auth.example.com/token", policy)
    # validate_url_scheme returns None on success (raises on failure)


# ============================================================================
# JWK Parsing Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="jwk")
def test_bench_jwks_from_dict(benchmark, sample_jwk_dict):
    result = benchmark(jwks_from_dict, sample_jwk_dict)
    assert result is not None


# ============================================================================
# Identity / Claims Benchmarks
# ============================================================================


@pytest.mark.benchmark(group="identity")
def test_bench_to_principal(benchmark, sample_claims):
    result = benchmark(to_principal, sample_claims)
    assert result is not None


# ============================================================================
# JWT Decode Benchmarks (core validation operation)
# ============================================================================


@pytest.mark.benchmark(group="jwt")
def test_bench_pyjwt_decode_baseline(benchmark, sample_signed_jwt, ec_public_pem):
    """Benchmark raw pyjwt.decode() as a baseline for comparison (not py-identity-model code)."""

    def decode_jwt():
        return pyjwt.decode(
            sample_signed_jwt,
            ec_public_pem,
            algorithms=["ES256"],
            audience="bench-api",
        )

    result = benchmark(decode_jwt)
    assert result is not None


# ============================================================================
# End-to-end validate_token warm-path Benchmark
# ============================================================================
#
# The raw ``pyjwt.decode`` baseline above measures only the crypto verify. The
# function that actually runs on every resource-server request is
# ``aio.validate_token`` — discovery lookup, JWKS lookup, key resolution, decode
# and claim validation. On the warm path (disco + JWKS both cached) every
# upstream fetch is skipped, so this micro measures the per-request overhead the
# cache is meant to eliminate. Upstream is respx-mocked and the caches are
# pre-warmed once, so the benched runs never touch the network.

_BENCH_ISSUER = "https://bench.example.com"
_BENCH_DISCO_URL = f"{_BENCH_ISSUER}/.well-known/openid-configuration"
_BENCH_JWKS_URL = f"{_BENCH_ISSUER}/jwks"
_BENCH_AUDIENCE = "bench-api"


def _rsa_public_jwk(public_key, kid: str) -> dict:
    """Build an RS256 JWK dict from a cryptography RSA public key."""
    numbers = public_key.public_numbers()

    def _b64u(value: int, length: int) -> str:
        return (
            base64.urlsafe_b64encode(value.to_bytes(length, "big"))
            .rstrip(b"=")
            .decode()
        )

    return {
        "kty": "RSA",
        "kid": kid,
        "n": _b64u(numbers.n, 256),
        "e": _b64u(numbers.e, 3),
        "alg": "RS256",
        "use": "sig",
    }


@pytest.mark.benchmark(group="validation")
def test_bench_validate_token_warm_path(benchmark, rsa_private_key, rsa_private_pem):
    """Benchmark the async ``validate_token`` warm path (disco + JWKS cached)."""
    kid = "bench-validate-key"
    jwk = _rsa_public_jwk(rsa_private_key.public_key(), kid)
    disco_doc = {
        "issuer": _BENCH_ISSUER,
        "authorization_endpoint": f"{_BENCH_ISSUER}/authorize",
        "token_endpoint": f"{_BENCH_ISSUER}/token",
        "jwks_uri": _BENCH_JWKS_URL,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": _BENCH_ISSUER,
            "sub": "bench-user",
            "aud": _BENCH_AUDIENCE,
            "exp": now + 86400,
            "iat": now,
            "nbf": now,
        },
        rsa_private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    config = TokenValidationConfig(perform_disco=True, audience=_BENCH_AUDIENCE)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(clear_discovery_cache())
        loop.run_until_complete(clear_jwks_cache())
        with respx.mock:
            respx.get(_BENCH_DISCO_URL).mock(
                return_value=httpx.Response(200, json=disco_doc)
            )
            respx.get(_BENCH_JWKS_URL).mock(
                return_value=httpx.Response(200, json={"keys": [jwk]})
            )
            # Warm both caches once so the benched runs are pure cache-hit path.
            loop.run_until_complete(aio_validate_token(token, config, _BENCH_DISCO_URL))
            result = benchmark(
                lambda: loop.run_until_complete(
                    aio_validate_token(token, config, _BENCH_DISCO_URL)
                )
            )
        assert result is not None
        assert result["sub"] == "bench-user"
    finally:
        loop.run_until_complete(clear_discovery_cache())
        loop.run_until_complete(clear_jwks_cache())
        loop.close()
