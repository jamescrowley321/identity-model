"""Adversarial response-body size-cap tests (F-09).

Only ``parse_jwks_response`` enforces a size cap (``Config.jwks_max_size``). The
token / auth-code / refresh / introspection / userinfo / discovery / PAR /
device-authorization parsers all call ``.json()``/``.content``/``.text`` on an
attacker-influenced response with NO size gate and NO streaming read-limit, so
a malicious or compromised OP/RS can drive unbounded memory allocation
(OOM DoS) — the exact attacker class the JWKS cap (#353) already concedes.

Each parametrized case feeds an oversized (but otherwise well-formed) body and
asserts the parser fails closed with a "too large"-style error, mirroring the
JWKS cap's own message. They XFAIL until a generic per-response cap lands.

The bodies exceed ``DEFAULT_MAX_JWKS_SIZE`` (512 KiB) so a fix that reuses that
limit for the other parsers flips these to XPASS.
"""

import httpx
import pytest
import respx

from py_identity_model import DiscoveryDocumentRequest, get_discovery_document
from py_identity_model.core.device_auth_logic import process_device_auth_response
from py_identity_model.core.http_utils import DEFAULT_MAX_JWKS_SIZE
from py_identity_model.core.par_logic import process_par_response
from py_identity_model.core.response_processors import (
    parse_auth_code_token_response,
    parse_introspection_response,
    parse_refresh_token_response,
    parse_token_response,
    parse_userinfo_response,
)


pytestmark = pytest.mark.unit

# A padding string comfortably larger than the only shipped cap (512 KiB), so a
# fix reusing that limit for the other parsers rejects these bodies.
_PAD = "A" * (2 * DEFAULT_MAX_JWKS_SIZE)


def _resp(body: dict) -> httpx.Response:
    return httpx.Response(200, json=body)


# (label, parser, oversized-but-well-formed body). Each body would be a
# *successful* parse today; the only thing missing is a size gate.
_CASES = [
    ("token", parse_token_response, {"access_token": _PAD, "token_type": "Bearer"}),
    (
        "auth_code",
        parse_auth_code_token_response,
        {"access_token": _PAD, "token_type": "Bearer"},
    ),
    (
        "refresh",
        parse_refresh_token_response,
        {"access_token": _PAD, "token_type": "Bearer"},
    ),
    ("introspection", parse_introspection_response, {"active": True, "pad": _PAD}),
    ("userinfo", parse_userinfo_response, {"sub": "user", "pad": _PAD}),
    (
        "par",
        process_par_response,
        {
            "request_uri": "urn:ietf:params:oauth:request_uri:x",
            "expires_in": 90,
            "pad": _PAD,
        },
    ),
    (
        "device_auth",
        process_device_auth_response,
        {
            "device_code": "dc",
            "user_code": "UC",
            "verification_uri": "https://as.example.com/device",
            "expires_in": 900,
            "pad": _PAD,
        },
    ),
]


@pytest.mark.parametrize(
    ("parser", "body"),
    [(c[1], c[2]) for c in _CASES],
    ids=[c[0] for c in _CASES],
)
@pytest.mark.xfail(
    strict=True,
    reason="F-09: only JWKS is size-capped; the other parsers buffer unbounded "
    "attacker-controlled response bodies (OOM DoS)",
)
def test_oversized_response_body_is_rejected(parser, body) -> None:
    result = parser(_resp(body))
    assert result.is_successful is False
    assert "too large" in (result.error or "").lower()


@pytest.mark.xfail(
    strict=True,
    reason="F-09: discovery response body is buffered unbounded via .json() with "
    "no size gate",
)
@respx.mock
def test_oversized_discovery_body_is_rejected() -> None:
    disco_url = "https://as.example.com/.well-known/openid-configuration"
    doc = {
        "issuer": "https://as.example.com",
        "jwks_uri": "https://as.example.com/jwks",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "service_documentation": _PAD,
    }
    respx.get(disco_url).mock(return_value=httpx.Response(200, json=doc))
    result = get_discovery_document(DiscoveryDocumentRequest(address=disco_url))
    assert result.is_successful is False
    assert "too large" in (result.error or "").lower()
