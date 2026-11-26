"""Adversarial fail-closed tests for discovery-endpoint SSRF (F-05, F-06).

The discovery parser authority/scheme-validates seven endpoint fields
(``response_processors.py`` ``_endpoint_names``) but omits two endpoint-bearing
fields:

* ``mtls_endpoint_aliases`` (F-05) — routes mTLS-authenticated token/PAR/etc.
  requests, and is copied into ``DiscoveryDocumentResponse`` verbatim, so a
  malicious/compromised OP can redirect a cert-bearing request to a link-local
  metadata host over plaintext HTTP (SSRF + HTTPS->HTTP downgrade).
* ``pushed_authorization_request_endpoint`` (F-06) — a compromised OP can make
  the client POST ``client_id``/``redirect_uri``/PKCE ``code_challenge``/
  ``client_secret`` to an attacker or plaintext host (credential-exfil SSRF).

``pushed_authorization_request_endpoint`` (F-06) now joins the authority/scheme
validation loop (``_endpoint_names``), so a discovery document advertising a
foreign-authority / plaintext URL there is REJECTED (``is_successful=False`` —
``DiscoveryException`` collapsed by ``handle_discovery_error``).

``mtls_endpoint_aliases`` (F-05) cannot be issuer-authority-matched, because
RFC 8705 §5 mTLS endpoints legitimately live on a separate host (e.g.
``mtls.example.com`` under issuer ``example.com`` — see
``test_mtls.py::TestDiscoveryParsesMtlsFields``). Instead each alias URL is
scheme-validated (no HTTPS->HTTP downgrade) and rejected if its host is an
internal/reserved IP literal (link-local metadata / RFC1918 / loopback SSRF);
a legitimate cross-host *hostname* alias is still accepted. Hostname-based SSRF
(DNS rebinding) is out of scope (tracked as T9).

``TestSiblingFieldIsValidated`` is a passing control (NOT xfail): it feeds the
identical malicious URL to a *guarded* sibling field (``token_endpoint``) and
proves it is rejected today — pinning the asymmetry the two findings describe.
"""

import httpx
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    DiscoveryPolicy,
    get_discovery_document,
)


pytestmark = pytest.mark.unit

ISSUER = "https://as.example.com"
DISCO_URL = f"{ISSUER}/.well-known/openid-configuration"

# The classic link-local metadata SSRF target, plaintext HTTP.
METADATA_HTTP = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# A foreign-authority but HTTPS URL — bypasses a naive "https only" check and
# must still be rejected on an authority mismatch against the issuer.
FOREIGN_HTTPS = "https://attacker.evil.example/token"
# Internal IP literals reached over HTTPS — pass a naive "https only" check but
# must be rejected as SSRF targets (link-local cloud metadata, RFC1918).
METADATA_HTTPS = "https://169.254.169.254/token"
PRIVATE_HTTPS = "https://10.0.0.5/token"
# A legitimate cross-host mTLS endpoint (RFC 8705 §5) on a separate hostname —
# must be ALLOWED (mTLS aliases are not authority-matched to the issuer).
LEGIT_MTLS_HOST = "https://mtls.as.example.com/token"
# Alternate IPv4 encodings of 127.0.0.1 that the OS resolver (inet_aton) honours
# but a naive ``ipaddress.ip_address`` literal check treats as hostnames — the
# decimal/octal/hex SSRF-evasion class. All HTTPS so only the internal-IP check
# (not the scheme check) can reject them.
ENC_DECIMAL_HTTPS = "https://2130706433/token"  # 127.0.0.1
ENC_OCTAL_HTTPS = "https://0177.0.0.1/token"  # 127.0.0.1
ENC_HEX_HTTPS = "https://0x7f.0.0.1/token"  # 127.0.0.1
# A legitimate off-host PAR endpoint (RFC 9126 §5 permits a different host).
OFFHOST_PAR = "https://par.example.net/par"
# A loopback mTLS endpoint (local development). Rejected by default; allowed
# only when DiscoveryPolicy(allow_loopback_endpoints=True) is set.
LOOPBACK_MTLS_HTTPS = "https://127.0.0.1:8443/token"

_BASE_DISCO = {
    "issuer": ISSUER,
    "jwks_uri": "https://as.example.com/jwks",
    "authorization_endpoint": "https://as.example.com/authorize",
    "token_endpoint": "https://as.example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


def _fetch(doc: dict) -> DiscoveryDocumentResponse:
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=doc))
    return get_discovery_document(DiscoveryDocumentRequest(issuer=ISSUER))


@pytest.mark.parametrize(
    "malicious_url", [METADATA_HTTP, METADATA_HTTPS, PRIVATE_HTTPS]
)
@respx.mock
def test_mtls_endpoint_alias_internal_target_is_rejected(malicious_url: str) -> None:
    """F-05: an mTLS alias pointing at a plaintext or internal-IP host fails
    closed — a poisoned discovery document could otherwise route the
    cert-bearing mTLS request to link-local cloud metadata / an RFC1918 host.

    mTLS aliases can't be issuer-authority-matched (RFC 8705 §5 hosts them on a
    separate hostname), so the guard is scheme (no HTTP downgrade) + an
    internal-IP-literal block. Legit foreign *hostname* aliases are covered by
    ``test_mtls_endpoint_alias_cross_host_is_allowed``.
    """
    doc = {**_BASE_DISCO, "mtls_endpoint_aliases": {"token_endpoint": malicious_url}}
    result = _fetch(doc)
    assert result.is_successful is False


@respx.mock
def test_mtls_endpoint_alias_cross_host_is_allowed() -> None:
    """RFC 8705 §5: a legitimate mTLS endpoint on a separate hostname must be
    ACCEPTED (mTLS aliases are not authority-matched to the issuer) — guards
    against an over-strict F-05 fix that would break real cross-host mTLS."""
    doc = {**_BASE_DISCO, "mtls_endpoint_aliases": {"token_endpoint": LEGIT_MTLS_HOST}}
    result = _fetch(doc)
    assert result.is_successful is True


@pytest.mark.parametrize(
    "encoded_url", [ENC_DECIMAL_HTTPS, ENC_OCTAL_HTTPS, ENC_HEX_HTTPS]
)
@respx.mock
def test_mtls_endpoint_alias_encoded_internal_target_is_rejected(
    encoded_url: str,
) -> None:
    """F-05 (encoding evasion): decimal/octal/hex encodings of an internal IP
    resolve to the same host as the dotted-quad literal, so a poisoned mTLS
    alias using ``https://2130706433/`` (127.0.0.1) must fail closed exactly
    like ``https://127.0.0.1/``. The dotted-quad-only ``ipaddress`` check let
    these through — they parse as ``ValueError`` (treated as a hostname) while
    the OS resolver still routes them internally.
    """
    doc = {**_BASE_DISCO, "mtls_endpoint_aliases": {"token_endpoint": encoded_url}}
    result = _fetch(doc)
    assert result.is_successful is False


@respx.mock
def test_loopback_mtls_alias_rejected_by_default() -> None:
    """Secure default: a loopback mTLS alias is rejected. Routing a
    certificate-bearing request to the client's own localhost is a limited SSRF,
    so it must not be permitted unless the operator explicitly opts in."""
    doc = {
        **_BASE_DISCO,
        "mtls_endpoint_aliases": {"token_endpoint": LOOPBACK_MTLS_HTTPS},
    }
    assert _fetch(doc).is_successful is False


@respx.mock
def test_loopback_mtls_alias_allowed_when_opted_in() -> None:
    """Local-dev opt-in: ``allow_loopback_endpoints=True`` permits a loopback
    mTLS alias so a developer can debug against a local OP whose discovery doc
    advertises the ``127.0.0.1`` literal (not the ``localhost`` hostname)."""
    doc = {
        **_BASE_DISCO,
        "mtls_endpoint_aliases": {"token_endpoint": LOOPBACK_MTLS_HTTPS},
    }
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=doc))
    result = get_discovery_document(
        DiscoveryDocumentRequest(
            issuer=ISSUER,
            policy=DiscoveryPolicy(allow_loopback_endpoints=True),
        )
    )
    assert result.is_successful is True


@respx.mock
def test_link_local_mtls_alias_rejected_even_with_loopback_opt_in() -> None:
    """The loopback opt-in must NOT unblock link-local (169.254.x cloud
    metadata) or RFC1918 — those are the real SSRF targets and stay blocked
    regardless of ``allow_loopback_endpoints``."""
    doc = {**_BASE_DISCO, "mtls_endpoint_aliases": {"token_endpoint": METADATA_HTTPS}}
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=doc))
    result = get_discovery_document(
        DiscoveryDocumentRequest(
            issuer=ISSUER,
            policy=DiscoveryPolicy(allow_loopback_endpoints=True),
        )
    )
    assert result.is_successful is False


@pytest.mark.parametrize("malicious_url", [METADATA_HTTP, FOREIGN_HTTPS])
@respx.mock
def test_par_endpoint_ssrf_is_rejected(malicious_url: str) -> None:
    doc = {**_BASE_DISCO, "pushed_authorization_request_endpoint": malicious_url}
    result = _fetch(doc)
    assert result.is_successful is False


@respx.mock
def test_offhost_par_rejected_by_default_but_accepted_when_allowlisted() -> None:
    """F-06 keeps the PAR authority-pin by default (a compromised OP must not be
    able to redirect the client's ``client_secret``/PKCE POST to an attacker
    host). But RFC 9126 §5 permits a legitimate off-host PAR endpoint, so the
    documented escape hatch (``additional_endpoint_base_addresses``) must admit
    it — and the default-rejection error must name that escape hatch so a real
    split-host OP is a one-line config fix, not a silent break.
    """
    doc = {**_BASE_DISCO, "pushed_authorization_request_endpoint": OFFHOST_PAR}

    # Default policy: rejected, and the error points at the escape hatch.
    default = _fetch(doc)
    assert default.is_successful is False
    assert "additional_endpoint_base_addresses" in (default.error or "")

    # With the off-host base allow-listed: accepted.
    respx.get(DISCO_URL).mock(return_value=httpx.Response(200, json=doc))
    allowlisted = get_discovery_document(
        DiscoveryDocumentRequest(
            issuer=ISSUER,
            policy=DiscoveryPolicy(
                additional_endpoint_base_addresses=["https://par.example.net"]
            ),
        )
    )
    assert allowlisted.is_successful is True


class TestSiblingFieldIsValidated:
    """Control (passes today): a guarded sibling field rejects the same URLs.

    Proves the asymmetry — the identical malicious URL that F-05/F-06 accept in
    an unguarded field is already rejected in ``token_endpoint``.
    """

    @respx.mock
    def test_foreign_authority_https_token_endpoint_is_rejected(self) -> None:
        doc = {**_BASE_DISCO, "token_endpoint": FOREIGN_HTTPS}
        result = _fetch(doc)
        assert result.is_successful is False

    @respx.mock
    def test_plaintext_metadata_token_endpoint_is_rejected(self) -> None:
        doc = {**_BASE_DISCO, "token_endpoint": METADATA_HTTP}
        result = _fetch(doc)
        assert result.is_successful is False
