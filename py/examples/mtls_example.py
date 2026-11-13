"""
Mutual-TLS (mTLS) Client Authentication + Certificate-Bound Tokens (RFC 8705)

Demonstrates the second FAPI 2.0 sender-constraining path (DPoP is the first;
see ``dpop_example.py``): the client authenticates by presenting an X.509
certificate at the TLS layer instead of a client secret, and the authorization
server issues access tokens bound to that certificate's thumbprint.

Flow:
1. Generate a self-signed client certificate + key pair (for real deployments
   use a CA-issued cert for ``tls_client_auth`` or any cert for
   ``self_signed_tls_client_auth``; see ``examples/cert-generator``).
2. Build an ``MtlsClientAuth`` config and attach it to a token request. Observe
   that the request uses no ``Authorization`` header — ``client_id`` goes in the
   body and the certificate is presented at the TLS layer (RFC 8705 §2).
3. Route requests through ``mtls_endpoint_aliases`` when the AS advertises them
   (RFC 8705 §5).
4. Validate a certificate-bound access token's ``cnf["x5t#S256"]`` confirmation
   against the presented client certificate (RFC 8705 §3).

Run: ``uv run python examples/mtls_example.py``
"""

import datetime
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from py_identity_model import (
    CertificateBindingError,
    ClientAuthMethod,
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    MtlsClientAuth,
    compute_certificate_thumbprint,
    get_discovery_document,
    validate_certificate_binding,
)
from py_identity_model.core.mtls import resolve_mtls_endpoint


# A placeholder issuer; swap for a provider that advertises mTLS when running
# for real (e.g. one exposing ``mtls_endpoint_aliases``).
DEMO_DISCOVERY_URL = "https://demo.duendesoftware.com/.well-known/openid-configuration"


def generate_self_signed_client_cert(tmp_dir: Path) -> tuple[str, str, bytes]:
    """Generate a self-signed EC P-256 client certificate and key.

    Returns ``(cert_path, key_path, cert_der)``. In production the certificate
    is registered with the authorization server (``tls_client_auth`` uses a
    CA-issued cert; ``self_signed_tls_client_auth`` uses the cert directly).
    ``examples/cert-generator`` produces certs the same way for the test IdPs.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "my-mtls-client")]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_path = tmp_dir / "client-cert.pem"
    key_path = tmp_dir / "client-key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return str(cert_path), str(key_path), cert.public_bytes(serialization.Encoding.DER)


def discover_mtls_metadata_example():
    """Discover mTLS-related metadata from the authorization server."""
    print("\n" + "=" * 60)
    print("Discover mTLS metadata (RFC 8705 §4/§5)")
    print("=" * 60)

    response = get_discovery_document(
        DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL)
    )

    if not response.is_successful:
        print(f"  Discovery failed: {response.error}")
        return None

    methods = response.token_endpoint_auth_methods_supported or []
    print(f"\n  Token endpoint: {response.token_endpoint}")
    print(f"  Supported auth methods: {methods}")
    print(
        "  Cert-bound access tokens supported: "
        f"{response.tls_client_certificate_bound_access_tokens}"
    )
    print(f"  mtls_endpoint_aliases: {response.mtls_endpoint_aliases}")

    if any(m in methods for m in ("tls_client_auth", "self_signed_tls_client_auth")):
        print("  -> Server supports mTLS client authentication")
    else:
        print("  -> Server did NOT advertise mTLS client authentication")

    # RFC 8705 §5: prefer the mTLS-specific endpoint alias when present so the
    # certificate is presented on the right connection.
    resolved = resolve_mtls_endpoint(response, "token_endpoint")
    print(f"  Resolved token endpoint (mTLS-aware): {resolved}")
    return response


def mtls_token_request_example(token_endpoint: str, cert_path: str, key_path: str):
    """Build a client credentials request authenticated with mTLS."""
    print("\n" + "=" * 60)
    print("Client Credentials with mTLS (RFC 8705 §2)")
    print("=" * 60)

    # Step 1: Build the mTLS authentication config from the cert/key file paths.
    #   - auth_method "tls_client_auth" (default) is the PKI/CA-issued variant;
    #     use "self_signed_tls_client_auth" for a self-registered certificate.
    #   - certificate/private_key are filesystem paths to PEM files.
    mtls = MtlsClientAuth(
        certificate_path=cert_path,
        private_key_path=key_path,
        auth_method=ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
    )

    # Step 2: Attach the config to a token request. A client_secret is included
    # here only to demonstrate precedence: when mtls is set it WINS over the
    # secret, so NO Authorization: Basic header is sent — client_id goes in the
    # body and the certificate is presented at the TLS layer. (private_key_jwt,
    # if also set, would take precedence over mtls.)
    token_request = ClientCredentialsTokenRequest(
        address=token_endpoint,
        client_id="my-mtls-client",
        client_secret="ignored-because-mtls-takes-precedence",
        scope="api",
        mtls=mtls,
    )

    print(f"\n  Token endpoint: {token_request.address}")
    print(f"  Client ID: {token_request.client_id}")
    print(f"  Auth method: {mtls.auth_method}")
    print(f"  mtls set: {token_request.mtls is not None}")
    # The private key path is repr-suppressed so it never leaks into logs.
    print(f"  repr(mtls): {mtls!r}")
    print("  client_secret present but IGNORED (mtls wins over client_secret).")
    print("  No Authorization: Basic header; client_id is carried in the body")
    print("    and the certificate is presented at the TLS layer.")
    print("  (Would call request_client_credentials_token(token_request) here;")
    print("   the sync/async wrapper builds a short-lived cert-configured")
    print("   httpx client for the request and closes it afterwards.)")


def certificate_binding_example(cert_der: bytes):
    """Validate a certificate-bound access token confirmation (RFC 8705 §3)."""
    print("\n" + "=" * 60)
    print("Certificate-bound access token validation (RFC 8705 §3)")
    print("=" * 60)

    # The AS issues a token whose cnf["x5t#S256"] is the base64url-no-pad
    # SHA-256 of the client certificate DER. As the RP, after normal signature
    # + time validation, confirm the token is bound to the cert we presented.
    thumbprint = compute_certificate_thumbprint(cert_der)
    print(f"\n  Presented cert thumbprint (x5t#S256): {thumbprint}")

    bound_claims = {"sub": "svc", "cnf": {"x5t#S256": thumbprint}}
    validate_certificate_binding(bound_claims, cert_der)
    print("  Bound token: VALID — cnf[x5t#S256] matches the presented cert.")

    # Adversarial path: a token bound to a DIFFERENT certificate must be
    # rejected fail-closed (this is what stops a stolen token being replayed
    # over a connection without the matching client certificate).
    tampered = {"sub": "svc", "cnf": {"x5t#S256": "not-the-right-thumbprint"}}
    try:
        validate_certificate_binding(tampered, cert_der)
        print("  ERROR: mismatched binding was accepted (should not happen).")
    except CertificateBindingError as exc:
        print(f"  Mismatched token: REJECTED as expected -> {exc}")

    # A plain bearer token (no cnf) is likewise rejected when binding is
    # required.
    try:
        validate_certificate_binding({"sub": "svc"}, cert_der)
        print("  ERROR: unbound token was accepted (should not happen).")
    except CertificateBindingError as exc:
        print(f"  Unbound token: REJECTED as expected -> {exc}")


def mtls_vs_dpop_notes():
    """Print guidance on choosing mTLS vs DPoP sender-constraining."""
    print("\n" + "=" * 60)
    print("mTLS vs DPoP — choosing a FAPI 2.0 sender-constraining method")
    print("=" * 60)
    print(
        "\n  Both bind an access token to a key the client must prove it holds,"
        "\n  defeating bearer-token theft/replay. FAPI 2.0 accepts either.\n"
        "\n  mTLS (RFC 8705):"
        "\n    + Binding happens at the TLS layer; no per-request app work.\n"
        "    + Reuses existing PKI; strong for service-to-service backends.\n"
        "    - Needs client-cert provisioning + TLS-terminating infra that\n"
        "      forwards the cert; harder through some proxies/CDNs.\n"
        "\n  DPoP (RFC 9449, already shipped — see dpop_example.py):\n"
        "    + Application-layer proof; works over ordinary TLS and proxies.\n"
        "    + Good for public/SPA/mobile clients without cert provisioning.\n"
        "    - The client signs a proof JWT per request.\n"
        "\n  Rule of thumb: mTLS for confidential backend clients with PKI;\n"
        "  DPoP for public clients or where cert plumbing is impractical."
    )


def main():
    print("\n" + "=" * 60)
    print("mTLS CLIENT AUTHENTICATION + CERT-BOUND TOKENS (RFC 8705)")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path, cert_der = generate_self_signed_client_cert(Path(tmp))
        print(f"\n  Generated self-signed client cert: {cert_path}")

        disco = discover_mtls_metadata_example()
        token_endpoint = (
            resolve_mtls_endpoint(disco, "token_endpoint")
            if disco is not None
            else None
        ) or "https://auth.example.com/token"

        mtls_token_request_example(token_endpoint, cert_path, key_path)
        certificate_binding_example(cert_der)
        mtls_vs_dpop_notes()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
