"""
private_key_jwt Client Authentication Example (RFC 7523)

Demonstrates authenticating a confidential client to the token endpoint with
a signed JWT assertion (``private_key_jwt``) instead of a client secret, as
required by FAPI 2.0 and recommended by OAuth 2.1 / OpenID Connect Core 1.0
Section 9.

Flow:
1. Generate an EC P-256 (ES256) key pair and serialize the private key to PEM.
2. Discover ``token_endpoint_auth_methods_supported`` to confirm the
   authorization server accepts ``private_key_jwt``.
3. Build a ``PrivateKeyJwt`` and attach it to a token request.
4. Observe that the assertion (not Basic auth, not client_secret) is used.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    PrivateKeyJwt,
    get_discovery_document,
)


# A placeholder issuer; swap for your own provider when running for real.
DEMO_DISCOVERY_URL = "https://demo.duendesoftware.com/.well-known/openid-configuration"


def generate_es256_private_key_pem() -> str:
    """Generate an EC P-256 key pair and return the private key as PEM.

    ES256 (ECDSA on the NIST P-256 curve) is one of the two signing
    algorithms permitted by FAPI 2.0 for ``private_key_jwt`` (the other is
    ``PS256``). In production the matching public key (JWK) is registered with
    the authorization server so it can verify the assertion signature.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def discover_auth_methods_example():
    """Discover the auth methods supported by the authorization server."""
    print("\n" + "=" * 60)
    print("Discover token_endpoint_auth_methods_supported")
    print("=" * 60)

    response = get_discovery_document(
        DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL)
    )

    if not response.is_successful:
        print(f"  Discovery failed: {response.error}")
        return None, None

    methods = response.token_endpoint_auth_methods_supported or []
    print(f"\n  Token endpoint: {response.token_endpoint}")
    print(f"  Supported auth methods: {methods}")

    if "private_key_jwt" in methods:
        print("  -> Server supports private_key_jwt")
    else:
        print("  -> Server did NOT advertise private_key_jwt")

    return response.issuer, response.token_endpoint


def private_key_jwt_token_request(issuer: str, token_endpoint: str):
    """Build a client credentials request authenticated with private_key_jwt."""
    print("\n" + "=" * 60)
    print("Client Credentials with private_key_jwt")
    print("=" * 60)

    # Step 1: Generate (or load) the signing key.
    private_key_pem = generate_es256_private_key_pem()
    print("\n  Generated EC P-256 (ES256) private key (PEM).")

    # Step 2: Build the private_key_jwt authentication parameters.
    #   - algorithm "ES256" matches the key type (FAPI 2.0 compliant).
    #   - issuer is the AS issuer identifier (the discovery ``issuer``); it is
    #     the assertion's sole ``aud``, never the token endpoint (RFC 10070 §4).
    #   - kid is optional; set it when the AS needs help locating your key.
    auth = PrivateKeyJwt(private_key=private_key_pem, algorithm="ES256", issuer=issuer)

    # Step 3: Attach the assertion to a token request. Note that a
    # client_secret is also provided here only to demonstrate precedence:
    # when private_key_jwt is set, it WINS and the client_secret is ignored,
    # so no HTTP Basic (client_secret_basic) header is sent.
    token_request = ClientCredentialsTokenRequest(
        address=token_endpoint,
        client_id="my-confidential-client",
        client_secret="ignored-because-private-key-jwt-takes-precedence",
        scope="api",
        private_key_jwt=auth,
    )

    print(f"  Token endpoint: {token_request.address}")
    print(f"  Assertion aud (issuer): {auth.issuer}")
    print(f"  Client ID: {token_request.client_id}")
    print(f"  Assertion algorithm: {auth.algorithm}")
    print(f"  private_key_jwt set: {token_request.private_key_jwt is not None}")
    print("  client_secret present but IGNORED (private_key_jwt wins).")
    print("  No Authorization: Basic header is sent; the request body carries")
    print("    client_assertion_type + client_assertion instead.")
    print("  (Would call request_client_credentials_token(token_request) here)")


def main():
    print("\n" + "=" * 60)
    print("private_key_jwt CLIENT AUTHENTICATION (RFC 7523)")
    print("=" * 60)

    issuer, token_endpoint = discover_auth_methods_example()
    # Fall back to placeholders when discovery is unavailable.
    private_key_jwt_token_request(
        issuer or "https://auth.example.com",
        token_endpoint or "https://auth.example.com/token",
    )

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
