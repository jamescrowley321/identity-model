"""
FAPI 2.0 Security Profile Client Example

Builds a fail-closed FAPI 2.0 client profile from an authorization server's
discovery document and uses it to prepare the pushed authorization request
and the token request.
"""

from py_identity_model import (
    DiscoveryDocumentResponse,
    FAPI2ClientProfile,
    FAPIProfileError,
    PrivateKeyJwt,
    generate_dpop_key,
    generate_pkce_pair,
)


ISSUER = "https://bank.example.com"

# A FAPI 2.0 authorization server's metadata. In a real client this comes
# from get_discovery_document().
DISCOVERY = DiscoveryDocumentResponse(
    is_successful=True,
    issuer=ISSUER,
    authorization_endpoint=f"{ISSUER}/authorize",
    token_endpoint=f"{ISSUER}/token",
    pushed_authorization_request_endpoint=f"{ISSUER}/par",
    response_types_supported=["code"],
    token_endpoint_auth_methods_supported=["private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported=["ES256"],
    id_token_signing_alg_values_supported=["ES256", "PS256"],
    code_challenge_methods_supported=["S256"],
    authorization_response_iss_parameter_supported=True,
    dpop_signing_alg_values_supported=["ES256"],
)


def build_profile_example() -> FAPI2ClientProfile:
    """Build the profile; the assertion aud is set to the discovery issuer."""
    print("\n" + "=" * 60)
    print("FAPI 2.0 - Client Profile")
    print("=" * 60)

    client_key = generate_dpop_key("ES256")
    profile = FAPI2ClientProfile(
        DISCOVERY,
        client_id="fapi-client",
        redirect_uri="https://client.example.com/callback",
        client_auth=PrivateKeyJwt(
            private_key=client_key.private_key_pem, algorithm="ES256"
        ),
    )
    print(f"\n  Issuer: {profile.issuer}")
    if profile.private_key_jwt is not None:
        print(f"  Assertion issuer: {profile.private_key_jwt.issuer}")
    print(f"  Accepted algorithms: {profile.signing_algorithms}")
    return profile


def build_requests_example(profile: FAPI2ClientProfile) -> None:
    """Prepare the PAR request and the authorization URL."""
    print("\n" + "=" * 60)
    print("FAPI 2.0 - Pushed Authorization Request")
    print("=" * 60)

    dpop_key = generate_dpop_key("ES256")
    _verifier, challenge = generate_pkce_pair()
    request = profile.pushed_authorization_request(
        state="state-value", code_challenge=challenge, dpop_key=dpop_key
    )
    print(f"\n  PAR endpoint: {request.address}")
    print(f"  PKCE method: {request.code_challenge_method}")
    print(f"  Authorization URL: {profile.authorization_url('urn:example:request')}")


def refused_example(profile: FAPI2ClientProfile) -> None:
    """Weakening the flow raises FAPIProfileError."""
    print("\n" + "=" * 60)
    print("FAPI 2.0 - Refused Requests")
    print("=" * 60)

    try:
        profile.pushed_authorization_request(
            state="state-value", code_challenge="challenge"
        )
    except FAPIProfileError as exc:
        print("\n  PAR without a DPoP key refused:")
        for violation in exc.violations:
            print(f"    - {violation}")


def main():
    profile = build_profile_example()
    build_requests_example(profile)
    refused_example(profile)
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
