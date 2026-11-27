"""
JWT-Secured Authorization Response Mode (JARM) Examples for py-identity-model.

JARM returns the OAuth 2.0 / OpenID Connect authorization response as a signed
JWT carried in a single ``response`` parameter, instead of individual
query/fragment parameters. The relying party (RP) verifies the JWT signature
against the authorization server's (AS) JWKS and validates the mandatory
``iss``/``aud``/``exp`` claims before trusting ``code``/``state``.

Why JARM (over a plain query/fragment response)?
  * Integrity — the response is signed, so an attacker cannot tamper with
    ``code``/``state`` in transit (e.g. a malicious browser extension or an
    open-redirect intermediary).
  * Mix-up defense — the ``iss`` claim is signed *inside* the JWT, so
    ``process_jarm_response`` binds the response to the AS that issued it
    (RFC 9207), closing the authorization-response mix-up attack class.
  * FAPI 2.0 — JARM is one of the response modes permitted by the FAPI 2.0
    Security Profile.

This example runs fully offline: it mints its own EC signing key and JARM JWTs,
then feeds them to ``process_jarm_response`` in *offline mode* (issuer + jwks +
algorithms supplied directly). In production you pass only the ``issuer`` and
the library fetches the JWKS and allowed algorithms from its discovery document.

**Scope:** signed JARM (JARM §4.1). Encrypted JARM (JWE, §4.2) is not yet
supported.
"""

import json
import time

from cryptography.hazmat.primitives.asymmetric import ec
from jwt import algorithms, encode

from py_identity_model import (
    InvalidAudienceException,
    InvalidIssuerException,
    JarmValidationException,
    JwksResponse,
    SignatureVerificationException,
    TokenExpiredException,
    is_jarm_response,
    process_jarm_response,
    validate_authorize_callback_state,
)
from py_identity_model.core.parsers import jwks_from_dict


ISSUER = "https://as.example.com"
CLIENT_ID = "example-client"
KID = "jarm-sig-1"


def _make_signing_context() -> tuple[ec.EllipticCurvePrivateKey, JwksResponse]:
    """Generate an EC signing key and the matching single-key JWKS.

    In production the AS holds the private key and publishes only the public
    JWK at its ``jwks_uri``; here we hold both so the example can mint the
    responses it then verifies.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update(kid=KID, use="sig", alg="ES256")
    jwks = JwksResponse(is_successful=True, keys=[jwks_from_dict(public_jwk)])
    return private_key, jwks


def _mint_response_jwt(
    private_key: ec.EllipticCurvePrivateKey,
    claims: dict,
    *,
    algorithm: str = "ES256",
    key: ec.EllipticCurvePrivateKey | None = None,
) -> str:
    """Mint a signed JARM response JWT (simulates what the AS returns)."""
    return encode(
        claims,
        key if key is not None else private_key,
        algorithm=algorithm,
        headers={"kid": KID},
    )


def _base_claims(**overrides: object) -> dict[str, object]:
    """Build a valid JARM claim set (iss/aud/exp are mandatory, JARM §4.1)."""
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "exp": int(time.time()) + 300,
        "code": "SplxlOBeZQQYbYS6WxSbIA",
        "state": "af0ifjsldkj",
    }
    claims.update(overrides)
    return claims


def happy_path_example(private_key, jwks) -> None:
    """Detect, verify, and parse a legitimate ``query.jwt`` JARM response."""
    print("\n" + "=" * 60)
    print("Example 1: Successful JARM Response (query.jwt)")
    print("=" * 60)

    response_jwt = _mint_response_jwt(private_key, _base_claims())
    callback_url = f"https://app.example.com/callback?response={response_jwt}"

    # Step 1: detect that this callback is JARM-encoded.
    print(f"  is_jarm_response: {is_jarm_response(callback_url)}")

    # Step 2: verify the signature + iss/aud/exp and parse the claims.
    result = process_jarm_response(
        callback_url,
        client_id=CLIENT_ID,
        issuer=ISSUER,
        jwks=jwks,
        algorithms=["ES256"],
    )
    print(f"  Verified! code={result.code} state={result.state} iss={result.issuer}")

    # Step 3: bind the response to the original request via state (CSRF defense).
    expected_state = "af0ifjsldkj"  # stored in the session before redirect
    state_check = validate_authorize_callback_state(result, expected_state)
    print(f"  State binding valid: {state_check.is_valid}")


def form_post_jwt_example(private_key, jwks) -> None:
    """Process a ``form_post.jwt`` response, where the JWT arrives in the body."""
    print("\n" + "=" * 60)
    print("Example 2: form_post.jwt (raw JWT, not a URL)")
    print("=" * 60)

    response_jwt = _mint_response_jwt(private_key, _base_claims())
    # The AS POSTs `response=<jwt>`; the RP pulls the raw JWT from the form body
    # and passes it with is_jwt=True (there is no callback URL to parse).
    result = process_jarm_response(
        response_jwt,
        client_id=CLIENT_ID,
        issuer=ISSUER,
        jwks=jwks,
        algorithms=["ES256"],
        is_jwt=True,
    )
    print(f"  Verified form_post.jwt response: code={result.code}")


def error_response_example(private_key, jwks) -> None:
    """A JARM response can also carry an ``error`` — still signed and bound."""
    print("\n" + "=" * 60)
    print("Example 3: JARM Error Response")
    print("=" * 60)

    error_jwt = _mint_response_jwt(
        private_key,
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 300,
            "error": "access_denied",
            "state": "af0ifjsldkj",
        },
    )
    result = process_jarm_response(
        f"https://app.example.com/callback?response={error_jwt}",
        client_id=CLIENT_ID,
        issuer=ISSUER,
        jwks=jwks,
        algorithms=["ES256"],
    )
    print(f"  is_successful={result.is_successful} error={result.error}")
    # `state` remains accessible on error responses so the RP can clean up.
    print(f"  state (still readable on error): {result.state}")


def adversarial_examples(private_key, jwks) -> None:
    """Every tampered / downgraded / mismatched response must be rejected."""
    print("\n" + "=" * 60)
    print("Example 4: Adversarial Responses (all rejected)")
    print("=" * 60)

    def _expect(label: str, exc: type[Exception], jwt: str, **kwargs) -> None:
        try:
            process_jarm_response(
                f"https://app.example.com/callback?response={jwt}",
                client_id=kwargs.pop("client_id", CLIENT_ID),
                issuer=kwargs.pop("issuer", ISSUER),
                jwks=jwks,
                algorithms=kwargs.pop("algorithms", ["ES256"]),
                **kwargs,
            )
        except exc as caught:
            print(f"  {label}: rejected ({type(caught).__name__})")
        else:
            raise AssertionError(f"{label} was NOT rejected")

    # alg=none — an unsigned response must never be trusted.
    none_jwt = encode(_base_claims(), key="", algorithm="none")
    _expect("alg=none", JarmValidationException, none_jwt)

    # Symmetric (HS256) — JARM signatures are asymmetric; reject shared-secret MAC.
    hs_jwt = encode(
        _base_claims(), key="shared-secret", algorithm="HS256", headers={"kid": KID}
    )
    _expect("HS256 (symmetric)", JarmValidationException, hs_jwt)

    # Tampered signature — signed by a different key with the same kid.
    other_key = ec.generate_private_key(ec.SECP256R1())
    tampered = _mint_response_jwt(private_key, _base_claims(), key=other_key)
    _expect("tampered signature", SignatureVerificationException, tampered)

    # Mix-up — iss belongs to a different (attacker) AS.
    _expect(
        "issuer mismatch (mix-up)",
        InvalidIssuerException,
        _mint_response_jwt(
            private_key, _base_claims(iss="https://attacker-as.example.com")
        ),
    )

    # Wrong audience — response minted for a different client.
    _expect(
        "audience mismatch",
        InvalidAudienceException,
        _mint_response_jwt(private_key, _base_claims(aud="other-client")),
    )

    # Expired response.
    _expect(
        "expired",
        TokenExpiredException,
        _mint_response_jwt(private_key, _base_claims(exp=int(time.time()) - 30)),
    )


def main() -> None:
    """Run all JARM examples."""
    print("\n" + "=" * 60)
    print("PY-IDENTITY-MODEL JARM EXAMPLES")
    print("=" * 60)

    private_key, jwks = _make_signing_context()

    happy_path_example(private_key, jwks)
    form_post_jwt_example(private_key, jwks)
    error_response_example(private_key, jwks)
    adversarial_examples(private_key, jwks)

    print("\n" + "=" * 60)
    print("All JARM examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
