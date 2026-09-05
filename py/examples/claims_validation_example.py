"""
Injectable, composable claims validators (issue #603)

Claims validators run after the standard token checks (signature, iss, aud, exp,
nbf) and let you assert application-specific requirements as small, reusable,
composable pieces. This example runs them against sample decoded claims so it
executes with no network or credentials.
"""

from py_identity_model import (
    ClaimsValidationError,
    TokenValidationConfig,
    combine_claims_validators,
    require_claim_value,
    require_claims,
    require_scopes,
)


def _run(title: str, validator, claims: dict) -> None:
    try:
        validator(claims)
        print(f"  ACCEPT  {title}")
    except ClaimsValidationError as exc:
        who = f" (claim={exc.claim})" if exc.claim else ""
        print(f"  REJECT  {title}{who}: {exc.reason}")


def ready_made_validators() -> None:
    """The three ready-made validators, accepting and rejecting."""
    print("\n" + "=" * 60)
    print("Ready-made validators")
    print("=" * 60)

    claims = {"sub": "user-1", "email": "a@example.com", "scope": "orders:read"}
    _run("require_claims(sub, email)", require_claims("sub", "email"), claims)
    _run("require_claims(sub, groups)", require_claims("sub", "groups"), claims)
    _run(
        "require_claim_value(token_use, access)",
        require_claim_value("token_use", "access"),
        {**claims, "token_use": "access"},
    )
    _run("require_scopes(orders:read)", require_scopes("orders:read"), claims)
    _run("require_scopes(orders:write)", require_scopes("orders:write"), claims)


def composing_validators() -> None:
    """Compose several with combine_claims_validators (all / any)."""
    print("\n" + "=" * 60)
    print("Composing validators")
    print("=" * 60)

    all_of = combine_claims_validators(
        [require_claim_value("token_use", "access"), require_scopes("orders:read")]
    )  # require="all" (default): every validator must accept
    any_of = combine_claims_validators(
        [require_scopes("admin"), require_scopes("orders:read")], require="any"
    )  # passes if at least one accepts

    claims = {"token_use": "access", "scope": "orders:read"}
    _run("all-of [token_use=access, orders:read]", all_of, claims)
    _run("any-of [admin OR orders:read]", any_of, claims)


def wire_into_validation() -> None:
    """Drop a composed validator straight into TokenValidationConfig."""
    print("\n" + "=" * 60)
    print("Wiring into token validation")
    print("=" * 60)

    config = TokenValidationConfig(
        perform_disco=True,
        issuer="https://issuer.example.com",
        audience="orders-api",
        claims_validator=combine_claims_validators(
            [require_claim_value("token_use", "access"), require_scopes("orders:read")]
        ),
    )
    # The same callable also drops into the FastAPI middleware / WebSocket
    # authenticator via `custom_claims_validator` — no adapter needed.
    print(f"  configured claims_validator: {config.claims_validator is not None}")


if __name__ == "__main__":
    ready_made_validators()
    composing_validators()
    wire_into_validation()
