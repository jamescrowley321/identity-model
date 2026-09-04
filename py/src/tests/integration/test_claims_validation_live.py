"""Live integration for the injectable claims validators (issue #603).

Runs the NEW claims-validation API through the REAL token-validation pipeline —
real HTTP discovery + JWKS fetch + signature / audience / issuer verification
against a :class:`~harness.MockOP` served over localhost — proving the injected
validators run *after* the standard checks on a genuinely valid, signed token
(the unit tests mock ``validate_token``, so they cannot show that). Self-contained:
the mock OP needs no Docker.
"""

import logging

import pytest

from py_identity_model import (
    ClaimsValidationError,
    TokenValidationConfig,
    combine_claims_validators,
    require_claim_value,
    require_claims,
    require_scopes,
)
from py_identity_model.aio import validate_token

from ..harness import CORPUS_AUDIENCE, build_corpus, serve_mock_op


pytest.importorskip("uvicorn")

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


@pytest.fixture(scope="module")
def mock_op():
    with serve_mock_op() as op:
        yield op


def _config(op, validator) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=CORPUS_AUDIENCE,
        issuer=op.issuer,
        require_https=False,  # the mock OP is served over http://127.0.0.1
        claims_validator=validator,
    )


async def _validate(op, token, validator) -> dict:
    return await validate_token(
        jwt=token,
        token_validation_config=_config(op, validator),
        disco_doc_address=op.discovery_url,
    )


async def test_passing_validator_accepts_real_token(mock_op):
    token = build_corpus(mock_op)["valid"].jwt
    claims = await _validate(mock_op, token, require_scopes("read"))
    assert claims["sub"] == "mock-subject"


async def test_rejecting_validator_rejects_after_standard_checks(mock_op):
    # The token is genuinely valid (signature / aud / iss all pass) — only the
    # injected claims validator rejects it, proving the hook runs in the real
    # pipeline, not merely in an isolated unit.
    token = build_corpus(mock_op)["valid"].jwt
    with pytest.raises(ClaimsValidationError) as exc:
        await _validate(mock_op, token, require_scopes("admin"))
    assert "admin" in exc.value.reason
    assert exc.value.claim == "scope"


async def test_combined_validators_through_real_pipeline(mock_op):
    token = build_corpus(mock_op)["valid"].jwt
    validator = combine_claims_validators(
        [
            require_claims("sub"),
            require_claim_value("iss", mock_op.issuer),
            require_scopes("read"),
        ]
    )
    claims = await _validate(mock_op, token, validator)
    assert claims["scope"] == "read"


async def test_rejection_is_logged_server_side(mock_op, caplog):
    # The structured rejection is logged even though it propagates unwrapped.
    token = build_corpus(mock_op)["valid"].jwt
    with (
        caplog.at_level(logging.INFO, logger="py_identity_model"),
        pytest.raises(ClaimsValidationError),
    ):
        await _validate(mock_op, token, require_claims("nonexistent_claim"))
    assert "Claims validation rejected" in caplog.text
    assert "nonexistent_claim" in caplog.text
