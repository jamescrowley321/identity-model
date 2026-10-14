"""Security tests: the discovery path enforces the caller's ``algorithms`` list (#905).

``build_resolved_config`` is the chokepoint where the discovery and retry paths
narrow ``algorithms`` to the resolved key's alg. An alg outside the caller's list
must be rejected there with the full error contract, so a caller (or log
pipeline) can tell an allowlist rejection from any other header failure.
"""

from __future__ import annotations

import pytest

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import build_resolved_config
from py_identity_model.exceptions import TokenValidationException


class TestResolvedAlgOutsideAllowlist:
    def test_rejected_with_full_contract(self):
        original = TokenValidationConfig(
            perform_disco=True, algorithms=["PS256", "ES256"]
        )
        with pytest.raises(TokenValidationException) as exc_info:
            build_resolved_config(original, {"kty": "RSA"}, "RS256")
        exc = exc_info.value
        assert str(exc) == "Algorithm 'RS256' is not in the allowed algorithms"
        assert exc.token_part == "header"
        assert exc.details == {"alg": "RS256", "allowed": ["PS256", "ES256"]}

    def test_alg_in_allowlist_resolves(self):
        original = TokenValidationConfig(perform_disco=True, algorithms=["RS256"])
        resolved = build_resolved_config(original, {"kty": "RSA"}, "RS256")
        assert resolved.algorithms == ["RS256"]
