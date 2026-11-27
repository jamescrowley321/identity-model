"""Integration tests for JARM — JWT-Secured Authorization Response Mode (#218).

These hit the live OIDC provider fixture.  A *positive* JARM roundtrip needs an
interactive browser login to obtain a provider-signed ``response`` JWT, which
this headless fixture cannot drive non-interactively (same gap class as the
live DPoP/mTLS handshake tests — see the T126 precedent).  What we CAN exercise
against the real provider without a browser:

* the discovery document really advertises the JARM signing algorithms and the
  ``*.jwt`` response modes, and the typed model parses them (RFC 8414 §2); and
* ``process_jarm_response`` in discovery mode really fetches the provider's
  discovery + JWKS and rejects a response signed by an untrusted key.

The full signature/claims verification is covered exhaustively by the offline
unit tests (``src/tests/unit/test_jarm.py``) which mint their own keys.
"""

import json
import time

from cryptography.hazmat.primitives.asymmetric import ec
import jwt as pyjwt
from jwt import algorithms as jwt_algorithms
import pytest

from py_identity_model import (
    JarmValidationException,
    process_jarm_response,
)
from py_identity_model.exceptions import TokenValidationException


@pytest.mark.integration
class TestJarmDiscoveryMetadata:
    """The real provider advertises JARM metadata and the model parses it."""

    def test_discovery_advertises_jarm_capability(
        self, provider_capabilities, discovery_document
    ):
        if "jarm" not in provider_capabilities:
            pytest.skip("Provider does not advertise JARM (jwtResponseModes)")

        # Assert an INDEPENDENT property from the capability probe: the probe is
        # derived from the raw discovery dict, so re-checking that dict would be
        # tautological. Instead assert the *parsed typed model* surfaces the JARM
        # markers — this exercises the RFC 8414 §2 parse (the code under test).
        # If the parse dropped these fields the capability would still be True
        # (raw-derived) while the typed model came back empty → this fails.
        modes = discovery_document.response_modes_supported or []
        has_jwt_mode = any(m.endswith(".jwt") or m == "jwt" for m in modes)
        has_signing_algs = bool(
            discovery_document.authorization_signing_alg_values_supported
        )
        assert has_signing_algs or has_jwt_mode, (
            "jarm capability detected but the parsed discovery model surfaces "
            "neither authorization_signing_alg_values_supported nor a *.jwt "
            "response mode"
        )

    def test_signing_alg_values_parsed(
        self, provider_capabilities, discovery_document, raw_discovery
    ):
        """The typed discovery_document mirrors the raw JARM signing algs."""
        if "jarm" not in provider_capabilities:
            pytest.skip("Provider does not advertise JARM (jwtResponseModes)")

        raw_algs = raw_discovery.get("authorization_signing_alg_values_supported")
        if raw_algs is None:
            pytest.skip("Provider advertises *.jwt modes but not signing algs")

        # Typed model must equal the raw discovery values (RFC 8414 §2 parse).
        assert discovery_document.authorization_signing_alg_values_supported == raw_algs
        # JARM asymmetric signing algs; 'none' must never be advertised.
        assert "none" not in raw_algs
        assert any(alg in raw_algs for alg in ("RS256", "ES256", "PS256"))

    def test_jwt_response_modes_advertised(self, provider_capabilities, raw_discovery):
        """At least one ``*.jwt`` response mode is advertised when JARM is on."""
        if "jarm" not in provider_capabilities:
            pytest.skip("Provider does not advertise JARM (jwtResponseModes)")

        modes = raw_discovery.get("response_modes_supported", [])
        # Only assert when the provider chose to expose response_modes_supported.
        if modes:
            assert any(m.endswith(".jwt") or m == "jwt" for m in modes)


@pytest.mark.integration
class TestJarmLiveVerification:
    """process_jarm_response against the live discovery + JWKS endpoints."""

    def test_rejects_response_signed_with_untrusted_key(
        self, provider_capabilities, discovery_document, test_config, require_https
    ):
        """A JARM JWT signed by a key the AS does not publish must be rejected.

        Exercises the real discovery + JWKS fetch, algorithm allow-listing
        (from the provider's advertised
        ``authorization_signing_alg_values_supported``), and key lookup — the
        signature/key check fails because the minting key is not in the
        provider's JWKS.
        """
        if "jarm" not in provider_capabilities:
            pytest.skip("Provider does not advertise JARM (jwtResponseModes)")

        allowed = discovery_document.authorization_signing_alg_values_supported or []
        if "ES256" not in allowed:
            pytest.skip("Provider does not advertise ES256 for JARM")

        # Mint a JARM response with our OWN EC key + a kid the provider's JWKS
        # does not contain. The alg (ES256) IS advertised, so it clears the
        # allow-list; the untrusted key means verification/lookup must fail.
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        _public_jwk = json.loads(
            jwt_algorithms.ECAlgorithm.to_jwk(attacker_key.public_key())
        )
        forged = pyjwt.encode(
            {
                "iss": discovery_document.issuer,
                "aud": "test-auth-code",
                "exp": int(time.time()) + 300,
                "code": "forged-code",
                "state": "forged-state",
            },
            attacker_key,
            algorithm="ES256",
            headers={"kid": "attacker-kid-not-in-jwks"},
        )
        callback = f"http://localhost:8080/callback?response={forged}"

        # Either the key lookup fails (no matching kid) or the signature check
        # fails — both are correct fail-closed rejections.
        with pytest.raises((TokenValidationException, JarmValidationException)):
            process_jarm_response(
                callback,
                client_id="test-auth-code",
                issuer=test_config["TEST_ISSUER"],
                require_https=require_https,
            )

    def test_live_positive_roundtrip_documented_gap(self, provider_capabilities):
        """A provider-signed positive JARM roundtrip needs interactive login.

        The headless fixture cannot complete the browser-based authorization
        that yields a provider-signed ``response`` JWT, so the positive path is
        covered by the offline unit tests + example rather than a live flow.
        This mirrors the documented live-handshake gap for DPoP/mTLS (T126).
        """
        if "jarm" not in provider_capabilities:
            pytest.skip("Provider does not advertise JARM (jwtResponseModes)")
        pytest.skip(
            "Live positive JARM roundtrip requires interactive browser login; "
            "positive verification covered by offline unit tests + example "
            "(documented gap, T126 precedent)"
        )
