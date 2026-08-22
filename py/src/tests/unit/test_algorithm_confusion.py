"""Tests for algorithm confusion prevention (Batch 4, #349).

Validates that key type / algorithm consistency is enforced to prevent
algorithm confusion attacks.
"""

# Minimal JWT headers for testing (base64-encoded, no signature needed)
import base64
import json

import pytest

from py_identity_model.core.models import JsonWebKey
from py_identity_model.core.parsers import (
    _validate_key_alg_consistency,
    find_key_by_kid,
    get_public_key_from_jwk,
)
from py_identity_model.exceptions import TokenValidationException


def _make_jwt(kid: str | None = "k1", alg: str = "RS256") -> str:
    """Build a minimal unsigned JWT with given header fields."""
    header: dict = {"typ": "JWT", "alg": alg}
    if kid is not None:
        header["kid"] = kid
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
    return f"{h}.{p}.fake_sig"


class TestValidateKeyAlgConsistency:
    """Direct tests for _validate_key_alg_consistency."""

    def test_rsa_key_with_rs256(self):
        key = JsonWebKey(kty="RSA", kid="k1", n="n", e="e")
        _validate_key_alg_consistency(key, "RS256")  # should not raise

    def test_rsa_key_with_ps256(self):
        key = JsonWebKey(kty="RSA", kid="k1", n="n", e="e")
        _validate_key_alg_consistency(key, "PS256")  # should not raise

    def test_ec_key_with_es256(self):
        key = JsonWebKey(kty="EC", kid="k1", crv="P-256", x="x", y="y")
        _validate_key_alg_consistency(key, "ES256")  # should not raise

    def test_rsa_key_rejects_es256(self):
        key = JsonWebKey(kty="RSA", kid="k1", n="n", e="e")
        with pytest.raises(TokenValidationException, match="incompatible"):
            _validate_key_alg_consistency(key, "ES256")

    def test_ec_key_rejects_rs256(self):
        key = JsonWebKey(kty="EC", kid="k1", crv="P-256", x="x", y="y")
        with pytest.raises(TokenValidationException, match="incompatible"):
            _validate_key_alg_consistency(key, "RS256")

    def test_key_alg_mismatch(self):
        key = JsonWebKey(kty="RSA", kid="k1", alg="RS256", n="n", e="e")
        with pytest.raises(TokenValidationException, match="does not match"):
            _validate_key_alg_consistency(key, "RS384")

    def test_key_alg_matches(self):
        key = JsonWebKey(kty="RSA", kid="k1", alg="RS256", n="n", e="e")
        _validate_key_alg_consistency(key, "RS256")  # should not raise

    def test_no_jwt_alg_skips_validation(self):
        key = JsonWebKey(kty="RSA", kid="k1", n="n", e="e")
        _validate_key_alg_consistency(key, None)  # should not raise

    def test_unknown_alg_skips_kty_check(self):
        """Unknown algorithms skip kty check but still check key.alg."""
        key = JsonWebKey(kty="RSA", kid="k1", n="n", e="e")
        _validate_key_alg_consistency(key, "CUSTOM")  # should not raise

    def test_okp_key_with_eddsa(self):
        key = JsonWebKey(kty="OKP", kid="k1", crv="Ed25519", x="x")
        _validate_key_alg_consistency(key, "EdDSA")  # should not raise

    def test_okp_key_rejects_rs256(self):
        key = JsonWebKey(kty="OKP", kid="k1", crv="Ed25519", x="x")
        with pytest.raises(TokenValidationException, match="incompatible"):
            _validate_key_alg_consistency(key, "RS256")


class TestFindKeyByKidAlgorithmEnforcement:
    """Test that find_key_by_kid enforces key/algorithm consistency."""

    def test_rejects_ec_key_with_rs256_jwt(self):
        keys = [JsonWebKey(kty="EC", kid="k1", crv="P-256", x="x", y="y")]
        with pytest.raises(TokenValidationException, match="incompatible"):
            find_key_by_kid("k1", keys, jwt_alg="RS256")

    def test_rejects_rsa_key_with_es256_jwt(self):
        keys = [JsonWebKey(kty="RSA", kid="k1", n="n", e="e")]
        with pytest.raises(TokenValidationException, match="incompatible"):
            find_key_by_kid("k1", keys, jwt_alg="ES256")

    def test_allows_rsa_key_with_rs256_jwt(self):
        keys = [JsonWebKey(kty="RSA", kid="k1", n="n", e="e")]
        key_dict, _alg = find_key_by_kid("k1", keys, jwt_alg="RS256")
        assert key_dict["kid"] == "k1"

    def test_rejects_key_alg_mismatch(self):
        keys = [JsonWebKey(kty="RSA", kid="k1", alg="RS256", n="n", e="e")]
        with pytest.raises(TokenValidationException, match="does not match"):
            find_key_by_kid("k1", keys, jwt_alg="RS384")

    def test_no_kid_single_key_validates(self):
        keys = [JsonWebKey(kty="EC", kid="k1", crv="P-256", x="x", y="y")]
        with pytest.raises(TokenValidationException, match="incompatible"):
            find_key_by_kid(None, keys, jwt_alg="RS256")


class TestFindKeyByKidAlgorithmResolution:
    """The resolved algorithm for a kid-matched key.

    Regression: a kid-matched JWKS key that omits the optional ``alg`` member
    must fall back to the (consistency-checked) JWT header alg, not the RS256
    default — otherwise a valid PS256/ES256/EdDSA token signed by an alg-less
    key is wrongly rejected on the discovery path (common with Azure AD and
    FAPI 2.0's mandated PS256).
    """

    def test_rsa_key_without_alg_falls_back_to_ps256_header(self):
        keys = [JsonWebKey(kty="RSA", kid="k1", n="n", e="e")]
        _key_dict, alg = find_key_by_kid("k1", keys, jwt_alg="PS256")
        assert alg == "PS256"

    def test_ec_key_without_alg_falls_back_to_es256_header(self):
        keys = [JsonWebKey(kty="EC", kid="k1", crv="P-256", x="x", y="y")]
        _key_dict, alg = find_key_by_kid("k1", keys, jwt_alg="ES256")
        assert alg == "ES256"

    def test_key_declared_alg_is_preferred(self):
        keys = [JsonWebKey(kty="RSA", kid="k1", alg="PS256", n="n", e="e")]
        _key_dict, alg = find_key_by_kid("k1", keys, jwt_alg="PS256")
        assert alg == "PS256"

    def test_defaults_to_rs256_when_neither_key_nor_header_has_alg(self):
        keys = [JsonWebKey(kty="RSA", kid="k1", n="n", e="e")]
        _key_dict, alg = find_key_by_kid("k1", keys, jwt_alg=None)
        assert alg == "RS256"


class TestGetPublicKeyFromJwkAlgorithmEnforcement:
    """Test that get_public_key_from_jwk enforces key/algorithm consistency."""

    def test_rejects_ec_key_with_rs256_jwt(self):
        jwt = _make_jwt(kid="k1", alg="RS256")
        keys = [JsonWebKey(kty="EC", kid="k1", crv="P-256", x="x", y="y")]
        with pytest.raises(TokenValidationException, match="incompatible"):
            get_public_key_from_jwk(jwt, keys)

    def test_allows_matching_key(self):
        jwt = _make_jwt(kid="k1", alg="RS256")
        keys = [JsonWebKey(kty="RSA", kid="k1", n="n", e="e")]
        key = get_public_key_from_jwk(jwt, keys)
        assert key.kid == "k1"

    def test_rejects_key_alg_mismatch(self):
        jwt = _make_jwt(kid="k1", alg="RS384")
        keys = [JsonWebKey(kty="RSA", kid="k1", alg="RS256", n="n", e="e")]
        with pytest.raises(TokenValidationException, match="does not match"):
            get_public_key_from_jwk(jwt, keys)

    def test_no_kid_single_key_validates(self):
        jwt = _make_jwt(kid=None, alg="RS256")
        keys = [JsonWebKey(kty="EC", crv="P-256", x="x", y="y")]
        with pytest.raises(TokenValidationException, match="incompatible"):
            get_public_key_from_jwk(jwt, keys)
