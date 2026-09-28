"""Unit tests for core parsers module."""

import base64
import json
import logging

import pytest

import py_identity_model.core as core_mod
from py_identity_model.core.models import JsonWebKey
import py_identity_model.core.parsers as parsers_mod
from py_identity_model.core.parsers import (
    extract_jwt_header_fields,
    extract_kid_from_jwt,
    find_key_by_kid,
    get_public_key_from_jwk,
    jwks_from_dict,
)
from py_identity_model.exceptions import TokenValidationException


class TestFindKeyByKid:
    """Tests for the find_key_by_kid function."""

    def test_find_key_by_kid_success(self):
        """Test finding a key with matching kid."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", alg="RS384", n="ghi", e="jkl"),
        ]

        key_dict, alg = find_key_by_kid("key1", keys)

        assert key_dict["kid"] == "key1"
        assert alg == "RS256"

    def test_find_key_by_kid_default_algorithm(self):
        """Test that RS256 is used as default when no alg specified."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
        ]

        key_dict, alg = find_key_by_kid("key1", keys)

        assert key_dict["kid"] == "key1"
        assert alg == "RS256"

    def test_find_key_by_kid_no_keys(self):
        """Test that empty keys list raises exception."""
        with pytest.raises(TokenValidationException) as exc_info:
            find_key_by_kid("key1", [])

        assert "No keys available" in str(exc_info.value)

    def test_find_key_by_kid_no_matching_key(self):
        """Test that missing kid raises exception with available kids."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", n="ghi", e="jkl"),
        ]

        with pytest.raises(TokenValidationException) as exc_info:
            find_key_by_kid("nonexistent", keys)

        error_msg = str(exc_info.value)
        assert "No matching kid found" in error_msg
        assert "nonexistent" in error_msg

    def test_find_key_by_kid_none_kid_single_key_fallback(self):
        """Per OIDC Core Section 10.1: use the single JWKS key when JWT has no kid."""
        keys = [
            JsonWebKey(kty="RSA", kid="server-key-1", alg="RS256", n="abc", e="def"),
        ]

        key_dict, alg = find_key_by_kid(None, keys)

        assert key_dict["kid"] == "server-key-1"
        assert alg == "RS256"

    def test_find_key_by_kid_none_kid_single_key_no_kid_on_key(self):
        """Fallback works even when the single JWKS key itself has no kid."""
        keys = [
            JsonWebKey(kty="RSA", kid=None, alg="RS256", n="abc", e="def"),
        ]

        key_dict, alg = find_key_by_kid(None, keys)

        assert key_dict.get("kid") is None
        assert alg == "RS256"

    def test_find_key_by_kid_none_kid_multiple_signing_keys_error(self):
        """When JWT has no kid and JWKS has multiple signing keys, raise an error."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", alg="RS384", n="ghi", e="jkl"),
        ]

        with pytest.raises(TokenValidationException) as exc_info:
            find_key_by_kid(None, keys)

        error_msg = str(exc_info.value)
        assert "no kid header" in error_msg.lower()
        assert "multiple signing keys" in error_msg.lower()

    def test_find_key_by_kid_none_kid_filters_signing_keys(self):
        """When JWT has no kid, filter to use=sig keys and use single match."""
        keys = [
            JsonWebKey(
                kty="RSA", kid="sig-key", alg="RS256", use="sig", n="abc", e="def"
            ),
            JsonWebKey(
                kty="RSA", kid="enc-key1", alg="RSA-OAEP", use="enc", n="ghi", e="jkl"
            ),
            JsonWebKey(
                kty="RSA",
                kid="enc-key2",
                alg="RSA-OAEP-256",
                use="enc",
                n="mno",
                e="pqr",
            ),
        ]

        key_dict, alg = find_key_by_kid(None, keys)

        assert key_dict["kid"] == "sig-key"
        assert alg == "RS256"

    def test_find_key_by_kid_none_kid_single_key_logs_warning(self, caplog):
        """Verify a warning is logged when falling back to single key."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
        ]

        with caplog.at_level(logging.WARNING):
            find_key_by_kid(None, keys)

        assert any("no kid header" in r.message.lower() for r in caplog.records)

    def test_find_key_by_kid_none_kid_kty_filtering(self):
        """When JWT has no kid, filter by kty matching JWT alg to find unique key."""
        keys = [
            JsonWebKey(
                kty="RSA", kid="rsa-key", alg="RS256", use="sig", n="abc", e="def"
            ),
            JsonWebKey(
                kty="EC",
                kid="ec-key",
                alg="ES256",
                use="sig",
                crv="P-256",
                x="x",
                y="y",
            ),
        ]

        key_dict, alg = find_key_by_kid(None, keys, jwt_alg="ES256")

        assert key_dict["kid"] == "ec-key"
        assert alg == "ES256"

    def test_find_key_by_kid_none_kid_fallback_to_all_keys(self):
        """When all keys have use=enc, fall back to all keys."""
        keys = [
            JsonWebKey(
                kty="RSA", kid="enc-key", alg="RSA-OAEP", use="enc", n="abc", e="def"
            ),
        ]

        key_dict, _alg = find_key_by_kid(None, keys)

        assert key_dict["kid"] == "enc-key"

    def test_find_key_by_kid_none_kid_uses_jwt_alg_as_default(self):
        """When single signing key has no alg, use jwt_alg as default."""
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
        ]

        _key_dict, alg = find_key_by_kid(None, keys, jwt_alg="RS384")

        assert alg == "RS384"


def _create_jwt_with_kid(kid: str, alg: str = "RS256") -> str:
    """Helper to create a minimal JWT with a specific kid in the header."""
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    payload = {"sub": "test"}
    # Create unsigned JWT (header.payload.signature)
    # Use compact JSON without spaces for proper JWT format
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    # Create a fake but valid base64 signature
    fake_sig = base64.urlsafe_b64encode(b"fake_signature_bytes").rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{fake_sig}"


def _create_jwt_without_kid(alg: str = "RS256") -> str:
    """Helper to create a minimal JWT without a kid in the header."""
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "test"}
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    fake_sig = base64.urlsafe_b64encode(b"fake_signature_bytes").rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{fake_sig}"


class TestNoKidSelectionWithUnusableKeys:
    """No-kid key selection against a JWK Set carrying keys the RP can't use.

    Newer OpenID conformance suites publish such keys (unknown ``alg``,
    unknown ``kty``) next to the real signing key; see
    AddUnusableKeysToServerPublicJwks in the suite.
    """

    SIGNING = JsonWebKey(kty="RSA", kid="signing", alg="RS256", n="abc", e="AQAB")
    UNKNOWN_ALG = JsonWebKey(
        kty="RSA", kid="unusable-rsa-unknown-alg-key", alg="RS9999", n="def", e="AQAB"
    )

    def test_key_declaring_another_alg_is_not_a_candidate(self):
        key_dict, alg = find_key_by_kid(
            None, [self.UNKNOWN_ALG, self.SIGNING], jwt_alg="RS256"
        )

        assert (key_dict, alg) == (self.SIGNING.as_dict(), "RS256")

    def test_deprecated_lookup_skips_key_declaring_another_alg(self):
        jwt = _create_jwt_without_kid("RS256")

        with pytest.warns(DeprecationWarning, match="get_public_key_from_jwk"):
            key = get_public_key_from_jwk(jwt, [self.UNKNOWN_ALG, self.SIGNING])

        assert key == self.SIGNING

    @pytest.mark.parametrize("alg", [1, ["RS256"]], ids=["int", "list"])
    @pytest.mark.parametrize("multiple_keys", [True, False], ids=["multi", "single"])
    def test_non_string_alg_is_a_typed_rejection(self, alg, multiple_keys):
        keys = [self.UNKNOWN_ALG, self.SIGNING] if multiple_keys else [self.SIGNING]

        with pytest.raises(TokenValidationException, match="'alg'"):
            find_key_by_kid(None, keys, jwt_alg=alg)

    def test_alg_none_is_rejected_before_key_selection(self):
        with pytest.raises(
            TokenValidationException,
            match="Algorithm 'none' is not permitted",
        ):
            find_key_by_kid(None, [self.UNKNOWN_ALG, self.SIGNING], jwt_alg="none")


class TestExtractKidFromJwt:
    """Tests for the extract_kid_from_jwt function."""

    def test_extract_kid_success(self):
        """Test extracting kid from JWT header."""
        jwt = _create_jwt_with_kid("test-key-id")
        kid = extract_kid_from_jwt(jwt)
        assert kid == "test-key-id"

    def test_extract_kid_missing(self):
        """Test extracting kid when not present returns None."""
        jwt = _create_jwt_without_kid()
        kid = extract_kid_from_jwt(jwt)
        assert kid is None


class TestExtractJwtHeaderFields:
    """Tests for the extract_jwt_header_fields function."""

    def test_extract_both_kid_and_alg(self):
        """Test extracting kid and alg from JWT header."""
        jwt = _create_jwt_with_kid("test-key", "ES256")
        kid, alg = extract_jwt_header_fields(jwt)
        assert kid == "test-key"
        assert alg == "ES256"

    def test_extract_alg_when_kid_absent(self):
        """Test extracting alg when kid is not present."""
        jwt = _create_jwt_without_kid(alg="RS384")
        kid, alg = extract_jwt_header_fields(jwt)
        assert kid is None
        assert alg == "RS384"


class TestGetPublicKeyFromJwk:
    """Tests for the get_public_key_from_jwk function."""

    def test_get_public_key_success(self):
        """Test finding matching key from JWKS."""
        jwt = _create_jwt_with_kid("key1", "RS256")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", alg="RS384", n="ghi", e="jkl"),
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.kid == "key1"
        assert key.alg == "RS256"

    def test_get_public_key_sets_alg_from_header(self):
        """Test that alg is set from JWT header when not in key."""
        jwt = _create_jwt_with_kid("key1", "RS384")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),  # No alg
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.kid == "key1"
        assert key.alg == "RS384"  # Set from JWT header

    def test_get_public_key_not_found(self):
        """Test exception when no matching key found."""
        jwt = _create_jwt_with_kid("nonexistent")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),
        ]

        with pytest.raises(TokenValidationException) as exc_info:
            get_public_key_from_jwk(jwt, keys)

        assert "No matching kid found" in str(exc_info.value)

    def test_get_public_key_no_kid_single_key_fallback(self):
        """Per OIDC Core Section 10.1: use the single JWKS key when JWT has no kid."""
        jwt = _create_jwt_without_kid()
        keys = [
            JsonWebKey(kty="RSA", kid="server-key", alg="RS256", n="abc", e="def"),
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.kid == "server-key"
        assert key.alg == "RS256"

    def test_get_public_key_no_kid_multiple_signing_keys_error(self):
        """When JWT has no kid and several keys could verify it, raise an error."""
        jwt = _create_jwt_without_kid()
        keys = [
            JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def"),
            JsonWebKey(kty="RSA", kid="key2", alg="RS256", n="ghi", e="jkl"),
        ]

        with pytest.raises(TokenValidationException) as exc_info:
            get_public_key_from_jwk(jwt, keys)

        error_msg = str(exc_info.value)
        assert "no kid header" in error_msg.lower()
        assert "multiple signing keys" in error_msg.lower()

    def test_get_public_key_no_kid_sets_alg_from_header(self):
        """When falling back to single key without alg, set it from JWT header."""
        jwt = _create_jwt_without_kid(alg="RS384")
        keys = [
            JsonWebKey(kty="RSA", kid="key1", n="abc", e="def"),  # No alg
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.alg == "RS384"

    def test_get_public_key_no_kid_kty_filtering(self):
        """When JWT has no kid, filter by kty matching JWT alg to find unique key."""
        jwt = _create_jwt_without_kid(alg="ES256")
        keys = [
            JsonWebKey(
                kty="RSA", kid="rsa-key", alg="RS256", use="sig", n="abc", e="def"
            ),
            JsonWebKey(
                kty="EC",
                kid="ec-key",
                alg="ES256",
                use="sig",
                crv="P-256",
                x="x",
                y="y",
            ),
        ]

        key = get_public_key_from_jwk(jwt, keys)

        assert key.kid == "ec-key"
        assert key.alg == "ES256"

    def test_get_public_key_no_kid_fallback_to_all_keys_rejects_alg_mismatch(self):
        """When all keys have use=enc and alg doesn't match JWT, reject."""
        jwt = _create_jwt_without_kid()
        keys = [
            JsonWebKey(
                kty="RSA", kid="enc-key", alg="RSA-OAEP", use="enc", n="abc", e="def"
            ),
        ]

        with pytest.raises(TokenValidationException, match="does not match"):
            get_public_key_from_jwk(jwt, keys)


class TestGetPublicKeyFromJwkSecurityFixes:
    """Security tests for get_public_key_from_jwk (T200 / #375).

    Validates that the deprecation + copy-on-use fix blocks the cached key
    mutation exploit where an attacker's JWT header could permanently alter
    the alg field on a cached JsonWebKey.
    """

    def test_key_mutation_via_jwt_header_blocked(self):
        """Exploit scenario: JWT with alg=HS256 must not mutate cached key's alg."""
        original_key = JsonWebKey(kty="RSA", kid="key1", alg=None, n="abc", e="def")
        jwt = _create_jwt_with_kid("key1", alg="RS256")

        with pytest.warns(DeprecationWarning, match="deprecated"):
            returned_key = get_public_key_from_jwk(jwt, [original_key])

        # Returned key should have the alg set
        assert returned_key.alg == "RS256"
        # Original key must NOT be mutated
        assert original_key.alg is None

    def test_kid_path_no_mutation(self):
        """Kid-matched path must also not mutate the original key."""
        original_key = JsonWebKey(kty="RSA", kid="target", alg=None, n="abc", e="def")
        jwt = _create_jwt_with_kid("target", alg="RS384")

        with pytest.warns(DeprecationWarning, match="deprecated"):
            returned_key = get_public_key_from_jwk(jwt, [original_key])

        assert returned_key.alg == "RS384"
        assert original_key.alg is None

    def test_no_kid_path_no_mutation(self):
        """No-kid single-key fallback path must not mutate the original key."""
        original_key = JsonWebKey(kty="RSA", kid="only-key", alg=None, n="abc", e="def")
        jwt = _create_jwt_without_kid(alg="RS256")

        with pytest.warns(DeprecationWarning, match="deprecated"):
            returned_key = get_public_key_from_jwk(jwt, [original_key])

        assert returned_key.alg == "RS256"
        assert original_key.alg is None

    def test_deprecation_warning_emitted(self):
        """Calling get_public_key_from_jwk must emit DeprecationWarning."""
        jwt = _create_jwt_with_kid("key1", alg="RS256")
        keys = [JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def")]

        with pytest.warns(DeprecationWarning, match="deprecated"):
            get_public_key_from_jwk(jwt, keys)

    def test_returned_key_has_correct_alg_when_key_already_has_alg(self):
        """When key already has alg set, returned copy preserves it."""
        original_key = JsonWebKey(kty="RSA", kid="key1", alg="RS256", n="abc", e="def")
        jwt = _create_jwt_with_kid("key1", alg="RS256")

        with pytest.warns(DeprecationWarning, match="deprecated"):
            returned_key = get_public_key_from_jwk(jwt, [original_key])

        assert returned_key.alg == "RS256"
        # Original still untouched (was already RS256, but verify identity differs)
        assert returned_key is not original_key

    def test_not_in_core_all(self):
        """get_public_key_from_jwk must not be in core.__all__ (removed from public API)."""
        assert "get_public_key_from_jwk" not in core_mod.__all__
        assert "get_public_key_from_jwk" not in parsers_mod.__all__

    def test_still_importable_for_backwards_compat(self):
        """Function is still importable even though removed from __all__."""
        assert callable(get_public_key_from_jwk)


class TestJwksFromDict:
    """Tests for the jwks_from_dict function."""

    def test_jwks_from_dict_rsa(self):
        """Test parsing RSA key from dict."""
        key_dict = {
            "kty": "RSA",
            "kid": "test-key",
            "alg": "RS256",
            "n": "modulus",
            "e": "exponent",
        }

        jwk = jwks_from_dict(key_dict)

        assert jwk.kty == "RSA"
        assert jwk.kid == "test-key"
        assert jwk.alg == "RS256"
        assert jwk.n == "modulus"
        assert jwk.e == "exponent"

    def test_jwks_from_dict_ec(self):
        """Test parsing EC key from dict."""
        key_dict = {
            "kty": "EC",
            "kid": "ec-key",
            "crv": "P-256",
            "x": "x-coord",
            "y": "y-coord",
        }

        jwk = jwks_from_dict(key_dict)

        assert jwk.kty == "EC"
        assert jwk.kid == "ec-key"
        assert jwk.crv == "P-256"
        assert jwk.x == "x-coord"
        assert jwk.y == "y-coord"

    def test_jwks_from_dict_optional_fields(self):
        """Test that optional fields are properly handled."""
        key_dict = {
            "kty": "RSA",
            "n": "modulus",
            "e": "exponent",
            # No kid, alg, or other optional fields
        }

        jwk = jwks_from_dict(key_dict)

        assert jwk.kty == "RSA"
        assert jwk.kid is None
        assert jwk.alg is None

    def test_x5t_s256_round_trips_via_as_dict(self):
        """x5t#S256 (RFC 7517) survives as_dict / from_json / jwks_from_dict.

        Providers such as Keycloak emit the ``x5t#S256`` SHA-256 thumbprint in
        their JWKS. ``as_dict()`` must serialize it under the RFC member name so
        the dictionary form round-trips; previously it used the ``x5t_s256``
        Python attribute name, which ``from_json``/``jwks_from_dict`` do not read.
        """
        key_dict = {
            "kty": "RSA",
            "kid": "keycloak-sig",
            "alg": "RS256",
            "use": "sig",
            "n": "modulus",
            "e": "AQAB",
            "x5t#S256": "abc123thumbprint",
        }

        jwk = jwks_from_dict(key_dict)
        assert jwk.x5t_s256 == "abc123thumbprint"

        # as_dict() emits the RFC member name, not the Python attribute name
        as_dict = jwk.as_dict()
        assert as_dict["x5t#S256"] == "abc123thumbprint"
        assert "x5t_s256" not in as_dict

        # The dictionary form round-trips back through both parse paths
        assert jwks_from_dict(as_dict).x5t_s256 == "abc123thumbprint"
        assert JsonWebKey.from_json(json.dumps(as_dict)).x5t_s256 == (
            "abc123thumbprint"
        )
