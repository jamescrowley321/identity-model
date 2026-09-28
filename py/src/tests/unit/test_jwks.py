import json
from pathlib import Path

import httpx
import pytest
import respx

from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.exceptions import (
    ConfigurationException,
    FailedResponseAccessError,
)
from py_identity_model.jwks import (
    JsonWebKey,
    JwksRequest,
    JwksResponse,
    get_jwks,
    jwks_from_dict,
)


# Expected JWKS key count
EXPECTED_KEY_COUNT = 2


class TestJwksResponse:
    def test_jwks_response_creation_failure(self):
        error_msg = "Request failed"
        response = JwksResponse(is_successful=False, error=error_msg)
        assert response.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = response.keys
        assert response.error == error_msg


class TestJsonWebKey:
    def test_json_web_key_validation_missing_kty(self):
        with pytest.raises(
            ConfigurationException,
            match="The 'kty' \\(Key Type\\) parameter is required",
        ):
            JsonWebKey(kty=None, use="sig")  # type: ignore

    def test_json_web_key_validation_missing_rsa_params(self):
        with pytest.raises(
            ConfigurationException,
            match="RSA keys require 'n' and 'e' parameters",
        ):
            JsonWebKey(kty="RSA", use="sig")

    def test_json_web_key_from_json_valid(self):
        json_str = '{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key1", "n": "example_n", "e": "AQAB"}'
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "RSA"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.kid == "key1"

    def test_json_web_key_from_json_empty(self):
        with pytest.raises(
            ConfigurationException,
            match="JSON string cannot be empty",
        ):
            JsonWebKey.from_json("")

    def test_json_web_key_from_json_invalid_json(self):
        with pytest.raises(
            ConfigurationException,
            match="Invalid JSON format",
        ):
            JsonWebKey.from_json("invalid json")

    def test_json_web_key_from_json_missing_kty(self):
        """Test that JSON missing required 'kty' field raises ConfigurationException"""
        json_str = '{"use": "sig", "alg": "RS256"}'
        with pytest.raises(
            ConfigurationException,
            match=r"Invalid JWK format.*missing.*required.*argument.*'kty'",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_null_kty(self):
        """Test that JSON with null kty value raises ConfigurationException"""
        json_str = '{"kty": null, "use": "sig"}'
        with pytest.raises(
            ConfigurationException,
            match=r"The 'kty' \(Key Type\) parameter is required",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_empty_object(self):
        """Test that empty JSON object raises ConfigurationException"""
        json_str = "{}"
        with pytest.raises(
            ConfigurationException,
            match=r"Invalid JWK format.*missing.*required.*argument.*'kty'",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_rsa_missing_required_params(self):
        """Test that RSA key without n and e parameters raises ConfigurationException"""
        json_str = '{"kty": "RSA", "use": "sig"}'
        with pytest.raises(
            ConfigurationException,
            match="RSA keys require 'n' and 'e' parameters",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_ec_missing_required_params(self):
        """Test that EC key without required parameters raises ConfigurationException"""
        json_str = '{"kty": "EC", "use": "sig", "crv": "P-256"}'
        with pytest.raises(
            ConfigurationException,
            match="EC keys require 'crv', 'x', and 'y' parameters",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_oct_missing_k(self):
        """Test that symmetric key without k parameter raises ConfigurationException"""
        json_str = '{"kty": "oct", "use": "enc"}'
        with pytest.raises(
            ConfigurationException,
            match="Symmetric keys require 'k' parameter",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_invalid_use_value(self):
        """Test that invalid 'use' parameter value raises ValueError"""
        json_str = '{"kty": "RSA", "n": "example_n", "e": "AQAB", "use": "invalid"}'
        with pytest.raises(
            ConfigurationException,
            match="Invalid 'use' parameter",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_invalid_key_ops(self):
        """Test that invalid key_ops values raise ValueError"""
        json_str = (
            '{"kty": "RSA", "n": "example_n", "e": "AQAB", "key_ops": ["invalid_op"]}'
        )
        with pytest.raises(
            ConfigurationException,
            match="Invalid key operation",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_mutually_exclusive_use_and_key_ops(self):
        """Test that having both 'use' and 'key_ops' raises ConfigurationException"""
        json_str = '{"kty": "RSA", "n": "example_n", "e": "AQAB", "use": "sig", "key_ops": ["sign"]}'
        with pytest.raises(
            ConfigurationException,
            match="The 'use' and 'key_ops' parameters are mutually exclusive",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_invalid_ec_curve(self):
        """Test that EC key with unsupported curve raises ValueError"""
        json_str = (
            '{"kty": "EC", "crv": "invalid-curve", "x": "example_x", "y": "example_y"}'
        )
        with pytest.raises(ConfigurationException, match="Unsupported curve"):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_json_array_instead_of_object(self):
        """Test that JSON array instead of object raises ValueError"""
        json_str = '[{"kty": "RSA"}]'
        with pytest.raises(ConfigurationException, match="Invalid JWK format"):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_string_instead_of_object(self):
        """Test that JSON string instead of object raises ValueError"""
        json_str = '"just a string"'
        with pytest.raises(ConfigurationException, match="Invalid JWK format"):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_number_instead_of_object(self):
        """Test that JSON number instead of object raises ValueError"""
        json_str = "42"
        with pytest.raises(ConfigurationException, match="Invalid JWK format"):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_boolean_instead_of_object(self):
        """Test that JSON boolean instead of object raises ValueError"""
        json_str = "true"
        with pytest.raises(ConfigurationException, match="Invalid JWK format"):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_null(self):
        """Test that JSON null raises ValueError"""
        json_str = "null"
        with pytest.raises(ConfigurationException, match="Invalid JWK format"):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_whitespace_only(self):
        """Test that whitespace-only string raises ValueError"""
        json_str = "   \n\t  "
        with pytest.raises(
            ConfigurationException,
            match="JSON string cannot be empty",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_with_x5t_s256(self):
        """Test that x5t#S256 field is correctly mapped to x5t_s256"""
        json_str = (
            '{"kty": "RSA", "n": "example_n", "e": "AQAB", "x5t#S256": "thumbprint"}'
        )
        key = JsonWebKey.from_json(json_str)
        assert key.x5t_s256 == "thumbprint"

    def test_json_web_key_from_json_key_ops_as_string(self):
        """Test that key_ops provided as string is converted to list"""
        json_str = '{"kty": "RSA", "n": "example_n", "e": "AQAB", "key_ops": "sign"}'
        key = JsonWebKey.from_json(json_str)
        assert key.key_ops == ["sign"]

    def test_json_web_key_from_json_x5c_as_string(self):
        """Test that x5c provided as string is converted to list"""
        json_str = '{"kty": "RSA", "n": "example_n", "e": "AQAB", "x5c": "cert_string"}'
        key = JsonWebKey.from_json(json_str)
        assert key.x5c == ["cert_string"]

    def test_json_web_key_from_json_unexpected_field_types(self):
        """Test that unexpected field types that can't be unpacked raise ValueError"""
        json_str = (
            '{"kty": "RSA", "n": "example_n", "e": "AQAB", "kid": {"nested": "object"}}'
        )
        # This should work as kid will be set to a dict, which __init__ will accept but may not be ideal
        # The from_json doesn't explicitly validate field types, it relies on __init__ validation
        key = JsonWebKey.from_json(json_str)
        assert key.kid == {"nested": "object"}

    def test_json_web_key_from_json_invalid_json_trailing_comma(self):
        """Test that invalid JSON with trailing comma raises ValueError"""
        json_str = '{"kty": "RSA", "n": "example_n",}'
        with pytest.raises(
            ConfigurationException,
            match="Invalid JSON format",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_invalid_json_single_quotes(self):
        """Test that invalid JSON with single quotes raises ValueError"""
        json_str = "{'kty': 'RSA', 'n': 'example_n'}"
        with pytest.raises(
            ConfigurationException,
            match="Invalid JSON format",
        ):
            JsonWebKey.from_json(json_str)

    def test_json_web_key_from_json_with_additional_fields_rsa(self):
        """Test that RSA key with additional unknown fields doesn't fail"""
        json_str = '{"kty": "RSA", "n": "example_n", "e": "AQAB", "unknown_field": "value", "extra_number": 123}'
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "RSA"
        assert key.n == "example_n"
        assert key.e == "AQAB"
        assert not hasattr(key, "unknown_field")
        assert not hasattr(key, "extra_number")

    def test_json_web_key_from_json_with_additional_fields_ec(self):
        """Test that EC key with additional unknown fields doesn't fail"""
        json_str = '{"kty": "EC", "crv": "P-256", "x": "example_x", "y": "example_y", "custom_field": "custom_value"}'
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "EC"
        assert key.crv == "P-256"
        assert key.x == "example_x"
        assert key.y == "example_y"
        assert not hasattr(key, "custom_field")

    def test_json_web_key_from_json_with_additional_fields_oct(self):
        """Test that symmetric key with additional unknown fields doesn't fail"""
        json_str = '{"kty": "oct", "k": "example_k", "metadata": {"info": "test"}}'
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "oct"
        assert key.k == "example_k"
        assert not hasattr(key, "metadata")

    def test_json_web_key_from_json_with_many_additional_fields(self):
        """Test that key with many additional unknown fields doesn't fail"""
        json_str = """{
            "kty": "RSA",
            "n": "example_n",
            "e": "AQAB",
            "use": "sig",
            "alg": "RS256",
            "kid": "key1",
            "extra1": "value1",
            "extra2": "value2",
            "extra3": 123,
            "extra4": true,
            "extra5": ["array", "values"],
            "extra6": {"nested": "object"}
        }"""
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "RSA"
        assert key.n == "example_n"
        assert key.e == "AQAB"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.kid == "key1"
        # Verify extra fields are not present
        assert not hasattr(key, "extra1")
        assert not hasattr(key, "extra2")
        assert not hasattr(key, "extra3")
        assert not hasattr(key, "extra4")
        assert not hasattr(key, "extra5")
        assert not hasattr(key, "extra6")

    def test_json_web_key_from_json_with_additional_fields_and_valid_optional(
        self,
    ):
        """Test that additional fields are filtered out while valid optional fields are kept"""
        json_str = '{"kty": "RSA", "n": "example_n", "e": "AQAB", "x5t": "thumbprint", "unknown": "value"}'
        key = JsonWebKey.from_json(json_str)
        assert key.kty == "RSA"
        assert key.n == "example_n"
        assert key.e == "AQAB"
        assert key.x5t == "thumbprint"
        assert not hasattr(key, "unknown")

    def test_json_web_key_to_json(self):
        key = JsonWebKey(
            kty="RSA",
            use="sig",
            alg="RS256",
            kid="key1",
            n="example_n",
            e="AQAB",
        )
        json_str = key.to_json()
        parsed = json.loads(json_str)
        assert parsed["kty"] == "RSA"
        assert parsed["use"] == "sig"
        assert parsed["alg"] == "RS256"
        assert parsed["kid"] == "key1"

    def test_json_web_key_has_private_key_rsa_false(self):
        key = JsonWebKey(kty="RSA", n="example_n", e="AQAB")
        assert key.has_private_key is False

    def test_json_web_key_has_private_key_rsa_true(self):
        key = JsonWebKey(
            kty="RSA",
            n="example_n",
            e="AQAB",
            d="private_d",
            p="private_p",
            q="private_q",
            dp="private_dp",
            dq="private_dq",
            qi="private_qi",
        )
        assert key.has_private_key is True

    def test_json_web_key_has_private_key_ec_false(self):
        key = JsonWebKey(kty="EC", crv="P-256", x="example_x", y="example_y")
        assert key.has_private_key is False

    def test_json_web_key_has_private_key_ec_true(self):
        key = JsonWebKey(
            kty="EC",
            crv="P-256",
            x="example_x",
            y="example_y",
            d="private_d",
        )
        assert key.has_private_key is True

    def test_json_web_key_key_size_rsa(self):
        # Base64url encoded value that represents 2048 bits (256 bytes)
        n_value = "A" * 342  # This represents roughly 256 bytes when decoded
        key = JsonWebKey(kty="RSA", n=n_value, e="AQAB")
        # We test that key_size returns a value > 0, exact calculation depends on base64url decoding
        assert key.key_size > 0

    def test_json_web_key_key_size_ec(self):
        # Base64url encoded value
        x_value = "ABCD"
        key = JsonWebKey(kty="EC", crv="P-256", x=x_value, y="example_y")
        assert key.key_size > 0

    def test_json_web_key_key_size_oct(self):
        # Base64url encoded symmetric key
        k_value = "ABCD"
        key = JsonWebKey(kty="oct", k=k_value)
        assert key.key_size > 0

    def test_json_web_key_key_size_no_key_material(self):
        # Test with empty string for k parameter to test key_size with no actual key material
        key = JsonWebKey(kty="oct", k="")
        assert key.key_size == 0

    def test_json_web_key_decode_base64url(self):
        # Test the static method
        result = JsonWebKey._decode_base64url("AQAB")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_json_web_key_decode_base64url_empty(self):
        result = JsonWebKey._decode_base64url("")
        assert result == b""

    def test_json_web_key_decode_base64url_none(self):
        result = JsonWebKey._decode_base64url(None)
        assert result == b""

    def test_json_web_key_as_dict(self):
        key = JsonWebKey(
            kty="RSA",
            use="sig",
            alg="RS256",
            kid="key1",
            n="example_n",
            e="AQAB",
        )
        result = key.as_dict()
        assert result["kty"] == "RSA"
        assert result["use"] == "sig"
        assert result["alg"] == "RS256"
        assert result["kid"] == "key1"
        assert result["n"] == "example_n"
        assert result["e"] == "AQAB"

    def test_json_web_key_as_dict_excludes_none(self):
        key = JsonWebKey(
            kty="EC",
            crv="P-256",
            x="example_x",
            y="example_y",
            use="sig",
            alg=None,
        )
        result = key.as_dict()
        assert "alg" not in result
        assert result["kty"] == "EC"
        assert result["use"] == "sig"


class TestJwksFromDict:
    def test_jwks_from_dict_rsa(self):
        key_dict = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "key1",
            "n": "example_n",
            "e": "AQAB",
        }
        key = jwks_from_dict(key_dict)
        assert key.kty == "RSA"
        assert key.use == "sig"
        assert key.alg == "RS256"
        assert key.kid == "key1"
        assert key.n == "example_n"
        assert key.e == "AQAB"

    def test_jwks_from_dict_ec(self):
        key_dict = {
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": "key2",
            "crv": "P-256",
            "x": "example_x",
            "y": "example_y",
        }
        key = jwks_from_dict(key_dict)
        assert key.kty == "EC"
        assert key.use == "sig"
        assert key.alg == "ES256"
        assert key.crv == "P-256"

    def test_jwks_from_dict_x5t_s256_mapping(self):
        key_dict = {
            "kty": "RSA",
            "n": "example_n",
            "e": "AQAB",
            "x5t#S256": "thumbprint_sha256",
        }
        key = jwks_from_dict(key_dict)
        assert key.x5t_s256 == "thumbprint_sha256"

    def test_jwks_from_dict_comprehensive(self):
        """Test that jwks_from_dict handles all JWK fields correctly"""
        test_jwk_dict = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "test-key-id",
            "x5u": "https://example.com/cert",
            "x5c": ["MIICertificate"],
            "x5t": "thumbprint",
            "x5t#S256": "sha256-thumbprint",
            "crv": "P-256",
            "x": "ec-x-coordinate",
            "y": "ec-y-coordinate",
            "d": "ec-private-key",
            "n": "rsa-modulus",
            "e": "AQAB",
            "p": "rsa-prime-p",
            "q": "rsa-prime-q",
            "dp": "rsa-dp",
            "dq": "rsa-dq",
            "qi": "rsa-qi",
            "oth": [{"r": "additional", "d": "prime", "t": "info"}],
            "k": "symmetric-key",
        }

        jwk = jwks_from_dict(test_jwk_dict)

        assert jwk.kty == "RSA"
        assert jwk.use == "sig"
        assert jwk.key_ops is None
        assert jwk.alg == "RS256"
        assert jwk.kid == "test-key-id"
        assert jwk.x5u == "https://example.com/cert"
        assert jwk.x5c == ["MIICertificate"]
        assert jwk.x5t == "thumbprint"
        assert jwk.x5t_s256 == "sha256-thumbprint"
        assert jwk.crv == "P-256"
        assert jwk.x == "ec-x-coordinate"
        assert jwk.y == "ec-y-coordinate"
        assert jwk.d == "ec-private-key"
        assert jwk.n == "rsa-modulus"
        assert jwk.e == "AQAB"
        assert jwk.p == "rsa-prime-p"
        assert jwk.q == "rsa-prime-q"
        assert jwk.dp == "rsa-dp"
        assert jwk.dq == "rsa-dq"
        assert jwk.qi == "rsa-qi"
        assert jwk.oth == [{"r": "additional", "d": "prime", "t": "info"}]
        assert jwk.k == "symmetric-key"

    def test_jwks_from_dict_minimal(self):
        """Test jwks_from_dict with minimal required fields"""
        minimal_rsa_dict = {"kty": "RSA", "n": "modulus", "e": "AQAB"}
        rsa_jwk = jwks_from_dict(minimal_rsa_dict)
        assert rsa_jwk.kty == "RSA"
        assert rsa_jwk.n == "modulus"
        assert rsa_jwk.e == "AQAB"
        assert rsa_jwk.use is None
        assert rsa_jwk.kid is None
        assert rsa_jwk.alg is None

        minimal_ec_dict = {
            "kty": "EC",
            "crv": "P-256",
            "x": "x-coord",
            "y": "y-coord",
        }
        ec_jwk = jwks_from_dict(minimal_ec_dict)
        assert ec_jwk.kty == "EC"
        assert ec_jwk.crv == "P-256"
        assert ec_jwk.x == "x-coord"
        assert ec_jwk.y == "y-coord"
        assert ec_jwk.use is None
        assert ec_jwk.kid is None

        minimal_oct_dict = {"kty": "oct", "k": "symmetric-key-value"}
        oct_jwk = jwks_from_dict(minimal_oct_dict)
        assert oct_jwk.kty == "oct"
        assert oct_jwk.k == "symmetric-key-value"
        assert oct_jwk.use is None
        assert oct_jwk.kid is None

    def test_jwks_from_dict_error_handling(self):
        """Test jwks_from_dict error handling"""
        with pytest.raises(
            ConfigurationException,
            match="The 'kty' \\(Key Type\\) parameter is required",
        ):
            jwks_from_dict({})

        with pytest.raises(
            ConfigurationException,
            match="The 'kty' \\(Key Type\\) parameter is required",
        ):
            jwks_from_dict({"kty": None})

        with pytest.raises(
            ConfigurationException,
            match="RSA keys require 'n' and 'e' parameters",
        ):
            jwks_from_dict({"kty": "RSA"})

        with pytest.raises(
            ConfigurationException,
            match="EC keys require 'crv', 'x', and 'y' parameters",
        ):
            jwks_from_dict({"kty": "EC"})

        with pytest.raises(
            ConfigurationException,
            match="Symmetric keys require 'k' parameter",
        ):
            jwks_from_dict({"kty": "oct"})


class TestGetJwks:
    @respx.mock
    def test_get_jwks_success(self):
        # Mock successful response
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "kid": "key1",
                            "n": "example_n",
                            "e": "AQAB",
                        },
                        {
                            "kty": "EC",
                            "use": "sig",
                            "alg": "ES256",
                            "kid": "key2",
                            "crv": "P-256",
                            "x": "example_x",
                            "y": "example_y",
                        },
                    ],
                },
            )
        )

        request = JwksRequest(address=url)
        result = get_jwks(request)

        assert result.is_successful is True
        assert result.keys is not None
        assert len(result.keys) == EXPECTED_KEY_COUNT
        assert result.keys[0].kty == "RSA"
        assert result.keys[0].kid == "key1"
        assert result.keys[1].kty == "EC"
        assert result.keys[1].kid == "key2"

    @respx.mock
    def test_get_jwks_http_error(self):
        # Mock HTTP error response
        url = "https://example.com/jwks"
        respx.get(url).mock(return_value=httpx.Response(404, content=b"Not Found"))

        request = JwksRequest(address=url)
        result = get_jwks(request)

        assert result.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = result.keys
        assert result.error is not None
        assert "404" in result.error
        assert "Not Found" in result.error

    @respx.mock
    def test_get_jwks_exception_handling(self):
        # Mock exception during request
        url = "https://example.com/jwks"
        respx.get(url).mock(side_effect=Exception("Network error"))

        request = JwksRequest(address=url)
        result = get_jwks(request)

        assert result.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = result.keys
        assert result.error is not None
        assert "Unhandled exception during JWKS request" in result.error
        assert "Network error" in result.error

    @respx.mock
    def test_get_jwks_json_decode_error(self):
        # Mock response with valid Content-Type but invalid JSON body
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                content=b"invalid json{",
                headers={"Content-Type": "application/json"},
            )
        )

        request = JwksRequest(address=url)
        result = get_jwks(request)

        assert result.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = result.keys
        assert result.error is not None
        assert "Unhandled exception during JWKS request" in result.error


_SIGNING_KEY = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "signing",
    "n": "example_n",
    "e": "AQAB",
}
_UNSUPPORTED_CURVE_KEY = {
    "kty": "EC",
    "use": "sig",
    "kid": "unsupported-curve",
    "crv": "P-9999",
    "x": "example_x",
    "y": "example_y",
}


class TestGetJwksUnsupportedKeys:
    """RFC 7517 §5: a JWK Set member the client cannot use is ignored.

    The hosted OpenID conformance suite publishes an EC key on curve
    ``P-9999`` next to its real signing key. Rejecting the whole set over it
    made every ID token unverifiable, so the happy path failed and every
    negative test "passed" for the wrong reason.
    """

    @respx.mock
    def test_unsupported_key_is_ignored(self):
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_UNSUPPORTED_CURVE_KEY, _SIGNING_KEY]},
            )
        )

        result = get_jwks(JwksRequest(address=url))

        assert result.is_successful is True
        assert result.keys == [jwks_from_dict(_SIGNING_KEY)]

    @respx.mock
    def test_shared_unusable_keys_fixture(self):
        """JWKS-008 against the fixture Go and Rust also run."""
        fixture = next(
            (
                parent / "spec" / "test-fixtures" / "jwks" / "unusable-keys.json"
                for parent in Path(__file__).resolve().parents
                if (parent / "spec" / "test-fixtures" / "jwks").is_dir()
            ),
            None,
        )
        assert fixture is not None, "spec/test-fixtures/jwks not found"
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json=json.loads(fixture.read_text()))
        )

        result = get_jwks(JwksRequest(address=url))

        assert result.is_successful is True
        assert result.keys is not None
        kids = {key.kid for key in result.keys}
        assert "rsa-sig-key" in kids
        assert "unusable-rsa-missing-n" not in kids
        assert "unusable-ec-unknown-crv-key" not in kids

    @respx.mock
    def test_set_with_no_usable_key_fails(self):
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_UNSUPPORTED_CURVE_KEY]},
            )
        )

        result = get_jwks(JwksRequest(address=url))

        assert result.is_successful is False
        assert result.error is not None
        assert "Unsupported curve: P-9999" in result.error


class TestGetJwksSchemeValidation:
    """get_jwks() must reject non-HTTP(S) schemes before issuing a request.

    Regression coverage for #380: prior to scheme pre-flight, calling
    get_jwks() with ftp://, file://, javascript:, etc. would either hit
    the HTTP client (SSRF surface) or fail with an opaque error. The
    public API now mirrors discovery's pre-flight check.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://example.com/jwks",
            "file:///etc/passwd",
            "data:application/json,{}",
            "javascript:alert(1)",
        ],
    )
    @respx.mock(assert_all_called=False)
    def test_rejects_non_http_schemes(self, url):
        # respx.mock with assert_all_called=False intercepts every network
        # call. The pre-flight check must reject the URL before any HTTP
        # request, so there's nothing for respx to route — the absence of
        # an unhandled-call error confirms no network egress happened.
        result = get_jwks(JwksRequest(address=url))

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid JWKS endpoint URL" in result.error

    @respx.mock
    def test_https_is_accepted(self):
        url = "https://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"keys": []}),
        )
        result = get_jwks(JwksRequest(address=url))
        assert result.is_successful is True

    @respx.mock(assert_all_called=False)
    def test_http_rejected_under_default_policy(self):
        # Default DiscoveryPolicy requires HTTPS off loopback. example.com is
        # not loopback, so http:// must be rejected before any request goes out.
        url = "http://example.com/jwks"
        route = respx.get(url)
        result = get_jwks(JwksRequest(address=url))

        assert result.is_successful is False
        assert result.error is not None
        assert "HTTPS is required" in result.error
        assert route.call_count == 0

    @respx.mock
    def test_http_loopback_allowed_under_default_policy(self):
        url = "http://127.0.0.1:8080/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"keys": []}),
        )
        result = get_jwks(JwksRequest(address=url))
        assert result.is_successful is True

    @respx.mock
    def test_http_allowed_when_policy_disables_require_https(self):
        url = "http://example.com/jwks"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"keys": []}),
        )
        policy = DiscoveryPolicy(require_https=False)
        result = get_jwks(JwksRequest(address=url, policy=policy))
        assert result.is_successful is True
