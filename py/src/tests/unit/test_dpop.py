"""Unit tests for DPoP (RFC 9449) utilities."""

from base64 import urlsafe_b64decode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt as pyjwt
import pytest

from py_identity_model.core.dpop import (
    build_dpop_headers,
    compute_ath,
    create_dpop_proof,
    generate_dpop_key,
)


# RFC 8032 §5.1.5: an Ed25519 public key is 32 octets.
ED25519_PUBLIC_KEY_BYTES = 32


@pytest.mark.unit
class TestDPoPKeyGeneration:
    def test_es256_default(self):
        key = generate_dpop_key()
        assert key.algorithm == "ES256"

    def test_rs256(self):
        key = generate_dpop_key("RS256")
        assert key.algorithm == "RS256"

    def test_es384(self):
        key = generate_dpop_key("ES384")
        assert key.algorithm == "ES384"
        jwk = key.public_jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-384"

    def test_es512(self):
        key = generate_dpop_key("ES512")
        assert key.algorithm == "ES512"
        jwk = key.public_jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-521"

    def test_ps256(self):
        key = generate_dpop_key("PS256")
        assert key.algorithm == "PS256"
        assert set(key.public_jwk) == {"kty", "n", "e"}
        assert key.public_jwk["kty"] == "RSA"

    def test_eddsa_okp_jwk(self):
        """RFC 8037 §2: an Ed25519 public key is an OKP JWK with crv and x."""
        key = generate_dpop_key("EdDSA")
        assert key.algorithm == "EdDSA"
        jwk = key.public_jwk
        assert set(jwk) == {"kty", "crv", "x"}
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert len(urlsafe_b64decode(jwk["x"] + "=")) == ED25519_PUBLIC_KEY_BYTES

    def test_eddsa_thumbprint_rfc8037_vector(self):
        """RFC 8037 Appendix A.1/A.3: the Ed25519 key's RFC 7638 thumbprint."""
        d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        key = generate_dpop_key("EdDSA")
        key._private_key = Ed25519PrivateKey.from_private_bytes(  # type: ignore[assignment]
            urlsafe_b64decode(d + "=")
        )
        assert key.public_jwk == {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }
        assert key.jwk_thumbprint == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

    def test_unsupported_algorithm(self):
        with pytest.raises(ValueError, match="Unsupported"):
            generate_dpop_key("HS256")

    def test_public_jwk_ec(self):
        key = generate_dpop_key("ES256")
        jwk = key.public_jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_public_jwk_rsa(self):
        key = generate_dpop_key("RS256")
        jwk = key.public_jwk
        assert jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk

    def test_jwk_thumbprint_deterministic(self):
        key = generate_dpop_key()
        t1 = key.jwk_thumbprint
        t2 = key.jwk_thumbprint
        assert t1 == t2

    def test_jwk_thumbprint_unique_per_key(self):
        k1 = generate_dpop_key()
        k2 = generate_dpop_key()
        assert k1.jwk_thumbprint != k2.jwk_thumbprint

    def test_private_key_pem(self):
        key = generate_dpop_key()
        pem = key.private_key_pem
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_rsa_jwk_thumbprint_deterministic(self):
        """RSA thumbprint uses different code path (e, kty, n members)."""
        key = generate_dpop_key("RS256")
        t1 = key.jwk_thumbprint
        t2 = key.jwk_thumbprint
        assert t1 == t2

    def test_rsa_jwk_thumbprint_unique_per_key(self):
        k1 = generate_dpop_key("RS256")
        k2 = generate_dpop_key("RS256")
        assert k1.jwk_thumbprint != k2.jwk_thumbprint


@pytest.mark.unit
class TestDPoPProofCreation:
    def test_basic_proof(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(key, "POST", "https://auth.example.com/token")

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"
        assert decoded["htu"] == "https://auth.example.com/token"
        assert "jti" in decoded
        assert "iat" in decoded

    def test_proof_header(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(key, "GET", "https://api.example.com/resource")

        header = pyjwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert "jwk" in header
        assert header["jwk"]["kty"] == "EC"

    def test_proof_with_access_token(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key,
            "GET",
            "https://api.example.com/resource",
            access_token="my_access_token",
        )

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert "ath" in decoded
        assert decoded["ath"] == compute_ath("my_access_token")

    def test_proof_with_nonce(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key,
            "POST",
            "https://auth.example.com/token",
            nonce="server_nonce_123",
        )

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["nonce"] == "server_nonce_123"

    def test_proof_method_uppercased(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(key, "post", "https://auth.example.com/token")

        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"

    def test_unique_jti(self):
        key = generate_dpop_key()
        p1 = create_dpop_proof(key, "POST", "https://auth.example.com/token")
        p2 = create_dpop_proof(key, "POST", "https://auth.example.com/token")

        d1 = pyjwt.decode(p1, options={"verify_signature": False})
        d2 = pyjwt.decode(p2, options={"verify_signature": False})
        assert d1["jti"] != d2["jti"]

    def test_htu_strips_query_and_fragment(self):
        """RFC 9449 §4.2: htu must not include query or fragment."""
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key,
            "GET",
            "https://api.example.com/resource?foo=bar#frag",
        )
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htu"] == "https://api.example.com/resource"

    def test_htu_preserves_path_without_query(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(key, "POST", "https://auth.example.com/token")
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htu"] == "https://auth.example.com/token"

    def test_empty_method_raises(self):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="method must not be empty"):
            create_dpop_proof(key, "", "https://example.com")

    def test_whitespace_method_raises(self):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="method must not be empty"):
            create_dpop_proof(key, "   ", "https://example.com")

    def test_empty_uri_raises(self):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="uri must not be empty"):
            create_dpop_proof(key, "GET", "")

    def test_relative_uri_raises(self):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="uri must be an absolute HTTP URI"):
            create_dpop_proof(key, "GET", "/relative/path")

    def test_schemeless_uri_raises(self):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="uri must be an absolute HTTP URI"):
            create_dpop_proof(key, "GET", "just-a-path")

    def test_htu_preserves_path_params(self):
        """RFC 9449 §4.2: only strip query and fragment, not path params."""
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key, "GET", "https://api.example.com/path;type=a?q=1#frag"
        )
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert decoded["htu"] == "https://api.example.com/path;type=a"

    def test_empty_string_access_token_skips_ath(self):
        """access_token='' should be treated as absent, not crash."""
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key, "POST", "https://auth.example.com/token", access_token=""
        )
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert "ath" not in decoded

    def test_empty_string_nonce_excluded(self):
        """nonce='' should be treated as absent."""
        key = generate_dpop_key()
        proof = create_dpop_proof(
            key,
            "POST",
            "https://auth.example.com/token",
            nonce="",
        )
        decoded = pyjwt.decode(proof, options={"verify_signature": False})
        assert "nonce" not in decoded

    @pytest.mark.parametrize(
        "algorithm", ["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"]
    )
    def test_proof_signature_verified(self, algorithm: str):
        """M2: Verify that the proof JWT has a valid signature."""
        key = generate_dpop_key(algorithm)
        proof = create_dpop_proof(key, "POST", "https://auth.example.com/token")

        # Build a PyJWK from the embedded JWK header for verification
        header = pyjwt.get_unverified_header(proof)
        # The jwk carries no "alg"; PyJWK would assume RS256 for any RSA key.
        jwk_key = pyjwt.PyJWK(header["jwk"], algorithm=header["alg"])

        # Decode WITH signature verification — this is the critical test
        decoded = pyjwt.decode(
            proof,
            jwk_key,
            algorithms=[algorithm],
            options={"verify_aud": False},
        )
        assert decoded["htm"] == "POST"
        assert decoded["htu"] == "https://auth.example.com/token"


@pytest.mark.unit
class TestComputeAth:
    def test_deterministic(self):
        assert compute_ath("token123") == compute_ath("token123")

    def test_different_tokens(self):
        assert compute_ath("token1") != compute_ath("token2")

    def test_base64url_no_padding(self):
        ath = compute_ath("test")
        assert "=" not in ath

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="access_token must not be empty"):
            compute_ath("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="access_token must not be empty"):
            compute_ath("   ")

    def test_non_ascii_raises(self):
        with pytest.raises(ValueError, match="ASCII"):
            compute_ath("tök\u00e9n")


@pytest.mark.unit
class TestBuildDPoPHeaders:
    def test_token_request_headers(self):
        headers = build_dpop_headers("proof_jwt")
        assert headers["DPoP"] == "proof_jwt"
        assert "Authorization" not in headers

    def test_resource_request_headers(self):
        headers = build_dpop_headers("proof_jwt", "my_token")
        assert headers["DPoP"] == "proof_jwt"
        assert headers["Authorization"] == "DPoP my_token"

    def test_empty_string_access_token_no_auth_header(self):
        """S2: Empty string should not produce malformed Authorization header."""
        headers = build_dpop_headers("proof_jwt", "")
        assert headers["DPoP"] == "proof_jwt"
        assert "Authorization" not in headers

    def test_none_access_token_no_auth_header(self):
        headers = build_dpop_headers("proof_jwt", None)
        assert "Authorization" not in headers

    def test_empty_proof_raises(self):
        with pytest.raises(ValueError, match="proof must not be empty"):
            build_dpop_headers("")

    def test_whitespace_proof_raises(self):
        with pytest.raises(ValueError, match="proof must not be empty"):
            build_dpop_headers("   ")

    def test_whitespace_access_token_no_auth_header(self):
        """Whitespace-only access_token should not produce malformed header."""
        headers = build_dpop_headers("proof_jwt", "   ")
        assert "Authorization" not in headers
