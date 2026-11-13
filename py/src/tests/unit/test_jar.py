"""Unit tests for JWT Secured Authorization Request (JAR, RFC 9101)."""

from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
import jwt as pyjwt
import pytest

from py_identity_model import generate_pkce_pair
from py_identity_model.core.jar import (
    build_jar_authorization_url,
    create_request_object,
)
from py_identity_model.exceptions import InvalidArgumentError


# Expected JAR token values
JAR_LIFETIME_SECONDS = 600
UUID_STRING_LENGTH = 36


def _ec_private_key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _rsa_private_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


AUTH_ENDPOINT = "https://auth.example.com/authorize"


@pytest.mark.unit
class TestCreateRequestObject:
    def test_basic_ec256(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="my-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "my-app"
        assert decoded["aud"] == "https://auth.example.com"
        assert decoded["client_id"] == "my-app"
        assert decoded["redirect_uri"] == "https://app.com/cb"
        assert decoded["scope"] == "openid"
        assert decoded["response_type"] == "code"
        assert "iat" in decoded
        assert "nbf" in decoded
        assert "exp" in decoded

    def test_basic_rsa256(self):
        pem = _rsa_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="RS256",
            client_id="rsa-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "rsa-app"

    def test_with_pkce(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            code_challenge="abc123",
            code_challenge_method="S256",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["code_challenge"] == "abc123"
        assert decoded["code_challenge_method"] == "S256"

    def test_with_state_and_nonce(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            state="csrf-value",
            nonce="nonce-value",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["state"] == "csrf-value"
        assert decoded["nonce"] == "nonce-value"

    def test_extra_claims(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            acr_values="urn:mace:incommon:iap:silver",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["acr_values"] == "urn:mace:incommon:iap:silver"

    def test_custom_scope_and_response_type(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            scope="openid profile email",
            response_type="code id_token",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["scope"] == "openid profile email"
        assert decoded["response_type"] == "code id_token"

    def test_lifetime(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            lifetime=600,
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["exp"] - decoded["iat"] == JAR_LIFETIME_SECONDS

    def test_unsupported_algorithm(self):
        pem = _ec_private_key_pem()
        with pytest.raises(InvalidArgumentError, match="Unsupported JAR algorithm"):
            create_request_object(
                private_key=pem,
                algorithm="HS256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
            )

    def test_reserved_claim_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="reserved claims"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                iss="evil-issuer",
            )

    def test_reserved_claim_exp_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="reserved claims"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                exp="99999999999",
            )

    def test_kid_included_in_header(self):
        """M2: kid parameter appears in JWT header for key lookup."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            kid="my-key-id-123",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["kid"] == "my-key-id-123"

    def test_kid_absent_when_not_provided(self):
        """M2: kid is not in header when omitted."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert "kid" not in header

    def test_jti_claim_present(self):
        """S2: jti claim included by default for replay protection."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert "jti" in decoded
        assert len(decoded["jti"]) == UUID_STRING_LENGTH  # UUID format

    def test_jti_unique_per_call(self):
        """S2: each request object gets a unique jti."""
        pem = _ec_private_key_pem()
        kwargs = {
            "private_key": pem,
            "algorithm": "ES256",
            "client_id": "app",
            "audience": "https://auth.example.com",
            "redirect_uri": "https://app.com/cb",
        }
        t1 = pyjwt.decode(
            create_request_object(**kwargs),
            options={"verify_signature": False},
        )
        t2 = pyjwt.decode(
            create_request_object(**kwargs),
            options={"verify_signature": False},
        )
        assert t1["jti"] != t2["jti"]

    def test_pkce_requires_both_challenge_and_method(self):
        """S3: code_challenge without code_challenge_method raises ValueError."""
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match=r"code_challenge.*both"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                code_challenge="abc",
            )

    def test_pkce_requires_both_method_and_challenge(self):
        """S3: code_challenge_method without code_challenge raises ValueError."""
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match=r"code_challenge.*both"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                code_challenge_method="S256",
            )

    def test_typ_header_oauth_authz_req_jwt(self):
        """Security: typ header prevents JWT type confusion per RFC 9101 §10.2."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["typ"] == "oauth-authz-req+jwt"

    def test_typ_header_present_with_kid(self):
        """typ header is set even when kid is provided."""
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            kid="key-1",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["typ"] == "oauth-authz-req+jwt"
        assert header["kid"] == "key-1"

    def test_empty_client_id_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="client_id must not be empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
            )

    def test_empty_audience_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="audience must not be empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="",
                redirect_uri="https://app.com/cb",
            )

    def test_empty_redirect_uri_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="redirect_uri must not be empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="",
            )

    def test_empty_private_key_rejected(self):
        with pytest.raises(ValueError, match="private_key must not be empty"):
            create_request_object(
                private_key=b"",
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
            )

    def test_empty_response_type_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="response_type must not be empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                response_type="",
            )

    def test_empty_kid_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="kid must be non-empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                kid="",
            )

    def test_empty_code_challenge_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="code_challenge must be non-empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                code_challenge="",
                code_challenge_method="S256",
            )

    def test_empty_code_challenge_method_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="code_challenge_method must be non-empty"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                code_challenge="abc123",
                code_challenge_method="",
            )

    def test_zero_lifetime_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="lifetime must be positive"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                lifetime=0,
            )

    def test_negative_lifetime_rejected(self):
        pem = _ec_private_key_pem()
        with pytest.raises(ValueError, match="lifetime must be positive"):
            create_request_object(
                private_key=pem,
                algorithm="ES256",
                client_id="app",
                audience="https://auth.example.com",
                redirect_uri="https://app.com/cb",
                lifetime=-10,
            )

    def test_optional_params_omitted_when_none(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert "state" not in decoded
        assert "nonce" not in decoded
        assert "code_challenge" not in decoded
        assert "code_challenge_method" not in decoded

    def test_jwt_header(self):
        pem = _ec_private_key_pem()
        token = create_request_object(
            private_key=pem,
            algorithm="ES256",
            client_id="app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "ES256"
        assert header["typ"] == "oauth-authz-req+jwt"


@pytest.mark.unit
class TestBuildJARAuthorizationUrl:
    def test_basic_url(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT,
            client_id="my-app",
            request_object="eyJ...",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["my-app"]
        assert params["request"] == ["eyJ..."]
        assert "scope" not in params
        assert "response_type" not in params

    def test_with_duplicated_params(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT,
            client_id="my-app",
            request_object="eyJ...",
            scope="openid",
            response_type="code",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["my-app"]
        assert params["request"] == ["eyJ..."]
        assert params["scope"] == ["openid"]
        assert params["response_type"] == ["code"]

    def test_endpoint_with_existing_query(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT + "?foo=bar",
            client_id="my-app",
            request_object="eyJ...",
        )
        assert "?foo=bar&client_id=" in url

    def test_endpoint_with_fragment_containing_question_mark(self):
        """URL separator uses urlparse, not naive '?' string check."""
        url = build_jar_authorization_url(
            authorization_endpoint="https://auth.example.com/authorize#section?ref",
            client_id="app",
            request_object="jwt",
        )
        # Should use '?' since there's no query string, only a fragment
        assert "authorize#section?ref?client_id=" in url

    def test_url_starts_with_endpoint(self):
        url = build_jar_authorization_url(
            authorization_endpoint=AUTH_ENDPOINT,
            client_id="app",
            request_object="jwt",
        )
        assert url.startswith(AUTH_ENDPOINT + "?")


def _ec_key_pair() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def _rsa_key_pair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


@pytest.mark.unit
class TestJARSignatureVerification:
    def test_ec256_signature_verifiable(self):
        """Create request object with EC key and verify signature with public key."""
        priv, pub = _ec_key_pair()
        request_jwt = create_request_object(
            private_key=priv,
            algorithm="ES256",
            client_id="sig-test-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/callback",
            scope="openid profile",
            state="test-state",
        )
        decoded = pyjwt.decode(
            request_jwt,
            pub,
            algorithms=["ES256"],
            audience="https://auth.example.com",
        )
        assert decoded["iss"] == "sig-test-app"
        assert decoded["scope"] == "openid profile"
        assert decoded["state"] == "test-state"

    def test_ps256_signature_verifiable(self):
        """Verify PS256 (RSA-PSS) algorithm produces verifiable signatures."""
        priv, pub = _rsa_key_pair()
        request_jwt = create_request_object(
            private_key=priv,
            algorithm="PS256",
            client_id="ps256-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        decoded = pyjwt.decode(
            request_jwt,
            pub,
            algorithms=["PS256"],
            audience="https://auth.example.com",
        )
        assert decoded["iss"] == "ps256-app"

    def test_jar_with_pkce_signature_verifiable(self):
        """Combine JAR with PKCE and verify the signed JWT."""
        priv, pub = _ec_key_pair()
        _verifier, challenge = generate_pkce_pair()
        request_jwt = create_request_object(
            private_key=priv,
            algorithm="ES256",
            client_id="pkce-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        decoded = pyjwt.decode(
            request_jwt,
            pub,
            algorithms=["ES256"],
            audience="https://auth.example.com",
        )
        assert decoded["code_challenge"] == challenge
        assert decoded["code_challenge_method"] == "S256"

    def test_build_url_jwt_signature_verifiable(self):
        """Build authorization URL and verify the embedded JWT signature."""
        priv, pub = _ec_key_pair()
        request_jwt = create_request_object(
            private_key=priv,
            algorithm="ES256",
            client_id="url-app",
            audience="https://auth.example.com",
            redirect_uri="https://app.com/cb",
        )
        url = build_jar_authorization_url(
            authorization_endpoint="https://auth.example.com/authorize",
            client_id="url-app",
            request_object=request_jwt,
            scope="openid",
            response_type="code",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["url-app"]

        extracted_jwt = params["request"][0]
        decoded = pyjwt.decode(
            extracted_jwt,
            pub,
            algorithms=["ES256"],
            audience="https://auth.example.com",
        )
        assert decoded["client_id"] == "url-app"
        assert decoded["redirect_uri"] == "https://app.com/cb"
