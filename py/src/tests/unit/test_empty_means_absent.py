"""An empty ``client_id``, JWK ``kid`` or JWK ``use`` means the value is absent.

Matches Go and Rust (#992, #1065): ``""`` behaves exactly like a missing
value, and a real value is unaffected. Also covers the relaxed ``key_ops`` /
``use`` acceptance rules from #992.
"""

import base64
import json
import time

import httpx
import pytest
import respx

from py_identity_model.core.id_token_logic import validate_id_token_claims
from py_identity_model.core.models import JsonWebKey, TokenValidationConfig
from py_identity_model.core.parsers import (
    extract_jwt_header_fields,
    extract_kid_from_jwt,
    find_key_by_kid,
    get_public_key_from_jwk,
    is_signing_key,
    jwks_from_dict,
)
from py_identity_model.exceptions import (
    AmbiguousKeyException,
    AzpRequiresClientIdError,
    ConfigurationException,
    KeyNotFoundException,
    UntrustedAudienceException,
)
from py_identity_model.jwks import JwksRequest, get_jwks
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


_CLIENT_ID = "s6BhdRkqt3"
_OTHER_AUD = "other-api"
_NOW = 1_700_000_000
_RSA = {"kty": "RSA", "n": "example_n", "e": "AQAB"}
_RSA_2 = {"kty": "RSA", "n": "other_n", "e": "AQAB"}
_JWKS_URL = "https://example.com/jwks"


def _claims(**overrides) -> dict:
    claims = {
        "iss": "https://op.example.com",
        "sub": "248289761001",
        "aud": _CLIENT_ID,
        "iat": _NOW - 100,
        "exp": _NOW + 3600,
    }
    claims.update(overrides)
    return claims


def _b64(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(header: dict) -> str:
    return f"{_b64(header)}.{_b64({'sub': 'x'})}.sig"


# ---------------------------------------------------------------- client_id


class TestEmptyClientId:
    @pytest.mark.parametrize("client_id", ["", None], ids=["empty", "missing"])
    def test_validate_azp_without_client_id_is_config_error(self, client_id):
        with pytest.raises(AzpRequiresClientIdError):
            validate_id_token_claims(
                _claims(),
                "RS256",
                client_id=client_id,
                trusted_audiences=[_CLIENT_ID],
                validate_azp=True,
                now=_NOW,
            )

    def test_validate_azp_with_real_client_id_runs(self):
        validate_id_token_claims(
            _claims(azp=_CLIENT_ID),
            "RS256",
            client_id=_CLIENT_ID,
            validate_azp=True,
            now=_NOW,
        )

    @pytest.mark.parametrize("client_id", ["", None], ids=["empty", "missing"])
    def test_empty_audience_is_not_trusted_without_client_id(self, client_id):
        with pytest.raises(UntrustedAudienceException) as exc_info:
            validate_id_token_claims(
                _claims(aud=[_OTHER_AUD, ""]),
                "RS256",
                client_id=client_id,
                trusted_audiences=[_OTHER_AUD],
                now=_NOW,
            )
        assert exc_info.value.details == {"untrusted_audiences": [""]}

    def test_real_client_id_is_trusted(self):
        validate_id_token_claims(
            _claims(aud=[_CLIENT_ID, _OTHER_AUD]),
            "RS256",
            client_id=_CLIENT_ID,
            trusted_audiences=[_OTHER_AUD],
            now=_NOW,
        )


# ---------------------------------------------------------------------- kid


class TestEmptyKid:
    @pytest.mark.parametrize(
        ("raw", "expected_kid"),
        [({"kid": ""}, None), ({}, None), ({"kid": "k1"}, "k1")],
        ids=["empty", "missing", "real"],
    )
    def test_jwk_kid(self, raw, expected_kid):
        assert jwks_from_dict({**_RSA, **raw}) == JsonWebKey(
            kty="RSA", n="example_n", e="AQAB", kid=expected_kid
        )

    @pytest.mark.parametrize(
        ("header", "expected_kid"),
        [
            ({"alg": "RS256", "kid": ""}, None),
            ({"alg": "RS256"}, None),
            ({"alg": "RS256", "kid": "k1"}, "k1"),
        ],
        ids=["empty", "missing", "real"],
    )
    def test_header_kid(self, header, expected_kid):
        token = _jwt(header)
        assert extract_kid_from_jwt(token) == expected_kid
        assert extract_jwt_header_fields(token) == (expected_kid, "RS256")

    @pytest.mark.parametrize("kid", ["", None], ids=["empty", "missing"])
    def test_absent_kid_uses_single_signing_key(self, kid):
        key = jwks_from_dict({**_RSA, "kid": "k1"})
        assert find_key_by_kid(kid, [key], "RS256") == (key.as_dict(), "RS256")

    @pytest.mark.parametrize("kid", ["", None], ids=["empty", "missing"])
    def test_absent_kid_with_two_signing_keys_is_ambiguous(self, kid):
        keys = [jwks_from_dict({**_RSA, "kid": ""}), jwks_from_dict(_RSA_2)]
        with pytest.raises(AmbiguousKeyException) as exc_info:
            find_key_by_kid(kid, keys, "RS256")
        assert exc_info.value.details == {"available_kids": [], "key_count": 2}

    @pytest.mark.parametrize("header", [{"kid": ""}, {}], ids=["empty", "missing"])
    def test_deprecated_lookup_treats_empty_kid_as_absent(self, header):
        key = jwks_from_dict({**_RSA, "kid": "k1"})
        token = _jwt({"alg": "RS256", **header})
        with pytest.warns(DeprecationWarning, match="get_public_key_from_jwk"):
            found = get_public_key_from_jwk(token, [key])
        assert found == JsonWebKey(
            kty="RSA", n="example_n", e="AQAB", kid="k1", alg="RS256"
        )

    @respx.mock
    def test_empty_header_kid_validates_without_kid_miss_refresh(self):
        clear_discovery_cache()
        clear_jwks_cache()
        key_dict, pem = generate_rsa_keypair()
        issuer = DISCO_RESPONSE_WITH_JWKS["issuer"]
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get(DISCO_RESPONSE_WITH_JWKS["jwks_uri"]).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )
        claims = {"iss": issuer, "sub": "u1", "exp": int(time.time()) + 300}
        token = sign_jwt(pem, claims, headers={"kid": ""})
        config = TokenValidationConfig(
            perform_disco=True, issuer=issuer, options={"verify_aud": False}
        )
        try:
            assert validate_token(token, config, DISCO_URL) == claims
            assert jwks_route.call_count == 1
        finally:
            clear_discovery_cache()
            clear_jwks_cache()

    def test_real_kid_is_looked_up(self):
        named = jwks_from_dict({**_RSA, "kid": "k1"})
        other = jwks_from_dict({**_RSA_2, "kid": "k2"})
        assert find_key_by_kid("k1", [other, named], "RS256") == (
            named.as_dict(),
            "RS256",
        )

    def test_real_kid_never_matches_an_empty_jwk_kid(self):
        with pytest.raises(KeyNotFoundException) as exc_info:
            find_key_by_kid("k1", [jwks_from_dict({**_RSA, "kid": ""})], "RS256")
        assert exc_info.value.details == {"kid": "k1", "available_kids": []}


# ---------------------------------------------------------------------- use


class TestEmptyUse:
    @pytest.mark.parametrize(
        ("raw", "expected_use", "signing"),
        [
            ({"use": ""}, None, True),
            ({}, None, True),
            ({"use": "sig"}, "sig", True),
            ({"use": "enc"}, "enc", False),
        ],
        ids=["empty", "missing", "sig", "enc"],
    )
    def test_jwk_use(self, raw, expected_use, signing):
        key = jwks_from_dict({**_RSA, **raw})
        assert key == JsonWebKey(kty="RSA", n="example_n", e="AQAB", use=expected_use)
        assert is_signing_key(key) is signing

    def test_use_set_empty_after_construction_is_still_signing(self):
        key = jwks_from_dict(_RSA)
        key.use = ""
        assert is_signing_key(key) is True

    @respx.mock
    def test_jwks_key_with_empty_use_is_kept(self):
        raw = {**_RSA, "kid": "k1", "use": ""}
        respx.get(_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [raw]})
        )
        result = get_jwks(JwksRequest(address=_JWKS_URL))
        assert result.keys == [JsonWebKey(kty="RSA", n="example_n", e="AQAB", kid="k1")]


# ---------------------------------------------------- key_ops / URI use (#992)


class TestRelaxedKeyOpsAndUse:
    @pytest.mark.parametrize(
        "raw",
        [
            {"use": "sig", "key_ops": ["verify"]},
            {"key_ops": ["verify", "x-custom-op"]},
            {"use": "urn:example:use"},
            {"use": "http://example.com/use"},
        ],
        ids=["use-and-key_ops", "unknown-key_ops", "urn-use", "http-uri-use"],
    )
    def test_key_is_accepted(self, raw):
        assert jwks_from_dict({**_RSA, **raw}) == JsonWebKey(
            kty="RSA", n="example_n", e="AQAB", **raw
        )

    @pytest.mark.parametrize(
        ("use", "signing"),
        [("urn:example:use", False), ("enc", False), ("sig", True)],
        ids=["uri", "enc", "sig"],
    )
    def test_only_sig_or_absent_use_signs(self, use, signing):
        key = jwks_from_dict({**_RSA, "use": use, "key_ops": ["verify"]})
        assert is_signing_key(key) is signing

    @pytest.mark.parametrize(
        "key_ops", ["verify", ["verify", 1]], ids=["bare-string", "non-string-op"]
    )
    def test_mistyped_key_ops_rejected(self, key_ops):
        with pytest.raises(ConfigurationException, match="key_ops"):
            jwks_from_dict({**_RSA, "key_ops": key_ops})

    def test_mistyped_use_rejected(self):
        with pytest.raises(ConfigurationException, match="'use'"):
            jwks_from_dict({**_RSA, "use": 1})
