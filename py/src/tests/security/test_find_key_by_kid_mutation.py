"""Fail-closed behavioural pins for ``find_key_by_kid`` (mutation gate).

``find_key_by_kid`` is the JWKS key-selection control on the token-validation
path: it chooses which public key verifies a token and which algorithm is used.
The existing algorithm-confusion tests cover the alg-consistency + alg-resolution
lines; this module pins the remaining branches — empty JWKS, kid filtering /
no-match, and the no-``kid`` signing-key selection (use filter, kty filter,
single vs. ambiguous) — with exact assertions on return values and on the raised
exception's message / ``details`` / ``token_part`` so that mutating any of them
is caught (Epic 19 mutation gate).
"""

import logging

import pytest

from py_identity_model.core.models import JsonWebKey
from py_identity_model.core.parsers import find_key_by_kid
from py_identity_model.exceptions import TokenValidationException


def _rsa(kid=None, alg=None, use=None):
    return JsonWebKey(kty="RSA", kid=kid, alg=alg, use=use, n="n", e="e")


def _ec(kid=None, alg=None, use=None):
    return JsonWebKey(kty="EC", kid=kid, alg=alg, use=use, crv="P-256", x="x", y="y")


class TestEmptyKeys:
    def test_empty_keys_raises(self):
        with pytest.raises(TokenValidationException) as exc:
            find_key_by_kid("k1", [])
        assert exc.value.message == "No keys available in JWKS response"


class TestKidNoMatch:
    def test_no_matching_kid_raises_with_details(self):
        keys = [_rsa(kid="a", alg="RS256"), _rsa(kid="b", alg="RS256")]
        with pytest.raises(TokenValidationException) as exc:
            find_key_by_kid("missing", keys, jwt_alg="RS256")
        assert exc.value.message == "No matching kid found: missing"
        assert exc.value.token_part == "header"
        assert exc.value.details["kid"] == "missing"
        assert exc.value.details["available_kids"] == ["a", "b"]

    def test_available_kids_excludes_keyless_entries(self):
        keys = [_rsa(kid=None, alg="RS256"), _rsa(kid="only", alg="RS256")]
        with pytest.raises(TokenValidationException) as exc:
            find_key_by_kid("x", keys, jwt_alg="RS256")
        assert exc.value.details["available_kids"] == ["only"]


class TestKidSelection:
    def test_selects_the_kid_matched_key_among_many(self):
        target = _rsa(kid="b", alg="RS384")
        keys = [_rsa(kid="a", alg="RS256"), target, _rsa(kid="c", alg="RS512")]
        key_dict, alg = find_key_by_kid("b", keys, jwt_alg="RS384")
        assert key_dict == target.as_dict()
        assert key_dict["kid"] == "b"
        assert alg == "RS384"

    def test_declared_key_alg_used_when_header_alg_absent(self):
        # Distinguishes "prefer key.alg" from the RS256 default: an EC key that
        # declares ES256 with no JWT header alg must resolve to ES256, not RS256.
        keys = [_ec(kid="k1", alg="ES256")]
        _key_dict, alg = find_key_by_kid("k1", keys, jwt_alg=None)
        assert alg == "ES256"


class TestNoKidSelection:
    def test_single_key_returned_and_warns(self, caplog):
        keys = [_rsa(kid="only", alg="RS256")]
        with caplog.at_level(logging.WARNING):
            key_dict, alg = find_key_by_kid(None, keys, jwt_alg="RS256")
        assert key_dict["kid"] == "only"
        assert alg == "RS256"
        # Exact warning text (kills message-text mutants of the log line).
        assert any(
            r.getMessage()
            == "JWT has no kid header; using the single signing key from JWKS"
            for r in caplog.records
        )

    def test_filters_by_use_sig(self):
        # Two RSA keys; only the sig-use one must be selected.
        keys = [
            _rsa(kid="enc", alg="RS256", use="enc"),
            _rsa(kid="sig", alg="RS256", use="sig"),
        ]
        key_dict, _alg = find_key_by_kid(None, keys, jwt_alg="RS256")
        assert key_dict["kid"] == "sig"

    def test_falls_back_to_all_keys_when_none_marked_sig(self):
        keys = [_rsa(kid="enc-only", alg="RS256", use="enc")]
        key_dict, _alg = find_key_by_kid(None, keys, jwt_alg="RS256")
        assert key_dict["kid"] == "enc-only"

    def test_multiple_keys_disambiguated_by_alg_kty(self):
        keys = [_rsa(kid="r", use="sig"), _ec(kid="e", use="sig")]
        key_dict, alg = find_key_by_kid(None, keys, jwt_alg="ES256")
        assert key_dict["kid"] == "e"
        assert alg == "ES256"

    def test_ambiguous_same_kty_raises_with_details(self):
        keys = [
            _rsa(kid="a", alg="RS256", use="sig"),
            _rsa(kid="b", alg="RS256", use="sig"),
        ]
        with pytest.raises(TokenValidationException) as exc:
            find_key_by_kid(None, keys, jwt_alg="RS256")
        assert exc.value.message == (
            "JWT has no kid header and JWKS contains multiple signing keys; "
            "cannot determine which key to use"
        )
        assert exc.value.token_part == "header"
        assert exc.value.details["available_kids"] == ["a", "b"]
        assert exc.value.details["key_count"] == len(keys)

    def test_single_key_no_alg_no_header_defaults_to_rs256(self):
        # No-kid branch: an alg-less single key with no JWT header alg resolves
        # to exactly "RS256" (the alg is handed to signature verification, so the
        # value — and its case — is a control, not cosmetic).
        keys = [_rsa(kid="only", use="sig")]
        _key_dict, alg = find_key_by_kid(None, keys, jwt_alg=None)
        assert alg == "RS256"

    def test_ambiguous_without_alg_raises(self):
        keys = [_rsa(kid="a", alg="RS256"), _rsa(kid="b", alg="RS256")]
        with pytest.raises(TokenValidationException) as exc:
            find_key_by_kid(None, keys, jwt_alg=None)
        assert "multiple signing keys" in exc.value.message
        assert exc.value.details["key_count"] == len(keys)

    def test_ambiguous_available_kids_excludes_keyless(self):
        keys = [_rsa(alg="RS256", use="sig"), _rsa(alg="RS256", use="sig")]
        with pytest.raises(TokenValidationException) as exc:
            find_key_by_kid(None, keys, jwt_alg="RS256")
        assert exc.value.details["available_kids"] == []
        assert exc.value.details["key_count"] == len(keys)
