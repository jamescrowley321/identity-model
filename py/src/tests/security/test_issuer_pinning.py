"""Fail-closed tests for multi-tenant issuer pinning (SC2 / Epic 16 R.9).

Audit RT-SPOOF-F1: the library validated the token's ``iss`` against whatever
discovery document the caller pointed at, with no approved-issuer allowlist. A
caller that resolves discovery from the untrusted token's ``iss`` (the idiomatic
multi-tenant pattern) would therefore accept a validly-signed token from an
attacker's own tenant. ``allowed_issuers`` pins the approved set and is enforced
before the discovery result is trusted.

Each test fails if the control is reverted:
* ``decode_with_config`` (the shared chokepoint for every path) rejects an
  effective issuer outside the allowlist;
* ``build_resolved_config`` propagates ``allowed_issuers`` — without this the
  discovery/retry paths (which validate via the resolved config) would silently
  skip the check;
* the ``_enforce_allowed_issuers`` logic fails closed on the edge cases.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

from py_identity_model.core import token_validation_logic
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import (
    _enforce_allowed_issuers,
    build_resolved_config,
    decode_with_config,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    InvalidIssuerException,
)


_LEGIT = "https://api.descope.com/v1/apps/LEGIT"
_ATTACKER = "https://api.descope.com/v1/apps/ATTACKER"
_LEEWAY_SENTINEL = 42.0


class TestChokepointRejectsUnapprovedIssuer:
    def test_attacker_tenant_issuer_rejected_before_decode(self):
        # The exact multi-tenant attack: discovery resolved to the attacker's own
        # tenant issuer. Even with a well-formed key/alg, pinning rejects it
        # before the token is decoded/trusted.
        cfg = TokenValidationConfig(
            perform_disco=True,
            key={"kty": "RSA"},
            algorithms=["RS256"],
            allowed_issuers=[_LEGIT],
        )
        with pytest.raises(
            InvalidIssuerException, match="not in the configured allowed_issuers"
        ):
            decode_with_config("a.b.c", cfg, issuer=_ATTACKER)

    def test_default_no_allowlist_does_not_pin(self):
        # OPT-IN: with allowed_issuers unset (the default), discovery stays
        # authoritative — no pinning. Decode proceeds past the (absent) issuer
        # check and fails downstream on the dummy token/key for an unrelated
        # reason — never with InvalidIssuerException. Locks in that this control
        # does not change default behaviour.
        cfg = TokenValidationConfig(
            perform_disco=True, key={"kty": "RSA"}, algorithms=["RS256"]
        )
        # The flow reaches decode (past the skipped pin) and fails there building
        # PyJWK from the dummy key — a jwt InvalidKeyError, NOT the
        # InvalidIssuerException pinning would raise. If pinning were not opt-in,
        # InvalidIssuerException would be raised first and this would fail.
        with pytest.raises(pyjwt.InvalidKeyError):
            decode_with_config("a.b.c", cfg, issuer=_ATTACKER)


class TestBuildResolvedConfigCopiesAllFields:
    """``build_resolved_config`` sets key/algorithms from the resolved JWK and
    copies every other field from the original. A dropped/altered field would let
    the disco/retry paths validate under the wrong config — most dangerously a
    silently-lost ``allowed_issuers`` (pin skipped). Pins each field explicitly."""

    def test_all_fields_propagated(self):
        def _cv(_claims: dict) -> bool:
            return True

        original = TokenValidationConfig(
            perform_disco=True,
            key={"orig": "unused"},
            audience="aud-sentinel",
            algorithms=["RS512", "ES256"],  # must be narrowed to [alg]
            issuer="iss-sentinel",
            subject="sub-sentinel",
            options={"verify_aud": False},
            claims_validator=_cv,
            require_https=False,
            leeway=_LEEWAY_SENTINEL,
            allowed_issuers=[_LEGIT],
        )
        resolved = build_resolved_config(original, {"resolved": "key"}, "ES256")
        # From the resolver arguments:
        assert resolved.key == {"resolved": "key"}
        assert resolved.algorithms == ["ES256"]
        # Copied from the original (distinct sentinels catch a field swap/drop):
        assert resolved.perform_disco is True
        assert resolved.audience == "aud-sentinel"
        assert resolved.issuer == "iss-sentinel"
        assert resolved.subject == "sub-sentinel"
        assert resolved.options == {"verify_aud": False}
        assert resolved.claims_validator is _cv
        assert resolved.require_https is False
        assert resolved.leeway == _LEEWAY_SENTINEL
        assert resolved.allowed_issuers == [_LEGIT]


class TestEnforceAllowedIssuers:
    def test_allowed_single_issuer_passes(self):
        assert _enforce_allowed_issuers(_LEGIT, [_LEGIT]) is None

    def test_all_of_a_list_allowed_passes(self):
        other = "https://api.descope.com/v1/apps/LEGIT2"
        assert _enforce_allowed_issuers([_LEGIT, other], [_LEGIT, other]) is None

    def test_disallowed_single_issuer_rejected_full_contract(self):
        with pytest.raises(InvalidIssuerException) as exc_info:
            _enforce_allowed_issuers(_ATTACKER, [_LEGIT])
        exc = exc_info.value
        assert exc.message == (
            f"Issuer '{_ATTACKER}' is not in the configured allowed_issuers"
        )
        assert exc.details == {"issuer": _ATTACKER, "allowed_issuers": [_LEGIT]}

    def test_list_with_one_disallowed_names_the_bad_issuer(self):
        with pytest.raises(InvalidIssuerException) as exc_info:
            _enforce_allowed_issuers([_LEGIT, _ATTACKER], [_LEGIT])
        exc = exc_info.value
        assert exc.message == (
            f"Issuer '{_ATTACKER}' is not in the configured allowed_issuers"
        )
        assert exc.details == {"issuer": _ATTACKER, "allowed_issuers": [_LEGIT]}

    @pytest.mark.parametrize("unresolvable", [None, []])
    def test_unresolvable_issuer_fails_closed_full_contract(self, unresolvable):
        # allowed_issuers configured but nothing resolved to check -> reject.
        with pytest.raises(InvalidIssuerException) as exc_info:
            _enforce_allowed_issuers(unresolvable, [_LEGIT])
        exc = exc_info.value
        assert exc.message == (
            "allowed_issuers is configured but no issuer was resolved to check "
            "against; refusing to validate without a pinned issuer"
        )
        assert exc.details == {"allowed_issuers": [_LEGIT]}

    def test_empty_string_issuer_is_treated_as_disallowed_not_unresolved(self):
        # "" is a resolved-but-bogus issuer, not an absent one: it must be
        # rejected as disallowed (pins the isinstance-str branch).
        with pytest.raises(InvalidIssuerException) as exc_info:
            _enforce_allowed_issuers("", [_LEGIT])
        assert exc_info.value.details == {"issuer": "", "allowed_issuers": [_LEGIT]}

    def test_details_allowed_issuers_is_sorted(self):
        with pytest.raises(InvalidIssuerException) as exc_info:
            _enforce_allowed_issuers(_ATTACKER, ["z-iss", "a-iss"])
        assert exc_info.value.details["allowed_issuers"] == ["a-iss", "z-iss"]


class TestDecodeWithConfigChokepoint:
    """Pins the decode chokepoint that SC2 modified: the key/algorithms guard, the
    opt-in pin (effective-issuer selection), and the pass-through to
    ``decode_and_validate_jwt``."""

    def test_missing_key_raises_typed_configuration_exception(self):
        cfg = TokenValidationConfig(
            perform_disco=True, algorithms=["RS256"]
        )  # key unset
        with pytest.raises(ConfigurationException) as exc_info:
            decode_with_config("a.b.c", cfg)
        assert exc_info.value.message == (
            "Token validation configuration must have key and algorithms set"
        )

    def test_missing_algorithms_raises_typed_configuration_exception(self):
        cfg = TokenValidationConfig(
            perform_disco=True, key={"kty": "oct", "k": "AA"}
        )  # algorithms unset
        with pytest.raises(ConfigurationException):
            decode_with_config("a.b.c", cfg)

    def test_pin_uses_config_issuer_when_no_discovery_override(self, monkeypatch):
        # issuer arg None -> the effective issuer for the pin is config.issuer; a
        # disallowed config.issuer must be rejected *before* decode runs.
        cfg = TokenValidationConfig(
            perform_disco=True,
            key={"kty": "oct", "k": "AA"},
            algorithms=["HS256"],
            issuer=_ATTACKER,
            allowed_issuers=[_LEGIT],
        )
        calls: list = []
        monkeypatch.setattr(
            token_validation_logic,
            "decode_and_validate_jwt",
            lambda **kwargs: calls.append(kwargs) or {},
        )
        with pytest.raises(InvalidIssuerException):
            decode_with_config("a.b.c", cfg, issuer=None)
        assert calls == []  # rejected before decode

    def test_decode_receives_every_field_and_discovery_issuer_wins(self, monkeypatch):
        override = "https://disco/OVERRIDE"
        cfg = TokenValidationConfig(
            perform_disco=True,
            key={"kty": "oct", "k": "AA"},
            algorithms=["HS256"],
            audience="aud-sentinel",
            issuer=_LEGIT,
            subject="sub-sentinel",
            options={"verify_aud": False},
            leeway=17.0,
            allowed_issuers=[_LEGIT, override],
        )
        captured: dict = {}
        monkeypatch.setattr(
            token_validation_logic,
            "decode_and_validate_jwt",
            lambda **kwargs: captured.update(kwargs) or {"ok": True},
        )
        result = decode_with_config("a.b.c", cfg, issuer=override)
        assert result == {"ok": True}
        assert captured == {
            "jwt": "a.b.c",
            "key": {"kty": "oct", "k": "AA"},
            "algorithms": ["HS256"],
            "audience": "aud-sentinel",
            "issuer": override,  # discovery override wins over config.issuer
            "options": {"verify_aud": False},
            "leeway": 17.0,
            "subject": "sub-sentinel",
        }

    def test_multi_issuer_list_with_discovery_override_warns(self, monkeypatch):
        cfg = TokenValidationConfig(
            perform_disco=True,
            key={"kty": "oct", "k": "AA"},
            algorithms=["HS256"],
            issuer=["iss-a", "iss-b"],  # a configured multi-issuer list
        )
        warnings: list = []
        monkeypatch.setattr(
            token_validation_logic,
            "decode_and_validate_jwt",
            lambda **_kwargs: {},
        )
        monkeypatch.setattr(
            token_validation_logic.logger,
            "warning",
            lambda msg, *_args: warnings.append(msg),
        )
        decode_with_config("a.b.c", cfg, issuer="https://disco/OVERRIDE")
        assert warnings == [
            "Discovery issuer overrides configured multi-issuer list; "
            "multi-issuer is not supported in discovery mode"
        ]

    def test_no_warning_without_discovery_override(self, monkeypatch):
        # No discovery override (issuer arg None) -> the multi-issuer warning must
        # not fire even with a configured list (pins the `issuer is not None` half).
        cfg = TokenValidationConfig(
            perform_disco=True,
            key={"kty": "oct", "k": "AA"},
            algorithms=["HS256"],
            issuer=["iss-a", "iss-b"],
        )
        warnings: list = []
        monkeypatch.setattr(
            token_validation_logic,
            "decode_and_validate_jwt",
            lambda **_kwargs: {},
        )
        monkeypatch.setattr(
            token_validation_logic.logger,
            "warning",
            lambda msg, *_args: warnings.append(msg),
        )
        decode_with_config("a.b.c", cfg, issuer=None)
        assert warnings == []
