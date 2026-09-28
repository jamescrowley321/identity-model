"""Thin Python executor for the shared /spec conformance vectors (CONS-1.5).

Drives every executable vector in ``spec/vectors/validation.json`` against
py-identity-model's validation API — the same language-neutral vector set the
Go (``go/internal/conformance``) and Rust (``rust/tests/spec_conformance.rs``)
runners execute — so the "build conformance vectors once" constraint holds.

Thin-executor contract: the vectors carry inputs and canonical expected
outcomes; only the mapping of canonical error codes to py-identity-model's
exception types lives here (see ``_assert_canonical_reject``).

Two deliberate deviations from the Go runner, both semantics-preserving:

* **Clock**: PyJWT validates time claims against the real clock and offers no
  injectable ``now``, so time claims (Go-style duration strings) are resolved
  relative to the real current time instead of ``options.now``. The vectors
  are written relative, precisely so this works in every language.
* **Nonce**: py-identity-model validates nonce through its documented custom
  claims-validator extension point (``TokenValidationConfig.claims_validator``
  + ``core.token_validation_logic.validate_claims``), not a dedicated option;
  the executor wires the vector's ``expected_nonce`` through that path.
* **iat presence** (JWT-013): Go/Rust hard-require ``iat`` natively; PIM keeps
  it opt-in (default-off) for backward compatibility, so the executor drives
  PIM into the required behaviour via its ``require`` option. An intentional,
  documented default difference — see the PARITY NOTE in ``_execute``.

Coverage: a case without vectors fails module collection (``_vector_params``),
and ``test_every_vector_case_is_parametrized`` checks every case id is
parametrized.
"""

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as pyjwt
import pytest

from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import validate_claims
from py_identity_model.exceptions import (
    InvalidAudienceException,
    InvalidIssuerException,
    PyIdentityModelException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)


def _find_repo_root() -> Path:
    """Locate the repo root by its ``/spec`` marker rather than a fixed depth.

    The mutation-security gate runs this suite from a mutmut sandbox
    (``py/mutants/``), which inserts a directory level, so a hardcoded
    ``parents[4]`` would resolve to ``py/`` and miss the (un-copied) repo-root
    ``spec/``. Walking up to the marker works in both the normal tree and the
    sandbox.
    """
    marker = Path("spec") / "vectors" / "validation.json"
    for parent in Path(__file__).resolve().parents:
        if (parent / marker).is_file():
            return parent
    # Historical layout fallback: /py at parents[3], repo root at parents[4].
    return Path(__file__).resolve().parents[4]


_REPO_ROOT = _find_repo_root()
_SPEC_FILE = _REPO_ROOT / "spec" / "vectors" / "validation.json"
_FIXTURE_ROOT = _REPO_ROOT / "spec" / "test-fixtures"

_CAPABILITY = json.loads(_SPEC_FILE.read_text())
_CASES = _CAPABILITY["tests"]

_SIGNING_JWK = json.loads(
    (_FIXTURE_ROOT / "validation" / "signing-key.jwk.json").read_text()
)
_PUBLIC_JWKS = json.loads((_FIXTURE_ROOT / "validation" / "jwks.json").read_text())

_TIME_CLAIMS = frozenset({"exp", "nbf", "iat"})

# Go time.ParseDuration subset used by the vectors: optional sign, h/m/s parts.
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(h|m|s)")
_DURATION_FULL = re.compile(r"^-?(?:\d+(?:\.\d+)?(?:h|m|s))+$")
_UNIT_SECONDS = {"h": 3600.0, "m": 60.0, "s": 1.0}


def _parse_go_duration(value: str) -> timedelta:
    if not _DURATION_FULL.match(value):
        raise ValueError(f"unsupported duration string: {value!r}")
    seconds = sum(
        float(amount) * _UNIT_SECONDS[unit]
        for amount, unit in _DURATION_PART.findall(value)
    )
    if value.startswith("-"):
        seconds = -seconds
    return timedelta(seconds=seconds)


def _resolve_claims(claims: dict) -> dict:
    """Convert exp/nbf/iat duration strings into absolute NumericDates.

    Resolved relative to the real current time (see module docstring).
    """
    now = datetime.now(UTC)
    out: dict = {}
    for name, value in claims.items():
        if name in _TIME_CLAIMS:
            out[name] = int((now + _parse_go_duration(value)).timestamp())
        else:
            out[name] = value
    return out


def _mint_token(token_spec: dict) -> str:
    if token_spec.get("static"):
        return (_FIXTURE_ROOT / token_spec["static"]).read_text().strip()

    alg = token_spec.get("alg", "RS256")
    signing_key = token_spec.get("signing_key", "fixture")
    if signing_key == "fixture":
        key = pyjwt.PyJWK(_SIGNING_JWK).key
        kid = token_spec.get("header_kid") or _SIGNING_JWK.get("kid", "test-key-1")
    elif signing_key == "ephemeral":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = token_spec.get("header_kid") or "ephemeral-key"
    else:
        raise ValueError(f"unknown signing_key {signing_key!r}")

    claims = _resolve_claims(token_spec.get("claims", {}))
    return pyjwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def _resolve_verification_key(token: str) -> dict:
    """Resolve the verification JWK by the token's header kid (JWT-001)."""
    header = pyjwt.get_unverified_header(token)
    kid = header.get("kid")
    for key in _PUBLIC_JWKS["keys"]:
        if key.get("kid") == kid:
            return key
    return _PUBLIC_JWKS["keys"][0]


def _nonce_validator(expected_nonce: str):
    def check(claims: dict) -> None:
        if claims.get("nonce") != expected_nonce:
            raise ValueError(
                f"nonce mismatch: token nonce {claims.get('nonce')!r} "
                f"does not equal expected {expected_nonce!r}"
            )

    return check


def _execute(vector: dict) -> dict:
    """Run one vector through py-identity-model's validation API."""
    options = vector.get("options", {})
    token = _mint_token(vector["token"])
    key = _resolve_verification_key(token)

    audience = options.get("expected_audience")
    issuer = options.get("expected_issuer")
    leeway = (
        _parse_go_duration(options["clock_skew"]).total_seconds()
        if "clock_skew" in options
        else None
    )
    algorithms = options.get("allowed_algorithms") or ["RS256"]
    # PARITY NOTE (JWT-013): the capability requires iat presence (RFC 7519
    # §4.1.6, profiled in spec/capabilities.md). Go and Rust enforce this
    # NATIVELY (go/pkg/jwt/claims.go, rust/src/jwt/claims.rs both hard-require
    # iat) — their runners pass no option for JWT-013. py-identity-model keeps
    # iat-presence OPT-IN (default-off) to stay backward-compatible for existing
    # consumers, so the executor drives PIM into the capability's required
    # behaviour via its documented `require` option. This is a real, intentional
    # default difference, not a masked gap: the assertion still exercises PIM's
    # option-plumbing + exception-wrapping path. Vector required_claims extend it.
    pyjwt_options: dict = {
        "require": ["iat", *options.get("required_claims", [])],
    }
    if audience is None:
        # PyJWT hard-fails an aud-bearing token when no audience is expected;
        # the capability treats an unexpected aud as ignorable (JWT-001).
        pyjwt_options["verify_aud"] = False

    decoded = decode_and_validate_jwt(
        token,
        key,
        algorithms,
        audience,
        issuer,
        pyjwt_options,
        leeway=leeway,
    )
    if "expected_nonce" in options:
        validate_claims(
            decoded,
            TokenValidationConfig(
                perform_disco=False,
                key=key,
                claims_validator=_nonce_validator(options["expected_nonce"]),
            ),
        )
    return decoded


def _assert_accept_claims(decoded: dict, expected_claims: dict) -> None:
    for name, want in expected_claims.items():
        assert name in decoded, f"accepted token is missing claim {name!r}"
        got = decoded[name]
        if name == "aud":
            audiences = got if isinstance(got, list) else [got]
            assert want in audiences, f"aud {audiences!r} does not contain {want!r}"
        else:
            assert got == want, f"claim {name!r} = {got!r}, want {want!r}"


# Canonical claim_validation codes map to py-identity-model's typed exceptions
# where one exists; everything else surfaces as the base
# TokenValidationException with the offending claim named in the message.
_CLAIM_EXCEPTION_TYPES = {
    "exp": TokenExpiredException,
    "aud": InvalidAudienceException,
    "iss": InvalidIssuerException,
}


def _assert_canonical_reject(err: PyIdentityModelException, expect: dict) -> None:
    code = expect["error"]
    message = str(err)
    if code == "signature":
        assert isinstance(err, SignatureVerificationException), (
            f"signature rejection surfaced as {type(err).__name__}: {message}"
        )
    elif code in ("alg_none", "unsupported_alg", "malformed", "key_conversion"):
        # py-identity-model surfaces these pre-claim failures as the base
        # TokenValidationException (exact type — the claim-specific and
        # signature exceptions are subclasses and must NOT match).
        assert type(err) is TokenValidationException, (
            f"{code} rejection surfaced as {type(err).__name__}: {message}"
        )
    elif code == "claim_validation":
        claim = expect["claim"]
        expected_type = _CLAIM_EXCEPTION_TYPES.get(claim, TokenValidationException)
        assert isinstance(err, expected_type), (
            f"claim {claim!r} rejection surfaced as {type(err).__name__}: {message}"
        )
        if expected_type is TokenValidationException:
            assert claim in message, (
                f"claim {claim!r} not named in rejection message: {message}"
            )
    else:
        pytest.fail(f"unknown canonical error code {code!r}")


def _vector_params() -> list:
    params = []
    for case in _CASES:
        vectors = case.get("vectors", [])
        assert vectors, f"{case['id']}: case has no vectors"
        for idx, vector in enumerate(vectors):
            label = vector.get("name") or str(idx)
            params.append(pytest.param(case["id"], vector, id=f"{case['id']}-{label}"))
    return params


@pytest.mark.parametrize(("case_id", "vector"), _vector_params())
def test_spec_vector(case_id: str, vector: dict) -> None:
    expect = vector["expect"]
    if expect["outcome"] == "accept":
        decoded = _execute(vector)
        _assert_accept_claims(decoded, expect.get("claims", {}))
    elif expect["outcome"] == "reject":
        with pytest.raises(PyIdentityModelException) as exc_info:
            _execute(vector)
        _assert_canonical_reject(exc_info.value, expect)
    else:
        pytest.fail(f"{case_id}: unknown expected outcome {expect['outcome']!r}")


def test_every_vector_case_is_parametrized() -> None:
    """Every case id in the spec file must be parametrized for execution."""
    parametrized = {p.values[0] for p in _vector_params()}
    missing = {c["id"] for c in _CASES} - parametrized
    assert not missing, f"vector cases not executed by the Python runner: {missing}"
