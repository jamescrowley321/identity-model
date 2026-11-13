"""
DPoP proof verification at the resource server, per RFC 9449.

The server-side counterpart of :mod:`.dpop`: given the ``DPoP`` request header,
the request method and URI, and the access token, :func:`verify_dpop_proof`
runs the RFC 9449 §4.3 checks (plus the §7.1 ``ath`` check) and returns the
proof key's RFC 7638 thumbprint, to be compared with the token's ``cnf.jkt``
(§6.1). :func:`.token_binding.check_token_binding` does that comparison as
part of ``validate_token``.

Every failure raises :class:`DPoPValidationError` with a typed
:class:`DPoPErrorKind`. It subclasses ``TokenValidationException``, so an
``except TokenValidationException`` handler fails closed on it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import enum
import hmac
import inspect
import json
import math
import threading
import time
import types
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.parse import urlsplit

import jwt as pyjwt
from jwt.api_jws import PyJWS

from ..exceptions import (
    ConfigurationException,
    TokenValidationException,
    WeakKeyException,
)
from .dpop import compute_ath, compute_jwk_thumbprint
from .jwt_signing import DEFAULT_ALLOWED_ALGORITHMS
from .key_strength import enforce_key_strength


if TYPE_CHECKING:
    from collections.abc import Callable


DPOP_PROOF_TYPE = "dpop+jwt"

# RFC 9449 §11.1: the server picks how long a proof is accepted after ``iat``.
DEFAULT_DPOP_PROOF_MAX_AGE = 60
# Accepted clock skew, either side of the window.
DEFAULT_DPOP_IAT_LEEWAY = 30
DEFAULT_DPOP_REPLAY_CACHE_MAX_ENTRIES = 100_000
_MAX_ENTRIES_MESSAGE = "max_entries must be a positive integer"
_REPLAY_CACHE_MESSAGE = (
    "replay_cache must be a DPoPReplayCache or an AsyncDPoPReplayCache (RFC 9449 §11.1)"
)
ASYNC_REPLAY_CACHE_MESSAGE = (
    "An AsyncDPoPReplayCache needs the async validators (py_identity_model.aio)"
)
REPLAY_ANSWER_MESSAGE = "replay_cache.check_and_store must return a DPoPReplayCheck"

# RFC 9449 §4.3 check 6: the key family each allowed ``alg`` requires.
_ALG_KEY_TYPES: types.MappingProxyType[str, tuple[str, str | None]] = (
    types.MappingProxyType(
        {
            "ES256": ("EC", "P-256"),
            "ES384": ("EC", "P-384"),
            "ES512": ("EC", "P-521"),
            "PS256": ("RSA", None),
            "PS384": ("RSA", None),
            "PS512": ("RSA", None),
            "RS256": ("RSA", None),
            "RS384": ("RSA", None),
            "RS512": ("RSA", None),
            "EdDSA": ("OKP", "Ed25519"),
        }
    )
)

# RFC 9449 §4.3 check 7: the ``jwk`` header must not carry a private key.
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

_DEFAULT_PORTS = types.MappingProxyType({"http": 80, "https": 443})


class DPoPErrorKind(enum.Enum):
    """Why a DPoP proof or a DPoP-bound token was rejected."""

    MALFORMED = "malformed"
    """The proof is not a well-formed JWS (RFC 9449 §4.3 checks 1-3)."""
    INVALID_TYPE = "invalid_type"
    """``typ`` header is not ``dpop+jwt`` (§4.3 check 4)."""
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    """``alg`` is ``none``, symmetric or not allowed (§4.3 check 5)."""
    INVALID_KEY = "invalid_key"
    """``jwk`` is missing, private, weak or does not fit ``alg`` (§4.3 checks 6-7)."""
    INVALID_SIGNATURE = "invalid_signature"
    """The signature does not verify with the ``jwk`` header (§4.3 check 6)."""
    MISSING_CLAIM = "missing_claim"
    """``jti``, ``htm``, ``htu`` or ``iat`` is absent or ill-typed (§4.2)."""
    HTM_MISMATCH = "htm_mismatch"
    """``htm`` differs from the request method (§4.3 check 8)."""
    HTU_MISMATCH = "htu_mismatch"
    """``htu`` differs from the request URI (§4.3 check 9)."""
    IAT_OUT_OF_WINDOW = "iat_out_of_window"
    """``iat`` is outside the acceptance window (§4.3 check 11)."""
    NONCE_MISMATCH = "nonce_mismatch"
    """``nonce`` is absent or differs from the expected nonce (§4.3 check 10)."""
    ATH_MISMATCH = "ath_mismatch"
    """``ath`` is absent or is not the access token hash (§4.3 check 12a)."""
    JKT_MISMATCH = "jkt_mismatch"
    """The proof key thumbprint differs from ``cnf.jkt`` (§4.3 check 12b, §6.1)."""
    REPLAYED_JTI = "replayed_jti"
    """The ``jti`` was already seen within the window (§11.1)."""
    REPLAY_CACHE_FULL = "replay_cache_full"
    """The replay cache is full of live ``jti`` values, so the proof cannot be
    recorded and is refused rather than risk a replay (§11.1)."""
    PROOF_REQUIRED = "proof_required"
    """A DPoP-bound token arrived without a ``DPoP`` proof, or with no
    presentation at all (§7.1, §7.2)."""
    WRONG_SCHEME = "wrong_scheme"
    """A DPoP-bound token arrived with a scheme other than ``DPoP`` (§7.1)."""
    NOT_BOUND = "not_bound"
    """A DPoP binding is required or claimed, but the token has no ``cnf.jkt``."""

    @property
    def oauth_error(self) -> str:
        """The RFC 9449 §7.1 / RFC 6750 §3.1 error code for a ``401``.

        ``invalid_dpop_proof`` for a bad proof; ``invalid_token`` when the
        token's binding fails (wrong key, wrong scheme, missing proof, unbound).
        """
        return (
            "invalid_token" if self in _TOKEN_BINDING_ERRORS else "invalid_dpop_proof"
        )


_TOKEN_BINDING_ERRORS = frozenset(
    {
        DPoPErrorKind.JKT_MISMATCH,
        DPoPErrorKind.PROOF_REQUIRED,
        DPoPErrorKind.WRONG_SCHEME,
        DPoPErrorKind.NOT_BOUND,
    }
)


_ERROR_MESSAGES: types.MappingProxyType[DPoPErrorKind, str] = types.MappingProxyType(
    {
        DPoPErrorKind.MALFORMED: "DPoP proof is not a well-formed JWS (RFC 9449 §4.3)",
        DPoPErrorKind.INVALID_TYPE: "DPoP proof typ must be dpop+jwt (RFC 9449 §4.3)",
        DPoPErrorKind.UNSUPPORTED_ALGORITHM: (
            "DPoP proof alg is not an allowed asymmetric algorithm (RFC 9449 §4.3)"
        ),
        DPoPErrorKind.INVALID_KEY: (
            "DPoP proof jwk is missing, private, weak or does not fit alg "
            "(RFC 9449 §4.3)"
        ),
        DPoPErrorKind.INVALID_SIGNATURE: "DPoP proof signature is invalid (RFC 9449 §4.3)",
        DPoPErrorKind.MISSING_CLAIM: (
            "DPoP proof needs string jti, htm, htu and a numeric iat (RFC 9449 §4.2)"
        ),
        DPoPErrorKind.HTM_MISMATCH: "DPoP proof htm does not match the request (RFC 9449 §4.3)",
        DPoPErrorKind.HTU_MISMATCH: "DPoP proof htu does not match the request (RFC 9449 §4.3)",
        DPoPErrorKind.IAT_OUT_OF_WINDOW: (
            "DPoP proof iat is outside the acceptance window (RFC 9449 §4.3)"
        ),
        DPoPErrorKind.NONCE_MISMATCH: "DPoP proof nonce does not match (RFC 9449 §4.3)",
        DPoPErrorKind.ATH_MISMATCH: (
            "DPoP proof ath does not match the access token (RFC 9449 §4.3)"
        ),
        DPoPErrorKind.JKT_MISMATCH: (
            "DPoP proof key does not match the access token cnf.jkt (RFC 9449 §6.1)"
        ),
        DPoPErrorKind.REPLAYED_JTI: "DPoP proof jti was already used (RFC 9449 §11.1)",
        DPoPErrorKind.REPLAY_CACHE_FULL: (
            "DPoP replay cache is full of live jti values; the proof cannot be "
            "recorded (RFC 9449 §11.1)"
        ),
        DPoPErrorKind.PROOF_REQUIRED: (
            "DPoP-bound access token was sent without a DPoP proof (RFC 9449 §7.1)"
        ),
        DPoPErrorKind.WRONG_SCHEME: (
            "DPoP-bound access token must be sent with the DPoP scheme (RFC 9449 §7.1)"
        ),
        DPoPErrorKind.NOT_BOUND: (
            "Access token is not DPoP-bound: no cnf.jkt (RFC 9449 §6.1)"
        ),
    }
)


class DPoPValidationError(TokenValidationException):
    """Raised when a DPoP proof or a DPoP-bound access token is rejected.

    ``kind`` says why; the message is fixed per kind. A resource server
    answers it with ``401`` and
    ``WWW-Authenticate: DPoP error="<kind.oauth_error>"`` (RFC 9449 §7.1).
    """

    def __init__(self, kind: DPoPErrorKind) -> None:
        self.kind = kind
        super().__init__(
            _ERROR_MESSAGES[kind], token_part="dpop", details={"kind": kind.value}
        )


class DPoPReplayCheck(enum.Enum):
    """What a replay cache did with one proof (RFC 9449 §11.1).

    The one way a :class:`DPoPReplayCache` reports its answer: it returns one
    of these and does not raise for a replay or a full cache.
    """

    RECORDED = "recorded"
    """The proof was unseen (or its record expired) and is now recorded."""
    REPLAYED = "replayed"
    """The proof was already recorded and its record is still live."""
    FULL = "full"
    """The proof could not be recorded, so it is refused rather than risk a
    replay."""


@runtime_checkable
class DPoPReplayCache(Protocol):
    """Records DPoP proofs to refuse a replay (RFC 9449 §11.1).

    The verifier calls :meth:`check_and_store` once per proof, after every
    other check passed, so a rejected proof is never recorded. A proof is
    identified by its key thumbprint and its ``jti``, so one client's proofs
    can never block another's. Implementations must be atomic: two concurrent
    calls for the same proof record at most one. They must never forget a
    proof before its ``expires_at``.

    Use with the sync validators. The async validators accept this or an
    :class:`AsyncDPoPReplayCache`.
    """

    def check_and_store(
        self, jkt: str, jti: str, expires_at: float, now: float
    ) -> DPoPReplayCheck:
        """Record the proof until *expires_at* (epoch seconds), inclusive.

        Args:
            jkt: The RFC 7638 thumbprint of the proof key.
            jti: The proof identifier.
            expires_at: The last instant the proof is inside the verifier's
                acceptance window.
            now: The verifier's current time; records with
                ``expires_at < now`` may be dropped.

        Returns:
            ``RECORDED``, ``REPLAYED`` or ``FULL``.
        """
        ...


@runtime_checkable
class AsyncDPoPReplayCache(Protocol):
    """An async :class:`DPoPReplayCache`, for a store reached over the network.

    The same contract, with an awaitable :meth:`check_and_store`. Use with the
    async validators (``py_identity_model.aio``); the sync validators refuse
    it with a :class:`~py_identity_model.exceptions.ConfigurationException`.
    """

    async def check_and_store(
        self, jkt: str, jti: str, expires_at: float, now: float
    ) -> DPoPReplayCheck:
        """Record the proof (see :meth:`DPoPReplayCache.check_and_store`)."""
        ...


class InMemoryDPoPReplayCache:
    """Thread-safe, bounded, per-process :class:`DPoPReplayCache`.

    Expired records are dropped on every insert. A live record is never
    evicted (that would let its proof replay): when the cache is full of live
    records, a new proof gets ``FULL`` and is refused, so *max_entries* should
    exceed the proofs a process accepts within one window. A deployment with
    several processes behind a load balancer needs a shared cache instead.

    Build one per resource server and keep it for the life of the process;
    a cache built per request records nothing that outlives the request.

    Args:
        max_entries: The most proofs held at once.
    """

    def __init__(
        self,
        max_entries: int = DEFAULT_DPOP_REPLAY_CACHE_MAX_ENTRIES,
    ) -> None:
        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or max_entries < 1
        ):
            raise ValueError(_MAX_ENTRIES_MESSAGE)
        self._max_entries = max_entries
        self._entries: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def check_and_store(
        self, jkt: str, jti: str, expires_at: float, now: float
    ) -> DPoPReplayCheck:
        """Record the proof (see :meth:`DPoPReplayCache.check_and_store`)."""
        key = (jkt, jti)
        with self._lock:
            # Purging first drops an expired record of this proof, so only a
            # live one is a replay.
            self._purge(now)
            if key in self._entries:
                return DPoPReplayCheck.REPLAYED
            if len(self._entries) >= self._max_entries:
                return DPoPReplayCheck.FULL
            self._entries[key] = expires_at
            return DPoPReplayCheck.RECORDED

    def _purge(self, now: float) -> None:
        # Live through ``expires_at`` inclusive, as the verifier's window is.
        expired = [key for key, until in self._entries.items() if until < now]
        for key in expired:
            del self._entries[key]


def _is_number(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        # An int too large for a float (JSON allows any integer).
        return False


def _sorted_algorithms(algorithms: frozenset[str] | None) -> tuple[str, ...]:
    # Module-level so the mutation gate can reach it; mutmut skips @property bodies.
    return tuple(
        sorted(DEFAULT_ALLOWED_ALGORITHMS if algorithms is None else algorithms)
    )


def _takes_replay_arguments(check: Callable[..., object]) -> bool:
    """Whether *check* takes ``(jkt, jti, expires_at, now)`` (not the 4.x three).

    A method with no introspectable signature (a C extension) is accepted.
    """
    try:
        inspect.signature(check).bind("jkt", "jti", 0.0, 0.0)
    except TypeError:
        return False
    except ValueError:
        return True
    return True


@dataclass(frozen=True, kw_only=True)
class DPoPVerificationOptions:
    """Resource-server settings for :func:`verify_dpop_proof`.

    The replay cache is the caller's: there is no process-wide default. Build
    one options value (and so one cache) per resource server and reuse it.

    Attributes:
        algorithms: Allowed proof ``alg`` values, a subset of
            ``DEFAULT_ALLOWED_ALGORITHMS`` (RS256/384/512, PS256/384/512,
            ES256/384/512, EdDSA). ``None`` allows all of them. For FAPI 2.0
            (Security Profile §5.4.1) pass
            ``FAPI2_ALLOWED_SIGNING_ALGORITHMS`` (PS256, ES256, EdDSA).
        max_age: Seconds a proof is accepted after its ``iat``.
        iat_leeway: Accepted clock skew in seconds, either side of the window.
        replay_cache: Where proofs are recorded (required). An
            :class:`InMemoryDPoPReplayCache` for one process, or a shared
            store behind a load balancer. An :class:`AsyncDPoPReplayCache`
            works only with the async validators.
    """

    replay_cache: DPoPReplayCache | AsyncDPoPReplayCache = field(compare=False)
    algorithms: frozenset[str] | None = None
    max_age: float = DEFAULT_DPOP_PROOF_MAX_AGE
    iat_leeway: float = DEFAULT_DPOP_IAT_LEEWAY

    def __post_init__(self) -> None:
        check = getattr(self.replay_cache, "check_and_store", None)
        if (
            isinstance(self.replay_cache, type)
            or not callable(check)
            or not _takes_replay_arguments(check)
        ):
            raise TypeError(_REPLAY_CACHE_MESSAGE)
        if self.algorithms is not None:
            unsupported = set(self.algorithms) - DEFAULT_ALLOWED_ALGORITHMS
            if unsupported or not self.algorithms:
                raise ValueError(
                    f"algorithms must be a non-empty subset of "
                    f"{sorted(DEFAULT_ALLOWED_ALGORITHMS)}; got unsupported "
                    f"{sorted(unsupported)}"
                )
        if not _is_number(self.max_age) or self.max_age <= 0:
            raise ValueError("max_age must be a positive number of seconds")
        if not _is_number(self.iat_leeway) or self.iat_leeway < 0:
            raise ValueError("iat_leeway must be a non-negative number of seconds")

    @property
    def accepted_algorithms(self) -> tuple[str, ...]:
        """The proof ``alg`` values accepted, sorted: the ``algs`` parameter of
        a ``WWW-Authenticate: DPoP`` challenge (RFC 9449 §7.1)."""
        return _sorted_algorithms(self.algorithms)


@dataclass(frozen=True)
class _ReplayRecord:
    """A verified proof waiting for its replay check, the verifier's last."""

    cache: DPoPReplayCache | AsyncDPoPReplayCache
    jkt: str
    jti: str
    expires_at: float
    now: float


def _replay_result(result: object) -> None:
    """Raise for a proof the replay cache did not record (any other answer).

    Raises:
        ConfigurationException: If *result* is not a :class:`DPoPReplayCheck`.
        DPoPValidationError: ``REPLAYED_JTI`` or ``REPLAY_CACHE_FULL``.
    """
    if not isinstance(result, DPoPReplayCheck):
        raise ConfigurationException(REPLAY_ANSWER_MESSAGE)
    if result is DPoPReplayCheck.REPLAYED:
        raise DPoPValidationError(DPoPErrorKind.REPLAYED_JTI)
    if result is not DPoPReplayCheck.RECORDED:
        raise DPoPValidationError(DPoPErrorKind.REPLAY_CACHE_FULL)


def record_proof(record: _ReplayRecord) -> None:
    """Run the replay check with a sync cache.

    Raises:
        ConfigurationException: If the cache is an
            :class:`AsyncDPoPReplayCache` (use the async validators), or its
            answer is not a :class:`DPoPReplayCheck`.
        DPoPValidationError: ``REPLAYED_JTI`` or ``REPLAY_CACHE_FULL``.
    """
    result = record.cache.check_and_store(
        record.jkt, record.jti, record.expires_at, record.now
    )
    if inspect.isawaitable(result):
        # Never run: nothing is recorded, and no "never awaited" warning.
        if inspect.iscoroutine(result):
            result.close()
        elif isinstance(result, asyncio.Future):
            result.cancel()
        raise ConfigurationException(ASYNC_REPLAY_CACHE_MESSAGE)
    _replay_result(result)


async def record_proof_async(record: _ReplayRecord) -> None:
    """Run the replay check with a sync or an async cache.

    Raises:
        ConfigurationException: If the cache's answer is not a
            :class:`DPoPReplayCheck`.
        DPoPValidationError: ``REPLAYED_JTI`` or ``REPLAY_CACHE_FULL``.
    """
    result = record.cache.check_and_store(
        record.jkt, record.jti, record.expires_at, record.now
    )
    if inspect.isawaitable(result):
        result = await result
    _replay_result(result)


@dataclass(frozen=True)
class DPoPProof:
    """A verified DPoP proof.

    Attributes:
        jkt: RFC 7638 thumbprint of the proof key (compare with ``cnf.jkt``).
        jti: The proof identifier.
        htm: The HTTP method the proof was made for.
        htu: The HTTP URI the proof was made for, as sent.
        iat: The proof's issue time.
        public_jwk: The proof's ``jwk`` header.
        nonce: The proof's ``nonce`` claim, if any.
    """

    jkt: str
    jti: str
    htm: str
    htu: str
    iat: float
    public_jwk: dict
    nonce: str | None = None


def _normalize_http_uri(value: object) -> str | None:
    """Normalize an absolute http(s) URI for the §4.3 check 9 comparison.

    Lowercases the scheme and host (RFC 3986 §6.2.2.1), applies §6.2.3
    scheme-based normalization (default port, empty path) and drops the query
    and fragment, which ``htu`` never covers (RFC 9449 §4.2). The path is
    compared as sent: percent-encodings are not normalized. Returns ``None``
    for anything else.
    """
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path or '/'}"


def _check_header(proof: str, allowed: frozenset[str]) -> tuple[str, dict]:
    """Return ``(alg, jwk)`` after the §4.3 header checks 4-7."""
    try:
        header = pyjwt.get_unverified_header(proof)
    except pyjwt.PyJWTError as exc:
        raise DPoPValidationError(DPoPErrorKind.MALFORMED) from exc
    if header.get("typ") != DPOP_PROOF_TYPE:
        raise DPoPValidationError(DPoPErrorKind.INVALID_TYPE)
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed:
        raise DPoPValidationError(DPoPErrorKind.UNSUPPORTED_ALGORITHM)
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or not jwk:
        raise DPoPValidationError(DPoPErrorKind.INVALID_KEY)
    if _PRIVATE_JWK_MEMBERS & jwk.keys():
        raise DPoPValidationError(DPoPErrorKind.INVALID_KEY)
    kty, crv = _ALG_KEY_TYPES[alg]
    if jwk.get("kty") != kty or (crv is not None and jwk.get("crv") != crv):
        raise DPoPValidationError(DPoPErrorKind.INVALID_KEY)
    return alg, jwk


def _verify_signature(proof: str, alg: str, jwk: dict) -> dict:
    """Return the payload after verifying the signature with *jwk*."""
    jws = PyJWS()
    try:
        enforce_key_strength(jwk)
        key = jws.get_algorithm_by_name(alg).from_jwk(jwk)
    except (WeakKeyException, pyjwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
        raise DPoPValidationError(DPoPErrorKind.INVALID_KEY) from exc
    try:
        payload = json.loads(jws.decode(proof, key, algorithms=[alg]))
    except pyjwt.InvalidSignatureError as exc:
        raise DPoPValidationError(DPoPErrorKind.INVALID_SIGNATURE) from exc
    except (pyjwt.PyJWTError, ValueError, RecursionError) as exc:
        # RecursionError: json.loads on a deeply nested payload.
        raise DPoPValidationError(DPoPErrorKind.MALFORMED) from exc
    if not isinstance(payload, dict):
        raise DPoPValidationError(DPoPErrorKind.MALFORMED)
    return payload


def _required_claims(payload: dict) -> tuple[str, str, str, float]:
    jti, htm, htu, iat = (payload.get(name) for name in ("jti", "htm", "htu", "iat"))
    if (
        isinstance(jti, str)
        and jti
        and isinstance(htm, str)
        and isinstance(htu, str)
        and isinstance(iat, (int, float))
        and _is_number(iat)
    ):
        return jti, htm, htu, iat
    raise DPoPValidationError(DPoPErrorKind.MISSING_CLAIM)


def _constant_time_equal(expected: str, presented: object) -> bool:
    if not isinstance(presented, str) or not presented.isascii():
        return False
    return hmac.compare_digest(expected.encode(), presented.encode())


@dataclass(frozen=True)
class DPoPProofRequest:
    """The request a DPoP proof must match (RFC 9449 §4.3 checks 8-12).

    Attributes:
        method: The request's HTTP method.
        url: The request's absolute http(s) URI, as the client addressed it.
        access_token: The access token sent with the proof, if any; the proof
            must then carry its ``ath`` (§7.1).
        expected_jkt: The token's ``cnf.jkt``, if any; the proof key must have
            this RFC 7638 thumbprint (§6.1).
        expected_nonce: The nonce the server requires, if it enforces one (§9).

    Raises:
        ValueError: If *method* is empty or *url* is not an absolute http(s)
            URI.
    """

    method: str
    url: str
    access_token: str | None = None
    expected_jkt: str | None = None
    expected_nonce: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or not self.method.strip():
            raise ValueError("method must not be empty")
        if _normalize_http_uri(self.url) is None:
            raise ValueError("url must be an absolute http(s) URI")


def verify_dpop_proof(
    proof: str,
    request: DPoPProofRequest,
    options: DPoPVerificationOptions,
    *,
    now: float | None = None,
) -> DPoPProof:
    """Verify a DPoP proof JWT received by a resource server (RFC 9449 §4.3).

    Checks, in order: JWS syntax; ``typ`` is ``dpop+jwt``; ``alg`` is an
    allowed asymmetric algorithm; ``jwk`` is a public key that fits ``alg``
    and meets the key-strength floor; the signature; ``jti``/``htm``/``htu``/
    ``iat`` are present; ``htm`` equals the request method; ``htu`` equals the
    request URI (query and fragment ignored; scheme and host case and
    default port normalized, RFC 3986 §6.2.2.1, §6.2.3; the path compared
    as sent); ``iat`` is within
    ``[now - max_age - iat_leeway, now + iat_leeway]``; ``nonce`` equals the
    expected nonce when one is set; ``ath`` is the hash of the access token
    when one is set (§7.1); the key thumbprint equals the expected ``jkt``
    when one is set; and last, the proof is unseen, so a rejected proof is
    never recorded. The async counterpart is
    ``py_identity_model.aio.verify_dpop_proof``.

    Args:
        proof: The ``DPoP`` request header value.
        request: The request the proof must match.
        options: Algorithms, window and the replay cache.
        now: Current time in epoch seconds (defaults to ``time.time()``).

    Returns:
        The verified :class:`DPoPProof`.

    Raises:
        DPoPValidationError: If any check fails; ``kind`` says which.
        ConfigurationException: If ``options.replay_cache`` is an
            :class:`AsyncDPoPReplayCache`.
    """
    verified, record = _check_dpop_proof(proof, request, options, now=now)
    record_proof(record)
    return verified


def _check_dpop_proof(
    proof: str,
    request: DPoPProofRequest,
    options: DPoPVerificationOptions,
    *,
    now: float | None = None,
) -> tuple[DPoPProof, _ReplayRecord]:
    """Run every check of :func:`verify_dpop_proof` except the replay check.

    Returns the verified proof and the record the caller must pass to
    :func:`record_proof` or :func:`record_proof_async`. The proof is not
    accepted until that call returns: without it a replay passes.
    """
    if not isinstance(proof, str) or not proof.isascii() or not proof.strip():
        raise DPoPValidationError(DPoPErrorKind.MALFORMED)

    allowed = (
        DEFAULT_ALLOWED_ALGORITHMS if options.algorithms is None else options.algorithms
    )
    alg, jwk = _check_header(proof, allowed)
    payload = _verify_signature(proof, alg, jwk)
    jti, htm, htu, iat = _required_claims(payload)

    if htm != request.method:
        raise DPoPValidationError(DPoPErrorKind.HTM_MISMATCH)
    if _normalize_http_uri(htu) != _normalize_http_uri(request.url):
        raise DPoPValidationError(DPoPErrorKind.HTU_MISMATCH)

    current = time.time() if now is None else now
    if not (
        current - options.max_age - options.iat_leeway
        <= iat
        <= current + options.iat_leeway
    ):
        raise DPoPValidationError(DPoPErrorKind.IAT_OUT_OF_WINDOW)

    nonce = payload.get("nonce")
    if request.expected_nonce is not None and not _constant_time_equal(
        request.expected_nonce, nonce
    ):
        raise DPoPValidationError(DPoPErrorKind.NONCE_MISMATCH)

    if request.access_token is not None and not _constant_time_equal(
        compute_ath(request.access_token), payload.get("ath")
    ):
        raise DPoPValidationError(DPoPErrorKind.ATH_MISMATCH)

    # The jwk already converted to a key of its alg's type, so it has every
    # RFC 7638 required member.
    jkt = compute_jwk_thumbprint(jwk)
    if request.expected_jkt is not None and not _constant_time_equal(
        jkt, request.expected_jkt
    ):
        raise DPoPValidationError(DPoPErrorKind.JKT_MISMATCH)

    verified = DPoPProof(
        jkt=jkt,
        jti=jti,
        htm=htm,
        htu=htu,
        iat=iat,
        public_jwk=jwk,
        nonce=nonce if isinstance(nonce, str) else None,
    )
    # The cache works on this call's clock, so the proof is held exactly as
    # long as the window would accept it again.
    record = _ReplayRecord(
        cache=options.replay_cache,
        jkt=jkt,
        jti=jti,
        expires_at=iat + options.max_age + options.iat_leeway,
        now=current,
    )
    return verified, record


__all__ = [
    "DEFAULT_DPOP_IAT_LEEWAY",
    "DEFAULT_DPOP_PROOF_MAX_AGE",
    "DPOP_PROOF_TYPE",
    "AsyncDPoPReplayCache",
    "DPoPErrorKind",
    "DPoPProof",
    "DPoPProofRequest",
    "DPoPReplayCache",
    "DPoPReplayCheck",
    "DPoPValidationError",
    "DPoPVerificationOptions",
    "InMemoryDPoPReplayCache",
    "verify_dpop_proof",
]
