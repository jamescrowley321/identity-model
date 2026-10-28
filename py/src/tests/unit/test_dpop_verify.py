"""Unit tests for resource-server DPoP proof verification (RFC 9449 §4.3, §7.1)."""

from __future__ import annotations

from base64 import urlsafe_b64encode
import json
import re
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
import jwt as pyjwt
import pytest

from py_identity_model.core.dpop import (
    DPoPKey,
    compute_ath,
    compute_jwk_thumbprint,
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.core.dpop_verify import (
    DEFAULT_DPOP_IAT_LEEWAY,
    DEFAULT_DPOP_PROOF_MAX_AGE,
    DPoPErrorKind,
    DPoPProof,
    DPoPProofRequest,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    _normalize_http_uri,
    get_default_dpop_replay_cache,
    verify_dpop_proof,
)
from py_identity_model.exceptions import TokenValidationException


URL = "https://rs.example.com/api/resource"
METHOD = "GET"
# RFC 7518 §3.3: RSA keys need at least 2048 bits.
WEAK_RSA_BITS = 1024
REPLAY_CACHE_BOUND = 2
ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2ln"


class FakeClock:
    """A settable clock for the replay cache."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class RecordingCache:
    """A replay cache that admits every jti and records each call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, float]] = []

    def check_and_store(self, jti: str, expires_at: float) -> bool:
        self.calls.append((jti, expires_at))
        return True


def _exactly(message: str) -> str:
    """A ``pytest.raises`` pattern matching *message* and nothing else."""
    return f"^{re.escape(message)}$"


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(
    key: DPoPKey,
    *,
    header: dict | None = None,
    payload: dict | None = None,
    drop: tuple[str, ...] = (),
) -> str:
    """Sign a DPoP proof with *key*, overriding header/payload members."""
    claims = {
        "jti": str(uuid.uuid4()),
        "htm": METHOD,
        "htu": URL,
        "iat": int(time.time()),
        "ath": compute_ath(ACCESS_TOKEN),
    }
    claims.update(payload or {})
    for name in drop:
        claims.pop(name, None)
    headers = {"typ": "dpop+jwt", "alg": key.algorithm, "jwk": key.public_jwk}
    headers.update(header or {})
    return pyjwt.encode(
        claims, key.private_key_pem, algorithm=key.algorithm, headers=headers
    )


def _options(**kwargs) -> DPoPVerificationOptions:
    """Options with a private replay cache so tests never share jti state."""
    kwargs.setdefault("replay_cache", InMemoryDPoPReplayCache())
    return DPoPVerificationOptions(**kwargs)


def _verify(
    proof: str,
    *,
    options: DPoPVerificationOptions | None = None,
    now: float | None = None,
    **request_fields: str | None,
) -> DPoPProof:
    """Verify *proof* against the default request, overriding its fields."""
    fields: dict = {"method": METHOD, "url": URL, "access_token": ACCESS_TOKEN}
    fields.update(request_fields)
    request = DPoPProofRequest(**fields)
    return verify_dpop_proof(proof, request, options or _options(), now=now)


def _kind(proof: str, **kwargs) -> DPoPErrorKind:
    with pytest.raises(DPoPValidationError) as exc:
        _verify(proof, **kwargs)
    return exc.value.kind


@pytest.mark.unit
class TestAccept:
    @pytest.mark.parametrize("algorithm", ["ES256", "PS256", "EdDSA", "RS256"])
    def test_valid_proof_returns_thumbprint(self, algorithm):
        key = generate_dpop_key(algorithm)
        proof = create_dpop_proof(key, METHOD, URL, access_token=ACCESS_TOKEN)

        result = _verify(proof)

        assert result.jkt == key.jwk_thumbprint
        assert result.htm == METHOD
        assert result.htu == URL
        assert result.public_jwk == key.public_jwk

    def test_without_access_token_ath_not_required(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(key, "POST", URL)

        result = _verify(proof, method="POST", access_token=None)

        assert result.jkt == key.jwk_thumbprint

    def test_query_and_fragment_ignored(self):
        key = generate_dpop_key()
        proof = create_dpop_proof(key, METHOD, URL, access_token=ACCESS_TOKEN)

        result = _verify(proof, url=f"{URL}?page=2#frag")

        assert result.jkt == key.jwk_thumbprint

    @pytest.mark.parametrize(
        ("htu", "url"),
        [
            ("https://RS.example.com/api/resource", URL),
            ("https://rs.example.com:443/api/resource", URL),
            ("http://rs.example.com:80/", "http://rs.example.com"),
            ("HTTPS://rs.example.com/api/resource", URL),
        ],
    )
    def test_htu_syntax_and_scheme_normalized(self, htu, url):
        key = generate_dpop_key()
        proof = _sign(key, payload={"htu": htu})

        assert _verify(proof, url=url).jkt == key.jwk_thumbprint

    def test_expected_nonce_matches(self):
        key = generate_dpop_key()
        proof = _sign(key, payload={"nonce": "server-nonce"})

        result = _verify(proof, expected_nonce="server-nonce")

        assert (result.jkt, result.nonce) == (key.jwk_thumbprint, "server-nonce")

    @pytest.mark.parametrize(("nonce", "expected"), [("n-1", "n-1"), (5, None)])
    def test_result_nonce(self, nonce, expected):
        proof = _sign(generate_dpop_key(), payload={"nonce": nonce})

        assert _verify(proof).nonce == expected

    def test_error_is_token_validation_exception(self):
        key = generate_dpop_key()
        with pytest.raises(TokenValidationException):
            _verify(_sign(key, payload={"htm": "POST"}))


@pytest.mark.unit
class TestNegativeMatrix:
    """Issue #478 negative matrix rows that the proof verifier owns."""

    def test_replayed_jti_rejected(self):
        key = generate_dpop_key()
        proof = _sign(key)
        options = _options()
        _verify(proof, options=options)

        assert _kind(proof, options=options) is DPoPErrorKind.REPLAYED_JTI

    def test_htu_mismatch_rejected(self):
        key = generate_dpop_key()
        proof = _sign(key)

        assert (
            _kind(proof, url="https://rs.example.com/api/other")
            is DPoPErrorKind.HTU_MISMATCH
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://other.example.com/api/resource",
            "http://rs.example.com/api/resource",
        ],
    )
    def test_htu_other_origin_rejected(self, url):
        key = generate_dpop_key()

        assert _kind(_sign(key), url=url) is DPoPErrorKind.HTU_MISMATCH

    def test_htm_mismatch_rejected(self):
        key = generate_dpop_key()

        assert _kind(_sign(key), method="POST") is DPoPErrorKind.HTM_MISMATCH

    def test_htm_case_sensitive(self):
        key = generate_dpop_key()
        proof = _sign(key, payload={"htm": "get"})

        assert _kind(proof) is DPoPErrorKind.HTM_MISMATCH

    @pytest.mark.parametrize(
        "offset",
        [
            -(DEFAULT_DPOP_PROOF_MAX_AGE + DEFAULT_DPOP_IAT_LEEWAY + 1),
            DEFAULT_DPOP_IAT_LEEWAY + 1,
        ],
        ids=["stale", "future"],
    )
    def test_iat_outside_window_rejected(self, offset):
        key = generate_dpop_key()
        now = time.time()
        proof = _sign(key, payload={"iat": int(now) + offset})

        assert _kind(proof, now=int(now)) is DPoPErrorKind.IAT_OUT_OF_WINDOW

    @pytest.mark.parametrize(
        "offset",
        [
            -(DEFAULT_DPOP_PROOF_MAX_AGE + DEFAULT_DPOP_IAT_LEEWAY),
            DEFAULT_DPOP_IAT_LEEWAY,
        ],
        ids=["oldest", "newest"],
    )
    def test_iat_window_edges_accepted(self, offset):
        key = generate_dpop_key()
        now = int(time.time())
        proof = _sign(key, payload={"iat": now + offset})

        assert _verify(proof, now=now).jkt == key.jwk_thumbprint

    def test_custom_window(self):
        key = generate_dpop_key()
        now = int(time.time())
        proof = _sign(key, payload={"iat": now - 20})
        options = _options(max_age=10, iat_leeway=5)

        assert _kind(proof, now=now, options=options) is DPoPErrorKind.IAT_OUT_OF_WINDOW

    def test_ath_mismatch_rejected(self):
        key = generate_dpop_key()
        proof = _sign(key, payload={"ath": compute_ath("another-token")})

        assert _kind(proof) is DPoPErrorKind.ATH_MISMATCH

    def test_ath_missing_with_access_token_rejected(self):
        key = generate_dpop_key()
        proof = _sign(key, drop=("ath",))

        assert _kind(proof) is DPoPErrorKind.ATH_MISMATCH

    def test_ath_non_string_rejected(self):
        key = generate_dpop_key()
        proof = _sign(key, payload={"ath": 7})

        assert _kind(proof) is DPoPErrorKind.ATH_MISMATCH

    def test_tampered_signature_rejected(self):
        key = generate_dpop_key()
        header, payload, signature = _sign(key).split(".")
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]

        assert _kind(f"{header}.{payload}.{flipped}") is DPoPErrorKind.INVALID_SIGNATURE

    def test_signed_by_other_key_rejected(self):
        key = generate_dpop_key()
        other = generate_dpop_key()
        proof = _sign(other, header={"jwk": key.public_jwk})

        assert _kind(proof) is DPoPErrorKind.INVALID_SIGNATURE

    @pytest.mark.parametrize("typ", ["JWT", "DPOP+JWT", "at+jwt", None])
    def test_wrong_typ_rejected(self, typ):
        key = generate_dpop_key()
        proof = _sign(key, header={"typ": typ})

        assert _kind(proof) is DPoPErrorKind.INVALID_TYPE

    def test_symmetric_alg_rejected(self):
        secret = b"0123456789abcdef0123456789abcdef"
        proof = pyjwt.encode(
            {"jti": "j", "htm": METHOD, "htu": URL, "iat": int(time.time())},
            secret,
            algorithm="HS256",
            headers={
                "typ": "dpop+jwt",
                "jwk": {"kty": "oct", "k": _b64(secret)},
            },
        )

        assert _kind(proof) is DPoPErrorKind.UNSUPPORTED_ALGORITHM

    def test_alg_none_rejected(self):
        key = generate_dpop_key()
        header = _b64(
            json.dumps(
                {"typ": "dpop+jwt", "alg": "none", "jwk": key.public_jwk}
            ).encode()
        )
        payload = _b64(
            json.dumps(
                {"jti": "j", "htm": METHOD, "htu": URL, "iat": int(time.time())}
            ).encode()
        )

        assert _kind(f"{header}.{payload}.") is DPoPErrorKind.UNSUPPORTED_ALGORITHM


@pytest.mark.unit
class TestKeyChecks:
    @pytest.mark.parametrize("jwk", [None, "not-a-dict", {}])
    def test_missing_or_invalid_jwk_rejected(self, jwk):
        key = generate_dpop_key()
        proof = _sign(key, header={"jwk": jwk})

        assert _kind(proof) is DPoPErrorKind.INVALID_KEY

    def test_private_key_in_jwk_rejected(self):
        key = generate_dpop_key()
        private_numbers = ec.derive_private_key(1, ec.SECP256R1()).private_numbers()
        jwk = {**key.public_jwk, "d": _b64(private_numbers.private_value.to_bytes(32))}
        proof = _sign(key, header={"jwk": jwk})

        assert _kind(proof) is DPoPErrorKind.INVALID_KEY

    def test_key_type_must_match_alg(self):
        ec_key = generate_dpop_key("ES256")
        rsa_key = generate_dpop_key("PS256")
        proof = _sign(rsa_key, header={"jwk": ec_key.public_jwk})

        assert _kind(proof) is DPoPErrorKind.INVALID_KEY

    def test_curve_must_match_alg(self):
        p256 = generate_dpop_key("ES256")
        p384 = generate_dpop_key("ES384")
        proof = _sign(p256, header={"jwk": p384.public_jwk})

        assert _kind(proof) is DPoPErrorKind.INVALID_KEY

    def test_weak_rsa_key_rejected(self):
        # The strength floor is checked on the jwk header before the signature,
        # so a 1024-bit modulus is enough: no weak key needs to sign.
        key = generate_dpop_key("PS256")
        weak_n = (1 << (WEAK_RSA_BITS - 1)) | 1
        jwk = {**key.public_jwk, "n": _b64(weak_n.to_bytes(WEAK_RSA_BITS // 8))}
        proof = _sign(key, header={"jwk": jwk})

        assert _kind(proof) is DPoPErrorKind.INVALID_KEY

    def test_narrowed_algorithms(self):
        key = generate_dpop_key("RS256")
        proof = _sign(key)
        options = _options(algorithms=frozenset({"ES256", "PS256", "EdDSA"}))

        assert _kind(proof, options=options) is DPoPErrorKind.UNSUPPORTED_ALGORITHM

    def test_algorithms_outside_supported_set_is_config_error(self):
        with pytest.raises(ValueError, match="HS256"):
            DPoPVerificationOptions(algorithms=frozenset({"HS256"}))

    @pytest.mark.parametrize(
        ("field", "value"),
        [("max_age", 0), ("max_age", -1), ("iat_leeway", -1), ("max_age", True)],
    )
    def test_invalid_window_is_config_error(self, field, value):
        with pytest.raises(ValueError, match=field):
            DPoPVerificationOptions(**{field: value})


@pytest.mark.unit
class TestMalformed:
    @pytest.mark.parametrize("proof", ["", "   ", "a.b", "not-a-jwt", 42])
    def test_unparseable_proof_rejected(self, proof):
        assert _kind(proof) is DPoPErrorKind.MALFORMED

    @pytest.mark.parametrize("claim", ["jti", "htm", "htu", "iat"])
    def test_missing_required_claim_rejected(self, claim):
        key = generate_dpop_key()
        proof = _sign(key, drop=(claim,))

        assert _kind(proof) is DPoPErrorKind.MISSING_CLAIM

    @pytest.mark.parametrize(
        ("claim", "value"),
        [
            ("jti", ""),
            ("jti", 5),
            ("htm", 1),
            ("htu", ["x"]),
            ("iat", "1"),
            ("iat", True),
        ],
    )
    def test_ill_typed_claim_rejected(self, claim, value):
        key = generate_dpop_key()
        proof = _sign(key, payload={claim: value})

        assert _kind(proof) is DPoPErrorKind.MISSING_CLAIM

    @pytest.mark.parametrize("htu", ["/api/resource", "rs.example.com/api", "https://"])
    def test_relative_htu_rejected(self, htu):
        key = generate_dpop_key()
        proof = _sign(key, payload={"htu": htu})

        assert _kind(proof) is DPoPErrorKind.HTU_MISMATCH

    def test_ipv6_htu_accepted(self):
        key = generate_dpop_key()
        url = "https://[::1]:8443/api/resource"
        proof = _sign(key, payload={"htu": url})

        assert _verify(proof, url=url).jkt == key.jwk_thumbprint

    def test_htu_with_invalid_port_rejected(self):
        key = generate_dpop_key()
        proof = _sign(key, payload={"htu": "https://rs.example.com:99999/api"})

        assert _kind(proof) is DPoPErrorKind.HTU_MISMATCH

    def test_signed_non_object_payload_rejected(self):
        key = generate_dpop_key()
        proof = pyjwt.PyJWS().encode(
            b"[1, 2]",
            key.private_key_pem,
            algorithm=key.algorithm,
            headers={"typ": "dpop+jwt", "jwk": key.public_jwk},
        )

        assert _kind(proof) is DPoPErrorKind.MALFORMED

    def test_signed_non_json_payload_rejected(self):
        key = generate_dpop_key()
        proof = pyjwt.PyJWS().encode(
            b"not-json",
            key.private_key_pem,
            algorithm=key.algorithm,
            headers={"typ": "dpop+jwt", "jwk": key.public_jwk},
        )

        assert _kind(proof) is DPoPErrorKind.MALFORMED

    @pytest.mark.parametrize("url", ["", "/api/resource", None])
    def test_relative_request_url_is_value_error(self, url):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="url"):
            _verify(_sign(key), url=url)

    def test_empty_method_is_value_error(self):
        key = generate_dpop_key()
        with pytest.raises(ValueError, match="method"):
            _verify(_sign(key), method="")


@pytest.mark.unit
class TestNonce:
    def test_missing_nonce_rejected(self):
        key = generate_dpop_key()

        assert (
            _kind(_sign(key), expected_nonce="server-nonce")
            is DPoPErrorKind.NONCE_MISMATCH
        )

    @pytest.mark.parametrize("nonce", ["other", 5])
    def test_wrong_nonce_rejected(self, nonce):
        key = generate_dpop_key()
        proof = _sign(key, payload={"nonce": nonce})

        assert (
            _kind(proof, expected_nonce="server-nonce") is DPoPErrorKind.NONCE_MISMATCH
        )


@pytest.mark.unit
class TestReplayCache:
    def test_invalid_proof_does_not_burn_jti(self):
        key = generate_dpop_key()
        jti = "fixed-jti"
        options = _options()
        bad = _sign(key, payload={"jti": jti, "htm": "POST"})
        good = _sign(key, payload={"jti": jti})

        assert _kind(bad, options=options) is DPoPErrorKind.HTM_MISMATCH
        assert _verify(good, options=options).jti == jti

    def test_check_and_store(self):
        cache = InMemoryDPoPReplayCache()
        now = time.time()

        assert cache.check_and_store("a", now + 60) is True
        assert cache.check_and_store("a", now + 60) is False
        assert cache.check_and_store("b", now + 60) is True

    def test_expired_entry_is_forgotten(self):
        cache = InMemoryDPoPReplayCache()
        now = time.time()
        cache.check_and_store("a", now - 1)

        assert cache.check_and_store("a", now + 60) is True

    def test_bounded(self):
        cache = InMemoryDPoPReplayCache(max_entries=REPLAY_CACHE_BOUND)
        later = time.time() + 60
        for jti in ("a", "b", "c"):
            cache.check_and_store(jti, later)

        assert len(cache) == REPLAY_CACHE_BOUND
        assert cache.check_and_store("c", later) is False

    @pytest.mark.parametrize("max_entries", [0, True, "10"])
    def test_invalid_max_entries(self, max_entries):
        with pytest.raises(
            ValueError, match=_exactly("max_entries must be a positive integer")
        ):
            InMemoryDPoPReplayCache(max_entries=max_entries)

    def test_single_entry_cache(self):
        cache = InMemoryDPoPReplayCache(max_entries=1)
        later = time.time() + 60

        assert [cache.check_and_store(j, later) for j in ("a", "a", "b")] == [
            True,
            False,
            True,
        ]

    def test_entry_expires_at_its_expiry(self):
        clock = FakeClock(50.0)
        cache = InMemoryDPoPReplayCache(clock=clock)
        cache.check_and_store("a", 100.0)
        clock.now = 99.0
        live = cache.check_and_store("a", 200.0)
        clock.now = 100.0

        assert (live, cache.check_and_store("a", 200.0)) == (False, True)

    def test_purge_drops_entries_at_their_expiry(self):
        clock = FakeClock(50.0)
        cache = InMemoryDPoPReplayCache(clock=clock)
        cache.check_and_store("old", 100.0)
        clock.now = 100.0
        cache.check_and_store("new", 300.0)

        assert len(cache) == 1

    def test_distinct_proofs_share_a_cache(self):
        key = generate_dpop_key()
        options = _options()

        assert [_verify(_sign(key), options=options).jkt for _ in range(2)] == [
            key.jwk_thumbprint
        ] * 2

    def test_records_jti_until_the_window_closes(self):
        recorder = RecordingCache()
        key = generate_dpop_key()
        now = int(time.time())
        proof = _sign(key, payload={"jti": "rec-1", "iat": now})
        options = _options(max_age=40, iat_leeway=7, replay_cache=recorder)

        _verify(proof, options=options, now=now)

        assert recorder.calls == [("rec-1", now + 40 + 7)]

    def test_concurrent_replay_admits_one(self):
        cache = InMemoryDPoPReplayCache()
        later = time.time() + 60
        results: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            outcome = cache.check_and_store("same", later)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(results) == [False] * 15 + [True]

    def test_default_cache_used_when_options_omitted(self):
        key = generate_dpop_key()
        proof = _sign(key)
        request = DPoPProofRequest(method=METHOD, url=URL, access_token=ACCESS_TOKEN)
        verify_dpop_proof(proof, request)

        with pytest.raises(DPoPValidationError) as exc:
            verify_dpop_proof(proof, request)
        assert exc.value.kind is DPoPErrorKind.REPLAYED_JTI

    def test_empty_custom_cache_is_used(self):
        # An empty cache is falsy (it has __len__); it must still be the one used.
        cache = InMemoryDPoPReplayCache()
        default_size = len(get_default_dpop_replay_cache())
        _verify(_sign(generate_dpop_key()), options=_options(replay_cache=cache))

        assert (len(cache), len(get_default_dpop_replay_cache())) == (1, default_size)

    def test_default_cache_is_singleton_in_process(self):
        assert get_default_dpop_replay_cache() is get_default_dpop_replay_cache()


@pytest.mark.unit
class TestJwkThumbprint:
    def test_matches_key_property(self):
        for algorithm in ("ES256", "PS256", "EdDSA"):
            key = generate_dpop_key(algorithm)
            assert compute_jwk_thumbprint(key.public_jwk) == key.jwk_thumbprint

    def test_rfc7638_vector(self):
        # RFC 7638 §3.1 example RSA key and thumbprint.
        jwk = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }

        assert (
            compute_jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        )

    def test_non_string_member(self):
        with pytest.raises(
            ValueError,
            match=_exactly("JWK thumbprint needs string members ('crv', 'kty', 'x')"),
        ):
            compute_jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": 5})

    def test_rfc8037_okp_vector(self):
        # RFC 8037 Appendix A.3.
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }

        assert (
            compute_jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        )

    def test_unsupported_kty(self):
        with pytest.raises(ValueError, match="kty"):
            compute_jwk_thumbprint({"kty": "oct", "k": "AAAA"})


@pytest.mark.unit
class TestNormalizeHttpUri:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://RS.Example.com", "https://rs.example.com/"),
            ("HTTPS://rs.example.com:443/a", "https://rs.example.com/a"),
            ("http://rs.example.com:80/a", "http://rs.example.com/a"),
            ("https://rs.example.com:8443/a?q=1#f", "https://rs.example.com:8443/a"),
            ("https://[::1]:8443/a", "https://[::1]:8443/a"),
            ("https://[::1:8443]/a", "https://[::1:8443]/a"),
            ("https://user@rs.example.com/a", "https://rs.example.com/a"),
            ("ftp://rs.example.com/a", None),
            ("https://rs.example.com:99999/a", None),
            ("https:///a", None),
            (5, None),
        ],
    )
    def test_normalized(self, value, expected):
        assert _normalize_http_uri(value) == expected


@pytest.mark.unit
class TestMessages:
    def test_message_per_kind(self):
        errors = {kind: DPoPValidationError(kind) for kind in DPoPErrorKind}

        assert {kind: str(error) for kind, error in errors.items()} == {
            DPoPErrorKind.MALFORMED: "DPoP proof is not a well-formed JWS (RFC 9449 §4.3)",
            DPoPErrorKind.INVALID_TYPE: "DPoP proof typ must be dpop+jwt (RFC 9449 §4.3)",
            DPoPErrorKind.UNSUPPORTED_ALGORITHM: (
                "DPoP proof alg is not an allowed asymmetric algorithm (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.INVALID_KEY: (
                "DPoP proof jwk is missing, private, weak or does not fit alg "
                "(RFC 9449 §4.3)"
            ),
            DPoPErrorKind.INVALID_SIGNATURE: (
                "DPoP proof signature is invalid (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.MISSING_CLAIM: (
                "DPoP proof needs string jti, htm, htu and a numeric iat "
                "(RFC 9449 §4.2)"
            ),
            DPoPErrorKind.HTM_MISMATCH: (
                "DPoP proof htm does not match the request (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.HTU_MISMATCH: (
                "DPoP proof htu does not match the request (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.IAT_OUT_OF_WINDOW: (
                "DPoP proof iat is outside the acceptance window (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.NONCE_MISMATCH: (
                "DPoP proof nonce does not match (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.ATH_MISMATCH: (
                "DPoP proof ath does not match the access token (RFC 9449 §4.3)"
            ),
            DPoPErrorKind.JKT_MISMATCH: (
                "DPoP proof key does not match the access token cnf.jkt (RFC 9449 §6.1)"
            ),
            DPoPErrorKind.REPLAYED_JTI: (
                "DPoP proof jti was already used (RFC 9449 §11.1)"
            ),
            DPoPErrorKind.PROOF_REQUIRED: (
                "DPoP-bound access token was sent without a DPoP proof (RFC 9449 §7.1)"
            ),
            DPoPErrorKind.WRONG_SCHEME: (
                "DPoP-bound access token must be sent with the DPoP scheme "
                "(RFC 9449 §7.1)"
            ),
            DPoPErrorKind.NOT_BOUND: (
                "Access token is not DPoP-bound: no cnf.jkt (RFC 9449 §6.1)"
            ),
        }
        assert {error.token_part for error in errors.values()} == {"dpop"}


@pytest.mark.unit
class TestOAuthError:
    @pytest.mark.parametrize(
        "kind",
        [
            DPoPErrorKind.JKT_MISMATCH,
            DPoPErrorKind.PROOF_REQUIRED,
            DPoPErrorKind.WRONG_SCHEME,
            DPoPErrorKind.NOT_BOUND,
        ],
    )
    def test_binding_errors_are_invalid_token(self, kind):
        assert kind.oauth_error == "invalid_token"

    def test_proof_errors_are_invalid_dpop_proof(self):
        binding = {
            DPoPErrorKind.JKT_MISMATCH,
            DPoPErrorKind.PROOF_REQUIRED,
            DPoPErrorKind.WRONG_SCHEME,
            DPoPErrorKind.NOT_BOUND,
        }
        assert {kind.oauth_error for kind in DPoPErrorKind if kind not in binding} == {
            "invalid_dpop_proof"
        }

    def test_error_details_carry_kind(self):
        key = generate_dpop_key()
        with pytest.raises(DPoPValidationError) as exc:
            _verify(_sign(key, payload={"htm": "POST"}))

        assert exc.value.details == {"kind": DPoPErrorKind.HTM_MISMATCH.value}
