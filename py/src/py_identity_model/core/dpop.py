"""
DPoP (Demonstrating Proof of Possession) utilities per RFC 9449.

Provides key pair generation, DPoP proof JWT creation, and access token
hash computation for binding OAuth 2.0 tokens to a client's private key.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
from enum import StrEnum
import hashlib
import json
import threading
import time
import types
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlsplit, urlunparse
import uuid

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
import jwt as pyjwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm


if TYPE_CHECKING:
    import httpx


class DPoPAlgorithm(StrEnum):
    """Algorithms a client :class:`DPoPKey` can sign proofs with.

    FAPI 2.0 (Security Profile §5.4.1) allows only ``ES256``, ``PS256`` and
    ``EdDSA``. Verifying proofs uses ``DEFAULT_ALLOWED_ALGORITHMS``
    (``dpop_verify``), not this set.
    """

    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    RS256 = "RS256"
    PS256 = "PS256"
    EDDSA = "EdDSA"
    """EdDSA with an Ed25519 key (RFC 8037 §3.1)."""


# Mapping from JWT algorithm to EC curve (immutable to prevent curve confusion)
_EC_CURVES: types.MappingProxyType[str, ec.EllipticCurve] = types.MappingProxyType(
    {
        DPoPAlgorithm.ES256: ec.SECP256R1(),
        DPoPAlgorithm.ES384: ec.SECP384R1(),
        DPoPAlgorithm.ES512: ec.SECP521R1(),
    }
)

# RSA keys smaller than this are refused, generated or loaded (RFC 7518 §3.3).
_MIN_RSA_KEY_BITS = 2048

_PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey

# JWK private-key parsers per ``kty``.
_JWK_PARSERS = types.MappingProxyType(
    {"EC": ECAlgorithm, "OKP": OKPAlgorithm, "RSA": RSAAlgorithm}
)


def _parse_algorithm(algorithm: DPoPAlgorithm | str) -> DPoPAlgorithm:
    try:
        return DPoPAlgorithm(algorithm)
    except ValueError:
        msg = (
            f"Unsupported DPoP algorithm: {algorithm}. "
            f"Supported: {sorted(a.value for a in DPoPAlgorithm)}"
        )
        raise ValueError(msg) from None


def _check_key_fits(algorithm: DPoPAlgorithm, key: object) -> _PrivateKey:
    """Return *key* if it is a private key *algorithm* can sign with."""
    curve = _EC_CURVES.get(algorithm)
    if curve is not None:
        fits = (
            isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == curve.name
        )
    elif algorithm is DPoPAlgorithm.EDDSA:
        fits = isinstance(key, ed25519.Ed25519PrivateKey)
    else:
        fits = isinstance(key, rsa.RSAPrivateKey) and key.key_size >= _MIN_RSA_KEY_BITS
    if not fits:
        msg = f"Key is not a private key {algorithm.value} can sign with"
        raise ValueError(msg)
    return key  # type: ignore[return-value]


def _int_to_b64url(n: int, length: int) -> str:
    """Encode an integer as base64url without padding."""
    return urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


class DPoPKey:
    """Manages a DPoP asymmetric key pair.

    Generate a new pair via :func:`generate_dpop_key`, or load a stored one
    with :meth:`from_pem` or :meth:`from_jwk` so tokens bound to it stay
    usable across restarts.  The key pair is immutable and thread-safe after
    construction.

    The key also remembers the latest ``DPoP-Nonce`` each server (origin) sent,
    on any response, and the library's DPoP-bound requests put it in the next
    proof to that server (RFC 9449 §8.2, §9). See :meth:`nonce_for`.

    Args:
        algorithm: The signing algorithm, as a :class:`DPoPAlgorithm` or its
            string value.

    Raises:
        ValueError: If *algorithm* is not a :class:`DPoPAlgorithm`.
    """

    __slots__ = ("_algorithm", "_nonce_lock", "_nonces", "_private_key")

    _algorithm: DPoPAlgorithm
    _private_key: _PrivateKey
    _nonces: dict[tuple[bool, str], str]
    _nonce_lock: threading.Lock

    def __init__(self, algorithm: DPoPAlgorithm | str = DPoPAlgorithm.ES256) -> None:
        self._init_nonces()
        self._algorithm = _parse_algorithm(algorithm)
        curve = _EC_CURVES.get(self._algorithm)
        if curve is not None:
            self._private_key = ec.generate_private_key(curve)
        elif self._algorithm is DPoPAlgorithm.EDDSA:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=_MIN_RSA_KEY_BITS
            )

    @classmethod
    def _wrap(cls, algorithm: DPoPAlgorithm, private_key: object) -> DPoPKey:
        key = cls.__new__(cls)
        key._init_nonces()
        key._private_key = _check_key_fits(algorithm, private_key)
        key._algorithm = algorithm
        return key

    def _init_nonces(self) -> None:
        self._nonces = {}
        self._nonce_lock = threading.Lock()

    def nonce_for(self, uri: str, *, resource_server: bool) -> str | None:
        """The latest ``DPoP-Nonce`` the server at *uri*'s origin supplied.

        RFC 9449 §8.2: the client MUST use a nonce the server supplied, also
        on a ``200`` response, for all subsequent requests until the server
        supplies a new one. Nonces are kept per origin (scheme, host, port)
        and per role, so a resource server's nonce is never sent to the
        authorization server, even on a shared origin, and one server's nonce
        never reaches another (§9).

        Args:
            uri: The request URI.
            resource_server: ``True`` for a resource request (e.g. UserInfo),
                ``False`` for an authorization-server request (token, PAR).

        Returns:
            The nonce, or ``None`` when that server has supplied none.
        """
        with self._nonce_lock:
            return self._nonces.get(_nonce_key(uri, resource_server))

    def remember_nonce(self, uri: str, nonce: str, *, resource_server: bool) -> None:
        """Record *nonce* as the latest ``DPoP-Nonce`` from *uri*'s server."""
        with self._nonce_lock:
            self._nonces[_nonce_key(uri, resource_server)] = nonce

    @classmethod
    def from_pem(
        cls,
        pem: bytes | str,
        algorithm: DPoPAlgorithm | str,
        password: bytes | None = None,
    ) -> DPoPKey:
        """Load a DPoP key from a PEM-encoded private key.

        Args:
            pem: The private key, PEM-encoded (PKCS#8 or traditional).
            algorithm: The algorithm to sign proofs with. It must fit the key:
                an EC key on that algorithm's curve, an Ed25519 key for
                ``EdDSA``, or an RSA key of at least 2048 bits.
            password: The PEM's password, if it is encrypted.

        Raises:
            ValueError: If *algorithm* is unsupported, the PEM cannot be
                loaded, or the key does not fit *algorithm*.
        """
        parsed = _parse_algorithm(algorithm)
        data = pem.encode() if isinstance(pem, str) else pem
        try:
            private_key = load_pem_private_key(data, password=password)
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            raise ValueError(f"Cannot load the DPoP private key: {e}") from e
        return cls._wrap(parsed, private_key)

    @classmethod
    def from_jwk(
        cls, jwk: dict, algorithm: DPoPAlgorithm | str | None = None
    ) -> DPoPKey:
        """Load a DPoP key from a private JWK (``EC``, ``OKP`` or ``RSA``).

        Args:
            jwk: The private JWK, including its private members (``d``, and
                for RSA the CRT members).
            algorithm: The algorithm to sign proofs with. Defaults to the
                JWK's ``alg`` member; one of the two is required.

        Raises:
            ValueError: If *jwk* is not a dict, no algorithm is given, it is
                unsupported, the JWK is not a private key, or the key does
                not fit the algorithm.
        """
        if not isinstance(jwk, dict):
            raise ValueError("A DPoP JWK must be a dict")
        alg = algorithm if algorithm is not None else jwk.get("alg")
        if not isinstance(alg, str):
            raise ValueError("A DPoP JWK needs an algorithm: pass one or set 'alg'")
        parsed = _parse_algorithm(alg)
        kty = jwk.get("kty")
        parser = _JWK_PARSERS.get(kty) if isinstance(kty, str) else None
        if parser is None:
            raise ValueError(f"Unsupported JWK kty for DPoP: {kty!r}")
        try:
            private_key = parser.from_jwk(json.dumps(jwk))
        except (pyjwt.InvalidKeyError, ValueError, TypeError) as e:
            raise ValueError(f"Cannot load the DPoP JWK: {e}") from e
        return cls._wrap(parsed, private_key)

    @property
    def algorithm(self) -> DPoPAlgorithm:
        """The signing algorithm."""
        return self._algorithm

    @property
    def private_key_pem(self) -> bytes:
        """PEM-encoded private key bytes."""
        return self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

    @property
    def public_jwk(self) -> dict:
        """Public key as a JWK dict suitable for the DPoP proof ``jwk`` header."""
        pub = self._private_key.public_key()

        if isinstance(pub, ed25519.Ed25519PublicKey):
            # RFC 8037 §2: octet key pair, x is the raw public key.
            raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
            }

        if isinstance(pub, ec.EllipticCurvePublicKey):
            numbers = pub.public_numbers()
            _curve_names = {
                "secp256r1": "P-256",
                "secp384r1": "P-384",
                "secp521r1": "P-521",
            }
            curve_name = _curve_names.get(pub.curve.name)
            if curve_name is None:
                raise ValueError(f"Unsupported EC curve: {pub.curve.name}")
            key_size = (pub.curve.key_size + 7) // 8
            return {
                "kty": "EC",
                "crv": curve_name,
                "x": _int_to_b64url(numbers.x, key_size),
                "y": _int_to_b64url(numbers.y, key_size),
            }

        # RSA
        numbers = pub.public_numbers()  # type: ignore[union-attr]
        return {
            "kty": "RSA",
            "n": _int_to_b64url(numbers.n, (numbers.n.bit_length() + 7) // 8),
            "e": _int_to_b64url(numbers.e, (numbers.e.bit_length() + 7) // 8),
        }

    @property
    def jwk_thumbprint(self) -> str:
        """JWK Thumbprint (RFC 7638) for use as ``dpop_jkt`` parameter."""
        return compute_jwk_thumbprint(self.public_jwk)


_SHA256_B64URL_LENGTH = 43

# RFC 7638 §3.2 / RFC 8037 §2: the required members hashed for each key type,
# in lexicographic order.
_THUMBPRINT_MEMBERS: types.MappingProxyType[str, tuple[str, ...]] = (
    types.MappingProxyType(
        {
            "EC": ("crv", "kty", "x", "y"),
            "OKP": ("crv", "kty", "x"),
            "RSA": ("e", "kty", "n"),
        }
    )
)


def compute_jwk_thumbprint(jwk: dict) -> str:
    """Compute the RFC 7638 JWK SHA-256 thumbprint of a public key.

    This is the value carried in ``cnf.jkt`` of a DPoP-bound access token
    (RFC 9449 §6.1) and in the ``dpop_jkt`` authorization parameter (§10).

    Args:
        jwk: An ``EC``, ``OKP`` or ``RSA`` public JWK. Members outside the
            required set (``kid``, ``alg``, ...) are ignored.

    Returns:
        The base64url-encoded (no padding) SHA-256 thumbprint.

    Raises:
        ValueError: If the key type is unsupported or a required member is
            missing or not a string.
    """
    kty = jwk.get("kty")
    members = _THUMBPRINT_MEMBERS.get(kty) if isinstance(kty, str) else None
    if members is None:
        raise ValueError(f"Unsupported JWK kty for thumbprint: {kty!r}")
    required = {name: jwk.get(name) for name in members}
    if not all(isinstance(value, str) and value for value in required.values()):
        raise ValueError(f"JWK thumbprint needs string members {members}")
    # RFC 7638 §3: lexicographically ordered members (_THUMBPRINT_MEMBERS lists
    # them in that order), no whitespace.
    thumbprint_input = json.dumps(required, separators=(",", ":"))
    digest = hashlib.sha256(thumbprint_input.encode()).digest()
    # A SHA-256 digest is 32 octets: 43 base64url characters plus one "=".
    return urlsafe_b64encode(digest).decode()[:_SHA256_B64URL_LENGTH]


def generate_dpop_key(
    algorithm: DPoPAlgorithm | str = DPoPAlgorithm.ES256,
) -> DPoPKey:
    """Generate a new DPoP key pair.

    Args:
        algorithm: Signing algorithm — ``"ES256"`` (default, recommended),
            ``"ES384"``, ``"ES512"``, ``"PS256"``, ``"EdDSA"`` (Ed25519,
            RFC 8037) or ``"RS256"``.  FAPI 2.0 (Security Profile §5.4.1)
            allows only ``"ES256"``, ``"PS256"`` and ``"EdDSA"``.

    Returns:
        A :class:`DPoPKey` with a fresh key pair.
    """
    return DPoPKey(algorithm)


def compute_ath(access_token: str) -> str:
    """Compute the access token hash (``ath``) claim value.

    Used when sending a DPoP proof alongside a bound access token to a
    resource server.

    Args:
        access_token: The access token string.

    Returns:
        Base64url-encoded SHA-256 hash of the access token.

    Raises:
        ValueError: If *access_token* is empty.
    """
    if not access_token or not access_token.strip():
        raise ValueError("access_token must not be empty")
    try:
        token_bytes = access_token.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("access_token must contain only ASCII characters") from None
    digest = hashlib.sha256(token_bytes).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def create_dpop_proof(
    key: DPoPKey,
    method: str,
    uri: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """Create a signed DPoP proof JWT (RFC 9449).

    Args:
        key: The :class:`DPoPKey` to sign the proof with.
        method: HTTP method (e.g. ``"POST"``, ``"GET"``).
        uri: The full HTTP URI of the request.
        access_token: If provided, includes the ``ath`` claim (required
            for resource server requests with bound tokens).
        nonce: Server-provided DPoP nonce (from a previous ``DPoP-Nonce``
            response header).

    Returns:
        The signed DPoP proof JWT string.

    Raises:
        ValueError: If *method* or *uri* is empty, or *uri* is not absolute.
    """
    if not method or not method.strip():
        raise ValueError("method must not be empty")
    if not uri or not uri.strip():
        raise ValueError("uri must not be empty")

    # RFC 9449 §4.2: htu must be an absolute HTTP URI without query or fragment
    parsed = urlparse(uri)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("uri must be an absolute HTTP URI")
    htu = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))

    headers = {
        "typ": "dpop+jwt",
        "alg": key.algorithm,
        "jwk": key.public_jwk,
    }

    payload: dict = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": htu,
        "iat": int(time.time()),
    }

    if access_token:
        payload["ath"] = compute_ath(access_token)

    if nonce:
        payload["nonce"] = nonce

    return pyjwt.encode(
        payload, key.private_key_pem, algorithm=key.algorithm, headers=headers
    )


def build_dpop_headers(
    proof: str,
    access_token: str | None = None,
) -> dict[str, str]:
    """Build HTTP headers dict with DPoP proof and optional Authorization.

    For **token endpoint** requests, only the ``DPoP`` header is needed.
    For **resource server** requests, both ``DPoP`` and
    ``Authorization: DPoP <token>`` headers are included.

    Args:
        proof: The signed DPoP proof JWT.
        access_token: If provided, adds ``Authorization: DPoP <token>`` header.

    Returns:
        Dict of HTTP headers to include in the request.

    Raises:
        ValueError: If *proof* is empty.
    """
    if not proof or not proof.strip():
        raise ValueError("proof must not be empty")
    headers: dict[str, str] = {"DPoP": proof}
    if access_token and access_token.strip():
        headers["Authorization"] = f"DPoP {access_token}"
    return headers


def _nonce_key(uri: str, resource_server: bool) -> tuple[bool, str]:
    parts = urlsplit(uri)
    return resource_server, f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def remember_dpop_nonce(
    key: DPoPKey, uri: str, response: httpx.Response, *, resource_server: bool
) -> None:
    """Record a ``DPoP-Nonce`` header from *response* on *key* for *uri*'s server.

    Any status counts: a server may supply the next nonce on a ``200``
    response (RFC 9449 §8.2) or with a ``use_dpop_nonce`` error (§8, §9).
    """
    nonce = response.headers.get("DPoP-Nonce")
    if nonce:
        key.remember_nonce(uri, nonce, resource_server=resource_server)


def extract_dpop_nonce(response: httpx.Response) -> str | None:
    """Return the server DPoP nonce when a response demands a nonced retry.

    Implements the RFC 9449 §8 ``use_dpop_nonce`` challenge: an authorization
    server (token/PAR endpoint, ``400``) or resource server (``401``) may reject
    a DPoP proof that lacks a server-chosen nonce, supplying the nonce in the
    ``DPoP-Nonce`` response header. The caller should re-mint the proof with the
    returned nonce and retry the request **once**.

    Args:
        response: The HTTP response to inspect.

    Returns:
        The ``DPoP-Nonce`` header value if this is a ``use_dpop_nonce`` error and
        a nonce is present, otherwise ``None``.
    """
    nonce = response.headers.get("DPoP-Nonce")
    if not nonce:
        return None
    if response.status_code not in (400, 401):
        return None
    # Token/PAR endpoints signal via the JSON error body (RFC 9449 §8.1);
    # resource servers signal via WWW-Authenticate (§8.2).
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    if isinstance(body, dict) and body.get("error") == "use_dpop_nonce":
        return nonce
    if "use_dpop_nonce" in response.headers.get("WWW-Authenticate", ""):
        return nonce
    return None


__all__ = [
    "DPoPKey",
    "build_dpop_headers",
    "compute_ath",
    "compute_jwk_thumbprint",
    "create_dpop_proof",
    "extract_dpop_nonce",
    "generate_dpop_key",
    "remember_dpop_nonce",
]
