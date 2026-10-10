"""DPoP proof helpers shared by the spec vector runners.

A built proof is verified against a key-pair fixture and compared by its
decoded header and payload; ``jti`` and ``iat`` are generated, so they are
checked only for presence and freshness. py-identity-model cannot load a
DPoPKey from existing key material (#786), so the fixture key is installed
into a DPoPKey in place of a generated one.
"""

import json
from pathlib import Path
import time

from jwt import PyJWK, PyJWS

from py_identity_model.core.dpop import DPoPKey


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "spec" / "vectors").is_dir():
            return parent
    raise RuntimeError("spec/vectors not found above this file")


FIXTURE_ROOT = _find_repo_root() / "spec" / "test-fixtures"

#: How far a freshly built proof's iat may be from now, in seconds.
PROOF_IAT_WINDOW = 60


def fixture(name: str) -> dict:
    """Return a spec/test-fixtures JSON document."""
    return json.loads((FIXTURE_ROOT / name).read_text())


def dpop_fixture_key(name: str) -> tuple[DPoPKey, object]:
    """Return a DPoPKey holding the fixture's private key, and its public key."""
    doc = fixture(name)
    key = DPoPKey.__new__(DPoPKey)
    key._algorithm = doc["algorithm"]
    key._private_key = PyJWK(doc["private"]).key
    return key, PyJWK(doc["public"]).key


def proof_jti(proof: str) -> str:
    """Return a proof's jti without verifying it."""
    payload = PyJWS().decode_complete(proof, options={"verify_signature": False})
    return json.loads(payload["payload"])["jti"]


def assert_dpop_proof(case_id: str, proof: str, key: tuple, want: dict) -> None:
    """Verify the proof with the fixture key and compare header and payload."""
    dpop_key, public_key = key
    decoded = PyJWS().decode_complete(
        proof, key=public_key, algorithms=[dpop_key.algorithm]
    )
    assert decoded["header"] == want["header"], case_id
    payload = json.loads(decoded["payload"])
    jti = payload.pop("jti")
    assert isinstance(jti, str), case_id
    assert jti, case_id
    assert abs(payload.pop("iat") - time.time()) <= PROOF_IAT_WINDOW, case_id
    assert payload == want["payload"], case_id
