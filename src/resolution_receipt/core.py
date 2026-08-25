"""Small, formula-independent signing and verification core.

The module proves authorship, integrity, ordering references, and a declared
task result. It deliberately contains no decision engine and makes no claim
that a signed statement is true merely because its signature is valid.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL = "resolution-receipt/0.1"
POLICY_DOMAIN = b"resolution-receipt/private-policy/v1\x00"
SIGNATURE_DOMAIN = b"resolution-receipt/signed-object/v1\n"
ED25519_MULTICODEC = b"\xed\x01"
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
OUTCOMES = {"PASS", "FAIL", "UNRESOLVED"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReceiptError(ValueError):
    """Raised when an artifact violates the public receipt contract."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise ReceiptError(f"floating-point JSON numbers are not allowed: {value}")


def _reject_constant(value: str) -> Any:
    raise ReceiptError(f"non-finite JSON value is not allowed: {value}")


def _validate_text(value: str) -> None:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ReceiptError("unpaired Unicode surrogate is not allowed")


def validate_json(value: Any) -> None:
    """Reject values whose serialization is ambiguous across implementations."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise ReceiptError("integer exceeds the interoperable JSON range")
        return
    if isinstance(value, float):
        raise ReceiptError("floating-point JSON numbers are not allowed")
    if isinstance(value, str):
        _validate_text(value)
        return
    if isinstance(value, list):
        for item in value:
            validate_json(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReceiptError("JSON object keys must be strings")
            _validate_text(key)
            validate_json(item)
        return
    raise ReceiptError(f"unsupported JSON value: {type(value).__name__}")


def load_json(path: str | os.PathLike[str]) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )
    validate_json(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_json(
    path: str | os.PathLike[str], value: Any, *, private: bool = False
) -> None:
    validate_json(value)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = 0o600 if private else 0o644
    descriptor = os.open(destination, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def hash_object(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ReceiptError("invalid base64url value")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ReceiptError("invalid base64url value") from exc


def _base58_encode(value: bytes) -> str:
    leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(BASE58_ALPHABET[remainder])
    encoded.reverse()
    return (BASE58_ALPHABET[:1] * leading_zeroes + encoded).decode("ascii")


def _base58_decode(value: str) -> bytes:
    if not value:
        raise ReceiptError("empty base58 value")
    index = {chr(char): position for position, char in enumerate(BASE58_ALPHABET)}
    number = 0
    try:
        for char in value:
            number = number * 58 + index[char]
    except KeyError as exc:
        raise ReceiptError("invalid base58 character") from exc
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + raw


def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ReceiptError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + _base58_encode(ED25519_MULTICODEC + public_key)


def public_key_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ReceiptError("expected a did:key with base58btc multibase")
    decoded = _base58_decode(did[len("did:key:z") :])
    if not decoded.startswith(ED25519_MULTICODEC):
        raise ReceiptError("DID is not an Ed25519 did:key")
    public_key = decoded[len(ED25519_MULTICODEC) :]
    if len(public_key) != 32:
        raise ReceiptError("Ed25519 did:key has the wrong length")
    if did_from_public_key(public_key) != did:
        raise ReceiptError("non-canonical did:key")
    return public_key


def _raw_private_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def create_key(path: str | os.PathLike[str], *, label: str) -> str:
    if not label or len(label) > 80:
        raise ReceiptError("key label must contain 1 to 80 characters")
    private_key = Ed25519PrivateKey.generate()
    did = did_from_public_key(_raw_public_key(private_key))
    write_json(
        path,
        {
            "algorithm": "Ed25519",
            "did": did,
            "label": label,
            "private_key": _b64url_encode(_raw_private_key(private_key)),
        },
        private=True,
    )
    return did


def _load_private_key(path: str | os.PathLike[str]) -> tuple[Ed25519PrivateKey, str]:
    data = load_json(path)
    if not isinstance(data, dict) or data.get("algorithm") != "Ed25519":
        raise ReceiptError("unsupported private key file")
    raw = _b64url_decode(data.get("private_key", ""))
    if len(raw) != 32:
        raise ReceiptError("Ed25519 private key must be 32 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    did = did_from_public_key(_raw_public_key(private_key))
    if data.get("did") != did:
        raise ReceiptError("private key file DID does not match its key")
    return private_key, did


def did_from_private_key(path: str | os.PathLike[str]) -> str:
    return _load_private_key(path)[1]


def _signature_message(kind: str, payload: Any) -> bytes:
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", kind):
        raise ReceiptError("invalid signed object kind")
    return SIGNATURE_DOMAIN + kind.encode("ascii") + b"\n" + canonical_bytes(payload)


def sign_envelope(
    kind: str, payload: Any, key_path: str | os.PathLike[str]
) -> dict[str, Any]:
    private_key, did = _load_private_key(key_path)
    signature = private_key.sign(_signature_message(kind, payload))
    return {
        "kind": kind,
        "payload": payload,
        "protocol": PROTOCOL,
        "signature": _b64url_encode(signature),
        "signer": did,
    }


def verify_envelope(
    envelope: Any, *, expected_kind: str | None = None
) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ReceiptError("signed object must be a JSON object")
    expected_fields = {"kind", "payload", "protocol", "signature", "signer"}
    if set(envelope) != expected_fields:
        raise ReceiptError("signed object has missing or unknown top-level fields")
    if envelope["protocol"] != PROTOCOL:
        raise ReceiptError("unsupported protocol")
    kind = envelope["kind"]
    if expected_kind is not None and kind != expected_kind:
        raise ReceiptError(f"expected kind {expected_kind}, found {kind}")
    public_key = Ed25519PublicKey.from_public_bytes(
        public_key_from_did(envelope["signer"])
    )
    signature = _b64url_decode(envelope["signature"])
    if len(signature) != 64:
        raise ReceiptError("Ed25519 signature must be 64 bytes")
    try:
        public_key.verify(signature, _signature_message(kind, envelope["payload"]))
    except InvalidSignature as exc:
        raise ReceiptError("invalid Ed25519 signature") from exc
    return envelope["payload"]


def policy_commitment(policy: Any, salt: bytes) -> str:
    if len(salt) < 32:
        raise ReceiptError("policy commitment salt must be at least 32 bytes")
    digest = hashlib.sha256(POLICY_DOMAIN + salt + canonical_bytes(policy)).hexdigest()
    return "sha256:" + digest


def create_policy_commitment(
    policy_path: str | os.PathLike[str],
    salt_path: str | os.PathLike[str],
) -> dict[str, str]:
    policy = load_json(policy_path)
    salt_destination = Path(salt_path)
    if salt_destination.exists():
        salt = salt_destination.read_bytes()
    else:
        salt_destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            salt_destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            salt = os.urandom(32)
            handle.write(salt)
    return {
        "algorithm": "SHA-256",
        "commitment": policy_commitment(policy, salt),
        "disclosure": "sealed",
        "domain": "resolution-receipt/private-policy/v1",
    }


def technocore_request(
    *, room: str, nonce: str, text: str, key_path: str | os.PathLike[str]
) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", room):
        raise ReceiptError("Technocore room must use 1-48 URL-safe characters")
    if not re.fullmatch(r"[0-9]{1,19}", nonce):
        raise ReceiptError("Technocore nonce must use 1-19 decimal digits")
    if not text or "|" in room:
        raise ReceiptError("invalid Technocore message")
    private_key, did = _load_private_key(key_path)
    message = f"{room}|{nonce}|{text}".encode()
    return {
        "did": did,
        "nonce": nonce,
        "sig": _b64url_encode(private_key.sign(message)),
        "text": text,
    }


def verify_technocore_request(*, room: str, request: Any) -> bool:
    if not isinstance(request, dict) or set(request) != {"did", "nonce", "sig", "text"}:
        raise ReceiptError("invalid Technocore request object")
    message = f"{room}|{request['nonce']}|{request['text']}".encode()
    public_key = Ed25519PublicKey.from_public_bytes(public_key_from_did(request["did"]))
    signature = _b64url_decode(request["sig"])
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise ReceiptError("invalid Technocore request signature") from exc
    return True


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReceiptError(f"{name} must be a sha256: hash")
    return value


def verify_bundle(
    *, manifest: Any, claim: Any, verdict: Any, receipt: Any
) -> dict[str, Any]:
    manifest_payload = verify_envelope(manifest, expected_kind="task-manifest")
    claim_payload = verify_envelope(claim, expected_kind="worker-claim")
    verdict_payload = verify_envelope(verdict, expected_kind="verifier-verdict")
    receipt_payload = verify_envelope(receipt, expected_kind="resolution-receipt")

    task_id = manifest_payload.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise ReceiptError("manifest task_id is required")
    for name, payload in (
        ("claim", claim_payload),
        ("verdict", verdict_payload),
        ("receipt", receipt_payload),
    ):
        if payload.get("task_id") != task_id:
            raise ReceiptError(f"{name} task_id does not match manifest")

    expected_hashes = {
        "manifest": hash_object(manifest),
        "claim": hash_object(claim),
        "verdict": hash_object(verdict),
    }
    references = receipt_payload.get("evidence_hashes")
    if not isinstance(references, dict) or set(references) != set(expected_hashes):
        raise ReceiptError(
            "receipt evidence_hashes must reference manifest, claim, and verdict"
        )
    for name, expected in expected_hashes.items():
        _require_hash(references.get(name), f"evidence_hashes.{name}")
        if references[name] != expected:
            raise ReceiptError(f"receipt {name} hash does not match")

    if claim_payload.get("manifest_hash") != expected_hashes["manifest"]:
        raise ReceiptError("claim does not reference the signed manifest")
    if verdict_payload.get("manifest_hash") != expected_hashes["manifest"]:
        raise ReceiptError("verdict does not reference the signed manifest")
    if verdict_payload.get("claim_hash") != expected_hashes["claim"]:
        raise ReceiptError("verdict does not reference the signed claim")

    outcome = verdict_payload.get("outcome")
    if outcome not in OUTCOMES:
        raise ReceiptError("verdict outcome must be PASS, FAIL, or UNRESOLVED")
    if receipt_payload.get("certified_exit") != outcome:
        raise ReceiptError("receipt certified_exit does not match verifier outcome")
    if receipt_payload.get("original_promise") != manifest_payload.get("target"):
        raise ReceiptError("receipt original_promise does not match manifest target")
    if receipt_payload.get("test_results") != verdict_payload.get("test_results"):
        raise ReceiptError("receipt test_results do not match verifier results")
    if receipt_payload.get("disagreements") != verdict_payload.get("disagreements"):
        raise ReceiptError("receipt disagreements do not match verifier verdict")
    if receipt["signer"] != manifest["signer"]:
        raise ReceiptError("receipt issuer must match the manifest issuer")
    if receipt["signer"] in {claim["signer"], verdict["signer"]}:
        raise ReceiptError("receipt issuer must be independent of worker and verifier")
    if claim["signer"] == verdict["signer"]:
        raise ReceiptError("worker and verifier must use separate DIDs")

    return {
        "certified_exit": outcome,
        "integrity": "PASS",
        "signers": {
            "issuer": receipt["signer"],
            "manifest_issuer": manifest["signer"],
            "verifier": verdict["signer"],
            "worker": claim["signer"],
        },
        "task_id": task_id,
    }
