"""Verify the public release without private material."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from resolution_receipt.core import (
    ReceiptError,
    hash_object,
    load_json,
    verify_bundle,
    verify_envelope,
    verify_technocore_request,
)

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
ROOM = "resolution-2332dba3f6ba"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def tracked_files() -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [part.decode("utf-8") for part in raw.split(b"\0") if part]


def audit_tracked_boundary() -> None:
    protected_names = {
        ".env",
        "manifest.payload.json",
        "policy.salt",
        "receipt.payload.json",
        "release-attestation.payload.json",
        "run-policy.json",
    }
    for path in tracked_files():
        candidate = Path(path)
        require(not path.startswith(".private/"), f"private path is tracked: {path}")
        require(
            candidate.name not in protected_names, f"protected file is tracked: {path}"
        )
        require(
            candidate.suffix not in {".key", ".seed", ".pyc"},
            f"secret or cache file is tracked: {path}",
        )


def main() -> None:
    audit_tracked_boundary()

    manifest = load_json(PUBLIC / "manifest.signed.json")
    claim = load_json(PUBLIC / "claim.signed.json")
    verdict = load_json(PUBLIC / "verdict.signed.json")
    receipt = load_json(PUBLIC / "receipt.signed.json")
    summary = load_json(PUBLIC / "verification-summary.json")
    commitment = load_json(PUBLIC / "policy-commitment.json")
    attestation = load_json(PUBLIC / "release-attestation.signed.json")
    publication = load_json(PUBLIC / "evidence" / "technocore-publication-request.json")

    bundle = verify_bundle(
        manifest=manifest,
        claim=claim,
        verdict=verdict,
        receipt=receipt,
    )
    manifest_payload = verify_envelope(manifest, expected_kind="task-manifest")
    verify_envelope(receipt, expected_kind="resolution-receipt")
    release_payload = verify_envelope(attestation, expected_kind="release-attestation")

    require(
        bundle["integrity"] == summary["bundle_integrity"], "summary integrity mismatch"
    )
    require(
        bundle["certified_exit"] == summary["certified_exit"], "summary exit mismatch"
    )
    require(
        hash_object(receipt) == summary["receipt_hash"], "summary receipt hash mismatch"
    )
    require(
        manifest_payload["policy_commitment"] == commitment,
        "policy commitment mismatch",
    )
    require(attestation["signer"] == receipt["signer"], "release issuer mismatch")
    require(release_payload["task_id"] == bundle["task_id"], "release task mismatch")
    require(
        release_payload["receipt_hash"] == hash_object(receipt),
        "release receipt mismatch",
    )

    expected_hashes = {
        "claim": hash_object(claim),
        "manifest": hash_object(manifest),
        "receipt": hash_object(receipt),
        "verdict": hash_object(verdict),
    }
    require(
        release_payload["artifact_hashes"] == expected_hashes,
        "release artifact hash mismatch",
    )

    verify_technocore_request(room=ROOM, request=publication)
    require(publication["did"] == receipt["signer"], "publication issuer mismatch")
    expected_text = (
        f"{bundle['task_id']} release {release_payload['repository']} "
        f"receipt {release_payload['receipt_hash']} attestation {hash_object(attestation)}"
    )
    require(publication["text"] == expected_text, "publication text mismatch")

    print(
        json.dumps(
            {
                "bundle_integrity": bundle["integrity"],
                "certified_exit": bundle["certified_exit"],
                "publication_signature": "PASS",
                "release_attestation": hash_object(attestation),
                "tracked_boundary": "PASS",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
