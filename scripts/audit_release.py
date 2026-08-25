"""Verify the public release without private material."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from resolution_receipt.core import (
    ReceiptError,
    hash_object,
    load_json,
    verify_bundle,
    verify_envelope,
    verify_technocore_record,
    verify_technocore_request,
)

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
ROOM = "resolution-2332dba3f6ba"
V2 = PUBLIC / "v2"
V2_ROOM = "resolution-pass-697b4af00819"


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


def raw_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


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

    v2_manifest = load_json(V2 / "manifest.signed.json")
    v2_claim = load_json(V2 / "claim.signed.json")
    v2_verdict = load_json(V2 / "verdict.signed.json")
    v2_receipt = load_json(V2 / "receipt.signed.json")
    v2_summary = load_json(V2 / "verification-summary.json")
    v2_attestation = load_json(V2 / "release-attestation.signed.json")
    v2_request = load_json(V2 / "evidence" / "technocore-request.json")
    v2_record = load_json(V2 / "evidence" / "technocore-record.json")
    v2_worker_evidence = load_json(V2 / "evidence" / "worker-evidence.json")
    v2_verifier_evidence = load_json(V2 / "evidence" / "verifier-evidence.json")

    v2_bundle = verify_bundle(
        manifest=v2_manifest,
        claim=v2_claim,
        verdict=v2_verdict,
        receipt=v2_receipt,
    )
    v2_manifest_payload = verify_envelope(v2_manifest, expected_kind="task-manifest")
    v2_claim_payload = verify_envelope(v2_claim, expected_kind="worker-claim")
    v2_verdict_payload = verify_envelope(v2_verdict, expected_kind="verifier-verdict")
    v2_receipt_payload = verify_envelope(v2_receipt, expected_kind="resolution-receipt")
    v2_release_payload = verify_envelope(
        v2_attestation, expected_kind="release-attestation"
    )

    require(v2_bundle["integrity"] == "PASS", "v2 bundle integrity")
    require(v2_bundle["certified_exit"] == "PASS", "v2 certified exit")
    require(
        all(
            result["result"] == "PASS" for result in v2_verdict_payload["test_results"]
        ),
        "v2 acceptance test failure",
    )
    require(
        [result["id"] for result in v2_verdict_payload["test_results"]]
        == ["T1", "T2", "T3", "T4"],
        "v2 acceptance test IDs",
    )
    require(
        v2_manifest_payload["policy_commitment"] == commitment,
        "v2 policy commitment mismatch",
    )
    require(
        v2_manifest_payload["prior_finding"]["receipt_hash"] == hash_object(receipt),
        "v2 prior finding mismatch",
    )
    require(
        v2_receipt_payload["prior_receipt_hash"] == hash_object(receipt),
        "v2 receipt history mismatch",
    )
    require(v2_summary["certified_exit"] == "PASS", "v2 summary exit")
    require(v2_summary["bundle_integrity"] == "PASS", "v2 summary integrity")
    require(
        v2_summary["receipt_hash"] == hash_object(v2_receipt),
        "v2 summary receipt hash",
    )
    require(
        v2_summary["release_attestation_hash"] == hash_object(v2_attestation),
        "v2 summary attestation hash",
    )

    v2_expected_hashes = {
        "claim": hash_object(v2_claim),
        "manifest": hash_object(v2_manifest),
        "receipt": hash_object(v2_receipt),
        "verdict": hash_object(v2_verdict),
    }
    require(
        v2_release_payload["artifact_hashes"] == v2_expected_hashes,
        "v2 release artifact hash mismatch",
    )
    require(
        v2_release_payload["receipt_hash"] == hash_object(v2_receipt),
        "v2 release receipt mismatch",
    )
    require(
        v2_release_payload["prior_receipt_hash"] == hash_object(receipt),
        "v2 release history mismatch",
    )

    verify_technocore_request(room=V2_ROOM, request=v2_request)
    verified_record = verify_technocore_record(room=V2_ROOM, record=v2_record)
    require(v2_request["did"] == v2_record["from"], "v2 request signer")
    require(v2_request["nonce"] == str(v2_record["nonce"]), "v2 request nonce")
    require(v2_request["text"] == v2_record["text"], "v2 request text")
    require(verified_record["signer"] == v2_claim["signer"], "v2 worker signer")
    require(
        v2_claim_payload["evidence_hashes"]["worker_evidence"]
        == hash_object(v2_worker_evidence),
        "v2 worker evidence hash",
    )
    require(
        v2_verdict_payload["evidence_hash"] == hash_object(v2_verifier_evidence),
        "v2 verifier evidence hash",
    )
    require(
        all(v2_verifier_evidence["tamper_tests"].values()),
        "v2 tamper tests",
    )
    v2_write_response = v2_worker_evidence["live_write"]["response"]
    v2_read_response = v2_worker_evidence["live_read"]["response"]
    require(
        raw_hash(v2_write_response["body_utf8"]) == v2_write_response["body_sha256"],
        "v2 write body hash",
    )
    require(
        raw_hash(v2_read_response["body_utf8"]) == v2_read_response["body_sha256"],
        "v2 read body hash",
    )
    require(
        json.loads(v2_read_response["body_utf8"])["messages"] == [v2_record],
        "v2 read response record mismatch",
    )

    print(
        json.dumps(
            {
                "latest_bundle_integrity": v2_bundle["integrity"],
                "latest_certified_exit": v2_bundle["certified_exit"],
                "latest_receipt": hash_object(v2_receipt),
                "latest_release_attestation": hash_object(v2_attestation),
                "prior_bundle_integrity": bundle["integrity"],
                "prior_certified_exit": bundle["certified_exit"],
                "prior_publication_signature": "PASS",
                "tracked_boundary": "PASS",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
