from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from resolution_receipt.core import (
    ReceiptError,
    canonical_bytes,
    create_key,
    hash_object,
    load_json,
    policy_commitment,
    sign_envelope,
    technocore_request,
    verify_bundle,
    verify_envelope,
    verify_technocore_request,
)


class CoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.issuer = self.root / "issuer.key"
        self.worker = self.root / "worker.key"
        self.verifier = self.root / "verifier.key"
        create_key(self.issuer, label="issuer")
        create_key(self.worker, label="worker")
        create_key(self.verifier, label="verifier")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_json_and_strict_loader(self) -> None:
        self.assertEqual(canonical_bytes({"b": 2, "a": "é"}), b'{"a":"\xc3\xa9","b":2}')
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
        with self.assertRaises(ReceiptError):
            load_json(duplicate)
        floating = self.root / "float.json"
        floating.write_text('{"a":1.5}', encoding="utf-8")
        with self.assertRaises(ReceiptError):
            load_json(floating)

    def test_sign_verify_and_tamper_detection(self) -> None:
        envelope = sign_envelope("task-manifest", {"task_id": "t1"}, self.issuer)
        self.assertEqual(verify_envelope(envelope), {"task_id": "t1"})
        envelope["payload"]["task_id"] = "changed"
        with self.assertRaises(ReceiptError):
            verify_envelope(envelope)

    def test_policy_commitment_is_salted(self) -> None:
        policy = {"private": "value"}
        salt_a = b"a" * 32
        salt_b = b"b" * 32
        self.assertEqual(
            policy_commitment(policy, salt_a), policy_commitment(policy, salt_a)
        )
        self.assertNotEqual(
            policy_commitment(policy, salt_a), policy_commitment(policy, salt_b)
        )

    def test_technocore_signature(self) -> None:
        request = technocore_request(
            room="receipt_demo", nonce="1001", text="bounded test", key_path=self.worker
        )
        self.assertTrue(verify_technocore_request(room="receipt_demo", request=request))
        request["text"] = "tampered"
        with self.assertRaises(ReceiptError):
            verify_technocore_request(room="receipt_demo", request=request)

    def test_complete_bundle(self) -> None:
        manifest = sign_envelope(
            "task-manifest", {"target": "bounded promise", "task_id": "t1"}, self.issuer
        )
        claim = sign_envelope(
            "worker-claim",
            {"manifest_hash": hash_object(manifest), "task_id": "t1"},
            self.worker,
        )
        results = [{"id": "T1", "result": "PASS"}]
        verdict = sign_envelope(
            "verifier-verdict",
            {
                "claim_hash": hash_object(claim),
                "disagreements": [],
                "manifest_hash": hash_object(manifest),
                "outcome": "PASS",
                "task_id": "t1",
                "test_results": results,
            },
            self.verifier,
        )
        receipt = sign_envelope(
            "resolution-receipt",
            {
                "certified_exit": "PASS",
                "disagreements": [],
                "evidence_hashes": {
                    "claim": hash_object(claim),
                    "manifest": hash_object(manifest),
                    "verdict": hash_object(verdict),
                },
                "issued_at": "2026-08-24T12:00:00Z",
                "original_promise": "bounded promise",
                "task_id": "t1",
                "test_results": results,
            },
            self.issuer,
        )
        result = verify_bundle(
            manifest=manifest, claim=claim, verdict=verdict, receipt=receipt
        )
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["certified_exit"], "PASS")

        receipt["payload"]["evidence_hashes"]["claim"] = "sha256:" + "0" * 64
        with self.assertRaises(ReceiptError):
            verify_bundle(
                manifest=manifest, claim=claim, verdict=verdict, receipt=receipt
            )

    def test_receipt_issuer_must_match_manifest_issuer(self) -> None:
        other_issuer = self.root / "other-issuer.key"
        create_key(other_issuer, label="other issuer")
        manifest = sign_envelope(
            "task-manifest", {"target": "bounded promise", "task_id": "t2"}, self.issuer
        )
        claim = sign_envelope(
            "worker-claim",
            {"manifest_hash": hash_object(manifest), "task_id": "t2"},
            self.worker,
        )
        results = [{"id": "T1", "result": "FAIL"}]
        verdict = sign_envelope(
            "verifier-verdict",
            {
                "claim_hash": hash_object(claim),
                "disagreements": [],
                "manifest_hash": hash_object(manifest),
                "outcome": "FAIL",
                "task_id": "t2",
                "test_results": results,
            },
            self.verifier,
        )
        receipt = sign_envelope(
            "resolution-receipt",
            {
                "certified_exit": "FAIL",
                "disagreements": [],
                "evidence_hashes": {
                    "claim": hash_object(claim),
                    "manifest": hash_object(manifest),
                    "verdict": hash_object(verdict),
                },
                "issued_at": "2026-08-24T12:00:00Z",
                "original_promise": "bounded promise",
                "task_id": "t2",
                "test_results": results,
            },
            other_issuer,
        )
        with self.assertRaises(ReceiptError):
            verify_bundle(
                manifest=manifest, claim=claim, verdict=verdict, receipt=receipt
            )


if __name__ == "__main__":
    unittest.main()
