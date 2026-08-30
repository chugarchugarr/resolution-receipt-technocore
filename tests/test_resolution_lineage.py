from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from resolution_receipt.core import ReceiptError, create_key, hash_object, sign_envelope
from resolution_receipt.resolution import (
    RESOLUTION_KIND,
    build_resolution_payload,
    derive_resolution_state,
    sign_resolution,
    verify_resolution,
    verify_resolution_lineage,
)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def evidence() -> dict[str, dict[str, str | None]]:
    return {
        "repro": {
            "kind": "test-output",
            "digest": DIGEST_A,
            "uri": "https://example.invalid/repro",
        },
        "review": {
            "kind": "review",
            "digest": DIGEST_B,
            "uri": None,
        },
    }


def check(
    check_id: str,
    outcome: str,
    refs: list[str],
    *,
    required: bool = True,
) -> dict[str, object]:
    return {
        "id": check_id,
        "requirement": f"{check_id} requirement",
        "required": required,
        "outcome": outcome,
        "evidence": refs,
    }


class ResolutionStateTests(unittest.TestCase):
    def test_survived_requires_all_required_checks_to_pass(self) -> None:
        checks = [check("reproduced", "PASS", ["repro"])]
        payload = build_resolution_payload(
            subject="github:flop-labs/technocore-chat#149",
            original_target="separate activity from resolved work",
            effective_target="separate activity from resolved work",
            evidence=evidence(),
            checks=checks,
        )
        self.assertEqual(payload["state"], "SURVIVED")

    def test_narrowed_is_derived_only_after_required_checks_pass(self) -> None:
        checks = [check("bounded-proof", "PASS", ["repro"])]
        self.assertEqual(
            derive_resolution_state(
                original_target="prove all useful work",
                effective_target="prove bounded test completion",
                checks=checks,
            ),
            "NARROWED",
        )

    def test_known_failure_dominates_unresolved(self) -> None:
        checks = [
            check("behavior", "FAIL", ["repro"]),
            check("acceptance", "UNRESOLVED", []),
        ]
        self.assertEqual(
            derive_resolution_state(
                original_target="target",
                effective_target="target",
                checks=checks,
            ),
            "FAILED",
        )

    def test_unresolved_when_required_evidence_is_missing(self) -> None:
        checks = [check("acceptance", "UNRESOLVED", [])]
        payload = build_resolution_payload(
            subject="pr:123",
            original_target="land upstream",
            effective_target="land upstream",
            evidence=evidence(),
            checks=checks,
        )
        self.assertEqual(payload["state"], "UNRESOLVED")

    def test_resolved_check_must_cite_known_evidence(self) -> None:
        with self.assertRaisesRegex(ReceiptError, "unknown evidence"):
            build_resolution_payload(
                subject="pr:123",
                original_target="target",
                effective_target="target",
                evidence=evidence(),
                checks=[check("ci", "PASS", ["missing"])],
            )
        with self.assertRaisesRegex(ReceiptError, "must cite evidence"):
            build_resolution_payload(
                subject="pr:123",
                original_target="target",
                effective_target="target",
                evidence=evidence(),
                checks=[check("ci", "PASS", [])],
            )

    def test_at_least_one_check_must_be_required(self) -> None:
        with self.assertRaisesRegex(ReceiptError, "at least one check"):
            build_resolution_payload(
                subject="pr:123",
                original_target="target",
                effective_target="target",
                evidence=evidence(),
                checks=[check("optional", "PASS", ["repro"], required=False)],
            )


class ResolutionLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.key_path = str(Path(self.tempdir.name) / "resolver.json")
        create_key(self.key_path, label="resolver")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _first(self) -> dict[str, object]:
        return sign_resolution(
            subject="github:flop-labs/technocore-chat#149",
            original_target="distinguish activity from resolution",
            effective_target="distinguish activity from resolution",
            evidence=evidence(),
            checks=[check("metric", "FAIL", ["repro"])],
            key_path=self.key_path,
        )

    def test_signed_resolution_verifies(self) -> None:
        record = self._first()
        payload = verify_resolution(record)
        self.assertEqual(payload["state"], "FAILED")

    def test_state_cannot_be_freely_declared(self) -> None:
        payload = build_resolution_payload(
            subject="pr:123",
            original_target="target",
            effective_target="target",
            evidence=evidence(),
            checks=[check("ci", "FAIL", ["repro"])],
        )
        payload["state"] = "SURVIVED"
        malicious = sign_envelope(RESOLUTION_KIND, payload, self.key_path)
        with self.assertRaisesRegex(ReceiptError, "does not match"):
            verify_resolution(malicious)

    def test_correction_preserves_prior_record_by_hash(self) -> None:
        first = self._first()
        second = sign_resolution(
            subject="github:flop-labs/technocore-chat#149",
            original_target="distinguish activity from resolution",
            effective_target="distinguish verified activity from scoped resolution",
            evidence=evidence(),
            checks=[
                check("metric", "PASS", ["repro"]),
                check("acceptance", "PASS", ["review"]),
            ],
            key_path=self.key_path,
            previous=first,
            revision_reason="new evidence narrowed the claim",
        )
        result = verify_resolution_lineage([first, second])
        self.assertEqual(result["state"], "NARROWED")
        self.assertEqual(result["records"], 2)
        self.assertEqual(result["head"], hash_object(second))

    def test_rewriting_history_breaks_lineage(self) -> None:
        first = self._first()
        second = sign_resolution(
            subject="github:flop-labs/technocore-chat#149",
            original_target="distinguish activity from resolution",
            effective_target="distinguish activity from resolution",
            evidence=evidence(),
            checks=[check("metric", "PASS", ["repro"])],
            key_path=self.key_path,
            previous=first,
            revision_reason="new evidence",
        )
        rewritten = copy.deepcopy(first)
        rewritten["payload"]["effective_target"] = "rewritten history"
        with self.assertRaises(ReceiptError):
            verify_resolution_lineage([rewritten, second])

    def test_lineage_cannot_change_subject(self) -> None:
        first = self._first()
        second = sign_resolution(
            subject="github:flop-labs/technocore-chat#225",
            original_target="distinguish activity from resolution",
            effective_target="distinguish activity from resolution",
            evidence=evidence(),
            checks=[check("metric", "PASS", ["repro"])],
            key_path=self.key_path,
            previous=first,
            revision_reason="wrong subject",
        )
        with self.assertRaisesRegex(ReceiptError, "changed subject"):
            verify_resolution(second, previous=first)


if __name__ == "__main__":
    unittest.main()
