from __future__ import annotations

import unittest
from pathlib import Path

from resolution_receipt.core import hash_object, load_json
from resolution_receipt.resolution import verify_resolution


CLAIM_DIR = (
    Path(__file__).resolve().parents[1]
    / "public"
    / "claims"
    / "glamsterdam-write-prepayment"
)


class PublicClaimTests(unittest.TestCase):
    def test_glamsterdam_claim_is_bound_and_unresolved(self) -> None:
        evidence = load_json(CLAIM_DIR / "evidence-pr-head.json")
        resolution = load_json(CLAIM_DIR / "resolution-0001.json")

        self.assertEqual(
            resolution["payload"]["evidence"]["pr-head"]["digest"],
            hash_object(evidence),
        )

        payload = verify_resolution(resolution)
        self.assertEqual(payload["subject"], "github:chugarchugarr/execution-specs#2")
        self.assertEqual(payload["state"], "UNRESOLVED")
        self.assertEqual(
            payload["checks"][-1]["id"],
            "external-falsification",
        )
        self.assertEqual(payload["checks"][-1]["outcome"], "UNRESOLVED")


if __name__ == "__main__":
    unittest.main()
