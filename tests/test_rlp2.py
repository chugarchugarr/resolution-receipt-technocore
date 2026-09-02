from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from resolution_receipt.authority import AUTHORITY_POLICY_VERSION
from resolution_receipt.core import ReceiptError, create_key, hash_object
from resolution_receipt.policy import derive_action_decision
from resolution_receipt.resolution import sign_resolution
from resolution_receipt.rlp2 import (
    sign_rlp2_resolution,
    verify_rlp2_lineage,
    verify_rlp2_resolution,
)


METHOD_DIGEST = "sha256:" + "a" * 64
ARTIFACT_DIGEST = "sha256:" + "b" * 64


def synthetic_adapter(descriptor, claims):
    expected = claims.get("digest")
    if expected is None:
        return None
    return descriptor.get("digest") == expected


def unresolved_adapter(descriptor, claims):
    return None


def evidence():
    return {
        "test": {
            "kind": "synthetic-test-output",
            "digest": ARTIFACT_DIGEST,
            "uri": None,
        }
    }


def specs(expected=ARTIFACT_DIGEST, method="synthetic/v1"):
    return {
        "test": {
            "method": method,
            "method_digest": METHOD_DIGEST,
            "claims": {"digest": expected},
        }
    }


def checks(outcome="PASS", refs=None):
    if refs is None:
        refs = ["test"] if outcome in {"PASS", "FAIL"} else []
    return [
        {
            "id": "bounded-check",
            "requirement": "synthetic evidence supports the bounded target",
            "required": True,
            "outcome": outcome,
            "evidence": refs,
        }
    ]


def scope(items=None):
    return {"adapter": "string-set/v1", "value": items or ["alpha", "beta"]}


def policy(mode, principals, *, threshold=None, external=None):
    return {
        "policy_version": AUTHORITY_POLICY_VERSION,
        "policy_id": "test-authority",
        "mode": mode,
        "principals": principals,
        "threshold": threshold,
        "external_evidence": external or [],
        "failure_mode": "ABSTAIN",
    }


def action_policy():
    return {
        "policy_version": "rlp.action.v2",
        "policy_id": "test-action",
        "rules": [
            {
                "action": "execute",
                "allowed_resolution_states": ["SURVIVED", "NARROWED"],
                "require_authority": "AUTHORIZED",
                "require_scope_containment": True,
            }
        ],
        "default": "HOLD",
    }


class RLP2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.a = str(root / "a.json")
        self.b = str(root / "b.json")
        self.c = str(root / "c.json")
        self.did_a = create_key(self.a, label="a")
        self.did_b = create_key(self.b, label="b")
        self.did_c = create_key(self.c, label="c")
        self.adapters = {"synthetic/v1": synthetic_adapter}

    def tearDown(self):
        self.temp.cleanup()

    def sign(self, *, authority=None, keys=None, previous=None, revision=None,
             transition_keys=None, verification_specs=None, adapters=None,
             outcome="PASS", effective_target="target", effective_scope=None):
        return sign_rlp2_resolution(
            subject="example:1",
            original_target="target",
            effective_target=effective_target,
            original_scope=scope(),
            effective_scope=effective_scope or scope(),
            evidence=evidence(),
            verification_specs=verification_specs or specs(),
            verification_adapters=adapters or self.adapters,
            authority_policy=authority or policy("EXACT", [self.did_a]),
            checks=checks(outcome),
            key_paths=keys or [self.a],
            previous=previous,
            revision_reason=revision,
            transition_key_paths=transition_keys,
        )

    def test_exact_authority_survives_and_recomputes_native_verification(self):
        record = self.sign()
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["state"], "SURVIVED")
        self.assertEqual(result["authority_state"], "AUTHORIZED")
        self.assertEqual(result["native_verification"], "RECOMPUTED")

    def test_invalid_evidence_cannot_support_resolved_check(self):
        with self.assertRaisesRegex(ReceiptError, "not VERIFIED"):
            self.sign(verification_specs=specs("sha256:" + "c" * 64))

    def test_unresolved_evidence_cannot_support_resolved_check(self):
        with self.assertRaisesRegex(ReceiptError, "not VERIFIED"):
            self.sign(adapters={"synthetic/v1": unresolved_adapter})

    def test_unresolved_check_can_preserve_unresolved_evidence(self):
        record = self.sign(
            adapters={"synthetic/v1": unresolved_adapter}, outcome="UNRESOLVED"
        )
        result = verify_rlp2_resolution(
            record, verification_adapters={"synthetic/v1": unresolved_adapter}
        )
        self.assertEqual(result["state"], "UNRESOLVED")

    def test_known_unauthorized_actor_is_separate_from_resolution(self):
        record = self.sign(
            authority=policy("EXACT", [self.did_b]), keys=[self.a]
        )
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["state"], "SURVIVED")
        self.assertEqual(result["authority_state"], "UNAUTHORIZED")

    def test_threshold_incomplete_is_unresolved_authority(self):
        record = self.sign(
            authority=policy("THRESHOLD", [self.did_a, self.did_b], threshold=2),
            keys=[self.a],
        )
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["authority_state"], "UNRESOLVED")

    def test_threshold_complete_is_authorized(self):
        record = self.sign(
            authority=policy("THRESHOLD", [self.did_a, self.did_b], threshold=2),
            keys=[self.a, self.b],
        )
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["authority_state"], "AUTHORIZED")

    def test_tampered_authority_state_is_rejected_by_signature(self):
        record = self.sign()
        tampered = copy.deepcopy(record)
        tampered["payload"]["authority_state"] = "UNAUTHORIZED"
        with self.assertRaises(ReceiptError):
            verify_rlp2_resolution(tampered)

    def test_authorized_policy_transition(self):
        first = self.sign()
        second = self.sign(
            authority=policy("EXACT", [self.did_b]),
            keys=[self.b],
            previous=first,
            revision="rotate resolver authority",
            transition_keys=[self.a],
        )
        result = verify_rlp2_lineage(
            [first, second], verification_adapters=self.adapters
        )
        self.assertEqual(result["authority_state"], "AUTHORIZED")
        self.assertEqual(result["records"], 2)

    def test_unauthorized_policy_transition_is_rejected(self):
        first = self.sign()
        second = self.sign(
            authority=policy("EXACT", [self.did_b]),
            keys=[self.b],
            previous=first,
            revision="attempt unauthorized authority replacement",
            transition_keys=[self.b],
        )
        with self.assertRaisesRegex(ReceiptError, "not authorized"):
            verify_rlp2_resolution(
                second, previous=first, verification_adapters=self.adapters
            )

    def test_lineage_rewrite_breaks_hash_or_signature(self):
        first = self.sign()
        second = self.sign(previous=first, revision="new evidence")
        rewritten = copy.deepcopy(first)
        rewritten["payload"]["body"]["effective_target"] = "rewritten"
        with self.assertRaises(ReceiptError):
            verify_rlp2_lineage([rewritten, second], verification_adapters=self.adapters)

    def test_narrowed_scope_is_preserved(self):
        record = self.sign(
            effective_target="narrow target",
            effective_scope=scope(["alpha"]),
        )
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["state"], "NARROWED")

    def test_action_permit_inside_narrowed_scope(self):
        record = self.sign(
            effective_target="narrow target",
            effective_scope=scope(["alpha"]),
        )
        verified = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        decision = derive_action_decision(
            action_id="execute",
            requested_scope=scope(["alpha"]),
            resolution_state=verified["state"],
            authority_state=verified["authority_state"],
            effective_scope=verified["effective_scope"],
            lineage_integrity=verified["integrity"],
            policy=action_policy(),
            resolution_head=verified["head"],
        )
        self.assertEqual(decision["decision"], "PERMIT")

    def test_action_denied_outside_narrowed_scope(self):
        record = self.sign(
            effective_target="narrow target",
            effective_scope=scope(["alpha"]),
        )
        verified = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        decision = derive_action_decision(
            action_id="execute",
            requested_scope=scope(["beta"]),
            resolution_state=verified["state"],
            authority_state=verified["authority_state"],
            effective_scope=verified["effective_scope"],
            lineage_integrity="PASS",
            policy=action_policy(),
            resolution_head=verified["head"],
        )
        self.assertEqual(decision["decision"], "DENY")

    def test_action_holds_on_unresolved_authority(self):
        record = self.sign(
            authority=policy("THRESHOLD", [self.did_a, self.did_b], threshold=2),
            keys=[self.a],
        )
        verified = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        decision = derive_action_decision(
            action_id="execute",
            requested_scope=scope(["alpha"]),
            resolution_state=verified["state"],
            authority_state=verified["authority_state"],
            effective_scope=verified["effective_scope"],
            lineage_integrity="PASS",
            policy=action_policy(),
            resolution_head=verified["head"],
        )
        self.assertEqual(decision["decision"], "HOLD")

    def test_action_holds_when_rule_missing(self):
        record = self.sign()
        verified = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        decision = derive_action_decision(
            action_id="unknown-action",
            requested_scope=scope(),
            resolution_state=verified["state"],
            authority_state=verified["authority_state"],
            effective_scope=verified["effective_scope"],
            lineage_integrity="PASS",
            policy=action_policy(),
            resolution_head=verified["head"],
        )
        self.assertEqual(decision["decision"], "HOLD")

    def test_rlp1_can_be_preserved_as_ancestor(self):
        first = sign_resolution(
            subject="example:1",
            original_target="target",
            effective_target="target",
            evidence=evidence(),
            checks=checks(),
            key_path=self.a,
        )
        second = self.sign(previous=first, revision="upgrade lineage to RLP-2")
        result = verify_rlp2_lineage(
            [first, second], verification_adapters=self.adapters
        )
        self.assertEqual(result["records"], 2)
        self.assertEqual(second["payload"]["body"]["previous_profile"], "RLP-1")

    def test_action_decision_binds_exact_resolution_head(self):
        record = self.sign()
        verified = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        decision = derive_action_decision(
            action_id="execute",
            requested_scope=scope(["alpha"]),
            resolution_state=verified["state"],
            authority_state=verified["authority_state"],
            effective_scope=verified["effective_scope"],
            lineage_integrity="PASS",
            policy=action_policy(),
            resolution_head=verified["head"],
        )
        self.assertEqual(decision["resolution_head"], hash_object(record))


if __name__ == "__main__":
    unittest.main()
