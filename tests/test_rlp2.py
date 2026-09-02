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
    verify_and_decide_action,
    verify_and_decide_action_heads,
    verify_rlp2_lineage,
    verify_rlp2_resolution,
)
from resolution_receipt.verification import (
    adapter_code_digest,
    validate_verification_results,
)


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


def specs(expected=ARTIFACT_DIGEST, method="synthetic/v1", adapter=synthetic_adapter):
    return {
        "test": {
            "method": method,
            "method_digest": adapter_code_digest(adapter),
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
        adapter_map = self.adapters if adapters is None else adapters
        if verification_specs is None:
            adapter_for_spec = adapter_map.get("synthetic/v1", synthetic_adapter)
            verification_specs = specs(adapter=adapter_for_spec)
        return sign_rlp2_resolution(
            subject="example:1",
            original_target="target",
            effective_target=effective_target,
            original_scope=scope(),
            effective_scope=effective_scope or scope(),
            evidence=evidence(),
            verification_specs=verification_specs,
            verification_adapters=adapter_map,
            authority_policy=authority or policy("EXACT", [self.did_a]),
            checks=checks(outcome),
            key_paths=keys or [self.a],
            previous=previous,
            revision_reason=revision,
            transition_key_paths=transition_keys,
        )

    def rlp1(self):
        return sign_resolution(
            subject="example:1",
            original_target="target",
            effective_target="target",
            evidence=evidence(),
            checks=checks(),
            key_path=self.a,
        )

    def test_exact_authority_survives_and_recomputes_native_verification(self):
        record = self.sign()
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["state"], "SURVIVED")
        self.assertEqual(result["authority_state"], "AUTHORIZED")
        self.assertEqual(result["native_verification"], "RECOMPUTED")

    def test_any_of_authority(self):
        record = self.sign(
            authority=policy("ANY_OF", [self.did_a, self.did_b]), keys=[self.a]
        )
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["authority_state"], "AUTHORIZED")

    def test_all_of_authority_requires_all_principals(self):
        incomplete = self.sign(
            authority=policy("ALL_OF", [self.did_a, self.did_b]), keys=[self.a]
        )
        self.assertEqual(
            verify_rlp2_resolution(incomplete, verification_adapters=self.adapters)["authority_state"],
            "UNRESOLVED",
        )
        complete = self.sign(
            authority=policy("ALL_OF", [self.did_a, self.did_b]), keys=[self.a, self.b]
        )
        self.assertEqual(
            verify_rlp2_resolution(complete, verification_adapters=self.adapters)["authority_state"],
            "AUTHORIZED",
        )

    def test_external_authority_requires_verified_external_evidence(self):
        record = self.sign(
            authority=policy("EXTERNAL", [self.did_a], external=["test"]),
            keys=[self.a],
        )
        result = verify_rlp2_resolution(record, verification_adapters=self.adapters)
        self.assertEqual(result["authority_state"], "AUTHORIZED")

    def test_invalid_evidence_cannot_support_resolved_check(self):
        with self.assertRaisesRegex(ReceiptError, "not VERIFIED"):
            self.sign(verification_specs=specs("sha256:" + "c" * 64))

    def test_unresolved_evidence_cannot_support_resolved_check(self):
        with self.assertRaisesRegex(ReceiptError, "not VERIFIED"):
            self.sign(adapters={"synthetic/v1": unresolved_adapter})

    def test_unresolved_check_can_preserve_unresolved_evidence(self):
        adapter_map = {"synthetic/v1": unresolved_adapter}
        record = self.sign(adapters=adapter_map, outcome="UNRESOLVED")
        result = verify_rlp2_resolution(record, verification_adapters=adapter_map)
        self.assertEqual(result["state"], "UNRESOLVED")

    def test_adapter_substitution_is_rejected(self):
        declared = specs(adapter=synthetic_adapter)
        with self.assertRaisesRegex(ReceiptError, "adapter digest mismatch"):
            self.sign(
                verification_specs=declared,
                adapters={"synthetic/v1": unresolved_adapter},
                outcome="UNRESOLVED",
            )

    def test_verification_result_metadata_must_match_spec(self):
        declared = specs()
        forged = {
            "test": {
                "method": "other/v1",
                "method_digest": declared["test"]["method_digest"],
                "claims_digest": hash_object(declared["test"]["claims"]),
                "result": "VERIFIED",
            }
        }
        with self.assertRaisesRegex(ReceiptError, "method does not match spec"):
            validate_verification_results(evidence(), forged, specs=declared)

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

    def test_scope_cannot_broaden_while_claiming_narrowing(self):
        with self.assertRaisesRegex(ReceiptError, "exceeds original_scope"):
            self.sign(
                effective_target="narrow target",
                effective_scope=scope(["alpha", "beta", "gamma"]),
            )

    def test_scope_cannot_change_while_target_survives(self):
        with self.assertRaisesRegex(ReceiptError, "requires a NARROWED"):
            self.sign(effective_scope=scope(["alpha"]))

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

    def test_integrated_action_path_derives_authority_from_lineage(self):
        first = self.rlp1()
        second = self.sign(
            previous=first,
            revision="bootstrap RLP-2 without external authority",
        )
        decision = verify_and_decide_action(
            [first, second],
            action_id="execute",
            requested_scope=scope(["alpha"]),
            policy=action_policy(),
            verification_adapters=self.adapters,
        )
        self.assertEqual(decision["authority_state"], "UNRESOLVED")
        self.assertEqual(decision["decision"], "HOLD")

    def test_rlp1_bootstrap_cannot_self_authorize(self):
        first = self.rlp1()
        second = self.sign(
            previous=first,
            revision="introduce RLP-2 authority policy",
        )
        result = verify_rlp2_lineage(
            [first, second], verification_adapters=self.adapters
        )
        self.assertEqual(result["authority_state"], "UNRESOLVED")

    def test_rlp1_bootstrap_can_use_verified_external_authority(self):
        first = self.rlp1()
        second = self.sign(
            authority=policy("EXTERNAL", [self.did_a], external=["test"]),
            previous=first,
            revision="bootstrap from verified external authority evidence",
        )
        result = verify_rlp2_lineage(
            [first, second], verification_adapters=self.adapters
        )
        self.assertEqual(result["authority_state"], "AUTHORIZED")

    def test_rlp1_can_be_preserved_as_ancestor(self):
        first = self.rlp1()
        second = self.sign(previous=first, revision="upgrade lineage to RLP-2")
        result = verify_rlp2_lineage(
            [first, second], verification_adapters=self.adapters
        )
        self.assertEqual(result["records"], 2)
        self.assertEqual(second["payload"]["body"]["previous_profile"], "RLP-1")

    def test_standalone_successor_verifies_structurally(self):
        first = self.sign()
        second = self.sign(previous=first, revision="new evidence")
        result = verify_rlp2_resolution(second, verification_adapters=self.adapters)
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["authority_state"], "AUTHORIZED")

    def test_competing_heads_force_action_hold(self):
        first = self.sign()
        left = self.sign(
            previous=first,
            revision="left branch",
            effective_target="left narrowed target",
            effective_scope=scope(["alpha"]),
        )
        right = self.sign(
            previous=first,
            revision="right branch",
            effective_target="right narrowed target",
            effective_scope=scope(["alpha"]),
        )
        decision = verify_and_decide_action_heads(
            [[first, left], [first, right]],
            action_id="execute",
            requested_scope=scope(["alpha"]),
            policy=action_policy(),
            verification_adapters=self.adapters,
        )
        self.assertEqual(decision["fork_state"], "FORK_UNRESOLVED")
        self.assertEqual(decision["decision"], "HOLD")
        self.assertEqual(len(decision["heads"]), 2)

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
