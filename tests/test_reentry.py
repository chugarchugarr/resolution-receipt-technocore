from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from resolution_receipt.authority import AUTHORITY_POLICY_VERSION
from resolution_receipt.continuity import (
    build_action_request,
    sign_action_decision,
    sign_manifestation_receipt,
    verify_action_decision,
)
from resolution_receipt.core import ReceiptError, create_key, hash_object
from resolution_receipt.reentry import (
    CONTINUITY_RECEIPT_METHOD,
    continuity_receipt_adapter,
    continuity_receipt_evidence,
    continuity_receipt_verification_spec,
)
from resolution_receipt.rlp2 import sign_rlp2_resolution, verify_rlp2_lineage
from resolution_receipt.verification import adapter_code_digest

SEED_DIGEST = "sha256:" + "3" * 64
MANIFEST_DIGEST = "sha256:" + "4" * 64


def seed_adapter(descriptor, claims):
    return (
        descriptor.get("kind") == "seed-event"
        and descriptor.get("digest") == claims.get("digest")
    )


def manifestation_adapter(descriptor, claims):
    return (
        descriptor.get("kind") == "manifestation-event"
        and descriptor.get("digest") == claims.get("artifact_digest")
        and isinstance(claims.get("decision_digest"), str)
        and isinstance(claims.get("request_digest"), str)
        and isinstance(claims.get("destination"), str)
    )


def scope(items=None):
    return {"adapter": "string-set/v1", "value": items or ["alpha", "beta"]}


def authority_policy(did):
    return {
        "policy_version": AUTHORITY_POLICY_VERSION,
        "policy_id": "loop-authority",
        "mode": "EXACT",
        "principals": [did],
        "threshold": None,
        "external_evidence": [],
        "failure_mode": "ABSTAIN",
    }


def action_policy():
    return {
        "policy_version": "rlp.action.v2",
        "policy_id": "loop-action",
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


class ReentryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.key = str(Path(self.temp.name) / "loop.json")
        self.did = create_key(self.key, label="loop")

    def tearDown(self):
        self.temp.cleanup()

    def initial_record(self):
        evidence = {
            "seed": {"kind": "seed-event", "digest": SEED_DIGEST, "uri": None}
        }
        specs = {
            "seed": {
                "method": "seed-fixture/v1",
                "method_digest": adapter_code_digest(seed_adapter),
                "claims": {"digest": SEED_DIGEST},
            }
        }
        checks = [
            {
                "id": "seed-condition",
                "requirement": "seed evidence satisfies the bounded world condition",
                "required": True,
                "outcome": "PASS",
                "evidence": ["seed"],
            }
        ]
        adapters = {"seed-fixture/v1": seed_adapter}
        record = sign_rlp2_resolution(
            subject="continuity:closed-loop",
            original_target="the world condition is satisfied",
            effective_target="the world condition is satisfied",
            original_scope=scope(),
            effective_scope=scope(),
            evidence=evidence,
            verification_specs=specs,
            verification_adapters=adapters,
            authority_policy=authority_policy(self.did),
            checks=checks,
            key_paths=[self.key],
        )
        return record, adapters

    def manifested_action(self, initial, adapters):
        request = build_action_request(
            action_id="execute",
            destination="system:destination",
            requested_scope=scope(["alpha"]),
            nonce="loop-1",
        )
        decision = sign_action_decision(
            [initial],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        manifest_method = "manifestation-loop/v1"
        manifest_adapters = {manifest_method: manifestation_adapter}
        spec = {
            "method": manifest_method,
            "method_digest": adapter_code_digest(manifestation_adapter),
            "claims": {
                "decision_digest": hash_object(decision),
                "request_digest": hash_object(request),
                "destination": request["destination"],
                "artifact_digest": MANIFEST_DIGEST,
            },
        }
        manifestation = sign_manifestation_receipt(
            decision,
            evidence={
                "kind": "manifestation-event",
                "digest": MANIFEST_DIGEST,
                "uri": None,
            },
            verification_spec=spec,
            verification_adapters=manifest_adapters,
            key_path=self.key,
        )
        return request, decision, manifestation

    def test_manifested_reality_becomes_successor_evidence_and_reenters(self):
        initial, initial_adapters = self.initial_record()
        request, decision, manifestation = self.manifested_action(
            initial, initial_adapters
        )

        evidence = {
            "manifestation": continuity_receipt_evidence(manifestation)
        }
        spec = continuity_receipt_verification_spec(
            manifestation,
            action_decision=decision,
            expected_manifestation_state="MANIFESTED",
            expected_policy_relation="COMPLIANT",
        )
        reentry_adapters = {CONTINUITY_RECEIPT_METHOD: continuity_receipt_adapter}
        successor = sign_rlp2_resolution(
            subject="continuity:closed-loop",
            original_target="the world condition is satisfied",
            effective_target="the world condition is satisfied",
            original_scope=scope(),
            effective_scope=scope(),
            evidence=evidence,
            verification_specs={"manifestation": spec},
            verification_adapters=reentry_adapters,
            authority_policy=authority_policy(self.did),
            checks=[
                {
                    "id": "manifested-consequence",
                    "requirement": "the previously permitted action manifested and is bound to its exact decision",
                    "required": True,
                    "outcome": "PASS",
                    "evidence": ["manifestation"],
                }
            ],
            key_paths=[self.key],
            previous=initial,
            revision_reason="manifested action returned from reality as successor evidence",
        )

        all_adapters = {
            **initial_adapters,
            **reentry_adapters,
        }
        verified = verify_rlp2_lineage(
            [initial, successor], verification_adapters=all_adapters
        )
        self.assertEqual(verified["records"], 2)
        self.assertEqual(verified["state"], "SURVIVED")
        self.assertEqual(verified["authority_state"], "AUTHORIZED")
        self.assertEqual(
            successor["payload"]["body"]["evidence"]["manifestation"]["digest"],
            hash_object(manifestation),
        )

        next_request = build_action_request(
            action_id="execute",
            destination="system:destination",
            requested_scope=scope(["alpha"]),
            nonce="loop-2",
        )
        next_decision = sign_action_decision(
            [initial, successor],
            request=next_request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=all_adapters,
        )
        next_verified = verify_action_decision(
            next_decision,
            [initial, successor],
            request=next_request,
            policy=action_policy(),
            verification_adapters=all_adapters,
        )
        self.assertEqual(next_verified["decision"], "PERMIT")

    def test_tampered_manifestation_cannot_be_reentered_as_valid_evidence(self):
        initial, adapters = self.initial_record()
        _, _, manifestation = self.manifested_action(initial, adapters)
        tampered = copy.deepcopy(manifestation)
        tampered["payload"]["manifestation_state"] = "UNRESOLVED"
        with self.assertRaises(ReceiptError):
            continuity_receipt_evidence(tampered)


if __name__ == "__main__":
    unittest.main()
