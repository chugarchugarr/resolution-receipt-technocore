from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from resolution_receipt.authority import AUTHORITY_POLICY_VERSION
from resolution_receipt.continuity import (
    build_action_request,
    derive_continuity_status,
    sign_action_decision,
    sign_manifestation_receipt,
    verify_action_decision,
    verify_manifestation_receipt,
)
from resolution_receipt.core import ReceiptError, create_key, hash_object
from resolution_receipt.resolution import sign_resolution
from resolution_receipt.rlp2 import sign_rlp2_resolution
from resolution_receipt.verification import adapter_code_digest


EVIDENCE_DIGEST = "sha256:" + "1" * 64
MANIFESTATION_DIGEST = "sha256:" + "2" * 64


def github_adapter(descriptor, claims):
    return (
        descriptor.get("kind") == "github-pr"
        and descriptor.get("digest") == claims.get("digest")
        and isinstance(descriptor.get("uri"), str)
        and descriptor["uri"].startswith("https://github.com/")
        and claims.get("merged") is True
    )


def ledger_adapter(descriptor, claims):
    return (
        descriptor.get("kind") == "ledger-checkpoint"
        and descriptor.get("digest") == claims.get("digest")
        and isinstance(claims.get("chain"), str)
        and isinstance(claims.get("height"), int)
        and claims["height"] >= 0
    )


def agent_adapter(descriptor, claims):
    return (
        descriptor.get("kind") == "agent-tool-result"
        and descriptor.get("digest") == claims.get("digest")
        and isinstance(claims.get("tool"), str)
        and bool(claims["tool"])
    )


def manifestation_adapter(descriptor, claims):
    return (
        descriptor.get("kind") == "manifestation-event"
        and descriptor.get("digest") == claims.get("artifact_digest")
        and isinstance(claims.get("decision_digest"), str)
        and isinstance(claims.get("request_digest"), str)
        and isinstance(claims.get("destination"), str)
    )


def unresolved_manifestation_adapter(descriptor, claims):
    return None


def scope(items=None):
    return {"adapter": "string-set/v1", "value": items or ["alpha", "beta"]}


def authority_policy(mode, principals, *, external=None):
    return {
        "policy_version": AUTHORITY_POLICY_VERSION,
        "policy_id": "continuity-authority",
        "mode": mode,
        "principals": principals,
        "threshold": None,
        "external_evidence": external or [],
        "failure_mode": "ABSTAIN",
    }


def action_policy():
    return {
        "policy_version": "rlp.action.v2",
        "policy_id": "continuity-action",
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


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.key = str(root / "resolver.json")
        self.did = create_key(self.key, label="resolver")

    def tearDown(self):
        self.temp.cleanup()

    def domain_material(self, domain):
        if domain == "github":
            adapter = github_adapter
            evidence = {
                "native": {
                    "kind": "github-pr",
                    "digest": EVIDENCE_DIGEST,
                    "uri": "https://github.com/example/project/pull/7",
                }
            }
            claims = {"digest": EVIDENCE_DIGEST, "merged": True}
            method = "github-pr-fixture/v1"
        elif domain == "ledger":
            adapter = ledger_adapter
            evidence = {
                "native": {
                    "kind": "ledger-checkpoint",
                    "digest": EVIDENCE_DIGEST,
                    "uri": None,
                }
            }
            claims = {"digest": EVIDENCE_DIGEST, "chain": "example-chain", "height": 42}
            method = "ledger-checkpoint-fixture/v1"
        elif domain == "agent":
            adapter = agent_adapter
            evidence = {
                "native": {
                    "kind": "agent-tool-result",
                    "digest": EVIDENCE_DIGEST,
                    "uri": None,
                }
            }
            claims = {"digest": EVIDENCE_DIGEST, "tool": "write-file"}
            method = "agent-tool-fixture/v1"
        else:
            raise AssertionError(domain)
        specs = {
            "native": {
                "method": method,
                "method_digest": adapter_code_digest(adapter),
                "claims": claims,
            }
        }
        adapters = {method: adapter}
        checks = [
            {
                "id": "domain-condition",
                "requirement": "native evidence satisfies the bounded condition",
                "required": True,
                "outcome": "PASS",
                "evidence": ["native"],
            }
        ]
        return evidence, specs, adapters, checks

    def rlp2(self, domain="github", *, previous=None, external_bootstrap=False):
        evidence, specs, adapters, checks = self.domain_material(domain)
        authority = authority_policy(
            "EXTERNAL" if external_bootstrap else "EXACT",
            [self.did],
            external=["native"] if external_bootstrap else None,
        )
        return sign_rlp2_resolution(
            subject=f"continuity:{domain}",
            original_target="native condition is satisfied",
            effective_target="native condition is satisfied",
            original_scope=scope(),
            effective_scope=scope(),
            evidence=evidence,
            verification_specs=specs,
            verification_adapters=adapters,
            authority_policy=authority,
            checks=checks,
            key_paths=[self.key],
            previous=previous,
            revision_reason="attach policy-bound continuation" if previous else None,
        ), adapters

    def request(self, action_id="execute", nonce="n-1"):
        return build_action_request(
            action_id=action_id,
            destination="system:destination",
            requested_scope=scope(["alpha"]),
            nonce=nonce,
        )

    def manifestation_spec(self, decision, request, adapter=manifestation_adapter):
        return {
            "method": "manifestation-fixture/v1",
            "method_digest": adapter_code_digest(adapter),
            "claims": {
                "decision_digest": hash_object(decision),
                "request_digest": hash_object(request),
                "destination": request["destination"],
                "artifact_digest": MANIFESTATION_DIGEST,
            },
        }

    def test_permission_does_not_imply_manifestation(self):
        record, adapters = self.rlp2()
        request = self.request()
        decision = sign_action_decision(
            [record],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        status = derive_continuity_status(decision)
        self.assertTrue(status["resolution_available"])
        self.assertTrue(status["action_permitted"])
        self.assertFalse(status["manifested"])

    def test_action_decision_recomputes_from_exact_lineage(self):
        record, adapters = self.rlp2()
        request = self.request()
        decision = sign_action_decision(
            [record],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        verified = verify_action_decision(
            decision,
            [record],
            request=request,
            policy=action_policy(),
            verification_adapters=adapters,
        )
        self.assertEqual(verified["decision"], "PERMIT")

    def test_action_request_replay_or_substitution_is_rejected(self):
        record, adapters = self.rlp2()
        request = self.request()
        decision = sign_action_decision(
            [record],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        changed = self.request(nonce="n-2")
        with self.assertRaisesRegex(ReceiptError, "different request"):
            verify_action_decision(
                decision,
                [record],
                request=changed,
                policy=action_policy(),
                verification_adapters=adapters,
            )

    def test_verified_manifestation_is_bound_and_compliant_after_permit(self):
        record, adapters = self.rlp2()
        request = self.request()
        decision = sign_action_decision(
            [record],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        manifest_adapters = {"manifestation-fixture/v1": manifestation_adapter}
        manifestation = sign_manifestation_receipt(
            decision,
            evidence={"kind": "manifestation-event", "digest": MANIFESTATION_DIGEST, "uri": None},
            verification_spec=self.manifestation_spec(decision, request),
            verification_adapters=manifest_adapters,
            key_path=self.key,
        )
        observed = verify_manifestation_receipt(
            manifestation, decision, verification_adapters=manifest_adapters
        )
        self.assertEqual(observed["manifestation_state"], "MANIFESTED")
        self.assertEqual(observed["policy_relation"], "COMPLIANT")
        status = derive_continuity_status(
            decision,
            manifestation=manifestation,
            verification_adapters=manifest_adapters,
        )
        self.assertTrue(status["manifested"])
        self.assertTrue(status["manifestation_bound_to_exact_decision"])

    def test_manifestation_after_hold_is_preserved_as_violation(self):
        record, adapters = self.rlp2()
        request = self.request(action_id="unknown-action")
        decision = sign_action_decision(
            [record],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        manifest_adapters = {"manifestation-fixture/v1": manifestation_adapter}
        manifestation = sign_manifestation_receipt(
            decision,
            evidence={"kind": "manifestation-event", "digest": MANIFESTATION_DIGEST, "uri": None},
            verification_spec=self.manifestation_spec(decision, request),
            verification_adapters=manifest_adapters,
            key_path=self.key,
        )
        observed = verify_manifestation_receipt(
            manifestation, decision, verification_adapters=manifest_adapters
        )
        self.assertEqual(observed["policy_relation"], "VIOLATION")

    def test_manifestation_cannot_be_replayed_against_another_decision(self):
        record, adapters = self.rlp2()
        request1 = self.request(nonce="n-1")
        request2 = self.request(nonce="n-2")
        decision1 = sign_action_decision(
            [record], request=request1, policy=action_policy(), key_path=self.key,
            verification_adapters=adapters,
        )
        decision2 = sign_action_decision(
            [record], request=request2, policy=action_policy(), key_path=self.key,
            verification_adapters=adapters,
        )
        manifest_adapters = {"manifestation-fixture/v1": manifestation_adapter}
        manifestation = sign_manifestation_receipt(
            decision1,
            evidence={"kind": "manifestation-event", "digest": MANIFESTATION_DIGEST, "uri": None},
            verification_spec=self.manifestation_spec(decision1, request1),
            verification_adapters=manifest_adapters,
            key_path=self.key,
        )
        with self.assertRaisesRegex(ReceiptError, "different action decision"):
            verify_manifestation_receipt(
                manifestation, decision2, verification_adapters=manifest_adapters
            )

    def test_unresolved_manifestation_is_not_promoted_to_execution(self):
        record, adapters = self.rlp2()
        request = self.request()
        decision = sign_action_decision(
            [record], request=request, policy=action_policy(), key_path=self.key,
            verification_adapters=adapters,
        )
        manifest_adapters = {"manifestation-fixture/v1": unresolved_manifestation_adapter}
        spec = self.manifestation_spec(
            decision, request, adapter=unresolved_manifestation_adapter
        )
        manifestation = sign_manifestation_receipt(
            decision,
            evidence={"kind": "manifestation-event", "digest": MANIFESTATION_DIGEST, "uri": None},
            verification_spec=spec,
            verification_adapters=manifest_adapters,
            key_path=self.key,
        )
        status = derive_continuity_status(
            decision,
            manifestation=manifestation,
            verification_adapters=manifest_adapters,
        )
        self.assertFalse(status["manifested"])
        self.assertEqual(status["policy_relation"], "UNRESOLVED")

    def test_same_kernel_survives_three_unrelated_domain_shapes(self):
        outcomes = {}
        for domain in ("github", "ledger", "agent"):
            record, adapters = self.rlp2(domain)
            request = self.request(nonce=f"{domain}-1")
            decision = sign_action_decision(
                [record],
                request=request,
                policy=action_policy(),
                key_path=self.key,
                verification_adapters=adapters,
            )
            verified = verify_action_decision(
                decision,
                [record],
                request=request,
                policy=action_policy(),
                verification_adapters=adapters,
            )
            outcomes[domain] = verified["decision"]
        self.assertEqual(outcomes, {"github": "PERMIT", "ledger": "PERMIT", "agent": "PERMIT"})

    def test_continuity_attaches_to_rlp1_without_rewriting_it(self):
        evidence, specs, adapters, checks = self.domain_material("github")
        rlp1 = sign_resolution(
            subject="continuity:github",
            original_target="native condition is satisfied",
            effective_target="native condition is satisfied",
            evidence=evidence,
            checks=checks,
            key_path=self.key,
        )
        rlp1_digest_before = hash_object(rlp1)
        rlp2, _ = self.rlp2(
            "github", previous=rlp1, external_bootstrap=True
        )
        request = self.request()
        decision = sign_action_decision(
            [rlp1, rlp2],
            request=request,
            policy=action_policy(),
            key_path=self.key,
            verification_adapters=adapters,
        )
        verified = verify_action_decision(
            decision,
            [rlp1, rlp2],
            request=request,
            policy=action_policy(),
            verification_adapters=adapters,
        )
        self.assertEqual(verified["decision"], "PERMIT")
        self.assertEqual(hash_object(rlp1), rlp1_digest_before)

    def test_manifestation_tampering_breaks_signature(self):
        record, adapters = self.rlp2()
        request = self.request()
        decision = sign_action_decision(
            [record], request=request, policy=action_policy(), key_path=self.key,
            verification_adapters=adapters,
        )
        manifest_adapters = {"manifestation-fixture/v1": manifestation_adapter}
        manifestation = sign_manifestation_receipt(
            decision,
            evidence={"kind": "manifestation-event", "digest": MANIFESTATION_DIGEST, "uri": None},
            verification_spec=self.manifestation_spec(decision, request),
            verification_adapters=manifest_adapters,
            key_path=self.key,
        )
        tampered = copy.deepcopy(manifestation)
        tampered["payload"]["policy_relation"] = "VIOLATION"
        with self.assertRaises(ReceiptError):
            verify_manifestation_receipt(
                tampered, decision, verification_adapters=manifest_adapters
            )


if __name__ == "__main__":
    unittest.main()
