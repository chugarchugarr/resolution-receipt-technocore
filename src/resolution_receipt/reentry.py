"""Re-entry adapters for Resolution Continuity receipts.

A manifested event must be able to become new evidence without changing the RLP
kernel. These helpers turn a signed continuity receipt into a normal RLP evidence
descriptor and provide an adapter that verifies the receipt's own cryptographic and
semantic bindings.

This adapter verifies the receipt artifact. It does not silently re-prove the foreign
world evidence that originally produced the receipt; that evidence keeps its native
adapter semantics and may be independently recomputed when available.
"""

from __future__ import annotations

from typing import Any

from .continuity import (
    ACTION_DECISION_KIND,
    MANIFESTATION_KIND,
    verify_manifestation_receipt,
)
from .core import ReceiptError, hash_object, verify_envelope
from .verification import adapter_code_digest

CONTINUITY_RECEIPT_METHOD = "continuity-receipt/v1"


def continuity_receipt_evidence(receipt: Any) -> dict[str, Any]:
    """Represent one signed continuity receipt as ordinary protocol-neutral evidence."""
    if not isinstance(receipt, dict):
        raise ReceiptError("continuity receipt must be an object")
    kind = receipt.get("kind")
    if kind not in {ACTION_DECISION_KIND, MANIFESTATION_KIND}:
        raise ReceiptError("unsupported continuity receipt kind")
    verify_envelope(receipt, expected_kind=kind)
    return {"kind": kind, "digest": hash_object(receipt), "uri": None}


def continuity_receipt_adapter(descriptor: dict[str, Any], claims: dict[str, Any]):
    """Verify a self-contained continuity receipt artifact for RLP re-entry."""
    receipt = claims.get("receipt")
    expected_kind = claims.get("expected_kind")
    if expected_kind not in {ACTION_DECISION_KIND, MANIFESTATION_KIND}:
        return False
    if not isinstance(receipt, dict):
        return False
    if descriptor.get("kind") != expected_kind:
        return False
    if descriptor.get("digest") != hash_object(receipt):
        return False
    try:
        payload = verify_envelope(receipt, expected_kind=expected_kind)
    except ReceiptError:
        return False

    if expected_kind == ACTION_DECISION_KIND:
        expected_decision = claims.get("expected_decision")
        if expected_decision is not None and payload.get("decision") != expected_decision:
            return False
        return True

    action_decision = claims.get("action_decision")
    if not isinstance(action_decision, dict):
        return False
    try:
        manifestation = verify_manifestation_receipt(
            receipt, action_decision, verification_adapters=None
        )
    except ReceiptError:
        return False
    expected_state = claims.get("expected_manifestation_state")
    expected_relation = claims.get("expected_policy_relation")
    if expected_state is not None and manifestation["manifestation_state"] != expected_state:
        return False
    if expected_relation is not None and manifestation["policy_relation"] != expected_relation:
        return False
    return True


def continuity_receipt_verification_spec(
    receipt: Any,
    *,
    action_decision: Any | None = None,
    expected_decision: str | None = None,
    expected_manifestation_state: str | None = None,
    expected_policy_relation: str | None = None,
) -> dict[str, Any]:
    """Build the exact verification spec for consuming a continuity receipt as evidence."""
    descriptor = continuity_receipt_evidence(receipt)
    kind = descriptor["kind"]
    claims: dict[str, Any] = {
        "receipt": receipt,
        "expected_kind": kind,
    }
    if kind == ACTION_DECISION_KIND:
        if action_decision is not None:
            raise ReceiptError("action_decision is only valid for manifestation receipt evidence")
        if expected_manifestation_state is not None or expected_policy_relation is not None:
            raise ReceiptError("manifestation expectations require a manifestation receipt")
        if expected_decision is not None:
            claims["expected_decision"] = expected_decision
    else:
        if not isinstance(action_decision, dict):
            raise ReceiptError("manifestation receipt evidence requires its bound action decision")
        if expected_decision is not None:
            raise ReceiptError("expected_decision applies only to action-decision receipts")
        claims["action_decision"] = action_decision
        if expected_manifestation_state is not None:
            claims["expected_manifestation_state"] = expected_manifestation_state
        if expected_policy_relation is not None:
            claims["expected_policy_relation"] = expected_policy_relation
    return {
        "method": CONTINUITY_RECEIPT_METHOD,
        "method_digest": adapter_code_digest(continuity_receipt_adapter),
        "claims": claims,
    }
