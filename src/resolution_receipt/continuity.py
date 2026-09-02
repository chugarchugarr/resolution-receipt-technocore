"""Resolution Continuity: bind verified resolution decisions to manifested reality.

This module does not create another resolution state machine. RLP-1 remains the
bounded-resolution kernel and RLP-2 remains the verified resolution-to-action gate.
Resolution Continuity packages the safe RLP-2 decision as a signed receipt and then
binds later independently verified manifestation evidence back to that exact decision.

The critical invariant is:

    PERMIT != EXECUTED

A permitted action becomes manifested only when new native evidence verifies against
an exact decision/request/destination binding. Manifestation after DENY or HOLD is
preserved as a policy violation rather than erased or reinterpreted.
"""

from __future__ import annotations

from typing import Any, Mapping

from .core import ReceiptError, SHA256_RE, hash_object, sign_envelope, verify_envelope
from .policy import action_policy_digest
from .rlp2 import verify_and_decide_action
from .scope import ScopeAdapter, validate_scope
from .verification import (
    VerificationAdapter,
    recompute_verification_results,
    validate_verification_results,
    validate_verification_spec,
    verify_evidence_set,
)

CONTINUITY_PROFILE = "resolution-continuity-1"
ACTION_DECISION_KIND = "resolution-continuity-action-decision"
MANIFESTATION_KIND = "resolution-continuity-manifestation"
MANIFESTATION_STATES = {"MANIFESTED", "UNRESOLVED"}
POLICY_RELATIONS = {"COMPLIANT", "VIOLATION", "UNRESOLVED"}

_ACTION_REQUEST_FIELDS = {"profile", "action_id", "destination", "requested_scope", "nonce"}
_ACTION_DECISION_FIELDS = {
    "profile",
    "request",
    "request_digest",
    "resolution_head",
    "resolution_state",
    "authority_state",
    "lineage_integrity",
    "action_policy_digest",
    "decision",
    "reason",
}
_MANIFESTATION_FIELDS = {
    "profile",
    "decision_digest",
    "request_digest",
    "destination",
    "evidence",
    "verification_spec",
    "verification_result",
    "manifestation_state",
    "policy_relation",
}


def _text(value: Any, name: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ReceiptError(f"{name} must contain 1 to {limit} characters")
    return value


def _validate_evidence_descriptor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"kind", "digest", "uri"}:
        raise ReceiptError("manifestation evidence must contain kind, digest, and uri")
    kind = _text(value["kind"], "manifestation evidence kind", limit=80)
    digest = value["digest"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReceiptError("manifestation evidence digest must be a sha256: hash")
    uri = value["uri"]
    if uri is not None:
        uri = _text(uri, "manifestation evidence uri", limit=2048)
    return {"kind": kind, "digest": digest, "uri": uri}


def build_action_request(
    *, action_id: str, destination: str, requested_scope: Any, nonce: str
) -> dict[str, Any]:
    """Build the exact proposed action that a continuity decision will bind."""
    return {
        "profile": CONTINUITY_PROFILE,
        "action_id": _text(action_id, "action_id", limit=160),
        "destination": _text(destination, "destination"),
        "requested_scope": validate_scope(requested_scope),
        "nonce": _text(nonce, "nonce", limit=256),
    }


def validate_action_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ACTION_REQUEST_FIELDS:
        raise ReceiptError("continuity action request has missing or unknown fields")
    if value["profile"] != CONTINUITY_PROFILE:
        raise ReceiptError("unsupported continuity profile")
    return build_action_request(
        action_id=value["action_id"],
        destination=value["destination"],
        requested_scope=value["requested_scope"],
        nonce=value["nonce"],
    )


def sign_action_decision(
    records: Any,
    *,
    request: Any,
    policy: Any,
    key_path: str,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
    scope_adapters: Mapping[str, ScopeAdapter] | None = None,
) -> dict[str, Any]:
    """Verify the lineage and sign the exact resulting action decision."""
    request = validate_action_request(request)
    decision = verify_and_decide_action(
        records,
        action_id=request["action_id"],
        requested_scope=request["requested_scope"],
        policy=policy,
        verification_adapters=verification_adapters,
        scope_adapters=scope_adapters,
    )
    payload = {
        "profile": CONTINUITY_PROFILE,
        "request": request,
        "request_digest": hash_object(request),
        "resolution_head": decision["resolution_head"],
        "resolution_state": decision["resolution_state"],
        "authority_state": decision["authority_state"],
        "lineage_integrity": decision["lineage_integrity"],
        "action_policy_digest": decision["action_policy_digest"],
        "decision": decision["decision"],
        "reason": decision["reason"],
    }
    return sign_envelope(ACTION_DECISION_KIND, payload, key_path)


def verify_action_decision(
    envelope: Any,
    records: Any,
    *,
    request: Any,
    policy: Any,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
    scope_adapters: Mapping[str, ScopeAdapter] | None = None,
) -> dict[str, Any]:
    """Recompute an action decision from the signed lineage and require exact equality."""
    payload = verify_envelope(envelope, expected_kind=ACTION_DECISION_KIND)
    if not isinstance(payload, dict) or set(payload) != _ACTION_DECISION_FIELDS:
        raise ReceiptError("continuity action decision has missing or unknown fields")
    if payload["profile"] != CONTINUITY_PROFILE:
        raise ReceiptError("unsupported continuity profile")
    request = validate_action_request(request)
    if payload["request"] != request or payload["request_digest"] != hash_object(request):
        raise ReceiptError("continuity action decision is bound to a different request")
    decision = verify_and_decide_action(
        records,
        action_id=request["action_id"],
        requested_scope=request["requested_scope"],
        policy=policy,
        verification_adapters=verification_adapters,
        scope_adapters=scope_adapters,
    )
    expected = {
        "profile": CONTINUITY_PROFILE,
        "request": request,
        "request_digest": hash_object(request),
        "resolution_head": decision["resolution_head"],
        "resolution_state": decision["resolution_state"],
        "authority_state": decision["authority_state"],
        "lineage_integrity": decision["lineage_integrity"],
        "action_policy_digest": action_policy_digest(policy),
        "decision": decision["decision"],
        "reason": decision["reason"],
    }
    if payload != expected:
        raise ReceiptError("continuity action decision does not match recomputed lineage state")
    return payload


def _manifestation_policy_relation(decision: str, state: str) -> str:
    if state != "MANIFESTED":
        return "UNRESOLVED"
    return "COMPLIANT" if decision == "PERMIT" else "VIOLATION"


def sign_manifestation_receipt(
    action_decision: Any,
    *,
    evidence: dict[str, Any],
    verification_spec: dict[str, Any],
    verification_adapters: Mapping[str, VerificationAdapter],
    key_path: str,
) -> dict[str, Any]:
    """Bind independently verified manifestation evidence to one exact decision.

    The verification spec claims must explicitly bind the exact decision digest,
    request digest, and destination. This prevents generic evidence from being replayed
    as proof that some other permitted action happened.
    """
    decision_payload = verify_envelope(action_decision, expected_kind=ACTION_DECISION_KIND)
    if not isinstance(decision_payload, dict) or set(decision_payload) != _ACTION_DECISION_FIELDS:
        raise ReceiptError("continuity action decision has missing or unknown fields")
    evidence = _validate_evidence_descriptor(evidence)
    decision_digest = hash_object(action_decision)
    spec = validate_verification_spec(verification_spec)
    claims = spec["claims"]
    required_claims = {
        "decision_digest": decision_digest,
        "request_digest": decision_payload["request_digest"],
        "destination": decision_payload["request"]["destination"],
    }
    for name, expected in required_claims.items():
        if claims.get(name) != expected:
            raise ReceiptError(f"manifestation verification claim {name} is not bound to the decision")
    results = verify_evidence_set(
        {"manifestation": evidence},
        {"manifestation": spec},
        verification_adapters,
    )
    result = results["manifestation"]
    state = "MANIFESTED" if result["result"] == "VERIFIED" else "UNRESOLVED"
    relation = _manifestation_policy_relation(decision_payload["decision"], state)
    payload = {
        "profile": CONTINUITY_PROFILE,
        "decision_digest": decision_digest,
        "request_digest": decision_payload["request_digest"],
        "destination": decision_payload["request"]["destination"],
        "evidence": evidence,
        "verification_spec": spec,
        "verification_result": result,
        "manifestation_state": state,
        "policy_relation": relation,
    }
    return sign_envelope(MANIFESTATION_KIND, payload, key_path)


def verify_manifestation_receipt(
    envelope: Any,
    action_decision: Any,
    *,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
) -> dict[str, Any]:
    """Verify exact decision binding and, when available, recompute native evidence."""
    payload = verify_envelope(envelope, expected_kind=MANIFESTATION_KIND)
    if not isinstance(payload, dict) or set(payload) != _MANIFESTATION_FIELDS:
        raise ReceiptError("continuity manifestation has missing or unknown fields")
    if payload["profile"] != CONTINUITY_PROFILE:
        raise ReceiptError("unsupported continuity profile")
    decision_payload = verify_envelope(action_decision, expected_kind=ACTION_DECISION_KIND)
    if not isinstance(decision_payload, dict) or set(decision_payload) != _ACTION_DECISION_FIELDS:
        raise ReceiptError("continuity action decision has missing or unknown fields")
    if payload["decision_digest"] != hash_object(action_decision):
        raise ReceiptError("manifestation is bound to a different action decision")
    if payload["request_digest"] != decision_payload["request_digest"]:
        raise ReceiptError("manifestation is bound to a different action request")
    if payload["destination"] != decision_payload["request"]["destination"]:
        raise ReceiptError("manifestation is bound to a different destination")

    descriptor = _validate_evidence_descriptor(payload["evidence"])
    if descriptor != payload["evidence"]:
        raise ReceiptError("manifestation evidence descriptor is not canonical")
    spec = validate_verification_spec(payload["verification_spec"])
    claims = spec["claims"]
    required_claims = {
        "decision_digest": payload["decision_digest"],
        "request_digest": payload["request_digest"],
        "destination": payload["destination"],
    }
    for name, expected in required_claims.items():
        if claims.get(name) != expected:
            raise ReceiptError(f"manifestation verification claim {name} is not bound to the decision")
    stored = {"manifestation": payload["verification_result"]}
    specs = {"manifestation": spec}
    evidence = {"manifestation": descriptor}
    validate_verification_results(evidence, stored, specs=specs)
    if verification_adapters is not None:
        recompute_verification_results(evidence, specs, stored, verification_adapters)
    expected_state = (
        "MANIFESTED"
        if payload["verification_result"]["result"] == "VERIFIED"
        else "UNRESOLVED"
    )
    if payload["manifestation_state"] != expected_state:
        raise ReceiptError("manifestation state does not follow native verification")
    expected_relation = _manifestation_policy_relation(
        decision_payload["decision"], expected_state
    )
    if payload["policy_relation"] != expected_relation:
        raise ReceiptError("manifestation policy relation is inconsistent with action decision")
    return payload


def derive_continuity_status(
    action_decision: Any,
    *,
    manifestation: Any | None = None,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
) -> dict[str, Any]:
    """Expose availability, permission, manifestation, and binding as separate facts."""
    decision = verify_envelope(action_decision, expected_kind=ACTION_DECISION_KIND)
    if not isinstance(decision, dict) or set(decision) != _ACTION_DECISION_FIELDS:
        raise ReceiptError("continuity action decision has missing or unknown fields")
    manifested = False
    relation = "UNRESOLVED"
    manifestation_digest = None
    if manifestation is not None:
        observed = verify_manifestation_receipt(
            manifestation,
            action_decision,
            verification_adapters=verification_adapters,
        )
        manifested = observed["manifestation_state"] == "MANIFESTED"
        relation = observed["policy_relation"]
        manifestation_digest = hash_object(manifestation)
    return {
        "resolution_available": decision["resolution_head"] is not None,
        "action_permitted": decision["decision"] == "PERMIT",
        "manifested": manifested,
        "manifestation_bound_to_exact_decision": manifested,
        "policy_relation": relation,
        "request_digest": decision["request_digest"],
        "decision_digest": hash_object(action_decision),
        "manifestation_digest": manifestation_digest,
    }
