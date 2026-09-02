"""RLP-2 policy-bound resolution lineage.

RLP-1 remains the resolution-state kernel. RLP-2 composes native evidence
verification and explicit resolver authority around that kernel, while retaining
append-only lineage and permitting a later deterministic action-policy gate.
"""

from __future__ import annotations

from typing import Any, Mapping

from .authority import (
    authority_policy_digest,
    derive_authority_state,
    sign_authority_approval,
    sign_transition_approval,
    validate_authority_policy,
    verify_authority_approvals,
    verify_transition_approvals,
)
from .core import ReceiptError, did_from_private_key, hash_object, sign_envelope, verify_envelope
from .resolution import RESOLUTION_KIND, build_resolution_payload, verify_resolution
from .scope import validate_scope
from .verification import (
    VerificationAdapter,
    recompute_verification_results,
    require_verified_check_evidence,
    validate_verification_results,
    validate_verification_spec,
    verify_evidence_set,
)

RLP2_KIND = "policy-bound-resolution"
RLP2_PROFILE = "rlp-2"
RLP2_FIELDS = {"body", "authority_state", "approvals", "transition_approvals"}
RLP2_BODY_FIELDS = {
    "profile",
    "subject",
    "original_target",
    "effective_target",
    "original_scope",
    "effective_scope",
    "evidence",
    "verification_specs",
    "verification_results",
    "authority_policy",
    "authority_policy_digest",
    "checks",
    "state",
    "previous",
    "previous_profile",
    "revision_reason",
}


def _previous_profile(record: dict[str, Any]) -> str:
    kind = record.get("kind")
    if kind == RESOLUTION_KIND:
        return "RLP-1"
    if kind == RLP2_KIND:
        return "RLP-2"
    raise ReceiptError("RLP-2 predecessor must be an RLP-1 or RLP-2 signed resolution")


def _previous_payload(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("kind") == RESOLUTION_KIND:
        return verify_resolution(record)
    payload = verify_envelope(record, expected_kind=RLP2_KIND)
    if not isinstance(payload, dict) or set(payload) != RLP2_FIELDS:
        raise ReceiptError("previous RLP-2 payload is malformed")
    body = payload.get("body")
    if not isinstance(body, dict) or set(body) != RLP2_BODY_FIELDS:
        raise ReceiptError("previous RLP-2 body is malformed")
    return body


def _validate_specs(evidence: Mapping[str, Any], specs: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(specs, dict) or set(specs) != set(evidence):
        raise ReceiptError("verification_specs must correspond exactly to evidence")
    return {key: validate_verification_spec(value) for key, value in specs.items()}


def _build_body(
    *,
    subject: str,
    original_target: str,
    effective_target: str,
    original_scope: dict[str, Any],
    effective_scope: dict[str, Any],
    evidence: dict[str, Any],
    verification_specs: dict[str, Any],
    verification_results: dict[str, Any],
    authority_policy: dict[str, Any],
    checks: list[dict[str, Any]],
    previous: dict[str, Any] | None,
    revision_reason: str | None,
) -> dict[str, Any]:
    # Reuse RLP-1 as the unchanged deterministic resolution kernel.
    base = build_resolution_payload(
        subject=subject,
        original_target=original_target,
        effective_target=effective_target,
        evidence=evidence,
        checks=checks,
    )
    original_scope = validate_scope(original_scope)
    effective_scope = validate_scope(effective_scope)
    specs = _validate_specs(base["evidence"], verification_specs)
    results = validate_verification_results(base["evidence"], verification_results)
    require_verified_check_evidence(base["checks"], results)
    authority_policy = validate_authority_policy(authority_policy)

    if previous is None:
        previous_hash = None
        previous_profile = None
        if revision_reason is not None:
            raise ReceiptError("first RLP-2 record cannot have a revision_reason")
    else:
        previous_hash = hash_object(previous)
        previous_profile = _previous_profile(previous)
        prior = _previous_payload(previous)
        if prior["subject"] != base["subject"]:
            raise ReceiptError("RLP-2 lineage changed subject")
        if prior["original_target"] != base["original_target"]:
            raise ReceiptError("RLP-2 lineage changed original_target")
        if not isinstance(revision_reason, str) or not revision_reason or len(revision_reason) > 2048:
            raise ReceiptError("successor RLP-2 record requires a revision_reason")

    return {
        "profile": RLP2_PROFILE,
        "subject": base["subject"],
        "original_target": base["original_target"],
        "effective_target": base["effective_target"],
        "original_scope": original_scope,
        "effective_scope": effective_scope,
        "evidence": base["evidence"],
        "verification_specs": specs,
        "verification_results": results,
        "authority_policy": authority_policy,
        "authority_policy_digest": authority_policy_digest(authority_policy),
        "checks": base["checks"],
        "state": base["state"],
        "previous": previous_hash,
        "previous_profile": previous_profile,
        "revision_reason": revision_reason,
    }


def sign_rlp2_resolution(
    *,
    subject: str,
    original_target: str,
    effective_target: str,
    original_scope: dict[str, Any],
    effective_scope: dict[str, Any],
    evidence: dict[str, Any],
    verification_specs: dict[str, Any],
    verification_adapters: Mapping[str, VerificationAdapter],
    authority_policy: dict[str, Any],
    checks: list[dict[str, Any]],
    key_paths: list[str],
    previous: dict[str, Any] | None = None,
    revision_reason: str | None = None,
    transition_key_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Create one signed RLP-2 record with independently verifiable approvals."""
    if not key_paths:
        raise ReceiptError("RLP-2 signing requires at least one authority key")
    results = verify_evidence_set(evidence, verification_specs, verification_adapters)
    body = _build_body(
        subject=subject,
        original_target=original_target,
        effective_target=effective_target,
        original_scope=original_scope,
        effective_scope=effective_scope,
        evidence=evidence,
        verification_specs=verification_specs,
        verification_results=results,
        authority_policy=authority_policy,
        checks=checks,
        previous=previous,
        revision_reason=revision_reason,
    )
    body_digest = hash_object(body)
    policy_digest = body["authority_policy_digest"]
    approvals = [
        sign_authority_approval(
            body_digest=body_digest, policy_digest=policy_digest, key_path=path
        )
        for path in key_paths
    ]
    actor = did_from_private_key(key_paths[0])
    signers = {approval["signer"] for approval in approvals}
    authority_state = derive_authority_state(
        body["authority_policy"],
        actor=actor,
        approval_signers=signers,
        verification_results=results,
    )

    transition_approvals: list[dict[str, Any]] = []
    if previous is not None and _previous_profile(previous) == "RLP-2":
        prior = _previous_payload(previous)
        old_digest = prior["authority_policy_digest"]
        if old_digest != policy_digest:
            if not transition_key_paths:
                raise ReceiptError("authority policy change requires prior-policy transition approvals")
            transition_approvals = [
                sign_transition_approval(
                    body_digest=body_digest,
                    from_policy_digest=old_digest,
                    to_policy_digest=policy_digest,
                    key_path=path,
                )
                for path in transition_key_paths
            ]

    payload = {
        "body": body,
        "authority_state": authority_state,
        "approvals": approvals,
        "transition_approvals": transition_approvals,
    }
    return sign_envelope(RLP2_KIND, payload, key_paths[0])


def verify_rlp2_resolution(
    envelope: Any,
    *,
    previous: dict[str, Any] | None = None,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
) -> dict[str, Any]:
    """Verify one RLP-2 record and, when supplied, its immediate predecessor link."""
    payload = verify_envelope(envelope, expected_kind=RLP2_KIND)
    if not isinstance(payload, dict) or set(payload) != RLP2_FIELDS:
        raise ReceiptError("RLP-2 payload has missing or unknown fields")
    body = payload["body"]
    if not isinstance(body, dict) or set(body) != RLP2_BODY_FIELDS:
        raise ReceiptError("RLP-2 body has missing or unknown fields")
    if body["profile"] != RLP2_PROFILE:
        raise ReceiptError("unsupported RLP-2 profile")

    rebuilt = _build_body(
        subject=body["subject"],
        original_target=body["original_target"],
        effective_target=body["effective_target"],
        original_scope=body["original_scope"],
        effective_scope=body["effective_scope"],
        evidence=body["evidence"],
        verification_specs=body["verification_specs"],
        verification_results=body["verification_results"],
        authority_policy=body["authority_policy"],
        checks=body["checks"],
        previous=previous,
        revision_reason=body["revision_reason"],
    )
    # _build_body can only reconstruct previous metadata when the predecessor is
    # supplied. For standalone structural verification, compare all non-lineage fields.
    if previous is None and body["previous"] is not None:
        for key in RLP2_BODY_FIELDS - {"previous", "previous_profile", "revision_reason"}:
            if rebuilt[key] != body[key]:
                raise ReceiptError(f"RLP-2 derived field mismatch: {key}")
    elif rebuilt != body:
        raise ReceiptError("RLP-2 body does not match deterministic derivation")

    if verification_adapters is not None:
        recompute_verification_results(
            body["evidence"],
            body["verification_specs"],
            body["verification_results"],
            verification_adapters,
        )

    body_digest = hash_object(body)
    signers = verify_authority_approvals(
        payload["approvals"],
        body_digest=body_digest,
        policy_digest=body["authority_policy_digest"],
    )
    actor = envelope["signer"]
    if actor not in signers:
        raise ReceiptError("RLP-2 envelope signer must also approve the resolution body")
    authority_state = derive_authority_state(
        body["authority_policy"],
        actor=actor,
        approval_signers=signers,
        verification_results=body["verification_results"],
    )
    if payload["authority_state"] != authority_state:
        raise ReceiptError("RLP-2 authority_state does not match authority policy")

    if previous is None:
        if body["previous"] is None:
            if body["previous_profile"] is not None or body["revision_reason"] is not None:
                raise ReceiptError("first RLP-2 record has invalid lineage metadata")
            if payload["transition_approvals"]:
                raise ReceiptError("first RLP-2 record cannot contain policy transition approvals")
    else:
        if body["previous"] != hash_object(previous):
            raise ReceiptError("RLP-2 previous hash does not match predecessor")
        profile = _previous_profile(previous)
        if body["previous_profile"] != profile:
            raise ReceiptError("RLP-2 previous_profile does not match predecessor")
        prior = _previous_payload(previous)
        if prior["subject"] != body["subject"] or prior["original_target"] != body["original_target"]:
            raise ReceiptError("RLP-2 lineage changed immutable identity")
        if profile == "RLP-1":
            if payload["transition_approvals"]:
                raise ReceiptError("RLP-1 to RLP-2 bootstrap is not a policy transition")
        else:
            old_digest = prior["authority_policy_digest"]
            new_digest = body["authority_policy_digest"]
            if old_digest == new_digest:
                if payload["transition_approvals"]:
                    raise ReceiptError("unchanged authority policy cannot have transition approvals")
            else:
                state = verify_transition_approvals(
                    payload["transition_approvals"],
                    body_digest=body_digest,
                    from_policy=prior["authority_policy"],
                    to_policy=body["authority_policy"],
                    verification_results=prior["verification_results"],
                )
                if state != "AUTHORIZED":
                    raise ReceiptError("authority policy transition was not authorized by prior policy")

    return {
        "integrity": "PASS",
        "profile": RLP2_PROFILE,
        "state": body["state"],
        "authority_state": authority_state,
        "subject": body["subject"],
        "original_target": body["original_target"],
        "effective_target": body["effective_target"],
        "effective_scope": body["effective_scope"],
        "head": hash_object(envelope),
        "native_verification": "RECOMPUTED" if verification_adapters is not None else "DECLARED",
    }


def verify_rlp2_lineage(
    records: Any,
    *,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
) -> dict[str, Any]:
    """Verify an optional RLP-1 ancestor followed by one or more RLP-2 records."""
    if not isinstance(records, list) or not records:
        raise ReceiptError("RLP-2 lineage must be a non-empty list")
    previous: dict[str, Any] | None = None
    current: dict[str, Any] | None = None
    seen_rlp2 = False
    for record in records:
        if record.get("kind") == RESOLUTION_KIND:
            if seen_rlp2 or previous is not None:
                raise ReceiptError("RLP-1 may appear only once at the start of an RLP-2 lineage")
            verify_resolution(record)
            previous = record
            continue
        seen_rlp2 = True
        current = verify_rlp2_resolution(
            record,
            previous=previous,
            verification_adapters=verification_adapters,
        )
        previous = record
    if current is None:
        raise ReceiptError("RLP-2 lineage contains no RLP-2 record")
    current["records"] = len(records)
    return current
