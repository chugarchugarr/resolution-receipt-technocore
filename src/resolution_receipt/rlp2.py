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
from .core import (
    ReceiptError,
    SHA256_RE,
    did_from_private_key,
    hash_object,
    sign_envelope,
    verify_envelope,
)
from .policy import action_policy_digest, derive_action_decision
from .resolution import RESOLUTION_KIND, build_resolution_payload, verify_resolution
from .scope import ScopeAdapter, validate_scope, validate_scope_transition
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


def _bootstrap_adjusted_authority_state(
    state: str,
    *,
    authority_policy: dict[str, Any],
    previous: dict[str, Any] | None,
) -> str:
    """Prevent RLP-1 signers from self-bootstrapping RLP-2 authority.

    RLP-1 intentionally had no authority semantics. Therefore the first RLP-2
    successor cannot become operative merely because its new policy names its own
    signer. A bootstrap may become authoritative only through EXTERNAL policy,
    whose required authority evidence is natively verified by the normal adapter
    path. Other bootstrap policies remain UNRESOLVED until an externally anchored
    RLP-2 policy exists and can authorize a later transition.
    """
    if previous is not None and _previous_profile(previous) == "RLP-1":
        if authority_policy["mode"] != "EXTERNAL":
            return "UNRESOLVED"
    return state


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
    validate_scope_transition(
        original_scope,
        effective_scope,
        resolution_state=base["state"],
    )
    specs = _validate_specs(base["evidence"], verification_specs)
    results = validate_verification_results(
        base["evidence"], verification_results, specs=specs
    )
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
    authority_state = _bootstrap_adjusted_authority_state(
        authority_state,
        authority_policy=body["authority_policy"],
        previous=previous,
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

    standalone_successor = previous is None and body["previous"] is not None
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
        revision_reason=None if standalone_successor else body["revision_reason"],
    )
    if standalone_successor:
        for key in RLP2_BODY_FIELDS - {"previous", "previous_profile", "revision_reason"}:
            if rebuilt[key] != body[key]:
                raise ReceiptError(f"RLP-2 derived field mismatch: {key}")
        if not isinstance(body["previous"], str) or not SHA256_RE.fullmatch(body["previous"]):
            raise ReceiptError("successor RLP-2 previous must be a sha256: hash")
        if body["previous_profile"] not in {"RLP-1", "RLP-2"}:
            raise ReceiptError("successor RLP-2 previous_profile is invalid")
        if not isinstance(body["revision_reason"], str) or not body["revision_reason"] or len(body["revision_reason"]) > 2048:
            raise ReceiptError("successor RLP-2 record requires a revision_reason")
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
    authority_state = _bootstrap_adjusted_authority_state(
        authority_state,
        authority_policy=body["authority_policy"],
        previous=previous,
    )
    # A standalone successor can establish structure and signature integrity, but
    # cannot claim an RLP-1 bootstrap authority result without its predecessor.
    if standalone_successor and body["previous_profile"] == "RLP-1":
        authority_state = "UNRESOLVED"
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
        if not isinstance(record, dict):
            raise ReceiptError("RLP-2 lineage records must be objects")
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


def verify_rlp2_heads(
    lineages: Any,
    *,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
) -> dict[str, Any]:
    """Verify competing candidate lineages without silently choosing a winner."""
    if not isinstance(lineages, list) or not lineages:
        raise ReceiptError("RLP-2 head set must contain at least one lineage")
    verified = [
        verify_rlp2_lineage(lineage, verification_adapters=verification_adapters)
        for lineage in lineages
    ]
    identities = {(item["subject"], item["original_target"]) for item in verified}
    if len(identities) != 1:
        raise ReceiptError("RLP-2 head set mixes unrelated resolution identities")
    heads = sorted({item["head"] for item in verified})
    return {
        "integrity": "PASS",
        "fork_state": "SINGLE" if len(heads) == 1 else "FORK_UNRESOLVED",
        "heads": heads,
        "subject": verified[0]["subject"],
        "original_target": verified[0]["original_target"],
        "candidates": verified,
    }


def verify_and_decide_action(
    records: Any,
    *,
    action_id: str,
    requested_scope: Any,
    policy: Any,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
    scope_adapters: Mapping[str, ScopeAdapter] | None = None,
) -> dict[str, Any]:
    """Verify the complete supplied lineage before deriving an action decision.

    Callers cannot inject precomputed authority, resolution, integrity, or head
    values into this path. Every such value is derived from the signed lineage.
    """
    verified = verify_rlp2_lineage(
        records, verification_adapters=verification_adapters
    )
    decision = derive_action_decision(
        action_id=action_id,
        requested_scope=requested_scope,
        resolution_state=verified["state"],
        authority_state=verified["authority_state"],
        effective_scope=verified["effective_scope"],
        lineage_integrity=verified["integrity"],
        policy=policy,
        resolution_head=verified["head"],
        scope_adapters=scope_adapters,
    )
    return {
        **decision,
        "resolution_state": verified["state"],
        "authority_state": verified["authority_state"],
        "lineage_integrity": verified["integrity"],
    }


def verify_and_decide_action_heads(
    lineages: Any,
    *,
    action_id: str,
    requested_scope: Any,
    policy: Any,
    verification_adapters: Mapping[str, VerificationAdapter] | None = None,
    scope_adapters: Mapping[str, ScopeAdapter] | None = None,
) -> dict[str, Any]:
    """Gate action across a set of possible heads; unresolved forks always HOLD."""
    head_set = verify_rlp2_heads(
        lineages, verification_adapters=verification_adapters
    )
    if head_set["fork_state"] != "SINGLE":
        return {
            "action_id": action_id,
            "decision": "HOLD",
            "reason": "multiple valid RLP-2 heads remain unresolved",
            "resolution_head": None,
            "action_policy_digest": action_policy_digest(policy),
            "fork_state": head_set["fork_state"],
            "heads": head_set["heads"],
        }
    candidate = head_set["candidates"][0]
    decision = derive_action_decision(
        action_id=action_id,
        requested_scope=requested_scope,
        resolution_state=candidate["state"],
        authority_state=candidate["authority_state"],
        effective_scope=candidate["effective_scope"],
        lineage_integrity=candidate["integrity"],
        policy=policy,
        resolution_head=candidate["head"],
        scope_adapters=scope_adapters,
    )
    return {
        **decision,
        "fork_state": "SINGLE",
        "heads": head_set["heads"],
        "resolution_state": candidate["state"],
        "authority_state": candidate["authority_state"],
        "lineage_integrity": candidate["integrity"],
    }
