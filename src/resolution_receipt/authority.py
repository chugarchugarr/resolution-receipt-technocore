"""RLP-2 resolver-authority policies and cryptographic approvals."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .core import ReceiptError, SHA256_RE, hash_object, sign_envelope, verify_envelope

AUTHORITY_POLICY_VERSION = "rlp.authority.v2"
AUTHORITY_APPROVAL_KIND = "rlp2-authority-approval"
TRANSITION_APPROVAL_KIND = "rlp2-policy-transition-approval"
AUTHORITY_STATES = {"AUTHORIZED", "UNAUTHORIZED", "UNRESOLVED"}
AUTHORITY_MODES = {"EXACT", "ANY_OF", "ALL_OF", "THRESHOLD", "EXTERNAL"}


def _text(value: Any, name: str, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ReceiptError(f"{name} must contain 1 to {limit} characters")
    return value


def validate_authority_policy(policy: Any) -> dict[str, Any]:
    fields = {
        "policy_version", "policy_id", "mode", "principals", "threshold",
        "external_evidence", "failure_mode"
    }
    if not isinstance(policy, dict) or set(policy) != fields:
        raise ReceiptError("authority policy has missing or unknown fields")
    if policy["policy_version"] != AUTHORITY_POLICY_VERSION:
        raise ReceiptError("unsupported authority policy version")
    policy_id = _text(policy["policy_id"], "authority policy_id")
    mode = policy["mode"]
    if mode not in AUTHORITY_MODES:
        raise ReceiptError("unsupported authority policy mode")
    principals = policy["principals"]
    if not isinstance(principals, list) or not principals or any(
        not isinstance(item, str) or not item for item in principals
    ) or len(principals) != len(set(principals)):
        raise ReceiptError("authority principals must be a non-empty unique string list")
    threshold = policy["threshold"]
    if mode == "THRESHOLD":
        if not isinstance(threshold, int) or isinstance(threshold, bool) or not (1 <= threshold <= len(principals)):
            raise ReceiptError("threshold must be between 1 and principal count")
    elif threshold is not None:
        raise ReceiptError("threshold must be null outside THRESHOLD mode")
    if mode == "EXACT" and len(principals) != 1:
        raise ReceiptError("EXACT authority requires exactly one principal")
    external = policy["external_evidence"]
    if not isinstance(external, list) or any(not isinstance(item, str) or not item for item in external):
        raise ReceiptError("external_evidence must be a string list")
    if mode == "EXTERNAL" and not external:
        raise ReceiptError("EXTERNAL authority requires external evidence")
    if mode != "EXTERNAL" and external:
        raise ReceiptError("external_evidence is only valid for EXTERNAL authority")
    if policy["failure_mode"] != "ABSTAIN":
        raise ReceiptError("RLP-2 authority failure_mode must be ABSTAIN")
    return {
        "policy_version": AUTHORITY_POLICY_VERSION,
        "policy_id": policy_id,
        "mode": mode,
        "principals": principals,
        "threshold": threshold,
        "external_evidence": external,
        "failure_mode": "ABSTAIN",
    }


def authority_policy_digest(policy: Any) -> str:
    return hash_object(validate_authority_policy(policy))


def approval_payload(*, body_digest: str, policy_digest: str) -> dict[str, str]:
    if not SHA256_RE.fullmatch(body_digest) or not SHA256_RE.fullmatch(policy_digest):
        raise ReceiptError("approval digests must be sha256: values")
    return {"body_digest": body_digest, "policy_digest": policy_digest}


def sign_authority_approval(*, body_digest: str, policy_digest: str, key_path: str) -> dict[str, Any]:
    return sign_envelope(
        AUTHORITY_APPROVAL_KIND,
        approval_payload(body_digest=body_digest, policy_digest=policy_digest),
        key_path,
    )


def verify_authority_approvals(
    approvals: Any, *, body_digest: str, policy_digest: str
) -> set[str]:
    if not isinstance(approvals, list):
        raise ReceiptError("authority approvals must be a list")
    signers: set[str] = set()
    expected = approval_payload(body_digest=body_digest, policy_digest=policy_digest)
    for envelope in approvals:
        payload = verify_envelope(envelope, expected_kind=AUTHORITY_APPROVAL_KIND)
        if payload != expected:
            raise ReceiptError("authority approval is bound to a different body or policy")
        signer = envelope["signer"]
        if signer in signers:
            raise ReceiptError("duplicate authority approval signer")
        signers.add(signer)
    return signers


def derive_authority_state(
    policy: Any,
    *,
    actor: str,
    approval_signers: Iterable[str],
    verification_results: Mapping[str, Mapping[str, Any]],
) -> str:
    policy = validate_authority_policy(policy)
    principals = set(policy["principals"])
    signers = set(approval_signers)
    if actor not in principals:
        return "UNAUTHORIZED"
    if actor not in signers:
        return "UNRESOLVED"
    mode = policy["mode"]
    eligible = signers & principals
    if mode in {"EXACT", "ANY_OF"}:
        return "AUTHORIZED"
    if mode == "ALL_OF":
        return "AUTHORIZED" if principals <= eligible else "UNRESOLVED"
    if mode == "THRESHOLD":
        return "AUTHORIZED" if len(eligible) >= policy["threshold"] else "UNRESOLVED"
    # EXTERNAL: the actor must be explicitly named and the required foreign
    # authority artifacts must all verify natively.
    states: list[str] = []
    for evidence_id in policy["external_evidence"]:
        result = verification_results.get(evidence_id)
        if result is None:
            return "UNRESOLVED"
        states.append(result.get("result"))
    if any(state == "INVALID" for state in states):
        return "UNAUTHORIZED"
    if all(state == "VERIFIED" for state in states):
        return "AUTHORIZED"
    return "UNRESOLVED"


def sign_transition_approval(
    *, body_digest: str, from_policy_digest: str, to_policy_digest: str, key_path: str
) -> dict[str, Any]:
    payload = {
        "body_digest": body_digest,
        "from_policy_digest": from_policy_digest,
        "to_policy_digest": to_policy_digest,
    }
    for value in payload.values():
        if not SHA256_RE.fullmatch(value):
            raise ReceiptError("policy transition digests must be sha256: values")
    return sign_envelope(TRANSITION_APPROVAL_KIND, payload, key_path)


def verify_transition_approvals(
    approvals: Any,
    *,
    body_digest: str,
    from_policy: Any,
    to_policy: Any,
    verification_results: Mapping[str, Mapping[str, Any]],
) -> str:
    if not isinstance(approvals, list):
        raise ReceiptError("policy transition approvals must be a list")
    from_digest = authority_policy_digest(from_policy)
    to_digest = authority_policy_digest(to_policy)
    expected = {
        "body_digest": body_digest,
        "from_policy_digest": from_digest,
        "to_policy_digest": to_digest,
    }
    signers: set[str] = set()
    for envelope in approvals:
        payload = verify_envelope(envelope, expected_kind=TRANSITION_APPROVAL_KIND)
        if payload != expected:
            raise ReceiptError("policy transition approval is bound to different policies")
        if envelope["signer"] in signers:
            raise ReceiptError("duplicate policy transition signer")
        signers.add(envelope["signer"])
    if not signers:
        return "UNRESOLVED"
    # A transition has no single privileged actor.  It succeeds if at least one
    # approving principal can serve as actor and the old policy's quorum is met.
    for actor in signers:
        state = derive_authority_state(
            from_policy,
            actor=actor,
            approval_signers=signers,
            verification_results=verification_results,
        )
        if state == "AUTHORIZED":
            return state
    if all(actor not in set(validate_authority_policy(from_policy)["principals"]) for actor in signers):
        return "UNAUTHORIZED"
    return "UNRESOLVED"
