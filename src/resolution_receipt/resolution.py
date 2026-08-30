"""Resolution lineage above activity and transport receipts.

A resolution record does not score messages or agents. It binds one explicit target
to named checks, the evidence those checks cite, and a state derived mechanically
from their outcomes. Later corrections link to the exact prior signed object rather
than rewriting it.
"""

from __future__ import annotations

from typing import Any

from .core import ReceiptError, SHA256_RE, hash_object, sign_envelope, verify_envelope

RESOLUTION_KIND = "resolution-state"
RESOLUTION_STATES = {"SURVIVED", "NARROWED", "FAILED", "UNRESOLVED"}
CHECK_OUTCOMES = {"PASS", "FAIL", "UNRESOLVED"}
EVIDENCE_FIELDS = {"kind", "digest", "uri"}
CHECK_FIELDS = {"id", "requirement", "required", "outcome", "evidence"}
PAYLOAD_FIELDS = {
    "subject",
    "original_target",
    "effective_target",
    "evidence",
    "checks",
    "state",
    "previous",
    "revision_reason",
}


def _nonempty_text(value: Any, name: str, *, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ReceiptError(f"{name} must contain 1 to {limit} characters")
    return value


def _validate_evidence(evidence: Any) -> dict[str, dict[str, str | None]]:
    if not isinstance(evidence, dict):
        raise ReceiptError("evidence must be an object keyed by stable evidence id")
    result: dict[str, dict[str, str | None]] = {}
    for evidence_id, descriptor in evidence.items():
        _nonempty_text(evidence_id, "evidence id", limit=120)
        if not isinstance(descriptor, dict) or set(descriptor) != EVIDENCE_FIELDS:
            raise ReceiptError(
                "each evidence descriptor must contain kind, digest, and uri"
            )
        kind = _nonempty_text(descriptor["kind"], f"evidence.{evidence_id}.kind", limit=80)
        digest = descriptor["digest"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ReceiptError(f"evidence.{evidence_id}.digest must be a sha256: hash")
        uri = descriptor["uri"]
        if uri is not None:
            uri = _nonempty_text(uri, f"evidence.{evidence_id}.uri", limit=2048)
        result[evidence_id] = {"kind": kind, "digest": digest, "uri": uri}
    return result


def _validate_checks(
    checks: Any, evidence_ids: set[str]
) -> list[dict[str, Any]]:
    if not isinstance(checks, list) or not checks:
        raise ReceiptError("checks must be a non-empty list")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    required_count = 0
    for check in checks:
        if not isinstance(check, dict) or set(check) != CHECK_FIELDS:
            raise ReceiptError(
                "each check must contain id, requirement, required, outcome, and evidence"
            )
        check_id = _nonempty_text(check["id"], "check.id", limit=120)
        if check_id in seen:
            raise ReceiptError(f"duplicate check id: {check_id}")
        seen.add(check_id)
        requirement = _nonempty_text(
            check["requirement"], f"check.{check_id}.requirement"
        )
        required = check["required"]
        if not isinstance(required, bool):
            raise ReceiptError(f"check.{check_id}.required must be boolean")
        if required:
            required_count += 1
        outcome = check["outcome"]
        if outcome not in CHECK_OUTCOMES:
            raise ReceiptError(
                f"check.{check_id}.outcome must be PASS, FAIL, or UNRESOLVED"
            )
        refs = check["evidence"]
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ReceiptError(f"check.{check_id}.evidence must be a list of ids")
        if len(refs) != len(set(refs)):
            raise ReceiptError(f"check.{check_id}.evidence contains duplicates")
        unknown = set(refs) - evidence_ids
        if unknown:
            raise ReceiptError(
                f"check.{check_id} references unknown evidence: {sorted(unknown)[0]}"
            )
        if outcome in {"PASS", "FAIL"} and not refs:
            raise ReceiptError(
                f"check.{check_id} must cite evidence for a resolved outcome"
            )
        result.append(
            {
                "id": check_id,
                "requirement": requirement,
                "required": required,
                "outcome": outcome,
                "evidence": refs,
            }
        )
    if required_count == 0:
        raise ReceiptError("at least one check must be required")
    return result


def derive_resolution_state(
    *, original_target: str, effective_target: str, checks: list[dict[str, Any]]
) -> str:
    """Derive the only allowed state from required check outcomes.

    Known failure dominates missing evidence. If nothing failed but a required check
    remains unresolved, the whole resolution stays unresolved. NARROWED is only
    possible after every required check passes and the effective target is strictly
    different from the original one.
    """
    required = [check for check in checks if check["required"]]
    outcomes = {check["outcome"] for check in required}
    if "FAIL" in outcomes:
        return "FAILED"
    if "UNRESOLVED" in outcomes:
        return "UNRESOLVED"
    if effective_target != original_target:
        return "NARROWED"
    return "SURVIVED"


def build_resolution_payload(
    *,
    subject: str,
    original_target: str,
    effective_target: str,
    evidence: dict[str, Any],
    checks: list[dict[str, Any]],
    previous: str | None = None,
    revision_reason: str | None = None,
) -> dict[str, Any]:
    """Build and validate one deterministic resolution payload."""
    subject = _nonempty_text(subject, "subject", limit=2048)
    original_target = _nonempty_text(original_target, "original_target")
    effective_target = _nonempty_text(effective_target, "effective_target")
    evidence_valid = _validate_evidence(evidence)
    checks_valid = _validate_checks(checks, set(evidence_valid))

    if previous is None:
        if revision_reason is not None:
            raise ReceiptError("first resolution cannot have a revision_reason")
    else:
        if not isinstance(previous, str) or not SHA256_RE.fullmatch(previous):
            raise ReceiptError("previous must be a sha256: hash")
        revision_reason = _nonempty_text(
            revision_reason, "revision_reason", limit=2048
        )

    state = derive_resolution_state(
        original_target=original_target,
        effective_target=effective_target,
        checks=checks_valid,
    )
    return {
        "subject": subject,
        "original_target": original_target,
        "effective_target": effective_target,
        "evidence": evidence_valid,
        "checks": checks_valid,
        "state": state,
        "previous": previous,
        "revision_reason": revision_reason,
    }


def sign_resolution(
    *,
    subject: str,
    original_target: str,
    effective_target: str,
    evidence: dict[str, Any],
    checks: list[dict[str, Any]],
    key_path: str,
    previous: dict[str, Any] | None = None,
    revision_reason: str | None = None,
) -> dict[str, Any]:
    """Sign one resolution record, optionally linking it to a prior signed record."""
    previous_hash = hash_object(previous) if previous is not None else None
    payload = build_resolution_payload(
        subject=subject,
        original_target=original_target,
        effective_target=effective_target,
        evidence=evidence,
        checks=checks,
        previous=previous_hash,
        revision_reason=revision_reason,
    )
    return sign_envelope(RESOLUTION_KIND, payload, key_path)


def verify_resolution(
    envelope: Any, *, previous: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify signature, evidence references, derived state, and optional lineage."""
    payload = verify_envelope(envelope, expected_kind=RESOLUTION_KIND)
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise ReceiptError("resolution payload has missing or unknown fields")

    rebuilt = build_resolution_payload(
        subject=payload["subject"],
        original_target=payload["original_target"],
        effective_target=payload["effective_target"],
        evidence=payload["evidence"],
        checks=payload["checks"],
        previous=payload["previous"],
        revision_reason=payload["revision_reason"],
    )
    if payload["state"] != rebuilt["state"]:
        raise ReceiptError("resolution state does not match required check outcomes")

    if previous is None:
        if payload["previous"] is not None:
            raise ReceiptError("previous resolution object is required to verify lineage")
    else:
        verify_resolution(previous)
        if payload["previous"] != hash_object(previous):
            raise ReceiptError("previous resolution hash does not match")
        previous_payload = previous["payload"]
        if payload["subject"] != previous_payload["subject"]:
            raise ReceiptError("resolution lineage changed subject")
        if payload["original_target"] != previous_payload["original_target"]:
            raise ReceiptError("resolution lineage changed original_target")
    return payload


def verify_resolution_lineage(records: Any) -> dict[str, Any]:
    """Verify an append-only chain and return its current resolution state."""
    if not isinstance(records, list) or not records:
        raise ReceiptError("resolution lineage must be a non-empty list")
    previous = None
    latest = None
    for index, record in enumerate(records):
        if index == 0:
            latest = verify_resolution(record)
        else:
            latest = verify_resolution(record, previous=previous)
        previous = record
    assert latest is not None
    return {
        "integrity": "PASS",
        "records": len(records),
        "state": latest["state"],
        "subject": latest["subject"],
        "original_target": latest["original_target"],
        "effective_target": latest["effective_target"],
        "head": hash_object(records[-1]),
    }
