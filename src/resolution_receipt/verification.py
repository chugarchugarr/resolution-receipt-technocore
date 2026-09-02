"""RLP-2 native-evidence verification boundary.

RLP-2 does not reinterpret foreign protocols.  A verification adapter owns the
native semantics for one evidence method and returns VERIFIED, INVALID, or
UNRESOLVED.  Stored results are deterministic, hash-bound observations that an
independent verifier can recompute when it has the same adapter implementation.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .core import ReceiptError, SHA256_RE, hash_object

VERIFICATION_STATES = {"VERIFIED", "INVALID", "UNRESOLVED"}
VerificationAdapter = Callable[[dict[str, Any], dict[str, Any]], str | bool | None]


def _text(value: Any, name: str, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ReceiptError(f"{name} must contain 1 to {limit} characters")
    return value


def _normalize_state(value: str | bool | None) -> str:
    if value is True:
        return "VERIFIED"
    if value is False:
        return "INVALID"
    if value is None:
        return "UNRESOLVED"
    if value not in VERIFICATION_STATES:
        raise ReceiptError("verification adapter returned an invalid state")
    return value


def validate_verification_spec(spec: Any) -> dict[str, Any]:
    if not isinstance(spec, dict) or set(spec) != {"method", "method_digest", "claims"}:
        raise ReceiptError("verification spec must contain method, method_digest, and claims")
    method = _text(spec["method"], "verification method")
    digest = spec["method_digest"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReceiptError("verification method_digest must be a sha256: hash")
    claims = spec["claims"]
    if not isinstance(claims, dict):
        raise ReceiptError("verification claims must be an object")
    return {"method": method, "method_digest": digest, "claims": claims}


def verify_evidence_set(
    evidence: Mapping[str, dict[str, Any]],
    specs: Mapping[str, dict[str, Any]],
    adapters: Mapping[str, VerificationAdapter],
) -> dict[str, dict[str, Any]]:
    """Run declared native adapters and return canonical verification results."""
    if set(specs) != set(evidence):
        raise ReceiptError("every evidence object must have exactly one verification spec")
    results: dict[str, dict[str, Any]] = {}
    for evidence_id in sorted(evidence):
        descriptor = evidence[evidence_id]
        if not isinstance(descriptor, dict):
            raise ReceiptError(f"evidence.{evidence_id} must be an object")
        spec = validate_verification_spec(specs[evidence_id])
        adapter = adapters.get(spec["method"])
        if adapter is None:
            state = "UNRESOLVED"
        else:
            state = _normalize_state(adapter(descriptor, spec["claims"]))
        results[evidence_id] = {
            "method": spec["method"],
            "method_digest": spec["method_digest"],
            "claims_digest": hash_object(spec["claims"]),
            "result": state,
        }
    return results


def validate_verification_results(
    evidence: Mapping[str, dict[str, Any]], results: Any
) -> dict[str, dict[str, Any]]:
    if not isinstance(results, dict) or set(results) != set(evidence):
        raise ReceiptError("verification_results must correspond exactly to evidence")
    validated: dict[str, dict[str, Any]] = {}
    fields = {"method", "method_digest", "claims_digest", "result"}
    for evidence_id, result in results.items():
        if not isinstance(result, dict) or set(result) != fields:
            raise ReceiptError(f"verification_results.{evidence_id} has invalid fields")
        method = _text(result["method"], f"verification_results.{evidence_id}.method")
        method_digest = result["method_digest"]
        claims_digest = result["claims_digest"]
        if not isinstance(method_digest, str) or not SHA256_RE.fullmatch(method_digest):
            raise ReceiptError(f"verification_results.{evidence_id}.method_digest must be sha256")
        if not isinstance(claims_digest, str) or not SHA256_RE.fullmatch(claims_digest):
            raise ReceiptError(f"verification_results.{evidence_id}.claims_digest must be sha256")
        state = result["result"]
        if state not in VERIFICATION_STATES:
            raise ReceiptError(f"verification_results.{evidence_id}.result is invalid")
        validated[evidence_id] = {
            "method": method,
            "method_digest": method_digest,
            "claims_digest": claims_digest,
            "result": state,
        }
    return validated


def require_verified_check_evidence(
    checks: list[dict[str, Any]], results: Mapping[str, dict[str, Any]]
) -> None:
    """Prevent PASS/FAIL checks from relying on unverified native evidence."""
    for check in checks:
        if check["outcome"] not in {"PASS", "FAIL"}:
            continue
        for evidence_id in check["evidence"]:
            if results[evidence_id]["result"] != "VERIFIED":
                raise ReceiptError(
                    f"resolved check {check['id']} cites evidence {evidence_id} "
                    "that is not VERIFIED"
                )


def recompute_verification_results(
    evidence: Mapping[str, dict[str, Any]],
    specs: Mapping[str, dict[str, Any]],
    stored: Mapping[str, dict[str, Any]],
    adapters: Mapping[str, VerificationAdapter],
) -> dict[str, dict[str, Any]]:
    """Re-run adapters and require exact equality with the signed stored result."""
    current = verify_evidence_set(evidence, specs, adapters)
    if current != stored:
        raise ReceiptError("native evidence verification no longer matches the signed result")
    return current
