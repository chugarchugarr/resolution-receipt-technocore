"""RLP-2 native-evidence verification boundary.

RLP-2 does not reinterpret foreign protocols. A verification adapter owns the
native semantics for one evidence method and returns VERIFIED, INVALID, or
UNRESOLVED. Stored results are deterministic, hash-bound observations that an
independent verifier can recompute when it has the same adapter implementation.

The declared ``method_digest`` is bound to the exact Python source returned for
the registered adapter callable. This is intentionally narrower than claiming a
transitive software-supply-chain proof: dependencies and runtime state remain an
external verification concern. It does prevent silently substituting a different
adapter implementation while retaining the same signed verification spec.
"""

from __future__ import annotations

import hashlib
import inspect
from typing import Any, Callable, Mapping

from .core import ReceiptError, SHA256_RE, hash_object

VERIFICATION_STATES = {"VERIFIED", "INVALID", "UNRESOLVED"}
VerificationAdapter = Callable[[dict[str, Any], dict[str, Any]], str | bool | None]


def _text(value: Any, name: str, *, limit: int = 160) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ReceiptError(f"{name} must contain 1 to {limit} characters")
    return value


def adapter_code_digest(adapter: VerificationAdapter) -> str:
    """Return a deterministic digest of the registered adapter's Python source.

    The digest authenticates the callable source presented to this verifier. It
    does not claim to cover transitive imports, interpreter state, or external
    services used by that callable.
    """
    if not callable(adapter):
        raise ReceiptError("verification adapter must be callable")
    try:
        source = inspect.getsource(adapter)
    except (OSError, TypeError) as exc:
        raise ReceiptError("verification adapter source is unavailable for digest binding") from exc
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


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
    """Run declared native adapters and return canonical verification results.

    If an adapter is available, its exact callable source digest must match the
    signed method_digest before the adapter may influence a result. A missing
    adapter remains UNRESOLVED rather than being promoted to VERIFIED.
    """
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
            actual_digest = adapter_code_digest(adapter)
            if actual_digest != spec["method_digest"]:
                raise ReceiptError(
                    f"verification adapter digest mismatch for method {spec['method']}"
                )
            state = _normalize_state(adapter(descriptor, spec["claims"]))
        results[evidence_id] = {
            "method": spec["method"],
            "method_digest": spec["method_digest"],
            "claims_digest": hash_object(spec["claims"]),
            "result": state,
        }
    return results


def validate_verification_results(
    evidence: Mapping[str, dict[str, Any]],
    results: Any,
    *,
    specs: Mapping[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Validate stored results and optionally bind them exactly to their specs."""
    if not isinstance(results, dict) or set(results) != set(evidence):
        raise ReceiptError("verification_results must correspond exactly to evidence")
    if specs is not None and set(specs) != set(evidence):
        raise ReceiptError("verification_specs must correspond exactly to evidence")
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
        if specs is not None:
            spec = validate_verification_spec(specs[evidence_id])
            expected_claims_digest = hash_object(spec["claims"])
            if method != spec["method"]:
                raise ReceiptError(f"verification_results.{evidence_id}.method does not match spec")
            if method_digest != spec["method_digest"]:
                raise ReceiptError(
                    f"verification_results.{evidence_id}.method_digest does not match spec"
                )
            if claims_digest != expected_claims_digest:
                raise ReceiptError(
                    f"verification_results.{evidence_id}.claims_digest does not match spec"
                )
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
    validate_verification_results(evidence, stored, specs=specs)
    current = verify_evidence_set(evidence, specs, adapters)
    if current != stored:
        raise ReceiptError("native evidence verification no longer matches the signed result")
    return current
