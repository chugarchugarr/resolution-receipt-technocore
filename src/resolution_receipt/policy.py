"""RLP-2 deterministic action-policy evaluation."""

from __future__ import annotations

from typing import Any, Mapping

from .core import ReceiptError, hash_object
from .scope import ScopeAdapter, scope_contains

ACTION_STATES = {"PERMIT", "DENY", "HOLD"}
ACTION_POLICY_VERSION = "rlp.action.v2"


def validate_action_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) != {
        "policy_version", "policy_id", "rules", "default"
    }:
        raise ReceiptError("action policy has missing or unknown fields")
    if policy["policy_version"] != ACTION_POLICY_VERSION:
        raise ReceiptError("unsupported action policy version")
    policy_id = policy["policy_id"]
    if not isinstance(policy_id, str) or not policy_id or len(policy_id) > 160:
        raise ReceiptError("action policy_id must be a non-empty string")
    if policy["default"] != "HOLD":
        raise ReceiptError("RLP-2 action policy default must be HOLD")
    rules = policy["rules"]
    if not isinstance(rules, list):
        raise ReceiptError("action policy rules must be a list")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "action", "allowed_resolution_states", "require_authority",
            "require_scope_containment"
        }:
            raise ReceiptError("action policy rule has invalid fields")
        action = rule["action"]
        if not isinstance(action, str) or not action or len(action) > 160:
            raise ReceiptError("action rule action must be a non-empty string")
        if action in seen:
            raise ReceiptError("action policy contains duplicate action rules")
        seen.add(action)
        allowed = rule["allowed_resolution_states"]
        if not isinstance(allowed, list) or not allowed or any(
            item not in {"SURVIVED", "NARROWED", "FAILED", "UNRESOLVED"}
            for item in allowed
        ) or len(allowed) != len(set(allowed)):
            raise ReceiptError("allowed_resolution_states is invalid")
        if rule["require_authority"] != "AUTHORIZED":
            raise ReceiptError("RLP-2 operative rules must require AUTHORIZED")
        if not isinstance(rule["require_scope_containment"], bool):
            raise ReceiptError("require_scope_containment must be boolean")
        validated.append({
            "action": action,
            "allowed_resolution_states": allowed,
            "require_authority": "AUTHORIZED",
            "require_scope_containment": rule["require_scope_containment"],
        })
    return {
        "policy_version": ACTION_POLICY_VERSION,
        "policy_id": policy_id,
        "rules": validated,
        "default": "HOLD",
    }


def action_policy_digest(policy: Any) -> str:
    return hash_object(validate_action_policy(policy))


def derive_action_decision(
    *,
    action_id: str,
    requested_scope: Any,
    resolution_state: str,
    authority_state: str,
    effective_scope: Any,
    lineage_integrity: str,
    policy: Any,
    resolution_head: str,
    scope_adapters: Mapping[str, ScopeAdapter] | None = None,
) -> dict[str, Any]:
    """Evaluate a specific proposed action against one exact resolution head."""
    policy = validate_action_policy(policy)
    if lineage_integrity != "PASS":
        decision = "HOLD"
        reason = "resolution lineage integrity is not established"
    elif authority_state == "UNAUTHORIZED":
        decision = "DENY"
        reason = "resolver is unauthorized under the bound authority policy"
    elif authority_state != "AUTHORIZED":
        decision = "HOLD"
        reason = "resolver authority is unresolved"
    else:
        rule = next((item for item in policy["rules"] if item["action"] == action_id), None)
        if rule is None:
            decision = "HOLD"
            reason = "no action-policy rule matches the requested action"
        elif resolution_state == "UNRESOLVED":
            decision = "HOLD"
            reason = "the bounded resolution remains unresolved"
        elif resolution_state not in rule["allowed_resolution_states"]:
            decision = "DENY"
            reason = "the current resolution state is not permitted for this action"
        elif rule["require_scope_containment"]:
            containment = scope_contains(
                effective_scope, requested_scope, adapters=scope_adapters
            )
            if containment == "TRUE":
                decision = "PERMIT"
                reason = "authority, resolution state, and scope satisfy policy"
            elif containment == "FALSE":
                decision = "DENY"
                reason = "requested action exceeds the effective resolved scope"
            else:
                decision = "HOLD"
                reason = "scope containment cannot be established"
        else:
            decision = "PERMIT"
            reason = "authority and resolution state satisfy policy"
    return {
        "action_id": action_id,
        "decision": decision,
        "reason": reason,
        "resolution_head": resolution_head,
        "action_policy_digest": hash_object(policy),
    }
