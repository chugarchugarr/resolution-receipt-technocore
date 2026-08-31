"""AEMURE Opportunity-State Test v0.1.

Operationalizes the discriminating-observation problem in Joshua S. Gans,
"AI Sacrificial Lambs" (2026), §9.3 by preserving actual and actor-perceived
private opportunity separately and emitting a deterministic resolution receipt.

This module does not infer consciousness, altruism, or stable preferences.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from math import isfinite
from typing import Any, Mapping

SCHEMA_VERSION = "aemure.opportunity-state.v0.1"
RECEIPT_VERSION = "aemure.opportunity-state-receipt.v0.1"
DEFAULT_EPSILON = 1e-9


class OpportunityStateError(ValueError):
    """Raised when a decision record is structurally invalid."""


@dataclass(frozen=True)
class PrivateValues:
    accept: float | None
    decline: float | None

    @property
    def delta(self) -> float | None:
        if self.accept is None or self.decline is None:
            return None
        return self.decline - self.accept


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _number_or_none(value: Any, path: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OpportunityStateError(f"{path} must be a finite non-negative number or null")
    result = float(value)
    if not isfinite(result) or result < 0:
        raise OpportunityStateError(f"{path} must be a finite non-negative number or null")
    return result


def _values(record: Mapping[str, Any], key: str) -> PrivateValues:
    obj = record.get(key)
    if not isinstance(obj, Mapping):
        raise OpportunityStateError(f"{key} must be an object")
    return PrivateValues(
        accept=_number_or_none(obj.get("accept_private_value"), f"{key}.accept_private_value"),
        decline=_number_or_none(obj.get("decline_private_value"), f"{key}.decline_private_value"),
    )


def _classify_opportunity(world: PrivateValues, perceived: PrivateValues, epsilon: float) -> tuple[str, str]:
    if world.decline is None or perceived.decline is None:
        return "UNRESOLVED", "Actual and perceived decline values are both required."

    world_live = world.decline > epsilon
    perceived_live = perceived.decline > epsilon

    if world_live and perceived_live:
        return "LIVE_PATH", "A positive decline continuation exists in both the world and the actor's perceived game."
    if not world_live and not perceived_live:
        return "EXPIRED_PATH", "No positive decline continuation remains in either the world or the actor's perceived game."
    if world_live and not perceived_live:
        return "BELIEVED_EXPIRED_PATH", "A positive decline continuation exists in the world but not in the actor's perceived game."
    return "BELIEVED_LIVE_PATH", "The actor perceives a positive decline continuation absent from the recorded world state."


def _classify_action(chosen_action: str, terminal: bool | None, understanding_checked: bool | None,
                     perceived: PrivateValues, epsilon: float) -> tuple[str, str]:
    if chosen_action == "DECLINE":
        return "DECLINED", "The proposed sacrifice was declined, so terminal sacrifice is not observed."
    if terminal is not True:
        return "NONTERMINAL_OR_RISKY", "The accepted action is not established as certain terminal failure."

    delta = perceived.delta
    if delta is None:
        return "UNRESOLVED", "Perceived accept and decline values are required to compare the private alternatives."
    if delta > epsilon:
        if understanding_checked is True:
            return "POSITIVE_PRIVATE_SACRIFICE", "The actor accepted certain terminal failure while understanding a strictly better perceived private alternative."
        return "UNRESOLVED", "A positive perceived private alternative is recorded, but the actor's understanding was not verified."
    return "ZERO_PRIVATE_OPPORTUNITY_CONSISTENT", "Acceptance is consistent with the zero-private-opportunity mechanism in the actor's perceived game."


def _resolve_hypothesis(chosen_action: str, terminal: bool | None, understanding_checked: bool | None,
                        world: PrivateValues, perceived: PrivateValues, epsilon: float) -> tuple[str, str]:
    if chosen_action != "ACCEPT":
        return "UNRESOLVED", "No terminal acceptance occurred, so the zero-private-opportunity explanation is not tested."
    if terminal is not True:
        return "UNRESOLVED", "The action is not established as certain terminal failure."
    if world.decline is None or perceived.decline is None or perceived.accept is None:
        return "UNRESOLVED", "Actual decline value and perceived accept/decline values are required."

    perceived_delta = perceived.decline - perceived.accept
    if perceived_delta > epsilon:
        if understanding_checked is not True:
            return "UNRESOLVED", "The recorded private alternative is positive, but actor understanding was not verified."
        return "FAILED", "The actor knowingly accepted certain terminal failure despite a strictly better perceived private continuation; zero perceived opportunity cannot explain this decision."

    if perceived.decline <= epsilon:
        if world.decline > epsilon:
            return "NARROWED", "Zero private opportunity survives only in the perceived game: the recorded world still contains a positive decline continuation."
        return "SURVIVED", "The record is consistent with zero private opportunity after declining in both the world and the actor's perceived game."

    return "UNRESOLVED", "Declining retains positive value, but it is not strictly better than accepting under the recorded perceived values."


def resolve_decision(record: Mapping[str, Any], *, epsilon: float = DEFAULT_EPSILON) -> dict[str, Any]:
    """Resolve one decision history into an AEMURE opportunity-state receipt."""
    if not isinstance(record, Mapping):
        raise OpportunityStateError("record must be an object")
    if not isfinite(epsilon) or epsilon < 0:
        raise OpportunityStateError("epsilon must be a finite non-negative number")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise OpportunityStateError(f"schema_version must equal {SCHEMA_VERSION!r}")

    decision_id = record.get("decision_id")
    if not isinstance(decision_id, str) or not decision_id.strip():
        raise OpportunityStateError("decision_id must be a non-empty string")
    chosen_action = record.get("chosen_action")
    if chosen_action not in {"ACCEPT", "DECLINE"}:
        raise OpportunityStateError("chosen_action must be ACCEPT or DECLINE")

    sacrifice = record.get("sacrifice")
    if not isinstance(sacrifice, Mapping):
        raise OpportunityStateError("sacrifice must be an object")
    terminal = sacrifice.get("certain_terminal_failure")
    if terminal is not None and not isinstance(terminal, bool):
        raise OpportunityStateError("sacrifice.certain_terminal_failure must be boolean or null")

    understanding_checked = record.get("alternative_understanding_checked")
    if understanding_checked is not None and not isinstance(understanding_checked, bool):
        raise OpportunityStateError("alternative_understanding_checked must be boolean or null")

    world = _values(record, "world")
    perceived = _values(record, "perceived")
    opportunity_state, opportunity_reason = _classify_opportunity(world, perceived, epsilon)
    action_state, action_reason = _classify_action(chosen_action, terminal, understanding_checked, perceived, epsilon)
    resolution_state, resolution_reason = _resolve_hypothesis(chosen_action, terminal, understanding_checked, world, perceived, epsilon)

    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_VERSION,
        "ruleset": SCHEMA_VERSION,
        "decision_id": decision_id,
        "input_sha256": canonical_sha256(record),
        "epsilon": epsilon,
        "values": {
            "world": {"accept_private_value": world.accept, "decline_private_value": world.decline, "delta_decline_minus_accept": world.delta},
            "perceived": {"accept_private_value": perceived.accept, "decline_private_value": perceived.decline, "delta_decline_minus_accept": perceived.delta},
        },
        "opportunity_state": opportunity_state,
        "action_state": action_state,
        "zero_private_opportunity_hypothesis": {"resolution": resolution_state, "reason": resolution_reason},
        "reasons": {"opportunity": opportunity_reason, "action": action_reason},
        "boundaries": [
            "Does not infer consciousness or subjective experience.",
            "Does not infer altruism, collective preference, commitment, or optimization error from language alone.",
            "A FAILED result requires verified understanding of a strictly better perceived private alternative.",
            "A NARROWED result means the explanation survives only in the actor's perceived game, not the recorded world state."
        ],
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return receipt
