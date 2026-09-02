"""RLP-2 machine-readable scope adapters."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .core import ReceiptError

SCOPE_STATES = {"TRUE", "FALSE", "UNRESOLVED"}
ScopeAdapter = Callable[[Any, Any], str | bool | None]


def validate_scope(scope: Any) -> dict[str, Any]:
    if not isinstance(scope, dict) or set(scope) != {"adapter", "value"}:
        raise ReceiptError("scope must contain adapter and value")
    adapter = scope["adapter"]
    if not isinstance(adapter, str) or not adapter or len(adapter) > 160:
        raise ReceiptError("scope adapter must be a non-empty string")
    return {"adapter": adapter, "value": scope["value"]}


def exact_scope_adapter(container: Any, requested: Any) -> bool:
    return container == requested


def string_set_scope_adapter(container: Any, requested: Any) -> bool | None:
    if not isinstance(container, list) or not isinstance(requested, list):
        return None
    if any(not isinstance(item, str) for item in container + requested):
        return None
    return set(requested) <= set(container)


BUILTIN_SCOPE_ADAPTERS: dict[str, ScopeAdapter] = {
    "exact/v1": exact_scope_adapter,
    "string-set/v1": string_set_scope_adapter,
}


def scope_contains(
    effective_scope: Any,
    requested_scope: Any,
    *,
    adapters: Mapping[str, ScopeAdapter] | None = None,
) -> str:
    effective = validate_scope(effective_scope)
    requested = validate_scope(requested_scope)
    if effective["adapter"] != requested["adapter"]:
        return "UNRESOLVED"
    registry = dict(BUILTIN_SCOPE_ADAPTERS)
    if adapters:
        registry.update(adapters)
    adapter = registry.get(effective["adapter"])
    if adapter is None:
        return "UNRESOLVED"
    result = adapter(effective["value"], requested["value"])
    if result is True or result == "TRUE":
        return "TRUE"
    if result is False or result == "FALSE":
        return "FALSE"
    if result is None or result == "UNRESOLVED":
        return "UNRESOLVED"
    raise ReceiptError("scope adapter returned an invalid containment state")
