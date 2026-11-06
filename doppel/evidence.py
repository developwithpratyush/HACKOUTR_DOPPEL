"""Helpers every tool uses to build evidence items in the contract format.

Tools don't own evidence IDs: the brain passes an ``Ids`` allocator so IDs stay
unique within a verdict. Called on their own (tests, notebooks), tools make a
fresh allocator.
"""

from __future__ import annotations

from typing import Any


class Ids:
    """Hands out E1, E2, … in order."""

    def __init__(self, start: int = 1) -> None:
        self._next = start

    def __call__(self) -> str:
        eid = f"E{self._next}"
        self._next += 1
        return eid


def brand_ref(brand: Any) -> dict[str, str] | None:
    """``{id, name}`` for a registry brand (anything with .id and .name), or None."""
    if brand is None:
        return None
    return {"id": brand.id, "name": brand.name}


def evidence(
    ids: Ids,
    *,
    tool: str,
    stage: str,
    criterion: str,
    finding: str,
    points_to: str,
    strength: str,
    score: float,
    summary: str,
    target_brand: dict[str, str] | None = None,
    duration_ms: float | None = None,
    **details: Any,
) -> dict[str, Any]:
    """One evidence item. Neutral findings always get score 0 (contract invariant 10)."""
    item: dict[str, Any] = {
        "evidence_id": ids(),
        "tool": tool,
        "stage": stage,
        "criterion": criterion,
        "finding": finding,
        "points_to": points_to,
        "strength": strength,
        "score": 0.0 if points_to == "neutral" else round(float(score), 4),
        "target_brand": target_brand,
        "summary": summary,
        "details": details,
    }
    if duration_ms is not None:
        item["duration_ms"] = round(duration_ms, 3)
    return item
