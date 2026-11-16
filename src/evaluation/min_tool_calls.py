"""Lower bound on oracle SIEM ``run_query`` calls needed to surface every
distinct attack event — the denominator of ``tool_call_efficiency``.

A SIEM query of the form ``SELECT * FROM <table> WHERE <entity_field> = X``
surfaces every attack event in that ``(entity, event_type)`` bucket. Modelling
each bucket as one candidate set makes the set-cover degenerate: the minimum
number of queries is simply the number of distinct ``(entity, event_type)``
pairs across the attack events.

Public API mirrors the call site in ``bench/report.py`` and
``streamlit_report_viewer.py``::

    min_tool_calls_for_events(events, use_ilp=False) -> Optional[int]
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from evaluation.events import SIGNATURE_FIELDS


def _entity_for_event(event: Dict[str, Any]) -> Optional[Any]:
    """Primary entity id for an attack event — ``source_ip`` for network
    events, ``employee_id`` otherwise. Mirrors ``SIGNATURE_FIELDS[*][0]``."""
    fields = SIGNATURE_FIELDS.get(event.get("_event_type"))
    if not fields:
        return None
    primary = fields[0]
    val = event.get(primary)
    if val is None or val == "":
        return None
    return val


def min_tool_calls_for_events(
    events: Iterable[Dict[str, Any]],
    *,
    use_ilp: bool = False,
) -> Optional[int]:
    """Minimum oracle ``run_query`` calls required to surface every attack
    event.

    Each event lives in a ``(entity, _event_type)`` bucket; one broad query
    per bucket covers it. The result is the number of non-empty distinct
    buckets across ``events``.

    Args:
        events: Iterable of attack-event dicts shaped like the output of
            ``attacks.engine.extract_attack_events`` — each carrying
            ``_event_type`` plus the matching primary entity field.
        use_ilp: Reserved for an exact ILP solver over a richer candidate-
            query set. The current bucket model is already optimal for the
            single-table-per-query oracle, so this flag is currently unused.

    Returns:
        The minimum query count, or ``None`` when no events have a usable
        signature (e.g. non-isolated mode where attack events aren't
        attached to the trace).
    """
    del use_ilp  # placeholder for future ILP path

    buckets: set = set()
    for evt in events or ():
        if not isinstance(evt, dict):
            continue
        et = evt.get("_event_type")
        if not et or et not in SIGNATURE_FIELDS:
            continue
        entity = _entity_for_event(evt)
        if entity is None:
            continue
        buckets.add((entity, et))

    if not buckets:
        return None
    return len(buckets)
