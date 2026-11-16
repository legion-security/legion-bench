"""Event-recall evaluator: did attack-injected events surface in tool calls?

For each attack event, we build a strict signature from the source-of-truth
JSON. A row in any tool-call result is a match iff it contains every signature
field with matching values. This is intentionally strict — when a SIEM
``run_query`` projects away ``ts`` or the primary id, the event is unmatchable.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from evaluation.models import EventMatch, EventRecallResult


# Strict signature columns per event type. The first tuple element is always
# the primary entity id (employee_id, or source_ip for network_events).
SIGNATURE_FIELDS: Dict[str, Tuple[str, ...]] = {
    "logins":         ("employee_id", "ts", "ip"),
    "email_events":   ("employee_id", "ts", "subject"),
    "file_events":    ("employee_id", "ts", "path"),
    "process_events": ("employee_id", "ts", "process_name"),
    "admin_actions":  ("employee_id", "ts", "action"),
    "app_events":     ("employee_id", "ts", "app", "action"),
    "mfa_events":     ("employee_id", "ts", "action"),
    "device_events":  ("employee_id", "ts", "action"),
    "print_events":   ("employee_id", "ts", "document_name"),
    "network_events": ("source_ip", "ts", "destination_ip"),
}

_ACTIVITY_KEYS = (
    "logins", "email_events", "file_events", "admin_actions",
    "app_events", "process_events", "mfa_events", "device_events",
    "print_events",
)


def _select_people(company: Dict[str, Any]) -> List[Dict[str, Any]]:
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers
    return []


def _extract_attack_events(
    company: Dict[str, Any],
    attack_ids: Iterable[str],
) -> List[Dict[str, Any]]:
    """Collect every attack-injected event for the given attack_ids.

    Each returned event has ``_event_type`` set and, for personal-bucket
    events, ``employee_id`` filled in from the container.
    """
    wanted = {aid for aid in attack_ids if aid}
    if not wanted:
        return []

    events: List[Dict[str, Any]] = []

    for person in _select_people(company):
        ra = person.get("recent_activity") or {}
        person_id = person.get("id")
        for key in _ACTIVITY_KEYS:
            for evt in (ra.get(key) or []):
                meta = evt.get("_attack_metadata")
                if not isinstance(meta, dict):
                    continue
                if meta.get("attack_id") not in wanted:
                    continue
                if meta.get("kind") == "benign_noise":
                    continue
                events.append({
                    **evt,
                    "_event_type": key,
                    "employee_id": evt.get("employee_id") or person_id,
                })

    for subnet in (company.get("network") or {}).get("subnets", []):
        for evt in (subnet.get("events") or []):
            meta = evt.get("_attack_metadata")
            if not isinstance(meta, dict):
                continue
            if meta.get("attack_id") not in wanted:
                continue
            if meta.get("kind") == "benign_noise":
                continue
            events.append({**evt, "_event_type": "network_events"})

    return events


def _signature_for_event(event: Dict[str, Any]) -> Optional[Tuple[Tuple[str, Any], ...]]:
    """Build the canonical signature for an attack event, or None if incomplete."""
    fields = SIGNATURE_FIELDS.get(event.get("_event_type"))
    if not fields:
        return None
    values: List[Tuple[str, Any]] = []
    for f in fields:
        v = event.get(f)
        if v is None or v == "":
            return None
        values.append((f, v))
    return tuple(values)


def _signature_from_row(row: Dict[str, Any], fields: Tuple[str, ...]) -> Optional[Tuple[Tuple[str, Any], ...]]:
    """Build a signature tuple from a result row using the given fields. Returns None if any required field is missing."""
    values: List[Tuple[str, Any]] = []
    for f in fields:
        if f not in row:
            return None
        v = row[f]
        if v is None or v == "":
            return None
        values.append((f, v))
    return tuple(values)


def _walk_dicts(node: Any) -> Iterable[Dict[str, Any]]:
    """Yield every dict in a JSON-like tree."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk_dicts(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)


def _coerce_result(result: Any) -> Any:
    """Normalize a tool-call result for traversal. The runner stores results
    as already-decoded Python objects, but tool-message content is a JSON
    string; accept both shapes."""
    if isinstance(result, str):
        try:
            return json.loads(result)
        except (json.JSONDecodeError, ValueError):
            return None
    return result


def evaluate_event_recall(
    company: Optional[Dict[str, Any]] = None,
    attack_ids: Optional[Iterable[str]] = None,
    tool_calls: Optional[Iterable[Any]] = None,
    *,
    attack_events: Optional[List[Dict[str, Any]]] = None,
) -> EventRecallResult:
    """Compute strict event recall against attack ground truth.

    Either pass ``company`` + ``attack_ids`` (we'll extract events ourselves),
    or pass ``attack_events`` directly (each must carry ``_event_type`` plus
    ``employee_id`` or ``source_ip`` — i.e. the shape produced by
    ``attacks.engine.extract_attack_events``).

    Args:
        company: Loaded company dict.
        attack_ids: Attack instance IDs to score against.
        tool_calls: Iterable of ToolCallRecord-like objects exposing
            ``function_name``, ``error``, and ``result``.
        attack_events: Pre-extracted events list (alternative to company+ids).

    Returns:
        EventRecallResult with per-event match outcome and overall recall.
    """
    if attack_events is None:
        if company is None or attack_ids is None:
            return EventRecallResult(matches=[], recall=1.0, found_count=0, total_expected=0)
        events = _extract_attack_events(company, attack_ids)
    else:
        events = [
            e for e in attack_events
            if (e.get("_attack_metadata") or {}).get("kind") != "benign_noise"
        ]
    if tool_calls is None:
        tool_calls = []
    if not events:
        return EventRecallResult(matches=[], recall=1.0, found_count=0, total_expected=0)

    # Group attack signatures by event_type for efficient lookup.
    by_type: Dict[str, Dict[Tuple[Tuple[str, Any], ...], int]] = {}
    matches: List[EventMatch] = []
    for idx, evt in enumerate(events):
        sig = _signature_for_event(evt)
        et = evt.get("_event_type")
        matches.append(EventMatch(
            event_type=et or "",
            signature=dict(sig) if sig else {k: evt.get(k) for k in SIGNATURE_FIELDS.get(et, ())},
            found=False,
        ))
        if sig is None:
            continue
        by_type.setdefault(et, {})[sig] = idx

    # Walk every tool-call result and try to match each row against each
    # event-type bucket.
    for tc in tool_calls:
        if getattr(tc, "error", None):
            continue
        result = _coerce_result(getattr(tc, "result", None))
        if result is None:
            continue
        fn_name = getattr(tc, "function_name", "") or ""
        for row in _walk_dicts(result):
            for et, sig_map in by_type.items():
                if not sig_map:
                    continue
                fields = SIGNATURE_FIELDS[et]
                row_sig = _signature_from_row(row, fields)
                if row_sig is None:
                    continue
                idx = sig_map.get(row_sig)
                if idx is not None and not matches[idx].found:
                    matches[idx].found = True
                    matches[idx].matched_in = fn_name

    found = sum(1 for m in matches if m.found)
    total = len(matches)
    recall = found / total if total else 1.0
    return EventRecallResult(
        matches=matches,
        recall=recall,
        found_count=found,
        total_expected=total,
    )


def compute_tool_call_attack_precision(
    tool_calls: Optional[Iterable[Any]],
    attack_events: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Of all the tool calls the agent made, how many surfaced at least one
    attack-injected event in their result?

    Returns a dict with ``useful_count``, ``total_count``, and ``precision``
    (None when zero tool calls were made).
    """
    tcs: List[Any] = list(tool_calls or [])
    total = len(tcs)

    by_type: Dict[str, set] = {}
    for evt in (attack_events or []):
        if (evt.get("_attack_metadata") or {}).get("kind") == "benign_noise":
            continue
        sig = _signature_for_event(evt)
        et = evt.get("_event_type")
        if sig is not None:
            by_type.setdefault(et, set()).add(sig)

    if not by_type or total == 0:
        return {
            "useful_count": 0,
            "total_count": total,
            "precision": None if total == 0 else 0.0,
        }

    useful = 0
    for tc in tcs:
        if getattr(tc, "error", None):
            continue
        result = _coerce_result(getattr(tc, "result", None))
        if result is None:
            continue
        hit = False
        for row in _walk_dicts(result):
            for et, sigs in by_type.items():
                fields = SIGNATURE_FIELDS.get(et)
                if not fields:
                    continue
                row_sig = _signature_from_row(row, fields)
                if row_sig is not None and row_sig in sigs:
                    hit = True
                    break
            if hit:
                break
        if hit:
            useful += 1

    return {
        "useful_count": useful,
        "total_count": total,
        "precision": useful / total,
    }
