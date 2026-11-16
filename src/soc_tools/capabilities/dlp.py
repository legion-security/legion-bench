"""DLP capabilities — DLP alerts, IRM alerts, file activity, classification, print audit."""

import sqlite3
from typing import Any, Dict, List, Optional


def _strip_internal(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _rows_to_dicts(cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    return [_strip_internal(dict(zip(cols, row))) for row in cursor.fetchall()]


def get_dlp_alerts(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    policy_name: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get DLP alerts based on sensitive file activity and email policy violations.

    Generates alerts from file events with sensitivity labels and email events
    with attachments that may violate DLP policies.

    Args:
        employee_id: Filter by employee ID.
        policy_name: Filter by policy name (substring match on label/category).
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        List of DLP alert dicts.
    """
    alerts: List[Dict[str, Any]] = []

    # File-based DLP alerts: sensitive file sharing/copying/downloading
    file_where = ["fe.label IS NOT NULL", "fe.action IN ('share', 'copy', 'download', 'modify')"]
    file_params: list = []

    if employee_id:
        file_where.append("fe.employee_id = ?")
        file_params.append(employee_id)
    if policy_name:
        file_where.append("(fe.label LIKE ? OR fe.category LIKE ?)")
        file_params.extend([f"%{policy_name}%", f"%{policy_name}%"])
    if time_start:
        file_where.append("fe.ts >= ?")
        file_params.append(time_start)
    if time_end:
        file_where.append("fe.ts <= ?")
        file_params.append(time_end)

    file_query = f"""
        SELECT fe.*, e.email, e.display_name
        FROM file_events fe
        LEFT JOIN employees e ON fe.employee_id = e.id
        WHERE {" AND ".join(file_where)}
        ORDER BY fe.ts DESC LIMIT ?
    """
    file_params.append(limit)

    cursor = conn.cursor()
    cursor.execute(file_query, file_params)
    for row in _rows_to_dicts(cursor):
        alerts.append({
            "alert_type": "dlp_file_policy",
            "policy_name": row.get("label", "Unknown"),
            "severity": "high" if row.get("action") in ("share", "copy") else "medium",
            "employee_id": row.get("employee_id"),
            "email": row.get("email"),
            "display_name": row.get("display_name"),
            "ts": row.get("ts"),
            "action": row.get("action"),
            "path": row.get("path"),
            "label": row.get("label"),
            "category": row.get("category"),
            "system": row.get("system"),
            "destination": row.get("destination"),
        })

    # Email-based DLP alerts: emails with sensitive attachments to external
    email_where = [
        "ee.external = 1",
        "ee.attachments IS NOT NULL",
        "ee.attachments != '[]'",
        "ee.attachments != 'null'",
    ]
    email_params: list = []

    if employee_id:
        email_where.append("ee.employee_id = ?")
        email_params.append(employee_id)
    if policy_name:
        email_where.append("(ee.subject LIKE ? OR ee.attachments LIKE ?)")
        email_params.extend([f"%{policy_name}%", f"%{policy_name}%"])
    if time_start:
        email_where.append("ee.ts >= ?")
        email_params.append(time_start)
    if time_end:
        email_where.append("ee.ts <= ?")
        email_params.append(time_end)

    email_query = f"""
        SELECT ee.*, e.email as owner_email, e.display_name
        FROM email_events ee
        LEFT JOIN employees e ON ee.employee_id = e.id
        WHERE {" AND ".join(email_where)}
        ORDER BY ee.ts DESC LIMIT ?
    """
    email_params.append(limit)

    cursor.execute(email_query, email_params)
    for row in _rows_to_dicts(cursor):
        alerts.append({
            "alert_type": "dlp_email_policy",
            "policy_name": "External email with attachments",
            "severity": "medium",
            "employee_id": row.get("employee_id"),
            "email": row.get("owner_email"),
            "display_name": row.get("display_name"),
            "ts": row.get("ts"),
            "sender": row.get("sender"),
            "subject": row.get("subject"),
            "recipients": row.get("recipients"),
            "attachments": row.get("attachments"),
        })

    alerts.sort(key=lambda a: a.get("ts", ""), reverse=True)
    return alerts[:limit]


def get_irm_alerts(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    policy_name: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get Insider Risk Management alerts for suspicious insider activity.

    Detects bulk downloads, unusual print activity, sensitive file access patterns,
    and data exfiltration indicators.

    Args:
        employee_id: Filter by employee ID.
        policy_name: Filter by policy name (substring match).
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        List of IRM alert dicts.
    """
    alerts: List[Dict[str, Any]] = []
    cursor = conn.cursor()

    # Build common time filter
    time_filter = ""
    time_params: list = []
    if time_start:
        time_filter += " AND ts >= ?"
        time_params.append(time_start)
    if time_end:
        time_filter += " AND ts <= ?"
        time_params.append(time_end)

    # 1. Bulk file operations (download/copy/share >= 10 in a window)
    if not policy_name or "bulk" in policy_name.lower() or "exfiltration" in policy_name.lower():
        bulk_where = "action IN ('read', 'download', 'copy', 'share')"
        bulk_params: list = []
        if employee_id:
            bulk_where += " AND employee_id = ?"
            bulk_params.append(employee_id)

        bulk_query = f"""
            SELECT employee_id, COUNT(*) as file_count,
                   MIN(ts) as first_ts, MAX(ts) as last_ts,
                   GROUP_CONCAT(DISTINCT action) as actions,
                   GROUP_CONCAT(DISTINCT system) as systems
            FROM file_events
            WHERE {bulk_where}{time_filter}
            GROUP BY employee_id
            HAVING file_count >= 10
            ORDER BY file_count DESC
        """
        cursor.execute(bulk_query, bulk_params + time_params)
        cols = [d[0] for d in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(cols, row))
            emp_id = d["employee_id"]
            cursor2 = conn.cursor()
            cursor2.execute("SELECT email, display_name FROM employees WHERE id = ?", (emp_id,))
            emp = cursor2.fetchone()
            alerts.append({
                "alert_type": "irm_bulk_activity",
                "policy_name": "Bulk file exfiltration",
                "severity": "high",
                "employee_id": emp_id,
                "email": emp[0] if emp else None,
                "display_name": emp[1] if emp else None,
                "ts": d["last_ts"],
                "file_count": d["file_count"],
                "first_event": d["first_ts"],
                "last_event": d["last_ts"],
                "actions": d["actions"],
                "systems": d["systems"],
            })

    # 2. Unusual print activity (print jobs with sensitive content)
    if not policy_name or "print" in policy_name.lower():
        print_where_parts = ["1=1"]
        print_params: list = []
        if employee_id:
            print_where_parts.append("pe.employee_id = ?")
            print_params.append(employee_id)
        if time_start:
            print_where_parts.append("pe.ts >= ?")
            print_params.append(time_start)
        if time_end:
            print_where_parts.append("pe.ts <= ?")
            print_params.append(time_end)

        print_query = f"""
            SELECT pe.employee_id, COUNT(*) as print_count,
                   SUM(pe.pages) as total_pages,
                   MIN(pe.ts) as first_ts, MAX(pe.ts) as last_ts,
                   e.email, e.display_name
            FROM print_events pe
            LEFT JOIN employees e ON pe.employee_id = e.id
            WHERE {" AND ".join(print_where_parts)}
            GROUP BY pe.employee_id
            HAVING print_count >= 5 OR total_pages >= 50
            ORDER BY total_pages DESC
        """
        cursor.execute(print_query, print_params)
        cols = [d[0] for d in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(cols, row))
            alerts.append({
                "alert_type": "irm_print_activity",
                "policy_name": "Unusual print volume",
                "severity": "medium",
                "employee_id": d["employee_id"],
                "email": d["email"],
                "display_name": d["display_name"],
                "ts": d["last_ts"],
                "print_count": d["print_count"],
                "total_pages": d["total_pages"],
                "first_event": d["first_ts"],
                "last_event": d["last_ts"],
            })

    # 3. Sensitive file access patterns
    if not policy_name or "sensitive" in policy_name.lower() or "access" in policy_name.lower():
        sens_where = "fe.label IS NOT NULL"
        sens_params: list = []
        if employee_id:
            sens_where += " AND fe.employee_id = ?"
            sens_params.append(employee_id)

        sens_query = f"""
            SELECT fe.employee_id, COUNT(*) as access_count,
                   GROUP_CONCAT(DISTINCT fe.label) as labels,
                   GROUP_CONCAT(DISTINCT fe.action) as actions,
                   MIN(fe.ts) as first_ts, MAX(fe.ts) as last_ts,
                   e.email, e.display_name
            FROM file_events fe
            LEFT JOIN employees e ON fe.employee_id = e.id
            WHERE {sens_where}{time_filter}
            GROUP BY fe.employee_id
            HAVING access_count >= 5
            ORDER BY access_count DESC
        """
        cursor.execute(sens_query, sens_params + time_params)
        cols = [d[0] for d in cursor.description]
        for row in cursor.fetchall():
            d = dict(zip(cols, row))
            alerts.append({
                "alert_type": "irm_sensitive_access",
                "policy_name": "Sensitive data access pattern",
                "severity": "medium",
                "employee_id": d["employee_id"],
                "email": d["email"],
                "display_name": d["display_name"],
                "ts": d["last_ts"],
                "access_count": d["access_count"],
                "labels": d["labels"],
                "actions": d["actions"],
                "first_event": d["first_ts"],
                "last_event": d["last_ts"],
            })

    alerts.sort(key=lambda a: a.get("ts", ""), reverse=True)
    return alerts[:limit]
