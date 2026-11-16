"""Identity capabilities — user lookup, sign-in logs, MFA, groups."""

import json
import sqlite3
from typing import Any, Dict, List, Optional


def _strip_internal(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _rows_to_dicts(cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    return [_strip_internal(dict(zip(cols, row))) for row in cursor.fetchall()]


def lookup_user(
    conn: sqlite3.Connection,
    *,
    user_ref: str,
) -> Optional[Dict[str, Any]]:
    """Look up a user by ID, email, or display name.

    Args:
        user_ref: User ID, email address, or display name to search for.

    Returns:
        User details dict or None if not found.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, email, display_name, department_id, department, title,
               manager_id, location, accounts, authorisations
        FROM employees
        WHERE id = ? OR email = ? OR display_name LIKE ?
        """,
        (user_ref, user_ref, f"%{user_ref}%"),
    )
    row = cursor.fetchone()
    if not row:
        return None

    return {
        "id": row[0],
        "email": row[1],
        "display_name": row[2],
        "department_id": row[3],
        "department": row[4],
        "title": row[5],
        "manager_id": row[6],
        "location": row[7],
        "accounts": json.loads(row[8]) if row[8] else [],
        "authorisations": json.loads(row[9]) if row[9] else [],
    }


def get_sign_in_logs(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    email: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    success: Optional[bool] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get sign-in logs for a user.

    Args:
        employee_id: Filter by employee ID.
        email: Filter by email (resolves to employee_id).
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        success: Filter by success/failure.
        limit: Max results.

    Returns:
        List of sign-in events.
    """
    where_parts: list = []
    params: list = []

    if email and not employee_id:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM employees WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            employee_id = row[0]
        else:
            return []

    if employee_id:
        where_parts.append("le.employee_id = ?")
        params.append(employee_id)
    if success is not None:
        where_parts.append("le.success = ?")
        params.append(1 if success else 0)
    if time_start:
        where_parts.append("le.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("le.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT le.*, e.email, e.display_name
        FROM login_events le
        LEFT JOIN employees e ON le.employee_id = e.id
        {where_clause}
        ORDER BY le.ts DESC LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_mfa_activity(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    action: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get MFA activity events.

    Args:
        employee_id: Filter by employee ID.
        action: Filter by MFA action (e.g. "push_sent", "push_denied").
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of MFA events.
    """
    where_parts: list = []
    params: list = []

    if employee_id:
        where_parts.append("m.employee_id = ?")
        params.append(employee_id)
    if action:
        where_parts.append("m.action = ?")
        params.append(action)
    if time_start:
        where_parts.append("m.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("m.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT m.*, e.email, e.display_name
        FROM mfa_events m
        LEFT JOIN employees e ON m.employee_id = e.id
        {where_clause}
        ORDER BY m.ts DESC
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_user_groups(
    conn: sqlite3.Connection,
    *,
    user_ref: str,
) -> List[Dict[str, Any]]:
    """Get all groups a user belongs to.

    Args:
        user_ref: User ID or email.

    Returns:
        List of group dicts with id, name, description, authorisations.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM employees WHERE id = ? OR email = ?", (user_ref, user_ref))
    row = cursor.fetchone()
    if not row:
        return []
    user_id = row[0]

    cursor.execute(
        """
        SELECT g.id, g.name, g.description, g.authorisations
        FROM group_members gm
        JOIN groups g ON gm.group_id = g.id
        WHERE gm.user_id = ?
        """,
        (user_id,),
    )
    results = []
    for r in cursor.fetchall():
        results.append({
            "id": r[0],
            "name": r[1],
            "description": r[2],
            "authorisations": json.loads(r[3]) if r[3] else [],
        })
    return results


def get_group_members(
    conn: sqlite3.Connection,
    *,
    group_ref: str,
) -> List[Dict[str, Any]]:
    """Get all members of a group.

    Args:
        group_ref: Group ID or group name.

    Returns:
        List of member dicts with id, email, display_name, title.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM groups WHERE id = ? OR name = ?", (group_ref, group_ref))
    row = cursor.fetchone()
    if not row:
        return []
    group_id = row[0]

    cursor.execute(
        """
        SELECT e.id, e.email, e.display_name, e.title
        FROM group_members gm
        JOIN employees e ON gm.user_id = e.id
        WHERE gm.group_id = ?
        """,
        (group_id,),
    )
    return [
        {"id": r[0], "email": r[1], "display_name": r[2], "title": r[3]}
        for r in cursor.fetchall()
    ]


def get_user_audit_log(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    action: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get user audit log entries.

    Args:
        employee_id: Filter by employee who performed action.
        action: Filter by action type.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        List of admin action events.
    """
    where_parts: list = []
    params: list = []

    if employee_id:
        where_parts.append("aa.employee_id = ?")
        params.append(employee_id)
    if action:
        where_parts.append("aa.action = ?")
        params.append(action)
    if time_start:
        where_parts.append("aa.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("aa.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT aa.*, e.email, e.display_name
        FROM admin_actions aa
        LEFT JOIN employees e ON aa.employee_id = e.id
        {where_clause}
        ORDER BY aa.ts DESC LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = _rows_to_dicts(cursor)
    for row in rows:
        if row.get("details") and isinstance(row["details"], str):
            try:
                row["details"] = json.loads(row["details"])
            except (json.JSONDecodeError, TypeError):
                pass
    return rows


# Keep backward compatibility alias
get_admin_audit_log = get_user_audit_log


def get_user_access_review(
    conn: sqlite3.Connection,
    *,
    user_ref: str,
) -> Optional[Dict[str, Any]]:
    """Get a comprehensive access review for a user.

    Args:
        user_ref: User ID or email.

    Returns:
        Dict with user info, groups, authorisations, devices, and recent admin changes.
    """
    user = lookup_user(conn, user_ref=user_ref)
    if not user:
        return None

    groups = get_user_groups(conn, user_ref=user["id"])

    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, hostname, os, ip_address
        FROM devices WHERE owner_user_id = ?
        """,
        (user["id"],),
    )
    devices = [
        {"id": r[0], "hostname": r[1], "os": r[2], "ip_address": r[3]}
        for r in cursor.fetchall()
    ]

    recent_admin = get_admin_audit_log(conn, employee_id=user["id"], limit=10)

    group_auths = []
    for g in groups:
        group_auths.extend(g.get("authorisations", []))

    return {
        "user": user,
        "groups": groups,
        "devices": devices,
        "recent_admin_actions": recent_admin,
        "all_authorisations": sorted(set(user.get("authorisations", []) + group_auths)),
    }


def get_risky_users(
    conn: sqlite3.Connection,
    *,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Identify users with risky activity patterns.

    Looks for: failed logins, MFA denials, admin actions, and impossible travel indicators.

    Args:
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of users with risk indicators and scores.
    """
    time_filter = ""
    params: list = []
    if time_start:
        time_filter += " AND ts >= ?"
        params.append(time_start)
    if time_end:
        time_filter += " AND ts <= ?"
        params.append(time_end)

    cursor = conn.cursor()

    # Failed logins
    cursor.execute(
        f"SELECT employee_id, COUNT(*) as cnt FROM login_events WHERE success = 0{time_filter} GROUP BY employee_id HAVING cnt >= 3",
        params,
    )
    failed_logins = {r[0]: r[1] for r in cursor.fetchall()}

    # MFA denials
    cursor.execute(
        f"SELECT employee_id, COUNT(*) as cnt FROM mfa_events WHERE action IN ('push_denied','code_failed'){time_filter} GROUP BY employee_id HAVING cnt >= 2",
        params,
    )
    mfa_denials = {r[0]: r[1] for r in cursor.fetchall()}

    all_user_ids = set(failed_logins.keys()) | set(mfa_denials.keys())
    if not all_user_ids:
        return []

    results = []
    for uid in all_user_ids:
        cursor.execute(
            "SELECT id, email, display_name, title FROM employees WHERE id = ?", (uid,)
        )
        row = cursor.fetchone()
        if not row:
            continue
        risk_score = failed_logins.get(uid, 0) * 2 + mfa_denials.get(uid, 0) * 3
        results.append({
            "employee_id": row[0],
            "email": row[1],
            "display_name": row[2],
            "title": row[3],
            "failed_logins": failed_logins.get(uid, 0),
            "mfa_denials": mfa_denials.get(uid, 0),
            "risk_score": risk_score,
        })

    results.sort(key=lambda r: r["risk_score"], reverse=True)
    return results
