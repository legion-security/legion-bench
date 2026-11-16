"""SIEM capabilities — SQL query execution and search dashboards."""

import re
import sqlite3
from typing import Any, Dict, List, Optional


def _strip_internal(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _rows_to_dicts(cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    return [_strip_internal(dict(zip(cols, row))) for row in cursor.fetchall()]


# Tables available for querying
_ALLOWED_TABLES = {
    "login_events", "email_events", "file_events", "admin_actions",
    "app_events", "process_events", "mfa_events", "device_events",
    "print_events", "network_events", "employees", "devices", "subnets",
    "groups", "group_members", "companies", "departments",
    "mailboxes", "mailbox_members",
    "cloud_instances", "cloud_containers",
    "cloud_vulnerabilities", "cloud_misconfigurations", "cloud_threats",
    "attack_ground_truth",
}


def run_query(
    conn: sqlite3.Connection,
    *,
    query: str,
    limit: int = 100,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Run a SQL SELECT query on the SIEM database.

    Args:
        query: SQL SELECT query to execute. Only SELECT is allowed.
        limit: Max results (default 100, capped at 1000).
        time_start: Optional ISO 8601 lower bound. When provided, a
            ``ts >= ?`` condition is injected automatically if the
            query references a table with a ``ts`` column and does not
            already contain an explicit ``ts >=`` / ``ts >`` filter.
        time_end: Optional ISO 8601 upper bound (same logic as above).

    Returns:
        List of result dicts.

    Raises:
        ValueError: If the query is not a SELECT statement.
    """
    # Validate: only allow SELECT
    stripped = query.strip().rstrip(";")
    if not re.match(r"(?i)^\s*SELECT\b", stripped):
        raise ValueError("Only SELECT queries are allowed.")

    # Cap limit
    limit = min(limit, 1000)

    # Auto-inject time bounds when the caller provides them and the query
    # doesn't already filter on ``ts``.
    params: List[str] = []
    if time_start or time_end:
        has_where = bool(re.search(r"(?i)\bWHERE\b", stripped))
        time_clauses: List[str] = []
        if time_start and not re.search(r"(?i)\bts\s*>=?\s*", stripped):
            time_clauses.append("ts >= ?")
            params.append(time_start)
        if time_end and not re.search(r"(?i)\bts\s*<=?\s*", stripped):
            time_clauses.append("ts <= ?")
            params.append(time_end)
        if time_clauses:
            joiner = " AND " if has_where else " WHERE "
            stripped = stripped + joiner + " AND ".join(time_clauses)

    # Add LIMIT if not already present
    if not re.search(r"(?i)\bLIMIT\b", stripped):
        stripped = f"{stripped} LIMIT {limit}"

    cursor = conn.cursor()
    cursor.execute(stripped, params)
    return _rows_to_dicts(cursor)


def search_app_events(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    app: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_name: Optional[str] = None,
    success: Optional[bool] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Search application activity events with flexible filters.

    Args:
        employee_id: Filter by employee ID.
        app: Filter by application name (e.g. 'Slack', 'GitHub', 'Salesforce').
        action: Filter by action (e.g. 'upload_file', 'send_message').
        resource_type: Filter by resource type (e.g. 'file', 'message').
        resource_name: Filter by resource name (substring match).
        success: Filter by success (true/false).
        time_start: ISO 8601 lower bound.
        time_end: ISO 8601 upper bound.
        limit: Max results (default 50, max 500).

    Returns:
        List of matching app event dicts with employee display_name.
    """
    limit = min(limit, 500)
    clauses: List[str] = []
    params: List[Any] = []

    if employee_id:
        clauses.append("a.employee_id = ?")
        params.append(employee_id)
    if app:
        clauses.append("a.app = ?")
        params.append(app)
    if action:
        clauses.append("a.action = ?")
        params.append(action)
    if resource_type:
        clauses.append("a.resource_type = ?")
        params.append(resource_type)
    if resource_name:
        clauses.append("a.resource_name LIKE ?")
        params.append(f"%{resource_name}%")
    if success is not None:
        clauses.append("a.success = ?")
        params.append(1 if success else 0)
    if time_start:
        clauses.append("a.ts >= ?")
        params.append(time_start)
    if time_end:
        clauses.append("a.ts <= ?")
        params.append(time_end)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        f"SELECT a.id, a.employee_id, e.display_name, a.ts, a.app, a.action, "
        f"a.resource_type, a.resource_name, a.description, a.success "
        f"FROM app_events a LEFT JOIN employees e ON a.employee_id = e.id"
        f"{where} ORDER BY a.ts DESC LIMIT {limit}"
    )
    cursor = conn.cursor()
    cursor.execute(sql, params)
    return _rows_to_dicts(cursor)


def search_dashboard(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    device_id: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a comprehensive search dashboard for a user or device.

    Executes a prefixed set of queries across all event tables to build
    a complete activity summary.

    Args:
        employee_id: Employee ID to generate dashboard for.
        device_id: Device ID to generate dashboard for.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        Dict with sections: user_info, login_summary, email_summary,
        file_summary, admin_summary, process_summary, device_summary, etc.
    """
    if not employee_id and not device_id:
        raise ValueError("Either employee_id or device_id is required.")

    cursor = conn.cursor()
    dashboard: Dict[str, Any] = {}

    # Resolve device to employee if needed
    if device_id and not employee_id:
        cursor.execute("SELECT owner_user_id FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        if row and row[0]:
            employee_id = row[0]
        # Also get device info
        cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        dev_row = cursor.fetchone()
        if dev_row:
            cols = [d[0] for d in cursor.description]
            dashboard["device_info"] = _strip_internal(dict(zip(cols, dev_row)))

    # Time filter helper
    def _time_filter(ts_col: str = "ts") -> tuple:
        parts: list = []
        params: list = []
        if time_start:
            parts.append(f"{ts_col} >= ?")
            params.append(time_start)
        if time_end:
            parts.append(f"{ts_col} <= ?")
            params.append(time_end)
        return (" AND " + " AND ".join(parts)) if parts else "", params

    if employee_id:
        # User info
        cursor.execute(
            "SELECT id, email, display_name, department, title, manager_id, location FROM employees WHERE id = ?",
            (employee_id,),
        )
        row = cursor.fetchone()
        if row:
            cols = [d[0] for d in cursor.description]
            dashboard["user_info"] = dict(zip(cols, row))

        time_clause, time_params = _time_filter()

        # Login summary
        cursor.execute(
            f"SELECT COUNT(*) as total, SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful, "
            f"SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed, "
            f"COUNT(DISTINCT ip) as unique_ips, COUNT(DISTINCT app) as unique_apps "
            f"FROM login_events WHERE employee_id = ?{time_clause}",
            [employee_id] + time_params,
        )
        row = cursor.fetchone()
        if row:
            cols = [d[0] for d in cursor.description]
            dashboard["login_summary"] = dict(zip(cols, row))

        # Recent logins (last 10)
        cursor.execute(
            f"SELECT ts, ip, app, success, geo, method FROM login_events "
            f"WHERE employee_id = ?{time_clause} ORDER BY ts DESC LIMIT 10",
            [employee_id] + time_params,
        )
        dashboard["recent_logins"] = _rows_to_dicts(cursor)

        # Email summary
        cursor.execute(
            f"SELECT COUNT(*) as total, "
            f"SUM(CASE WHEN direction = 'sent' THEN 1 ELSE 0 END) as sent, "
            f"SUM(CASE WHEN direction = 'received' THEN 1 ELSE 0 END) as received, "
            f"SUM(CASE WHEN external = 1 THEN 1 ELSE 0 END) as external "
            f"FROM email_events WHERE employee_id = ?{time_clause}",
            [employee_id] + time_params,
        )
        row = cursor.fetchone()
        if row:
            cols = [d[0] for d in cursor.description]
            dashboard["email_summary"] = dict(zip(cols, row))

        # File activity summary
        cursor.execute(
            f"SELECT action, COUNT(*) as count FROM file_events "
            f"WHERE employee_id = ?{time_clause} GROUP BY action ORDER BY count DESC",
            [employee_id] + time_params,
        )
        dashboard["file_summary"] = _rows_to_dicts(cursor)

        # Admin actions
        cursor.execute(
            f"SELECT COUNT(*) as total FROM admin_actions WHERE employee_id = ?{time_clause}",
            [employee_id] + time_params,
        )
        row = cursor.fetchone()
        admin_count = row[0] if row else 0
        dashboard["admin_action_count"] = admin_count

        if admin_count > 0:
            cursor.execute(
                f"SELECT ts, system, action, details FROM admin_actions "
                f"WHERE employee_id = ?{time_clause} ORDER BY ts DESC LIMIT 10",
                [employee_id] + time_params,
            )
            dashboard["recent_admin_actions"] = _rows_to_dicts(cursor)

        # Process events summary
        cursor.execute(
            f"SELECT COUNT(*) as total, COUNT(DISTINCT process_name) as unique_processes "
            f"FROM process_events WHERE employee_id = ?{time_clause}",
            [employee_id] + time_params,
        )
        row = cursor.fetchone()
        if row:
            cols = [d[0] for d in cursor.description]
            dashboard["process_summary"] = dict(zip(cols, row))

        # MFA summary
        cursor.execute(
            f"SELECT action, COUNT(*) as count FROM mfa_events "
            f"WHERE employee_id = ?{time_clause} GROUP BY action ORDER BY count DESC",
            [employee_id] + time_params,
        )
        dashboard["mfa_summary"] = _rows_to_dicts(cursor)

        # Device events
        cursor.execute(
            f"SELECT action, COUNT(*) as count FROM device_events "
            f"WHERE employee_id = ?{time_clause} GROUP BY action ORDER BY count DESC",
            [employee_id] + time_params,
        )
        dashboard["device_event_summary"] = _rows_to_dicts(cursor)

        # Print activity
        cursor.execute(
            f"SELECT COUNT(*) as jobs, COALESCE(SUM(pages), 0) as total_pages "
            f"FROM print_events WHERE employee_id = ?{time_clause}",
            [employee_id] + time_params,
        )
        row = cursor.fetchone()
        if row:
            cols = [d[0] for d in cursor.description]
            dashboard["print_summary"] = dict(zip(cols, row))

        # App events summary
        cursor.execute(
            f"SELECT app, action, COUNT(*) as count FROM app_events "
            f"WHERE employee_id = ?{time_clause} GROUP BY app, action ORDER BY count DESC",
            [employee_id] + time_params,
        )
        dashboard["app_event_summary"] = _rows_to_dicts(cursor)

        # Recent app events (last 10)
        cursor.execute(
            f"SELECT ts, app, action, resource_name, description, success FROM app_events "
            f"WHERE employee_id = ?{time_clause} ORDER BY ts DESC LIMIT 10",
            [employee_id] + time_params,
        )
        dashboard["recent_app_events"] = _rows_to_dicts(cursor)

    # Device-specific queries
    if device_id:
        time_clause, time_params = _time_filter()

        # Process events on device
        cursor.execute(
            f"SELECT COUNT(*) as total, COUNT(DISTINCT process_name) as unique_processes "
            f"FROM process_events WHERE device_id = ?{time_clause}",
            [device_id] + time_params,
        )
        row = cursor.fetchone()
        if row:
            cols = [d[0] for d in cursor.description]
            dashboard["device_process_summary"] = dict(zip(cols, row))

        # Recent processes on device
        cursor.execute(
            f"SELECT ts, process_name, command_line, employee_id FROM process_events "
            f"WHERE device_id = ?{time_clause} ORDER BY ts DESC LIMIT 10",
            [device_id] + time_params,
        )
        dashboard["device_recent_processes"] = _rows_to_dicts(cursor)

    return dashboard
