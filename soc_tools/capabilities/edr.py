"""EDR capabilities — process trees, device telemetry, suspicious process detection."""

import sqlite3
from typing import Any, Dict, List, Optional


def _strip_internal(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _rows_to_dicts(cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    return [_strip_internal(dict(zip(cols, row))) for row in cursor.fetchall()]


def get_process_tree(
    conn: sqlite3.Connection,
    *,
    device_id: Optional[str] = None,
    employee_id: Optional[str] = None,
    process_name: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get process execution tree.

    Args:
        device_id: Filter by device.
        employee_id: Filter by employee.
        process_name: Filter by process name.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of process events showing parent-child relationships.
    """
    where_parts: list = []
    params: list = []

    if device_id:
        where_parts.append("pe.device_id = ?")
        params.append(device_id)
    if employee_id:
        where_parts.append("pe.employee_id = ?")
        params.append(employee_id)
    if process_name:
        where_parts.append("pe.process_name = ?")
        params.append(process_name)
    if time_start:
        where_parts.append("pe.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("pe.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT pe.*, e.email, e.display_name
        FROM process_events pe
        LEFT JOIN employees e ON pe.employee_id = e.id
        {where_clause}
        ORDER BY pe.ts
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def search_process_by_hash(
    conn: sqlite3.Connection,
    *,
    hash: str,
) -> List[Dict[str, Any]]:
    """Search for processes by file hash.

    Args:
        hash: SHA256 or other file hash to search for.

    Returns:
        List of process events matching the hash.
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT pe.*, e.email, e.display_name
        FROM process_events pe
        LEFT JOIN employees e ON pe.employee_id = e.id
        WHERE pe.hash = ?
        ORDER BY pe.ts
        """,
        (hash,),
    )
    return _rows_to_dicts(cursor)


def search_process_by_command(
    conn: sqlite3.Connection,
    *,
    command_pattern: str,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search for processes by command line pattern.

    Args:
        command_pattern: Substring to search in command_line field.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of matching process events.
    """
    where_parts = ["pe.command_line LIKE ?"]
    params: list = [f"%{command_pattern}%"]

    if time_start:
        where_parts.append("pe.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("pe.ts <= ?")
        params.append(time_end)

    where_clause = " WHERE " + " AND ".join(where_parts)
    query = f"""
        SELECT pe.*, e.email, e.display_name
        FROM process_events pe
        LEFT JOIN employees e ON pe.employee_id = e.id
        {where_clause}
        ORDER BY pe.ts
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_host_timeline(
    conn: sqlite3.Connection,
    *,
    device_id: str,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get all activity on a specific host/device.

    Combines process events and device events for a device.

    Args:
        device_id: Device ID to get timeline for.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        Chronologically sorted events from the device.
    """
    all_events: List[Dict[str, Any]] = []

    # Process events
    where_parts = ["pe.device_id = ?"]
    params: list = [device_id]
    if time_start:
        where_parts.append("pe.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("pe.ts <= ?")
        params.append(time_end)
    where_clause = " WHERE " + " AND ".join(where_parts)

    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT pe.*, 'process' AS event_type, e.email, e.display_name
        FROM process_events pe
        LEFT JOIN employees e ON pe.employee_id = e.id
        {where_clause}
        ORDER BY pe.ts
        """,
        params,
    )
    all_events.extend(_rows_to_dicts(cursor))

    # Device events for the owner of this device
    cursor.execute("SELECT owner_user_id FROM devices WHERE id = ?", (device_id,))
    owner_row = cursor.fetchone()
    if owner_row and owner_row[0]:
        dev_where = ["de.employee_id = ?"]
        dev_params: list = [owner_row[0]]
        if time_start:
            dev_where.append("de.ts >= ?")
            dev_params.append(time_start)
        if time_end:
            dev_where.append("de.ts <= ?")
            dev_params.append(time_end)
        dev_where_clause = " WHERE " + " AND ".join(dev_where)

        cursor.execute(
            f"""
            SELECT de.*, 'device_event' AS event_type, e.email, e.display_name
            FROM device_events de
            LEFT JOIN employees e ON de.employee_id = e.id
            {dev_where_clause}
            ORDER BY de.ts
            """,
            dev_params,
        )
        all_events.extend(_rows_to_dicts(cursor))

    all_events.sort(key=lambda e: e.get("ts", ""))
    return all_events[:limit]


def get_device_events(
    conn: sqlite3.Connection,
    *,
    employee_id: Optional[str] = None,
    device_id: Optional[str] = None,
    action: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get device-related events (USB, software installs, bluetooth).

    Args:
        employee_id: Filter by employee.
        device_id: Filter by device (resolves to employee via ownership).
        action: Filter by action (e.g. "usb_connected", "software_install").
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of device events.
    """
    where_parts: list = []
    params: list = []

    if device_id and not employee_id:
        cursor = conn.cursor()
        cursor.execute("SELECT owner_user_id FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        if row and row[0]:
            employee_id = row[0]

    if employee_id:
        where_parts.append("de.employee_id = ?")
        params.append(employee_id)
    if action:
        where_parts.append("de.action = ?")
        params.append(action)
    if time_start:
        where_parts.append("de.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("de.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT de.*, e.email, e.display_name
        FROM device_events de
        LEFT JOIN employees e ON de.employee_id = e.id
        {where_clause}
        ORDER BY de.ts DESC
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_network_events(
    conn: sqlite3.Connection,
    *,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    action: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get network events with optional filters.

    Args:
        source_ip: Filter by source IP.
        destination_ip: Filter by destination IP.
        action: Filter by action (e.g. 'allow', 'deny').
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        List of network events.
    """
    where_parts: list = []
    params: list = []

    if source_ip:
        where_parts.append("ne.source_ip = ?")
        params.append(source_ip)
    if destination_ip:
        where_parts.append("ne.destination_ip = ?")
        params.append(destination_ip)
    if action:
        where_parts.append("ne.action = ?")
        params.append(action)
    if time_start:
        where_parts.append("ne.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ne.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT ne.*, s.cidr, s.location, s.name as subnet_name
        FROM network_events ne
        LEFT JOIN subnets s ON ne.network_id = s.id
        {where_clause}
        ORDER BY ne.ts DESC LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def search_network_events(
    conn: sqlite3.Connection,
    *,
    ip: Optional[str] = None,
    url: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Search network events by IP or URL pattern.

    Args:
        ip: IP address to search in source_ip or destination_ip.
        url: URL or domain pattern to search in description field.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        List of matching network events.
    """
    where_parts: list = []
    params: list = []

    if ip:
        where_parts.append("(ne.source_ip = ? OR ne.destination_ip = ?)")
        params.extend([ip, ip])
    if url:
        where_parts.append("ne.description LIKE ?")
        params.append(f"%{url}%")
    if time_start:
        where_parts.append("ne.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ne.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT ne.*, s.cidr, s.location, s.name as subnet_name
        FROM network_events ne
        LEFT JOIN subnets s ON ne.network_id = s.id
        {where_clause}
        ORDER BY ne.ts DESC LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def detect_suspicious_processes(
    conn: sqlite3.Connection,
    *,
    suspicious_names: Optional[List[str]] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Detect processes matching known suspicious patterns.

    Args:
        suspicious_names: List of process names to flag. Defaults to common LOLBins.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of matching process events.
    """
    if suspicious_names is None:
        suspicious_names = [
            "powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe",
            "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe",
            "bitsadmin.exe", "msiexec.exe", "psexec.exe", "mimikatz.exe",
        ]

    placeholders = ",".join("?" * len(suspicious_names))
    where_parts = [f"pe.process_name IN ({placeholders})"]
    params: list = list(suspicious_names)

    if time_start:
        where_parts.append("pe.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("pe.ts <= ?")
        params.append(time_end)

    where_clause = " WHERE " + " AND ".join(where_parts)
    query = f"""
        SELECT pe.*, e.email, e.display_name
        FROM process_events pe
        LEFT JOIN employees e ON pe.employee_id = e.id
        {where_clause}
        ORDER BY pe.ts DESC
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)
