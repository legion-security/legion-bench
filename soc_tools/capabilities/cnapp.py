"""CNAPP capabilities — cloud resource search, vulnerability, misconfiguration, and threat detection."""

import json
import sqlite3
from typing import Any, Dict, List, Optional


def _strip_internal(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _rows_to_dicts(cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cursor.description]
    rows = []
    for row in cursor.fetchall():
        d = _strip_internal(dict(zip(cols, row)))
        for field in ("tags", "security_groups", "permissions", "labels", "details"):
            if d.get(field) and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        rows.append(d)
    return rows


def search_resource(
    conn: sqlite3.Connection,
    *,
    resource_id: Optional[str] = None,
    identity: Optional[str] = None,
    provider: Optional[str] = None,
    resource_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search for cloud resources or cloud identities.

    Args:
        resource_id: Cloud resource ID to search for.
        identity: Cloud identity (IAM role, service principal) to search for.
        provider: Filter by cloud provider.
        resource_type: Filter by resource type ('instance' or 'container').

    Returns:
        List of cloud resource dicts with details.
    """
    results: List[Dict[str, Any]] = []
    cursor = conn.cursor()

    # Search instances
    if not resource_type or resource_type == "instance":
        where_parts: list = []
        params: list = []

        if resource_id:
            where_parts.append("ci.instance_id = ?")
            params.append(resource_id)
        if identity:
            where_parts.append("(ci.iam_role LIKE ? OR ci.service_principal LIKE ?)")
            params.extend([f"%{identity}%", f"%{identity}%"])
        if provider:
            where_parts.append("ci.provider = ?")
            params.append(provider)

        where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
        cursor.execute(
            f"SELECT ci.*, 'instance' as resource_type FROM cloud_instances ci{where_clause}",
            params,
        )
        results.extend(_rows_to_dicts(cursor))

    # Search containers
    if not resource_type or resource_type == "container":
        where_parts = []
        params = []

        if resource_id:
            where_parts.append("cc.id = ?")
            params.append(resource_id)
        if provider:
            where_parts.append("cc.provider = ?")
            params.append(provider)

        where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
        cursor.execute(
            f"SELECT cc.*, 'container' as resource_type FROM cloud_containers cc{where_clause}",
            params,
        )
        results.extend(_rows_to_dicts(cursor))

    # For each resource, attach finding counts
    for r in results:
        rid = r.get("instance_id") or r.get("id")
        if rid:
            cursor.execute("SELECT COUNT(*) FROM cloud_vulnerabilities WHERE resource_id = ?", (rid,))
            r["vulnerability_count"] = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM cloud_misconfigurations WHERE resource_id = ?", (rid,))
            r["misconfiguration_count"] = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM cloud_threats WHERE resource_id = ?", (rid,))
            r["threat_count"] = cursor.fetchone()[0]

    return results


def search_vulnerabilities(
    conn: sqlite3.Connection,
    *,
    resource_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Search cloud vulnerabilities.

    Args:
        resource_id: Filter by resource ID.
        cve_id: Search by CVE identifier.
        severity: Filter by severity (critical, high, medium, low).
        provider: Filter by cloud provider.
        limit: Max results.

    Returns:
        List of vulnerability dicts.
    """
    where_parts: list = []
    params: list = []

    if resource_id:
        where_parts.append("cv.resource_id = ?")
        params.append(resource_id)
    if cve_id:
        where_parts.append("cv.cve_id = ?")
        params.append(cve_id)
    if severity:
        where_parts.append("cv.severity = ?")
        params.append(severity)
    if provider:
        where_parts.append("cv.provider = ?")
        params.append(provider)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT cv.*
        FROM cloud_vulnerabilities cv
        {where_clause}
        ORDER BY
            CASE cv.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            cv.detected_at DESC
        LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def search_misconfigurations(
    conn: sqlite3.Connection,
    *,
    resource_id: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Search cloud misconfigurations.

    Args:
        resource_id: Filter by resource ID.
        category: Filter by misconfiguration category.
        severity: Filter by severity (critical, high, medium, low).
        provider: Filter by cloud provider.
        limit: Max results.

    Returns:
        List of misconfiguration dicts.
    """
    where_parts: list = []
    params: list = []

    if resource_id:
        where_parts.append("cm.resource_id = ?")
        params.append(resource_id)
    if category:
        where_parts.append("cm.category LIKE ?")
        params.append(f"%{category}%")
    if severity:
        where_parts.append("cm.severity = ?")
        params.append(severity)
    if provider:
        where_parts.append("cm.provider = ?")
        params.append(provider)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT cm.*
        FROM cloud_misconfigurations cm
        {where_clause}
        ORDER BY
            CASE cm.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            cm.detected_at DESC
        LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_threat_details(
    conn: sqlite3.Connection,
    *,
    resource_id: Optional[str] = None,
    identity: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get cloud threat detection details.

    Args:
        resource_id: Filter by resource ID.
        identity: Filter by cloud identity.
        threat_type: Filter by threat type.
        severity: Filter by severity (critical, high, medium, low).
        limit: Max results.

    Returns:
        List of threat dicts.
    """
    where_parts: list = []
    params: list = []

    if resource_id:
        where_parts.append("ct.resource_id = ?")
        params.append(resource_id)
    if identity:
        where_parts.append("ct.identity LIKE ?")
        params.append(f"%{identity}%")
    if threat_type:
        where_parts.append("ct.threat_type = ?")
        params.append(threat_type)
    if severity:
        where_parts.append("ct.severity = ?")
        params.append(severity)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT ct.*
        FROM cloud_threats ct
        {where_clause}
        ORDER BY
            CASE ct.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            ct.detected_at DESC
        LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def search_cloud_events(
    conn: sqlite3.Connection,
    *,
    instance_id: Optional[str] = None,
    identity: Optional[str] = None,
    event_name: Optional[str] = None,
    event_source: Optional[str] = None,
    event_category: Optional[str] = None,
    provider: Optional[str] = None,
    source_ip: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    response_status: Optional[str] = None,
    read_only: Optional[bool] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Search cloud API event logs (CloudTrail / Activity Log / Audit Log).

    Args:
        instance_id: Filter by cloud instance ID.
        identity: Filter by IAM identity (supports LIKE matching).
        event_name: Filter by API event name (e.g. 'GetObject', 'AssumeRole').
        event_source: Filter by event source service (e.g. 's3.amazonaws.com').
        event_category: Filter by category ('management', 'data', 'network', 'auth', 'monitoring').
        provider: Filter by cloud provider ('aws', 'azure', 'gcp').
        source_ip: Filter by source IP address.
        time_start: Start of time range (ISO 8601).
        time_end: End of time range (ISO 8601).
        response_status: Filter by response status ('Success', 'Failed', 'AccessDenied').
        read_only: Filter by read-only flag.
        limit: Max results (default 100).

    Returns:
        List of cloud event dicts.
    """
    where_parts: list = []
    params: list = []

    if instance_id:
        where_parts.append("ce.instance_id = ?")
        params.append(instance_id)
    if identity:
        where_parts.append("ce.identity LIKE ?")
        params.append(f"%{identity}%")
    if event_name:
        where_parts.append("ce.event_name = ?")
        params.append(event_name)
    if event_source:
        where_parts.append("ce.event_source LIKE ?")
        params.append(f"%{event_source}%")
    if event_category:
        where_parts.append("ce.event_category = ?")
        params.append(event_category)
    if provider:
        where_parts.append("ce.provider = ?")
        params.append(provider)
    if source_ip:
        where_parts.append("ce.source_ip = ?")
        params.append(source_ip)
    if time_start:
        where_parts.append("ce.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ce.ts <= ?")
        params.append(time_end)
    if response_status:
        where_parts.append("ce.response_status = ?")
        params.append(response_status)
    if read_only is not None:
        where_parts.append("ce.read_only = ?")
        params.append(1 if read_only else 0)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT ce.*
        FROM cloud_events ce
        {where_clause}
        ORDER BY ce.ts DESC
        LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_cloud_identity_activity(
    conn: sqlite3.Connection,
    *,
    identity: str,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get all cloud API activity for a specific IAM identity.

    Useful for investigating compromised service accounts or suspicious
    identity behavior.

    Args:
        identity: IAM identity to search for (supports LIKE matching).
        time_start: Start of time range (ISO 8601).
        time_end: End of time range (ISO 8601).
        limit: Max results (default 100).

    Returns:
        List of cloud event dicts for the given identity.
    """
    where_parts = ["ce.identity LIKE ?"]
    params: list = [f"%{identity}%"]

    if time_start:
        where_parts.append("ce.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ce.ts <= ?")
        params.append(time_end)

    where_clause = " WHERE " + " AND ".join(where_parts)
    query = f"""
        SELECT ce.*
        FROM cloud_events ce
        {where_clause}
        ORDER BY ce.ts DESC
        LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_cloud_event_summary(
    conn: sqlite3.Connection,
    *,
    instance_id: Optional[str] = None,
    identity: Optional[str] = None,
    provider: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get a summary of cloud API events grouped by event_name.

    Returns counts and time ranges per event type, useful for baselining
    normal activity and detecting anomalies.

    Args:
        instance_id: Filter by cloud instance ID.
        identity: Filter by IAM identity (supports LIKE matching).
        provider: Filter by cloud provider.
        time_start: Start of time range (ISO 8601).
        time_end: End of time range (ISO 8601).

    Returns:
        List of summary dicts with event_name, count, first_seen, last_seen,
        success_count, error_count.
    """
    where_parts: list = []
    params: list = []

    if instance_id:
        where_parts.append("ce.instance_id = ?")
        params.append(instance_id)
    if identity:
        where_parts.append("ce.identity LIKE ?")
        params.append(f"%{identity}%")
    if provider:
        where_parts.append("ce.provider = ?")
        params.append(provider)
    if time_start:
        where_parts.append("ce.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ce.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT
            ce.event_source,
            ce.event_name,
            COUNT(*) as event_count,
            MIN(ce.ts) as first_seen,
            MAX(ce.ts) as last_seen,
            SUM(CASE WHEN ce.response_status = 'Success' THEN 1 ELSE 0 END) as success_count,
            SUM(CASE WHEN ce.response_status != 'Success' THEN 1 ELSE 0 END) as error_count
        FROM cloud_events ce
        {where_clause}
        GROUP BY ce.event_source, ce.event_name
        ORDER BY event_count DESC
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]
