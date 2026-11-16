"""Email gateway capabilities — message trace, sender intel, phishing indicators."""

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
        # Parse JSON fields
        for field in ("recipients", "cc", "bcc", "attachment_types", "attachments"):
            if d.get(field) and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        rows.append(d)
    return rows


def message_trace(
    conn: sqlite3.Connection,
    *,
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    subject_contains: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    has_attachments: Optional[bool] = None,
    external_only: bool = False,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Trace email messages with filters.

    Args:
        sender: Filter by sender email address.
        recipient: Filter by recipient (searched in recipients JSON array).
        subject_contains: Substring search in subject.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        has_attachments: Filter to emails with/without attachments.
        external_only: Only show external emails.
        limit: Max results.

    Returns:
        List of matching email events.
    """
    where_parts: list = []
    params: list = []

    if sender:
        where_parts.append("ee.sender = ?")
        params.append(sender)
    if recipient:
        where_parts.append("ee.recipients LIKE ?")
        params.append(f"%{recipient}%")
    if subject_contains:
        where_parts.append("ee.subject LIKE ?")
        params.append(f"%{subject_contains}%")
    if time_start:
        where_parts.append("ee.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ee.ts <= ?")
        params.append(time_end)
    if has_attachments is True:
        where_parts.append("ee.attachments IS NOT NULL AND ee.attachments != '[]' AND ee.attachments != 'null'")
    elif has_attachments is False:
        where_parts.append("(ee.attachments IS NULL OR ee.attachments = '[]' OR ee.attachments = 'null')")
    if external_only:
        where_parts.append("ee.external = 1")

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT ee.*, e.email as owner_email, e.display_name
        FROM email_events ee
        LEFT JOIN employees e ON ee.employee_id = e.id
        {where_clause}
        ORDER BY ee.ts DESC LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def search_emails(
    conn: sqlite3.Connection,
    *,
    sender: Optional[str] = None,
    subject_contains: Optional[str] = None,
    recipient: Optional[str] = None,
    ip: Optional[str] = None,
    url: Optional[str] = None,
    filename: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Search emails by any combination of indicators with AND logic.

    Args:
        sender: Filter by sender email address.
        subject_contains: Substring search in subject.
        recipient: Filter by recipient email address.
        ip: Filter by IP address in email content.
        url: Filter by URL in email body.
        filename: Filter by attachment filename.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.
        limit: Max results.

    Returns:
        List of matching email events.
    """
    where_parts: list = []
    params: list = []

    if sender:
        where_parts.append("ee.sender = ?")
        params.append(sender)
    if subject_contains:
        where_parts.append("ee.subject LIKE ?")
        params.append(f"%{subject_contains}%")
    if recipient:
        where_parts.append("ee.recipients LIKE ?")
        params.append(f"%{recipient}%")
    if ip:
        where_parts.append("(ee.content LIKE ? OR ee.sender LIKE ?)")
        params.extend([f"%{ip}%", f"%{ip}%"])
    if url:
        where_parts.append("(ee.contains_url LIKE ? OR ee.content LIKE ?)")
        params.extend([f"%{url}%", f"%{url}%"])
    if filename:
        where_parts.append("ee.attachments LIKE ?")
        params.append(f"%{filename}%")
    if time_start:
        where_parts.append("ee.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ee.ts <= ?")
        params.append(time_end)

    where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    query = f"""
        SELECT ee.*, e.email as owner_email, e.display_name
        FROM email_events ee
        LEFT JOIN employees e ON ee.employee_id = e.id
        {where_clause}
        ORDER BY ee.ts DESC LIMIT ?
    """
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_email_attachments(
    conn: sqlite3.Connection,
    *,
    sender: Optional[str] = None,
    filename_contains: Optional[str] = None,
    file_type: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search for email attachments.

    Args:
        sender: Filter by sender.
        filename_contains: Substring match on attachment filenames.
        file_type: Filter by attachment type (e.g. "pdf", "exe").
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of emails with matching attachments.
    """
    where_parts = ["ee.attachments IS NOT NULL", "ee.attachments != '[]'", "ee.attachments != 'null'"]
    params: list = []

    if sender:
        where_parts.append("ee.sender = ?")
        params.append(sender)
    if filename_contains:
        where_parts.append("ee.attachments LIKE ?")
        params.append(f"%{filename_contains}%")
    if file_type:
        where_parts.append("ee.attachment_types LIKE ?")
        params.append(f"%{file_type}%")
    if time_start:
        where_parts.append("ee.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ee.ts <= ?")
        params.append(time_end)

    where_clause = " WHERE " + " AND ".join(where_parts)
    query = f"""
        SELECT ee.*, e.email as owner_email, e.display_name
        FROM email_events ee
        LEFT JOIN employees e ON ee.employee_id = e.id
        {where_clause}
        ORDER BY ee.ts DESC
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    return _rows_to_dicts(cursor)


def get_sender_summary(
    conn: sqlite3.Connection,
    *,
    sender: str,
) -> Dict[str, Any]:
    """Profile a sender email address.

    Args:
        sender: Email address to profile.

    Returns:
        Summary with message count, recipients, subjects, attachment stats.
    """
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM email_events WHERE sender = ?", (sender,)
    )
    total_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT MIN(ts), MAX(ts) FROM email_events WHERE sender = ?", (sender,)
    )
    time_row = cursor.fetchone()

    cursor.execute(
        "SELECT COUNT(*) FROM email_events WHERE sender = ? AND external = 1", (sender,)
    )
    external_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*) FROM email_events
        WHERE sender = ? AND attachments IS NOT NULL
        AND attachments != '[]' AND attachments != 'null'
        """,
        (sender,),
    )
    with_attachments = cursor.fetchone()[0]

    cursor.execute(
        "SELECT DISTINCT recipients FROM email_events WHERE sender = ?", (sender,)
    )
    all_recipients = set()
    for row in cursor.fetchall():
        if row[0]:
            try:
                recips = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                if isinstance(recips, list):
                    all_recipients.update(recips)
            except (json.JSONDecodeError, TypeError):
                pass

    cursor.execute(
        "SELECT subject FROM email_events WHERE sender = ? ORDER BY ts DESC",
        (sender,),
    )
    recent_subjects = [r[0] for r in cursor.fetchall() if r[0]]
    recent_subjects = list(set(recent_subjects))[:10]   

    # Check if sender is an internal employee
    cursor.execute("SELECT id, display_name FROM employees WHERE email = ?", (sender,))
    emp_row = cursor.fetchone()

    return {
        "sender": sender,
        "is_internal": emp_row is not None,
        "employee_id": emp_row[0] if emp_row else None,
        "employee_name": emp_row[1] if emp_row else None,
        "total_messages": total_count,
        "first_seen": time_row[0] if time_row else None,
        "last_seen": time_row[1] if time_row else None,
        "external_messages": external_count,
        "messages_with_attachments": with_attachments,
        "unique_recipients": sorted(all_recipients),
        "recent_subjects": recent_subjects,
    }


def find_phishing_indicators(
    conn: sqlite3.Connection,
    *,
    sender_domain: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Find emails with potential phishing indicators.

    Looks for: external emails with URLs, attachments from unknown senders,
    subjects with urgency keywords.

    Args:
        sender_domain: Filter to a specific sender domain.
        time_start: ISO timestamp lower bound.
        time_end: ISO timestamp upper bound.

    Returns:
        List of suspicious emails with indicator details.
    """
    where_parts = ["ee.external = 1"]
    params: list = []

    if sender_domain:
        where_parts.append("ee.sender LIKE ?")
        params.append(f"%@{sender_domain}")
    if time_start:
        where_parts.append("ee.ts >= ?")
        params.append(time_start)
    if time_end:
        where_parts.append("ee.ts <= ?")
        params.append(time_end)

    # Emails with URLs or attachments from external senders
    where_parts.append(
        "(ee.contains_url IS NOT NULL OR "
        "(ee.attachments IS NOT NULL AND ee.attachments != '[]' AND ee.attachments != 'null'))"
    )

    where_clause = " WHERE " + " AND ".join(where_parts)
    query = f"""
        SELECT ee.*, e.email as owner_email, e.display_name
        FROM email_events ee
        LEFT JOIN employees e ON ee.employee_id = e.id
        {where_clause}
        ORDER BY ee.ts DESC
    """

    cursor = conn.cursor()
    cursor.execute(query, params)
    results = _rows_to_dicts(cursor)

    # Add phishing indicator flags
    urgency_keywords = ["urgent", "immediate", "action required", "verify", "suspended", "expire"]
    for r in results:
        indicators = []
        if r.get("contains_url"):
            indicators.append("contains_url")
        attachments = r.get("attachments")
        if attachments and isinstance(attachments, list) and len(attachments) > 0:
            indicators.append("has_attachments")
        subj = (r.get("subject") or "").lower()
        if any(kw in subj for kw in urgency_keywords):
            indicators.append("urgency_language")
        r["phishing_indicators"] = indicators

    return results


