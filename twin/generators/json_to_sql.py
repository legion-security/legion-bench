import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


def create_schema(conn: sqlite3.Connection) -> None:
    """Create the database schema."""
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            locations TEXT  -- JSON array of location codes
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            manager_user_id TEXT,
            FOREIGN KEY (manager_user_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            department_id TEXT,
            department TEXT,
            title TEXT,
            manager_id TEXT,
            location TEXT,
            accounts TEXT,  -- JSON array
            authorisations TEXT,  -- JSON array
            baseline TEXT,  -- JSON object
            FOREIGN KEY (department_id) REFERENCES departments(id),
            FOREIGN KEY (manager_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            authorisations TEXT  -- JSON array
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups(id),
            FOREIGN KEY (user_id) REFERENCES employees(id)
        )
    """)

    # Subnets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subnets (
            id TEXT PRIMARY KEY,
            cidr TEXT NOT NULL,
            location TEXT NOT NULL,
            name TEXT NOT NULL,
            last_updated TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            os TEXT,
            owner_user_id TEXT,
            ip_address TEXT,
            network_id TEXT,
            FOREIGN KEY (owner_user_id) REFERENCES employees(id),
            FOREIGN KEY (network_id) REFERENCES subnets(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mailboxes (
            address TEXT PRIMARY KEY,
            created_at TEXT,
            is_distribution_list INTEGER NOT NULL DEFAULT 0,
            rules TEXT  -- JSON array
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mailbox_members (
            mailbox_address TEXT NOT NULL,
            member_email TEXT NOT NULL,
            is_delegate INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (mailbox_address, member_email),
            FOREIGN KEY (mailbox_address) REFERENCES mailboxes(address)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_instances (
            instance_id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            account_id TEXT,  -- AWS account ID or Azure subscription ID or GCP project ID
            region TEXT,
            zone TEXT,  -- GCP only
            image TEXT,
            instance_type TEXT,
            tags TEXT,  -- JSON object
            vpc TEXT,
            subnet TEXT,
            private_ip TEXT,
            public_ip TEXT,
            security_groups TEXT,  -- JSON array
            iam_role TEXT,  -- AWS/GCP
            service_principal TEXT,  -- Azure
            permissions TEXT  -- JSON array
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_containers (
            id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            cluster TEXT,
            node TEXT,
            namespace TEXT,
            pod TEXT,
            container TEXT,
            image TEXT,
            labels TEXT,  -- JSON object
            FOREIGN KEY (node) REFERENCES cloud_instances(instance_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_vulnerabilities (
            id TEXT PRIMARY KEY,
            resource_id TEXT,
            resource_type TEXT,
            provider TEXT,
            severity TEXT,
            cve_id TEXT,
            title TEXT,
            description TEXT,
            package_name TEXT,
            package_version TEXT,
            fixed_version TEXT,
            detected_at TEXT,
            status TEXT,
            FOREIGN KEY (resource_id) REFERENCES cloud_instances(instance_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_misconfigurations (
            id TEXT PRIMARY KEY,
            resource_id TEXT,
            resource_type TEXT,
            provider TEXT,
            severity TEXT,
            rule_id TEXT,
            title TEXT,
            description TEXT,
            category TEXT,
            compliance_framework TEXT,
            detected_at TEXT,
            status TEXT,
            FOREIGN KEY (resource_id) REFERENCES cloud_instances(instance_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_threats (
            id TEXT PRIMARY KEY,
            resource_id TEXT,
            resource_type TEXT,
            identity TEXT,
            provider TEXT,
            severity TEXT,
            threat_type TEXT,
            title TEXT,
            description TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            action TEXT,
            detected_at TEXT,
            status TEXT,
            details TEXT,  -- JSON object
            FOREIGN KEY (resource_id) REFERENCES cloud_instances(instance_id)
        )
    """)

    # Create indexes for common queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_network ON devices(network_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_employees_email ON employees(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_employees_department ON employees(department_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_subnets_location ON subnets(location)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_members_email ON mailbox_members(member_email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_vuln_resource ON cloud_vulnerabilities(resource_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_vuln_severity ON cloud_vulnerabilities(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_vuln_cve ON cloud_vulnerabilities(cve_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_misconfig_resource ON cloud_misconfigurations(resource_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_misconfig_category ON cloud_misconfigurations(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_threat_resource ON cloud_threats(resource_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_threat_identity ON cloud_threats(identity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_threat_type ON cloud_threats(threat_type)")

    _create_event_schema(conn)

    conn.commit()


def _create_event_schema(conn: sqlite3.Connection) -> None:
    """Create event tables for activity data."""
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            ip TEXT,
            method TEXT,
            success INTEGER,
            app TEXT,
            geo TEXT,
            user_agent TEXT,
            device_id TEXT,
            known_device INTEGER,
            failure_reason TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            direction TEXT,
            sender TEXT,
            recipients TEXT,  -- JSON array
            cc TEXT,          -- JSON array
            bcc TEXT,         -- JSON array
            subject TEXT,
            content TEXT,
            external INTEGER,
            attachment_types TEXT,  -- JSON array
            attachments TEXT,      -- JSON array
            scenario_id TEXT,
            thread_id TEXT,
            contains_url TEXT,
            url_clicked INTEGER,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            action TEXT,
            path TEXT,
            system TEXT,
            destination TEXT,
            size_bytes INTEGER,
            count INTEGER,
            label TEXT,
            category TEXT,
            description TEXT,
            shared_with TEXT,
            shared_by TEXT,
            granted_via TEXT,
            owner_role TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            system TEXT,
            action TEXT,
            approved_by TEXT,
            details TEXT,  -- JSON object
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            app TEXT,
            action TEXT,
            resource_type TEXT,
            resource_id TEXT,
            resource_name TEXT,
            description TEXT,
            success INTEGER,
            details TEXT,  -- JSON object
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            process_name TEXT,
            action TEXT,
            parent_process TEXT,
            command_line TEXT,
            pid INTEGER,
            hash TEXT,
            path TEXT,
            user_context TEXT,
            integrity_level TEXT,
            device_id TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mfa_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            action TEXT,
            device_name TEXT,
            method TEXT,
            count INTEGER,
            app TEXT,
            ip TEXT,
            success INTEGER,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            action TEXT,
            device_type TEXT,
            vendor TEXT,
            product TEXT,
            serial TEXT,
            volume_label TEXT,
            capacity_gb REAL,
            software_name TEXT,
            software_version TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS print_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            printer_name TEXT,
            document_name TEXT,
            pages INTEGER,
            copies INTEGER,
            color INTEGER,
            duplex INTEGER,
            paper_size TEXT,
            job_id TEXT,
            status TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            action TEXT,
            direction TEXT,
            username TEXT,
            auth TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            description TEXT,
            FOREIGN KEY (network_id) REFERENCES subnets(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cloud_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            provider TEXT NOT NULL,
            instance_id TEXT NOT NULL,
            region TEXT,
            account_id TEXT,
            identity TEXT,
            identity_type TEXT,
            event_source TEXT,
            event_name TEXT NOT NULL,
            event_category TEXT,
            read_only INTEGER,
            source_ip TEXT,
            user_agent TEXT,
            request_parameters TEXT,
            response_status TEXT,
            error_code TEXT,
            error_message TEXT,
            resources TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_ground_truth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT NOT NULL UNIQUE,
            scenario_id TEXT,
            victim_id TEXT,
            victim_email TEXT,
            success INTEGER,
            start_ts TEXT,
            compromise_ts TEXT,
            iocs TEXT,              -- JSON object
            expected_findings TEXT,  -- JSON array
            event_ids TEXT          -- JSON array
        )
    """)

    # Event table indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_employee ON login_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_ts ON login_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_ip ON login_events(ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_success ON login_events(success)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_employee ON email_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_ts ON email_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_sender ON email_events(sender)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_direction ON email_events(direction)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_employee ON file_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_ts ON file_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_events(path)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_action ON file_events(action)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_label ON file_events(label)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_employee ON admin_actions(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_ts ON admin_actions(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_action ON admin_actions(action)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_system ON admin_actions(system)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_employee ON app_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_ts ON app_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_app ON app_events(app)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_action ON app_events(action)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_process_employee ON process_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_process_ts ON process_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_process_name ON process_events(process_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_process_hash ON process_events(hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_process_device ON process_events(device_id)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_employee ON mfa_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_ts ON mfa_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_action ON mfa_events(action)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devevt_employee ON device_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devevt_ts ON device_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devevt_action ON device_events(action)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_print_employee ON print_events(employee_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_print_ts ON print_events(ts)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_network ON network_events(network_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_ts ON network_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_src_ip ON network_events(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_dst_ip ON network_events(destination_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_dst_port ON network_events(destination_port)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_net_action ON network_events(action)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_ts ON cloud_events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_instance ON cloud_events(instance_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_identity ON cloud_events(identity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_event_name ON cloud_events(event_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_event_source ON cloud_events(event_source)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_provider ON cloud_events(provider)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_status ON cloud_events(response_status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_evt_source_ip ON cloud_events(source_ip)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agt_scenario ON attack_ground_truth(scenario_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agt_victim ON attack_ground_truth(victim_id)")


def _strip_attack_metadata(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of event with keys starting with '_' removed."""
    return {k: v for k, v in event.items() if not k.startswith("_")}


def _normalize_ts(ts: Any) -> Any:
    """Strip microseconds from ISO 8601 timestamps to ensure consistent format.

    Data generators sometimes produce '2026-03-24T13:57:53.961965Z' (with
    microseconds) instead of the canonical '2026-03-24T13:57:53Z'.  Since SQL
    queries use string comparison (>=, <=), mixing formats breaks ordering
    because '.' (ASCII 46) sorts before 'Z' (ASCII 90).
    """
    if not isinstance(ts, str) or "T" not in ts:
        return ts
    dot = ts.find(".")
    if dot == -1:
        return ts
    # Everything after the dot up to the timezone suffix (Z or +HH:MM)
    for i in range(dot + 1, len(ts)):
        if not ts[i].isdigit():
            return ts[:dot] + ts[i:]
    # No timezone suffix — just truncate
    return ts[:dot]


def _is_attack_evt(evt: Dict[str, Any], filter_attack_id: Optional[str]) -> bool:
    """True if the event passes the attack filter (or no filter is set)."""
    if filter_attack_id is None:
        return True
    meta = evt.get("_attack_metadata") or {}
    return meta.get("attack_id") == filter_attack_id


def _insert_events(
    conn: sqlite3.Connection,
    data: Dict[str, Any],
    filter_attack_id: Optional[str] = None,
) -> None:
    """Insert event data from employee recent_activity into event tables.

    When ``filter_attack_id`` is set, only events tagged with that attack_id
    are inserted (used to add an attack's deltas onto a pre-built base DB).
    """
    cursor = conn.cursor()
    employees = data.get("employees", [])

    login_rows: List[tuple] = []
    email_rows: List[tuple] = []
    file_rows: List[tuple] = []
    admin_rows: List[tuple] = []
    app_rows: List[tuple] = []
    process_rows: List[tuple] = []
    mfa_rows: List[tuple] = []
    device_evt_rows: List[tuple] = []
    print_rows: List[tuple] = []
    network_rows: List[tuple] = []

    for emp in employees:
        emp_id = emp.get("id")
        activity = emp.get("recent_activity", {})

        for evt in activity.get("logins", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            login_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("ip"), e.get("method"),
                1 if e.get("success") else 0 if e.get("success") is not None else None,
                e.get("app"), e.get("geo"), e.get("user_agent"),
                e.get("device_id"),
                1 if e.get("known_device") else 0 if e.get("known_device") is not None else None,
                e.get("failure_reason"),
            ))

        for evt in activity.get("email_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            login_rows_sender = e.get("from", e.get("sender"))
            recipients = e.get("to", e.get("recipients"))
            url_clicked_raw = e.get("url_clicked")
            url_clicked_val = (
                1 if url_clicked_raw is True or url_clicked_raw == 1
                else 0 if url_clicked_raw is False or url_clicked_raw == 0
                else None
            )
            email_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("direction"),
                login_rows_sender,
                json.dumps(recipients) if isinstance(recipients, list) else recipients,
                json.dumps(e.get("cc")) if e.get("cc") else None,
                json.dumps(e.get("bcc")) if e.get("bcc") else None,
                e.get("subject"), e.get("content"),
                1 if e.get("external") else 0 if e.get("external") is not None else None,
                json.dumps(e.get("attachment_types")) if e.get("attachment_types") else None,
                json.dumps(e.get("attachments")) if e.get("attachments") else None,
                e.get("scenario_id"), e.get("thread_id"),
                e.get("contains_url"),
                url_clicked_val,
            ))

        for evt in activity.get("file_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            shared_with = e.get("shared_with")
            file_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("action"), e.get("path"),
                e.get("system"), e.get("destination"), e.get("size_bytes"),
                e.get("count"), e.get("label"), e.get("category"),
                e.get("description"),
                json.dumps(shared_with) if isinstance(shared_with, list) else shared_with,
                e.get("shared_by"),
                e.get("granted_via"),
                e.get("owner_role"),
            ))

        for evt in activity.get("admin_actions", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            details = e.get("details")
            admin_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("system"), e.get("action"),
                e.get("approved_by"),
                json.dumps(details) if isinstance(details, dict) else details,
            ))

        for evt in activity.get("app_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            details = e.get("details")
            app_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("app"), e.get("action"),
                e.get("resource_type"), e.get("resource_id"),
                e.get("resource_name"), e.get("description"),
                1 if e.get("success") else 0 if e.get("success") is not None else None,
                json.dumps(details) if isinstance(details, dict) else details,
            ))

        for evt in activity.get("process_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            process_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("process_name"), e.get("action"),
                e.get("parent_process"), e.get("command_line"), e.get("pid"),
                e.get("hash"), e.get("path"), e.get("user", e.get("user_context")),
                e.get("integrity_level"), e.get("device_id"),
            ))

        for evt in activity.get("mfa_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            mfa_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("action"), e.get("device_name"),
                e.get("method"), e.get("count"), e.get("app"), e.get("ip"),
                1 if e.get("success") else 0 if e.get("success") is not None else None,
            ))

        for evt in activity.get("device_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            device_evt_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("action"), e.get("device_type"),
                e.get("vendor"), e.get("product"), e.get("serial"),
                e.get("volume_label"), e.get("capacity_gb"),
                e.get("software_name"), e.get("software_version"),
            ))

        for evt in activity.get("print_events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            print_rows.append((
                emp_id, _normalize_ts(e.get("ts")), e.get("printer_name"),
                e.get("document_name"), e.get("pages"), e.get("copies"),
                1 if e.get("color") else 0 if e.get("color") is not None else None,
                1 if e.get("duplex") else 0 if e.get("duplex") is not None else None,
                e.get("paper_size"), e.get("job_id"), e.get("status"),
            ))

        # network_events are stored at subnet level, not per-employee

    # Extract network events from subnets
    for subnet in (data.get("network") or {}).get("subnets", []):
        subnet_id = subnet.get("id")
        for evt in subnet.get("events", []):
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            network_rows.append((
                subnet_id, _normalize_ts(e.get("ts")), e.get("source_ip"),
                e.get("destination_ip"), e.get("destination_port"),
                e.get("protocol"), e.get("action"), e.get("direction"),
                e.get("user"), e.get("auth"),
                e.get("bytes_sent"), e.get("bytes_received"),
                e.get("description"),
            ))

    if login_rows:
        cursor.executemany("""
            INSERT INTO login_events (
                employee_id, ts, ip, method, success, app, geo,
                user_agent, device_id, known_device, failure_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, login_rows)

    if email_rows:
        cursor.executemany("""
            INSERT INTO email_events (
                employee_id, ts, direction, sender, recipients, cc, bcc,
                subject, content, external, attachment_types, attachments,
                scenario_id, thread_id, contains_url, url_clicked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, email_rows)

    if file_rows:
        cursor.executemany("""
            INSERT INTO file_events (
                employee_id, ts, action, path, system, destination,
                size_bytes, count, label, category, description,
                shared_with, shared_by, granted_via, owner_role
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, file_rows)

    if admin_rows:
        cursor.executemany("""
            INSERT INTO admin_actions (
                employee_id, ts, system, action, approved_by, details
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, admin_rows)

    if app_rows:
        cursor.executemany("""
            INSERT INTO app_events (
                employee_id, ts, app, action, resource_type, resource_id,
                resource_name, description, success, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, app_rows)

    if process_rows:
        cursor.executemany("""
            INSERT INTO process_events (
                employee_id, ts, process_name, action, parent_process,
                command_line, pid, hash, path, user_context,
                integrity_level, device_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, process_rows)

    if mfa_rows:
        cursor.executemany("""
            INSERT INTO mfa_events (
                employee_id, ts, action, device_name, method, count,
                app, ip, success
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, mfa_rows)

    if device_evt_rows:
        cursor.executemany("""
            INSERT INTO device_events (
                employee_id, ts, action, device_type, vendor, product,
                serial, volume_label, capacity_gb, software_name,
                software_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, device_evt_rows)

    if print_rows:
        cursor.executemany("""
            INSERT INTO print_events (
                employee_id, ts, printer_name, document_name, pages,
                copies, color, duplex, paper_size, job_id, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, print_rows)

    if network_rows:
        cursor.executemany("""
            INSERT INTO network_events (
                network_id, ts, source_ip, destination_ip, destination_port,
                protocol, action, direction, username, auth,
                bytes_sent, bytes_received, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, network_rows)

    # Insert cloud events
    cloud_events = (data.get("cloud") or {}).get("events", [])
    if cloud_events:
        cloud_evt_rows = []
        for evt in cloud_events:
            if not _is_attack_evt(evt, filter_attack_id):
                continue
            e = _strip_attack_metadata(evt)
            cloud_evt_rows.append((
                e.get("event_id"), _normalize_ts(e.get("ts")), e.get("provider"),
                e.get("instance_id"), e.get("region"), e.get("account_id"),
                e.get("identity"), e.get("identity_type"),
                e.get("event_source"), e.get("event_name"),
                e.get("event_category"),
                1 if e.get("read_only") else 0 if e.get("read_only") is not None else None,
                e.get("source_ip"), e.get("user_agent"),
                e.get("request_parameters"), e.get("response_status"),
                e.get("error_code"), e.get("error_message"),
                e.get("resources"),
            ))
        cursor.executemany("""
            INSERT OR REPLACE INTO cloud_events (
                event_id, ts, provider, instance_id, region, account_id,
                identity, identity_type, event_source, event_name,
                event_category, read_only, source_ip, user_agent,
                request_parameters, response_status, error_code,
                error_message, resources
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, cloud_evt_rows)

    # Insert attack ground truth
    ground_truth = data.get("_attack_ground_truth", [])
    if ground_truth:
        gt_rows = []
        for gt in ground_truth:
            if filter_attack_id is not None and gt.get("attack_id") != filter_attack_id:
                continue
            gt_rows.append((
                gt.get("attack_id"), gt.get("scenario_id"),
                gt.get("victim_id"), gt.get("victim_email"),
                1 if gt.get("success") else 0,
                gt.get("start_ts"), gt.get("compromise_ts"),
                json.dumps(gt.get("iocs", {})),
                json.dumps(gt.get("expected_findings", [])),
                json.dumps(gt.get("event_ids", [])),
            ))
        cursor.executemany("""
            INSERT OR REPLACE INTO attack_ground_truth (
                attack_id, scenario_id, victim_id, victim_email, success,
                start_ts, compromise_ts, iocs, expected_findings, event_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, gt_rows)

    conn.commit()


def insert_company_data(conn: sqlite3.Connection, data: Dict[str, Any]) -> None:
    """Load company data into the database."""
    cursor = conn.cursor()

    company = data["company"]
    cursor.execute(
        """
        INSERT OR REPLACE INTO companies (id, name, domain, locations)
        VALUES (?, ?, ?, ?)
        """,
        (
            company['id'],
            company['name'],
            company['domain'],
            json.dumps(company['locations']),
        ),
    )

    departments = data.get("departments", [])
    if departments:
        dept_data = [
            (dept['id'], dept['name'], dept['manager_user_id'])
            for dept in departments
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO departments (id, name, manager_user_id)
            VALUES (?, ?, ?)
            """,
            dept_data,
        )

    employees = data.get("employees", [])
    if employees:
        emp_data = [
            (
                emp.get("id"),
                emp.get("email"),
                emp.get("display_name"),
                emp.get("department_id"),
                emp.get("department"),
                emp.get("title"),
                emp.get("manager_id"),
                emp.get("location"),
                json.dumps(emp.get("accounts", [])),
                json.dumps(emp.get("authorisations", [])),
                json.dumps(emp.get("baseline", {})),
            )
            for emp in employees
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO employees (
                id, email, display_name, department_id, department, title,
                manager_id, location, accounts, authorisations, baseline
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            emp_data,
        )

    groups = data.get("groups", [])
    if groups:
        group_data = [
            (
                group.get("id"),
                group.get("name"),
                group.get("description"),
                json.dumps(group.get("authorisations", [])),
            )
            for group in groups
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO groups (id, name, description, authorisations)
            VALUES (?, ?, ?, ?)
            """,
            group_data,
        )


        group_member_data = [
            (group["id"], user_id)
            for group in groups
            for user_id in group.get("members", [])
        ]
        if group_member_data:
            cursor.executemany(
                """
                INSERT OR REPLACE INTO group_members (group_id, user_id)
                VALUES (?, ?)
                """,
                group_member_data,
            )

    network = data.get("network", {})
    subnets = network.get("subnets", [])
    if subnets:
        last_updated = network.get("lastUpdated")
        subnet_data = [
            (
                subnet.get("id"),
                subnet.get("cidr"),
                subnet.get("location"),
                subnet.get("name"),
                last_updated,
            )
            for subnet in subnets
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO subnets (id, cidr, location, name, last_updated)
            VALUES (?, ?, ?, ?, ?)
            """,
            subnet_data,
        )

    devices = data.get("devices", [])
    if devices:
        device_data = [
            (
                device.get("id"),
                device.get("hostname"),
                device.get("os"),
                device.get("owner_user_id"),
                device.get("ip_address"),
                device.get("network_id"),
            )
            for device in devices
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO devices (
                id, hostname, os, owner_user_id, ip_address, network_id
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            device_data,
        )

    mailboxes = data.get("mailboxes", [])
    if mailboxes:
        mailbox_data = [
            (
                mailbox.get("address"),
                mailbox.get("created_at"),
                1 if mailbox.get("is_distribution_list", False) else 0,
                json.dumps(mailbox.get("rules", [])),
            )
            for mailbox in mailboxes
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO mailboxes (
                address, created_at, is_distribution_list, rules
            )
            VALUES (?, ?, ?, ?)
            """,
            mailbox_data,
        )

        mailbox_member_data = [
            (
                mailbox.get("address"),
                member_email,
                1 if member_email in set(mailbox.get("delegates", [])) else 0,
            )
            for mailbox in mailboxes
            for member_email in mailbox.get("members", [])
        ]
        if mailbox_member_data:
            cursor.executemany(
                """
                INSERT OR REPLACE INTO mailbox_members (
                    mailbox_address, member_email, is_delegate
                )
                VALUES (?, ?, ?)
                """,
                mailbox_member_data,
            )

    cloud = data.get("cloud", {})
    instances = cloud.get("instances", [])
    if instances:
        instance_data = []
        for instance in instances:
            network_info = instance.get("network", {})
            iam_info = instance.get("iam", {})
            account_id = (
                instance.get("accountId")
                or instance.get("subscriptionId")
                or instance.get("projectId")
            )
            instance_data.append((
                instance.get("instanceId"),
                instance.get("provider"),
                account_id,
                instance.get("region"),
                instance.get("zone"),  # GCP only
                instance.get("image"),
                instance.get("instanceType"),
                json.dumps(instance.get("tags", {})),
                network_info.get("vpc") or network_info.get("vnet"),
                network_info.get("subnet"),
                network_info.get("privateIp"),
                network_info.get("publicIp"),
                json.dumps(network_info.get("securityGroups", [])),
                iam_info.get("role"),
                iam_info.get("servicePrincipal"),
                json.dumps(iam_info.get("permissions", [])),
            ))
        cursor.executemany(
            """
            INSERT OR REPLACE INTO cloud_instances (
                instance_id, provider, account_id, region, zone, image, instance_type,
                tags, vpc, subnet, private_ip, public_ip, security_groups,
                iam_role, service_principal, permissions
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            instance_data,
        )

    # Cloud containers - batch insert
    containers = cloud.get("containers", [])
    if containers:
        container_data = [
            (
                container.get("id"),
                container.get("provider"),
                container.get("cluster"),
                container.get("node"),
                container.get("namespace"),
                container.get("pod"),
                container.get("container"),
                container.get("image"),
                json.dumps(container.get("labels", {})),
            )
            for container in containers
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO cloud_containers (
                id, provider, cluster, node, namespace, pod, container, image, labels
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            container_data,
        )

    # Cloud vulnerabilities
    vulnerabilities = cloud.get("vulnerabilities", [])
    if vulnerabilities:
        vuln_data = [
            (
                v.get("id"), v.get("resource_id"), v.get("resource_type"),
                v.get("provider"), v.get("severity"), v.get("cve_id"),
                v.get("title"), v.get("description"), v.get("package_name"),
                v.get("package_version"), v.get("fixed_version"),
                v.get("detected_at"), v.get("status"),
            )
            for v in vulnerabilities
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO cloud_vulnerabilities (
                id, resource_id, resource_type, provider, severity, cve_id,
                title, description, package_name, package_version, fixed_version,
                detected_at, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            vuln_data,
        )

    # Cloud misconfigurations
    misconfigurations = cloud.get("misconfigurations", [])
    if misconfigurations:
        misconfig_data = [
            (
                m.get("id"), m.get("resource_id"), m.get("resource_type"),
                m.get("provider"), m.get("severity"), m.get("rule_id"),
                m.get("title"), m.get("description"), m.get("category"),
                m.get("compliance_framework"), m.get("detected_at"), m.get("status"),
            )
            for m in misconfigurations
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO cloud_misconfigurations (
                id, resource_id, resource_type, provider, severity, rule_id,
                title, description, category, compliance_framework, detected_at, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            misconfig_data,
        )

    # Cloud threats
    threats = cloud.get("threats", [])
    if threats:
        threat_data = [
            (
                t.get("id"), t.get("resource_id"), t.get("resource_type"),
                t.get("identity"), t.get("provider"), t.get("severity"),
                t.get("threat_type"), t.get("title"), t.get("description"),
                t.get("source_ip"), t.get("destination_ip"), t.get("action"),
                t.get("detected_at"), t.get("status"),
                json.dumps(t.get("details", {})),
            )
            for t in threats
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO cloud_threats (
                id, resource_id, resource_type, identity, provider, severity,
                threat_type, title, description, source_ip, destination_ip,
                action, detected_at, status, details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            threat_data,
        )

    conn.commit()

    # Insert event data after static data
    _insert_events(conn, data)


def create_database(output_path: str, company_data: Dict[str, Any]) -> None:
    conn = sqlite3.connect(output_path)
    try:
        create_schema(conn)
        insert_company_data(conn, company_data)
    finally:
        conn.close()


def insert_attack_delta(db_path: str, company_data: Dict[str, Any], attack_id: str) -> None:
    """Insert ONLY events tagged with ``attack_id`` (plus its ground-truth row).

    Used to add a single attack's events into a base SQLite database that was
    built from the unattacked company. Static tables (employees, devices, etc.)
    are not touched.
    """
    conn = sqlite3.connect(db_path)
    try:
        _insert_events(conn, company_data, filter_attack_id=attack_id)
    finally:
        conn.close()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Convert static company json to SQL database")
    parser.add_argument(
        "--input",
        required=True,
        help="Path to static json file",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output SQLite database file",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing database if it exists
    if output_path.exists():
        output_path.unlink()

    # Load JSON data
    with input_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    create_database(str(output_path), data)

    # Count event rows
    conn = sqlite3.connect(str(output_path))
    cursor = conn.cursor()
    event_tables = [
        "login_events", "email_events", "file_events", "admin_actions",
        "app_events", "process_events", "mfa_events", "device_events",
        "print_events", "network_events", "cloud_events", "attack_ground_truth",
    ]
    event_counts = {}
    for table in event_tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        event_counts[table] = cursor.fetchone()[0]
    conn.close()

    print(f"Successfully created database: {output_path}")
    print(f"Loaded {len(data.get('employees', []))} employees")
    print(f"Loaded {len(data.get('devices', []))} devices")
    print(f"Loaded {len(data.get('groups', []))} groups")
    print(f"Loaded {len(data.get('cloud', {}).get('instances', []))} cloud instances")
    for table, count in event_counts.items():
        if count > 0:
            print(f"Loaded {count} {table}")


if __name__ == "__main__":
    main()
