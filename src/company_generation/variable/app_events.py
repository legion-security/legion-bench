"""
App event log generation with realistic enterprise usage patterns.

Generates in-app activity events using four layers of realism:
- Layer 1: Weighted actions, app frequency tiers, department affinity, role gating
- Layer 2: Session-based generation with Markov action transitions
- Layer 3: Cross-app workflow chains (meeting→doc→share, code review, etc.)
- Layer 4: Per-app temporal profiles (circadian, day-of-week, meeting snap)

Each event includes:
- app: The application name
- action: The specific action performed
- usage: The type of operation (read, write, admin)
- success: Whether the action succeeded
"""
from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_app_event_logs, _collect_person_apps, vary_count
from .temporal_model import (
    CircadianSampler,
    WeeklyCycleModulator,
    format_ts,
    get_window,
    resolve_event_count,
    resolve_person_temporal,
    sample_timestamp,
)
from .episodic_bursts import BurstSchedule, apply_burst_to_count

Person = Dict[str, Any]
Company = Dict[str, Any]

_DEFAULT_APP_EVENTS = 6

# ═══════════════════════════════════════════════════════════════════════════
# Layer 1: Weighted Actions + App Categories + Role Affinity
# ═══════════════════════════════════════════════════════════════════════════

# Usage types:
# - read: viewing, reading, downloading, viewing dashboards
# - write: creating, editing, uploading, sending messages, updating
# - admin: creating channels/teams/spaces, modifying permissions, installing apps

_APP_ACTIONS: Dict[str, List[Dict[str, Any]]] = {
    # ── Communication ──────────────────────────────────────────────────
    "Slack": [
        {"action": "send_message", "resource_type": "message", "usage": "write", "description": "Sent a message in channel", "weight": 40},
        {"action": "send_direct_message", "resource_type": "direct_message", "usage": "write", "description": "Sent a direct message", "weight": 25},
        {"action": "upload_file", "resource_type": "file", "usage": "write", "description": "Uploaded a file to channel", "weight": 5},
        {"action": "create_channel", "resource_type": "channel", "usage": "admin", "description": "Created a new channel", "weight": 1},
        {"action": "join_channel", "resource_type": "channel", "usage": "write", "description": "Joined a channel", "weight": 3},
        {"action": "add_reaction", "resource_type": "reaction", "usage": "write", "description": "Added a reaction to message", "weight": 20},
        {"action": "start_huddle", "resource_type": "huddle", "usage": "write", "description": "Started a huddle call", "weight": 2},
        {"action": "install_app", "resource_type": "app_integration", "usage": "admin", "description": "Installed a Slack app", "weight": 0.5},
        {"action": "view_channel", "resource_type": "channel", "usage": "read", "description": "Viewed channel messages", "weight": 30},
        {"action": "search_messages", "resource_type": "search", "usage": "read", "description": "Searched messages", "weight": 8},
    ],
    "Microsoft Teams": [
        {"action": "send_message", "resource_type": "message", "usage": "write", "description": "Sent a message in channel", "weight": 35},
        {"action": "send_chat", "resource_type": "chat", "usage": "write", "description": "Sent a chat message", "weight": 25},
        {"action": "upload_file", "resource_type": "file", "usage": "write", "description": "Uploaded a file", "weight": 5},
        {"action": "create_team", "resource_type": "team", "usage": "admin", "description": "Created a new team", "weight": 1},
        {"action": "schedule_meeting", "resource_type": "meeting", "usage": "write", "description": "Scheduled a meeting", "weight": 8},
        {"action": "join_meeting", "resource_type": "meeting", "usage": "read", "description": "Joined a meeting", "weight": 25},
        {"action": "share_screen", "resource_type": "screen_share", "usage": "write", "description": "Shared screen in meeting", "weight": 8},
        {"action": "view_files", "resource_type": "file", "usage": "read", "description": "Viewed shared files", "weight": 30},
    ],
    "Zoom": [
        {"action": "host_meeting", "resource_type": "meeting", "usage": "write", "description": "Hosted a meeting", "weight": 15},
        {"action": "join_meeting", "resource_type": "meeting", "usage": "read", "description": "Joined a meeting", "weight": 35},
        {"action": "share_screen", "resource_type": "screen_share", "usage": "write", "description": "Shared screen", "weight": 10},
        {"action": "record_meeting", "resource_type": "recording", "usage": "write", "description": "Started recording", "weight": 5},
        {"action": "send_chat", "resource_type": "chat", "usage": "write", "description": "Sent chat message in meeting", "weight": 20},
        {"action": "schedule_meeting", "resource_type": "meeting", "usage": "write", "description": "Scheduled a meeting", "weight": 8},
        {"action": "view_recording", "resource_type": "recording", "usage": "read", "description": "Viewed a recording", "weight": 15},
    ],

    # ── Productivity suites ────────────────────────────────────────────
    "Google Workspace": [
        {"action": "create_document", "resource_type": "document", "usage": "write", "description": "Created a Google Doc", "weight": 10},
        {"action": "edit_document", "resource_type": "document", "usage": "write", "description": "Edited a Google Doc", "weight": 25},
        {"action": "view_document", "resource_type": "document", "usage": "read", "description": "Viewed a Google Doc", "weight": 35},
        {"action": "create_spreadsheet", "resource_type": "spreadsheet", "usage": "write", "description": "Created a Google Sheet", "weight": 8},
        {"action": "edit_spreadsheet", "resource_type": "spreadsheet", "usage": "write", "description": "Edited a Google Sheet", "weight": 20},
        {"action": "share_file", "resource_type": "file", "usage": "admin", "description": "Shared a file", "weight": 2},
        {"action": "upload_file", "resource_type": "file", "usage": "write", "description": "Uploaded a file to Drive", "weight": 5},
        {"action": "send_email", "resource_type": "email", "usage": "write", "description": "Sent an email via Gmail", "weight": 25},
        {"action": "create_calendar_event", "resource_type": "calendar_event", "usage": "write", "description": "Created calendar event", "weight": 8},
        {"action": "view_calendar", "resource_type": "calendar", "usage": "read", "description": "Viewed calendar", "weight": 30},
    ],
    "Microsoft 365": [
        {"action": "create_document", "resource_type": "document", "usage": "write", "description": "Created a Word document", "weight": 10},
        {"action": "edit_document", "resource_type": "document", "usage": "write", "description": "Edited a Word document", "weight": 25},
        {"action": "view_document", "resource_type": "document", "usage": "read", "description": "Viewed a Word document", "weight": 35},
        {"action": "create_spreadsheet", "resource_type": "spreadsheet", "usage": "write", "description": "Created an Excel spreadsheet", "weight": 8},
        {"action": "edit_spreadsheet", "resource_type": "spreadsheet", "usage": "write", "description": "Edited an Excel spreadsheet", "weight": 20},
        {"action": "create_presentation", "resource_type": "presentation", "usage": "write", "description": "Created a PowerPoint", "weight": 5},
        {"action": "share_file", "resource_type": "file", "usage": "admin", "description": "Shared a file via OneDrive", "weight": 2},
        {"action": "send_email", "resource_type": "email", "usage": "write", "description": "Sent an email via Outlook", "weight": 25},
        {"action": "view_inbox", "resource_type": "email", "usage": "read", "description": "Viewed inbox", "weight": 30},
    ],

    # ── Project management ─────────────────────────────────────────────
    "Jira": [
        {"action": "create_issue", "resource_type": "issue", "usage": "write", "description": "Created a Jira issue", "weight": 8},
        {"action": "update_issue", "resource_type": "issue", "usage": "write", "description": "Updated a Jira issue", "weight": 20},
        {"action": "transition_issue", "resource_type": "issue", "usage": "write", "description": "Changed issue status", "weight": 15},
        {"action": "add_comment", "resource_type": "comment", "usage": "write", "description": "Added a comment to issue", "weight": 20},
        {"action": "assign_issue", "resource_type": "issue", "usage": "write", "description": "Assigned an issue", "weight": 8},
        {"action": "create_sprint", "resource_type": "sprint", "usage": "admin", "description": "Created a sprint", "weight": 1},
        {"action": "view_board", "resource_type": "board", "usage": "read", "description": "Viewed project board", "weight": 30},
        {"action": "view_issue", "resource_type": "issue", "usage": "read", "description": "Viewed an issue", "weight": 35},
    ],
    "Confluence": [
        {"action": "create_page", "resource_type": "page", "usage": "write", "description": "Created a Confluence page", "weight": 8},
        {"action": "edit_page", "resource_type": "page", "usage": "write", "description": "Edited a Confluence page", "weight": 20},
        {"action": "add_comment", "resource_type": "comment", "usage": "write", "description": "Added a comment", "weight": 15},
        {"action": "view_page", "resource_type": "page", "usage": "read", "description": "Viewed a page", "weight": 35},
        {"action": "share_page", "resource_type": "page", "usage": "admin", "description": "Shared a page", "weight": 1.5},
        {"action": "create_space", "resource_type": "space", "usage": "admin", "description": "Created a space", "weight": 0.5},
        {"action": "search_content", "resource_type": "search", "usage": "read", "description": "Searched for content", "weight": 25},
    ],
    "Asana": [
        {"action": "create_task", "resource_type": "task", "usage": "write", "description": "Created a task", "weight": 15},
        {"action": "complete_task", "resource_type": "task", "usage": "write", "description": "Completed a task", "weight": 15},
        {"action": "assign_task", "resource_type": "task", "usage": "write", "description": "Assigned a task", "weight": 10},
        {"action": "add_comment", "resource_type": "comment", "usage": "write", "description": "Added a comment", "weight": 15},
        {"action": "create_project", "resource_type": "project", "usage": "admin", "description": "Created a project", "weight": 1},
        {"action": "view_project", "resource_type": "project", "usage": "read", "description": "Viewed a project", "weight": 30},
    ],
    "Trello": [
        {"action": "create_card", "resource_type": "card", "usage": "write", "description": "Created a card", "weight": 15},
        {"action": "move_card", "resource_type": "card", "usage": "write", "description": "Moved a card", "weight": 20},
        {"action": "add_comment", "resource_type": "comment", "usage": "write", "description": "Added a comment", "weight": 15},
        {"action": "create_board", "resource_type": "board", "usage": "admin", "description": "Created a board", "weight": 1},
        {"action": "add_attachment", "resource_type": "attachment", "usage": "write", "description": "Added an attachment", "weight": 5},
        {"action": "view_board", "resource_type": "board", "usage": "read", "description": "Viewed a board", "weight": 35},
    ],
    "Notion": [
        {"action": "create_page", "resource_type": "page", "usage": "write", "description": "Created a page", "weight": 10},
        {"action": "edit_page", "resource_type": "page", "usage": "write", "description": "Edited a page", "weight": 25},
        {"action": "create_database", "resource_type": "database", "usage": "admin", "description": "Created a database", "weight": 1},
        {"action": "add_row", "resource_type": "database_row", "usage": "write", "description": "Added a database row", "weight": 15},
        {"action": "share_page", "resource_type": "page", "usage": "admin", "description": "Shared a page", "weight": 1.5},
        {"action": "view_page", "resource_type": "page", "usage": "read", "description": "Viewed a page", "weight": 35},
    ],

    # ── Source control / DevOps ────────────────────────────────────────
    "GitHub": [
        {"action": "push_commit", "resource_type": "commit", "usage": "write", "description": "Pushed commits", "weight": 20},
        {"action": "create_pull_request", "resource_type": "pull_request", "usage": "write", "description": "Created a pull request", "weight": 10},
        {"action": "merge_pull_request", "resource_type": "pull_request", "usage": "write", "description": "Merged a pull request", "weight": 5},
        {"action": "review_pull_request", "resource_type": "review", "usage": "write", "description": "Reviewed a pull request", "weight": 10},
        {"action": "create_issue", "resource_type": "issue", "usage": "write", "description": "Created an issue", "weight": 8},
        {"action": "close_issue", "resource_type": "issue", "usage": "write", "description": "Closed an issue", "weight": 4},
        {"action": "create_branch", "resource_type": "branch", "usage": "write", "description": "Created a branch", "weight": 6},
        {"action": "create_release", "resource_type": "release", "usage": "admin", "description": "Created a release", "weight": 1},
        {"action": "view_repository", "resource_type": "repository", "usage": "read", "description": "Viewed a repository", "weight": 35},
        {"action": "clone_repository", "resource_type": "repository", "usage": "read", "description": "Cloned a repository", "weight": 8},
    ],
    "GitLab": [
        {"action": "push_commit", "resource_type": "commit", "usage": "write", "description": "Pushed commits", "weight": 20},
        {"action": "create_merge_request", "resource_type": "merge_request", "usage": "write", "description": "Created a merge request", "weight": 10},
        {"action": "merge_request", "resource_type": "merge_request", "usage": "write", "description": "Merged a merge request", "weight": 5},
        {"action": "run_pipeline", "resource_type": "pipeline", "usage": "write", "description": "Triggered a pipeline", "weight": 10},
        {"action": "create_issue", "resource_type": "issue", "usage": "write", "description": "Created an issue", "weight": 8},
        {"action": "view_project", "resource_type": "project", "usage": "read", "description": "Viewed a project", "weight": 35},
    ],
    "Bitbucket": [
        {"action": "push_commit", "resource_type": "commit", "usage": "write", "description": "Pushed commits", "weight": 20},
        {"action": "create_pull_request", "resource_type": "pull_request", "usage": "write", "description": "Created a pull request", "weight": 10},
        {"action": "approve_pull_request", "resource_type": "pull_request", "usage": "write", "description": "Approved a pull request", "weight": 8},
        {"action": "run_pipeline", "resource_type": "pipeline", "usage": "write", "description": "Ran a pipeline", "weight": 10},
        {"action": "view_repository", "resource_type": "repository", "usage": "read", "description": "Viewed a repository", "weight": 35},
    ],

    # ── CRM ────────────────────────────────────────────────────────────
    "Salesforce": [
        {"action": "create_lead", "resource_type": "lead", "usage": "write", "description": "Created a lead", "weight": 8},
        {"action": "update_opportunity", "resource_type": "opportunity", "usage": "write", "description": "Updated an opportunity", "weight": 15},
        {"action": "log_call", "resource_type": "activity", "usage": "write", "description": "Logged a call", "weight": 15},
        {"action": "send_email", "resource_type": "email", "usage": "write", "description": "Sent an email from Salesforce", "weight": 12},
        {"action": "create_contact", "resource_type": "contact", "usage": "write", "description": "Created a contact", "weight": 8},
        {"action": "update_account", "resource_type": "account", "usage": "write", "description": "Updated an account", "weight": 10},
        {"action": "create_case", "resource_type": "case", "usage": "write", "description": "Created a support case", "weight": 5},
        {"action": "run_report", "resource_type": "report", "usage": "read", "description": "Ran a report", "weight": 25},
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed a dashboard", "weight": 30},
        {"action": "view_record", "resource_type": "record", "usage": "read", "description": "Viewed a record", "weight": 35},
    ],
    "HubSpot": [
        {"action": "create_contact", "resource_type": "contact", "usage": "write", "description": "Created a contact", "weight": 8},
        {"action": "update_deal", "resource_type": "deal", "usage": "write", "description": "Updated a deal", "weight": 15},
        {"action": "log_activity", "resource_type": "activity", "usage": "write", "description": "Logged an activity", "weight": 15},
        {"action": "send_email", "resource_type": "email", "usage": "write", "description": "Sent a marketing email", "weight": 12},
        {"action": "create_task", "resource_type": "task", "usage": "write", "description": "Created a task", "weight": 8},
        {"action": "view_contact", "resource_type": "contact", "usage": "read", "description": "Viewed a contact", "weight": 35},
    ],

    # ── Data / BI ──────────────────────────────────────────────────────
    "Snowflake": [
        {"action": "run_query", "resource_type": "query", "usage": "read", "description": "Ran a SQL query", "weight": 35},
        {"action": "create_table", "resource_type": "table", "usage": "admin", "description": "Created a table", "weight": 1},
        {"action": "load_data", "resource_type": "data_load", "usage": "write", "description": "Loaded data", "weight": 10},
        {"action": "create_view", "resource_type": "view", "usage": "admin", "description": "Created a view", "weight": 1},
        {"action": "grant_access", "resource_type": "permission", "usage": "admin", "description": "Granted access to role", "weight": 0.5},
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed query history", "weight": 25},
    ],
    "Tableau": [
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed a dashboard", "weight": 35},
        {"action": "create_workbook", "resource_type": "workbook", "usage": "write", "description": "Created a workbook", "weight": 10},
        {"action": "publish_workbook", "resource_type": "workbook", "usage": "admin", "description": "Published a workbook", "weight": 1},
        {"action": "export_data", "resource_type": "export", "usage": "read", "description": "Exported data", "weight": 20},
        {"action": "refresh_datasource", "resource_type": "datasource", "usage": "write", "description": "Refreshed data source", "weight": 8},
    ],
    "Power BI": [
        {"action": "view_report", "resource_type": "report", "usage": "read", "description": "Viewed a report", "weight": 35},
        {"action": "create_dashboard", "resource_type": "dashboard", "usage": "write", "description": "Created a dashboard", "weight": 10},
        {"action": "refresh_dataset", "resource_type": "dataset", "usage": "write", "description": "Refreshed a dataset", "weight": 8},
        {"action": "share_report", "resource_type": "report", "usage": "admin", "description": "Shared a report", "weight": 1},
        {"action": "export_data", "resource_type": "export", "usage": "read", "description": "Exported data", "weight": 20},
    ],

    # ── Support / ITSM ─────────────────────────────────────────────────
    "Zendesk": [
        {"action": "create_ticket", "resource_type": "ticket", "usage": "write", "description": "Created a support ticket", "weight": 10},
        {"action": "update_ticket", "resource_type": "ticket", "usage": "write", "description": "Updated a ticket", "weight": 20},
        {"action": "resolve_ticket", "resource_type": "ticket", "usage": "write", "description": "Resolved a ticket", "weight": 8},
        {"action": "add_comment", "resource_type": "comment", "usage": "write", "description": "Added a comment to ticket", "weight": 20},
        {"action": "assign_ticket", "resource_type": "ticket", "usage": "write", "description": "Assigned a ticket", "weight": 8},
        {"action": "view_ticket", "resource_type": "ticket", "usage": "read", "description": "Viewed a ticket", "weight": 35},
    ],
    "ServiceNow": [
        {"action": "create_incident", "resource_type": "incident", "usage": "write", "description": "Created an incident", "weight": 10},
        {"action": "update_incident", "resource_type": "incident", "usage": "write", "description": "Updated an incident", "weight": 20},
        {"action": "resolve_incident", "resource_type": "incident", "usage": "write", "description": "Resolved an incident", "weight": 8},
        {"action": "create_change", "resource_type": "change_request", "usage": "write", "description": "Created a change request", "weight": 5},
        {"action": "approve_change", "resource_type": "change_request", "usage": "admin", "description": "Approved a change request", "weight": 1},
        {"action": "view_incident", "resource_type": "incident", "usage": "read", "description": "Viewed an incident", "weight": 35},
    ],
    "Freshdesk": [
        {"action": "create_ticket", "resource_type": "ticket", "usage": "write", "description": "Created a ticket", "weight": 10},
        {"action": "reply_ticket", "resource_type": "ticket", "usage": "write", "description": "Replied to a ticket", "weight": 20},
        {"action": "close_ticket", "resource_type": "ticket", "usage": "write", "description": "Closed a ticket", "weight": 8},
        {"action": "view_ticket", "resource_type": "ticket", "usage": "read", "description": "Viewed a ticket", "weight": 35},
    ],

    # ── Identity / Security ────────────────────────────────────────────
    "Okta": [
        {"action": "login_sso", "resource_type": "session", "usage": "read", "description": "Logged in via SSO", "weight": 40},
        {"action": "reset_password", "resource_type": "credential", "usage": "write", "description": "Reset password", "weight": 3},
        {"action": "enroll_mfa", "resource_type": "mfa_factor", "usage": "write", "description": "Enrolled MFA factor", "weight": 2},
        {"action": "request_access", "resource_type": "access_request", "usage": "write", "description": "Requested app access", "weight": 3},
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed Okta dashboard", "weight": 25},
    ],
    "1Password": [
        {"action": "view_item", "resource_type": "item", "usage": "read", "description": "Viewed a vault item", "weight": 35},
        {"action": "create_item", "resource_type": "item", "usage": "write", "description": "Created a vault item", "weight": 5},
        {"action": "share_item", "resource_type": "item", "usage": "admin", "description": "Shared a vault item", "weight": 1},
        {"action": "copy_password", "resource_type": "credential", "usage": "read", "description": "Copied a password", "weight": 35},
        {"action": "update_item", "resource_type": "item", "usage": "write", "description": "Updated a vault item", "weight": 5},
    ],

    # ── Design ─────────────────────────────────────────────────────────
    "Figma": [
        {"action": "create_file", "resource_type": "design_file", "usage": "write", "description": "Created a design file", "weight": 8},
        {"action": "edit_file", "resource_type": "design_file", "usage": "write", "description": "Edited a design file", "weight": 25},
        {"action": "add_comment", "resource_type": "comment", "usage": "write", "description": "Added a comment", "weight": 15},
        {"action": "share_file", "resource_type": "design_file", "usage": "admin", "description": "Shared a design file", "weight": 2},
        {"action": "export_assets", "resource_type": "export", "usage": "read", "description": "Exported assets", "weight": 15},
        {"action": "view_file", "resource_type": "design_file", "usage": "read", "description": "Viewed a design file", "weight": 35},
    ],
    "Canva": [
        {"action": "create_design", "resource_type": "design", "usage": "write", "description": "Created a design", "weight": 10},
        {"action": "edit_design", "resource_type": "design", "usage": "write", "description": "Edited a design", "weight": 25},
        {"action": "share_design", "resource_type": "design", "usage": "admin", "description": "Shared a design", "weight": 1},
        {"action": "download_design", "resource_type": "export", "usage": "read", "description": "Downloaded a design", "weight": 15},
        {"action": "view_design", "resource_type": "design", "usage": "read", "description": "Viewed a design", "weight": 35},
    ],

    # ── HR ─────────────────────────────────────────────────────────────
    "Workday": [
        {"action": "submit_timesheet", "resource_type": "timesheet", "usage": "write", "description": "Submitted timesheet", "weight": 10},
        {"action": "request_time_off", "resource_type": "time_off_request", "usage": "write", "description": "Requested time off", "weight": 5},
        {"action": "view_payslip", "resource_type": "payslip", "usage": "read", "description": "Viewed payslip", "weight": 25},
        {"action": "update_profile", "resource_type": "profile", "usage": "write", "description": "Updated profile", "weight": 5},
        {"action": "complete_task", "resource_type": "task", "usage": "write", "description": "Completed HR task", "weight": 10},
        {"action": "view_directory", "resource_type": "directory", "usage": "read", "description": "Viewed employee directory", "weight": 30},
    ],
    "BambooHR": [
        {"action": "clock_in", "resource_type": "time_entry", "usage": "write", "description": "Clocked in", "weight": 25},
        {"action": "clock_out", "resource_type": "time_entry", "usage": "write", "description": "Clocked out", "weight": 25},
        {"action": "request_time_off", "resource_type": "time_off_request", "usage": "write", "description": "Requested time off", "weight": 5},
        {"action": "view_directory", "resource_type": "directory", "usage": "read", "description": "Viewed employee directory", "weight": 25},
        {"action": "view_payslip", "resource_type": "payslip", "usage": "read", "description": "Viewed payslip", "weight": 25},
    ],

    # ── Finance ────────────────────────────────────────────────────────
    "QuickBooks": [
        {"action": "create_invoice", "resource_type": "invoice", "usage": "write", "description": "Created an invoice", "weight": 15},
        {"action": "record_payment", "resource_type": "payment", "usage": "write", "description": "Recorded a payment", "weight": 15},
        {"action": "run_report", "resource_type": "report", "usage": "read", "description": "Ran a financial report", "weight": 25},
        {"action": "reconcile_account", "resource_type": "account", "usage": "admin", "description": "Reconciled an account", "weight": 2},
        {"action": "view_transactions", "resource_type": "transaction", "usage": "read", "description": "Viewed transactions", "weight": 30},
    ],
    "NetSuite": [
        {"action": "create_transaction", "resource_type": "transaction", "usage": "write", "description": "Created a transaction", "weight": 15},
        {"action": "approve_expense", "resource_type": "expense_report", "usage": "admin", "description": "Approved expense report", "weight": 2},
        {"action": "run_report", "resource_type": "report", "usage": "read", "description": "Ran a report", "weight": 25},
        {"action": "update_record", "resource_type": "record", "usage": "write", "description": "Updated a record", "weight": 15},
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed dashboard", "weight": 30},
    ],
    "Expensify": [
        {"action": "submit_expense", "resource_type": "expense", "usage": "write", "description": "Submitted an expense", "weight": 20},
        {"action": "approve_expense", "resource_type": "expense", "usage": "admin", "description": "Approved an expense", "weight": 2},
        {"action": "upload_receipt", "resource_type": "receipt", "usage": "write", "description": "Uploaded a receipt", "weight": 20},
        {"action": "view_expense", "resource_type": "expense", "usage": "read", "description": "Viewed an expense", "weight": 30},
    ],
    "Concur": [
        {"action": "submit_expense", "resource_type": "expense_report", "usage": "write", "description": "Submitted expense report", "weight": 20},
        {"action": "book_travel", "resource_type": "travel_booking", "usage": "write", "description": "Booked travel", "weight": 10},
        {"action": "approve_expense", "resource_type": "expense_report", "usage": "admin", "description": "Approved expense report", "weight": 2},
        {"action": "view_trips", "resource_type": "trip", "usage": "read", "description": "Viewed trips", "weight": 30},
    ],

    # ── File storage ───────────────────────────────────────────────────
    "Dropbox": [
        {"action": "upload_file", "resource_type": "file", "usage": "write", "description": "Uploaded a file", "weight": 15},
        {"action": "download_file", "resource_type": "file", "usage": "read", "description": "Downloaded a file", "weight": 30},
        {"action": "share_file", "resource_type": "file", "usage": "admin", "description": "Shared a file", "weight": 2},
        {"action": "create_folder", "resource_type": "folder", "usage": "write", "description": "Created a folder", "weight": 5},
        {"action": "view_file", "resource_type": "file", "usage": "read", "description": "Viewed a file", "weight": 35},
    ],
    "Box": [
        {"action": "upload_file", "resource_type": "file", "usage": "write", "description": "Uploaded a file", "weight": 15},
        {"action": "download_file", "resource_type": "file", "usage": "read", "description": "Downloaded a file", "weight": 30},
        {"action": "share_file", "resource_type": "file", "usage": "admin", "description": "Shared a file", "weight": 2},
        {"action": "add_collaborator", "resource_type": "collaboration", "usage": "admin", "description": "Added a collaborator", "weight": 1},
        {"action": "view_file", "resource_type": "file", "usage": "read", "description": "Viewed a file", "weight": 35},
    ],

    # ── Monitoring / DevOps ────────────────────────────────────────────
    "Datadog": [
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed a dashboard", "weight": 35},
        {"action": "create_monitor", "resource_type": "monitor", "usage": "admin", "description": "Created a monitor", "weight": 1},
        {"action": "acknowledge_alert", "resource_type": "alert", "usage": "write", "description": "Acknowledged an alert", "weight": 10},
        {"action": "run_query", "resource_type": "query", "usage": "read", "description": "Ran a metrics query", "weight": 25},
        {"action": "view_logs", "resource_type": "logs", "usage": "read", "description": "Viewed logs", "weight": 30},
    ],
    "PagerDuty": [
        {"action": "acknowledge_incident", "resource_type": "incident", "usage": "write", "description": "Acknowledged an incident", "weight": 20},
        {"action": "resolve_incident", "resource_type": "incident", "usage": "write", "description": "Resolved an incident", "weight": 15},
        {"action": "trigger_incident", "resource_type": "incident", "usage": "write", "description": "Triggered an incident", "weight": 5},
        {"action": "update_schedule", "resource_type": "schedule", "usage": "admin", "description": "Updated on-call schedule", "weight": 1},
        {"action": "view_incidents", "resource_type": "incident", "usage": "read", "description": "Viewed incidents", "weight": 35},
    ],
    "Splunk": [
        {"action": "run_search", "resource_type": "search", "usage": "read", "description": "Ran a search query", "weight": 35},
        {"action": "view_dashboard", "resource_type": "dashboard", "usage": "read", "description": "Viewed a dashboard", "weight": 30},
        {"action": "create_alert", "resource_type": "alert", "usage": "admin", "description": "Created an alert", "weight": 1},
        {"action": "export_results", "resource_type": "export", "usage": "read", "description": "Exported search results", "weight": 15},
    ],

    # ── Signing / Documents ────────────────────────────────────────────
    "DocuSign": [
        {"action": "send_envelope", "resource_type": "envelope", "usage": "write", "description": "Sent a document for signature", "weight": 15},
        {"action": "sign_document", "resource_type": "document", "usage": "write", "description": "Signed a document", "weight": 25},
        {"action": "view_envelope", "resource_type": "envelope", "usage": "read", "description": "Viewed envelope status", "weight": 35},
        {"action": "void_envelope", "resource_type": "envelope", "usage": "admin", "description": "Voided an envelope", "weight": 1},
    ],
}

_DEFAULT_ACTIONS = [
    {"action": "view_resource", "resource_type": "resource", "usage": "read", "description": "Viewed a resource", "weight": 35},
    {"action": "create_resource", "resource_type": "resource", "usage": "write", "description": "Created a resource", "weight": 15},
    {"action": "update_resource", "resource_type": "resource", "usage": "write", "description": "Updated a resource", "weight": 15},
    {"action": "delete_resource", "resource_type": "resource", "usage": "admin", "description": "Deleted a resource", "weight": 1},
    {"action": "export_data", "resource_type": "export", "usage": "read", "description": "Exported data", "weight": 20},
]

# Resource name templates by resource type
_RESOURCE_NAME_TEMPLATES = {
    "document": ["Q{q} Report", "Meeting Notes", "Project Plan", "Analysis Document", "Review Doc"],
    "spreadsheet": ["Budget {year}", "Metrics Dashboard", "Data Export", "Tracking Sheet", "Analysis"],
    "message": ["Team update", "Quick question", "FYI", "Follow-up", "Status check"],
    "channel": ["#project-{topic}", "#team-{dept}", "#general", "#announcements", "#random"],
    "issue": ["{prefix}-{num}", "Bug: {topic}", "Feature: {topic}", "Task: {topic}"],
    "pull_request": ["feat: {topic}", "fix: {topic}", "chore: update {topic}", "refactor: {topic}"],
    "ticket": ["TICKET-{num}", "Case #{num}", "Support request: {topic}"],
    "dashboard": ["{dept} Dashboard", "KPI Overview", "Executive Summary", "Metrics View"],
    "report": ["{dept} Report", "Weekly Summary", "Monthly Analysis", "Quarterly Review"],
    "default": ["Resource {num}", "Item {num}", "Record {num}"],
}

_TOPICS = [
    "authentication", "payments", "onboarding", "api", "performance",
    "security", "compliance", "migration", "integration", "analytics",
]

_DEPARTMENTS = ["Engineering", "Sales", "Marketing", "HR", "Finance", "IT", "Operations", "Product"]

# ── Frequency tiers ────────────────────────────────────────────────────


@dataclass
class FrequencyTier:
    """Per-category session parameters."""
    sessions_per_day_mean: float
    sessions_per_day_std: float
    session_size_min: int
    session_size_max: int
    session_size_alpha: float   # Zipf alpha for session size sampling
    intra_gap_mu: float         # log-normal mu for intra-session gaps (seconds)
    intra_gap_sigma: float


# App → category mapping
_APP_CATEGORY: Dict[str, str] = {
    "Slack": "COMMUNICATION", "Microsoft Teams": "COMMUNICATION",
    "Zoom": "MEETING",
    "Google Workspace": "PRODUCTIVITY", "Microsoft 365": "PRODUCTIVITY",
    "Jira": "PROJECT_MGMT", "Confluence": "PROJECT_MGMT", "Asana": "PROJECT_MGMT",
    "Trello": "PROJECT_MGMT", "Notion": "PROJECT_MGMT",
    "GitHub": "SOURCE_CONTROL", "GitLab": "SOURCE_CONTROL", "Bitbucket": "SOURCE_CONTROL",
    "Salesforce": "CRM", "HubSpot": "CRM",
    "Snowflake": "DATA_BI", "Tableau": "DATA_BI", "Power BI": "DATA_BI",
    "Zendesk": "SUPPORT", "ServiceNow": "SUPPORT", "Freshdesk": "SUPPORT",
    "Okta": "IDENTITY", "1Password": "IDENTITY",
    "Figma": "DESIGN", "Canva": "DESIGN",
    "Workday": "HR", "BambooHR": "HR",
    "QuickBooks": "FINANCE", "NetSuite": "FINANCE", "Expensify": "FINANCE", "Concur": "FINANCE",
    "Dropbox": "FILE_STORAGE", "Box": "FILE_STORAGE",
    "Datadog": "MONITORING", "PagerDuty": "MONITORING", "Splunk": "MONITORING",
    "DocuSign": "SIGNING",
}

_CATEGORY_TIERS: Dict[str, FrequencyTier] = {
    "COMMUNICATION": FrequencyTier(5.0, 1.5, 2, 8,  1.3, 3.5, 0.8),
    "MEETING":       FrequencyTier(1.5, 0.8, 3, 7,  1.5, 5.5, 0.7),
    "PRODUCTIVITY":  FrequencyTier(3.0, 1.0, 3, 10, 1.3, 4.0, 0.9),
    "PROJECT_MGMT":  FrequencyTier(2.5, 1.0, 3, 12, 1.3, 4.0, 0.9),
    "SOURCE_CONTROL": FrequencyTier(2.0, 0.8, 4, 15, 1.2, 4.5, 0.9),
    "CRM":           FrequencyTier(1.5, 0.7, 3, 8,  1.3, 3.8, 0.8),
    "DATA_BI":       FrequencyTier(1.0, 0.5, 2, 8,  1.3, 4.1, 0.9),
    "SUPPORT":       FrequencyTier(1.5, 0.7, 3, 8,  1.3, 3.7, 0.8),
    "IDENTITY":      FrequencyTier(2.0, 0.8, 1, 2,  1.5, 2.0, 0.6),
    "DESIGN":        FrequencyTier(1.0, 0.5, 5, 15, 1.2, 4.4, 0.9),
    "HR":            FrequencyTier(0.2, 0.1, 2, 5,  1.5, 3.4, 0.8),
    "FINANCE":       FrequencyTier(0.3, 0.15, 2, 5, 1.5, 3.4, 0.8),
    "FILE_STORAGE":  FrequencyTier(1.0, 0.5, 2, 6,  1.4, 3.7, 0.8),
    "MONITORING":    FrequencyTier(1.5, 0.7, 2, 8,  1.3, 3.9, 0.9),
    "SIGNING":       FrequencyTier(0.15, 0.08, 1, 3, 1.5, 3.0, 0.7),
}

# ── Department → app affinity multipliers ──────────────────────────────

_DEPT_APP_AFFINITY: Dict[str, Dict[str, float]] = {
    "Engineering":      {"GitHub": 3.0, "GitLab": 2.5, "Bitbucket": 2.0, "Jira": 2.0, "Confluence": 1.5, "Datadog": 2.0, "PagerDuty": 1.5},
    "Sales":            {"Salesforce": 3.0, "HubSpot": 2.0, "DocuSign": 2.0, "Zoom": 1.5},
    "Marketing":        {"HubSpot": 2.0, "Canva": 2.5, "Figma": 1.5},
    "HR":               {"Workday": 3.0, "BambooHR": 2.5, "DocuSign": 1.5},
    "Finance":          {"QuickBooks": 3.0, "NetSuite": 2.5, "Expensify": 2.0, "Concur": 2.0},
    "IT":               {"Okta": 2.5, "1Password": 2.0, "ServiceNow": 2.0},
    "Product":          {"Jira": 2.5, "Figma": 2.0, "Confluence": 2.0},
    "Design":           {"Figma": 3.0, "Canva": 2.5},
    "Data Science":     {"Snowflake": 2.5, "Tableau": 2.0, "Power BI": 1.5, "GitHub": 1.5},
    "Customer Success": {"Zendesk": 2.5, "Freshdesk": 2.0, "Salesforce": 1.5},
    "Operations":       {"ServiceNow": 2.0, "Jira": 1.5},
    "Security":         {"Splunk": 2.5, "Okta": 2.0, "1Password": 1.5, "Datadog": 1.5},
    "Infrastructure":   {"Datadog": 2.0, "PagerDuty": 2.0},
    "Legal":            {"DocuSign": 2.0},
    "Executive":        {"Zoom": 1.5},
}

# ── Role-based action gating ──────────────────────────────────────────

_ROLE_TIER_MAP: Dict[str, str] = {
    "admin": "admin", "administrator": "admin", "owner": "admin",
    "operator": "operator", "user": "operator", "member": "operator",
    "editor": "operator", "contributor": "operator", "developer": "operator",
    "reader": "reader", "viewer": "reader", "readonly": "reader", "read-only": "reader",
}

_ROLE_ALLOWED_USAGE: Dict[str, set] = {
    "admin":    {"read", "write", "admin"},
    "operator": {"read", "write"},
    "reader":   {"read"},
}

# Centrality ranking for Zipf weighting (lower rank → higher weight)
_APP_CENTRALITY_RANK: Dict[str, int] = {
    "Okta": 1, "Google Workspace": 2, "Slack": 3, "Microsoft 365": 4,
    "Microsoft Teams": 5, "Jira": 6, "GitHub": 7, "Zoom": 8,
    "Confluence": 9, "Salesforce": 10, "1Password": 11,
}


# ═══════════════════════════════════════════════════════════════════════════
# Layer 2: Session-Based Generation with Markov Transitions
# ═══════════════════════════════════════════════════════════════════════════

# Markov transition matrices per category.
# Maps current_action → {next_action: probability}.
# Actions not in the matrix fall back to marginal weighted sampling.
_MARKOV_TRANSITIONS: Dict[str, Dict[str, Dict[str, float]]] = {
    "COMMUNICATION": {
        "view_channel":       {"send_message": 0.40, "send_direct_message": 0.15, "add_reaction": 0.10, "view_channel": 0.15, "search_messages": 0.10, "upload_file": 0.05, "start_huddle": 0.05},
        "send_message":       {"view_channel": 0.25, "send_message": 0.20, "add_reaction": 0.15, "send_direct_message": 0.15, "upload_file": 0.10, "search_messages": 0.05, "start_huddle": 0.05, "view_files": 0.05},
        "send_direct_message": {"send_direct_message": 0.25, "view_channel": 0.25, "send_message": 0.20, "upload_file": 0.10, "add_reaction": 0.10, "search_messages": 0.10},
        "add_reaction":       {"view_channel": 0.35, "send_message": 0.30, "send_direct_message": 0.15, "search_messages": 0.10, "add_reaction": 0.05, "upload_file": 0.05},
        "search_messages":    {"view_channel": 0.35, "send_message": 0.25, "send_direct_message": 0.15, "search_messages": 0.10, "add_reaction": 0.10, "upload_file": 0.05},
    },
    "SOURCE_CONTROL": {
        "view_repository":     {"push_commit": 0.20, "create_branch": 0.15, "view_repository": 0.15, "create_pull_request": 0.10, "create_issue": 0.10, "clone_repository": 0.15, "review_pull_request": 0.15},
        "push_commit":         {"create_pull_request": 0.35, "push_commit": 0.20, "view_repository": 0.20, "create_branch": 0.10, "create_issue": 0.10, "merge_pull_request": 0.05},
        "create_pull_request": {"review_pull_request": 0.35, "view_repository": 0.25, "push_commit": 0.15, "merge_pull_request": 0.15, "create_issue": 0.05, "create_pull_request": 0.05},
        "review_pull_request": {"merge_pull_request": 0.30, "view_repository": 0.25, "push_commit": 0.15, "create_pull_request": 0.10, "review_pull_request": 0.10, "create_issue": 0.10},
        "merge_pull_request":  {"view_repository": 0.35, "push_commit": 0.20, "create_branch": 0.15, "create_issue": 0.15, "close_issue": 0.15},
        "create_branch":       {"push_commit": 0.50, "view_repository": 0.30, "create_issue": 0.15, "create_branch": 0.05},
        "create_issue":        {"view_repository": 0.25, "push_commit": 0.20, "create_branch": 0.15, "close_issue": 0.10, "create_issue": 0.10, "create_pull_request": 0.10, "review_pull_request": 0.10},
    },
    "PROJECT_MGMT": {
        "view_board":       {"view_issue": 0.35, "create_issue": 0.15, "view_board": 0.10, "view_page": 0.15, "search_content": 0.10, "create_task": 0.10, "view_project": 0.05},
        "view_issue":       {"update_issue": 0.25, "add_comment": 0.25, "transition_issue": 0.15, "assign_issue": 0.10, "view_board": 0.15, "view_issue": 0.10},
        "update_issue":     {"add_comment": 0.25, "transition_issue": 0.20, "view_board": 0.20, "view_issue": 0.15, "assign_issue": 0.10, "update_issue": 0.10},
        "add_comment":      {"view_board": 0.20, "view_issue": 0.20, "update_issue": 0.15, "transition_issue": 0.15, "add_comment": 0.10, "assign_issue": 0.10, "create_issue": 0.10},
        "transition_issue": {"view_board": 0.30, "view_issue": 0.25, "add_comment": 0.20, "create_issue": 0.10, "update_issue": 0.10, "transition_issue": 0.05},
        "create_issue":     {"update_issue": 0.20, "assign_issue": 0.20, "add_comment": 0.15, "view_board": 0.20, "view_issue": 0.20, "create_issue": 0.05},
        "view_page":        {"edit_page": 0.30, "view_page": 0.15, "add_comment": 0.15, "search_content": 0.15, "create_page": 0.10, "view_board": 0.15},
        "edit_page":        {"view_page": 0.30, "add_comment": 0.20, "edit_page": 0.15, "view_board": 0.15, "create_page": 0.10, "share_page": 0.10},
    },
    "CRM": {
        "view_record":        {"update_opportunity": 0.20, "log_call": 0.15, "send_email": 0.15, "view_dashboard": 0.15, "view_record": 0.10, "run_report": 0.10, "create_lead": 0.10, "view_contact": 0.05},
        "update_opportunity": {"log_call": 0.20, "send_email": 0.20, "view_record": 0.20, "view_dashboard": 0.15, "update_opportunity": 0.10, "create_lead": 0.05, "run_report": 0.10},
        "log_call":           {"send_email": 0.25, "update_opportunity": 0.20, "view_record": 0.20, "log_call": 0.10, "view_dashboard": 0.10, "create_lead": 0.05, "log_activity": 0.10},
        "send_email":         {"view_record": 0.25, "log_call": 0.15, "update_opportunity": 0.15, "view_dashboard": 0.15, "send_email": 0.10, "create_lead": 0.10, "update_deal": 0.10},
        "view_dashboard":     {"view_record": 0.30, "run_report": 0.25, "update_opportunity": 0.15, "view_dashboard": 0.10, "log_call": 0.10, "send_email": 0.10},
        "run_report":         {"view_dashboard": 0.30, "view_record": 0.25, "run_report": 0.10, "update_opportunity": 0.15, "send_email": 0.10, "export_data": 0.10},
    },
    "PRODUCTIVITY": {
        "view_document":    {"edit_document": 0.35, "view_document": 0.10, "view_calendar": 0.10, "send_email": 0.15, "share_file": 0.05, "create_document": 0.05, "view_inbox": 0.10, "edit_spreadsheet": 0.10},
        "edit_document":    {"view_document": 0.25, "edit_document": 0.20, "send_email": 0.15, "share_file": 0.05, "view_calendar": 0.10, "create_document": 0.05, "edit_spreadsheet": 0.10, "upload_file": 0.10},
        "send_email":       {"view_inbox": 0.25, "view_document": 0.15, "edit_document": 0.10, "send_email": 0.15, "view_calendar": 0.10, "create_calendar_event": 0.10, "create_document": 0.05, "edit_spreadsheet": 0.10},
        "view_calendar":    {"create_calendar_event": 0.25, "view_document": 0.15, "send_email": 0.15, "view_calendar": 0.10, "edit_document": 0.10, "view_inbox": 0.15, "edit_spreadsheet": 0.10},
        "view_inbox":       {"send_email": 0.30, "view_document": 0.15, "edit_document": 0.10, "view_inbox": 0.10, "view_calendar": 0.15, "create_document": 0.10, "edit_spreadsheet": 0.10},
        "edit_spreadsheet": {"view_document": 0.15, "edit_spreadsheet": 0.20, "send_email": 0.15, "edit_document": 0.10, "create_spreadsheet": 0.05, "share_file": 0.05, "view_calendar": 0.10, "upload_file": 0.10, "export_data": 0.10},
    },
    "MONITORING": {
        "view_dashboard":       {"run_query": 0.20, "view_logs": 0.20, "view_dashboard": 0.10, "acknowledge_alert": 0.10, "view_incidents": 0.10, "run_search": 0.15, "export_results": 0.05, "acknowledge_incident": 0.10},
        "view_logs":            {"view_dashboard": 0.25, "run_query": 0.20, "view_logs": 0.15, "run_search": 0.15, "acknowledge_alert": 0.10, "export_results": 0.05, "view_incidents": 0.10},
        "run_query":            {"view_dashboard": 0.25, "view_logs": 0.20, "run_query": 0.10, "export_results": 0.15, "run_search": 0.15, "acknowledge_alert": 0.10, "view_incidents": 0.05},
        "acknowledge_alert":    {"view_dashboard": 0.25, "view_logs": 0.20, "run_query": 0.15, "acknowledge_incident": 0.15, "resolve_incident": 0.10, "view_incidents": 0.15},
        "view_incidents":       {"acknowledge_incident": 0.25, "view_dashboard": 0.20, "view_incidents": 0.10, "resolve_incident": 0.15, "view_logs": 0.15, "run_query": 0.15},
        "acknowledge_incident": {"resolve_incident": 0.30, "view_dashboard": 0.20, "view_logs": 0.15, "run_query": 0.15, "view_incidents": 0.10, "acknowledge_incident": 0.10},
        "resolve_incident":     {"view_dashboard": 0.30, "view_incidents": 0.20, "view_logs": 0.15, "run_query": 0.10, "run_search": 0.10, "acknowledge_incident": 0.10, "resolve_incident": 0.05},
    },
    "SUPPORT": {
        "view_ticket":    {"update_ticket": 0.25, "add_comment": 0.20, "view_ticket": 0.10, "assign_ticket": 0.10, "resolve_ticket": 0.10, "create_ticket": 0.10, "reply_ticket": 0.15},
        "update_ticket":  {"add_comment": 0.25, "view_ticket": 0.20, "resolve_ticket": 0.15, "assign_ticket": 0.10, "update_ticket": 0.10, "reply_ticket": 0.10, "update_incident": 0.10},
        "create_ticket":  {"update_ticket": 0.25, "add_comment": 0.20, "assign_ticket": 0.15, "view_ticket": 0.20, "create_ticket": 0.05, "create_incident": 0.05, "reply_ticket": 0.10},
        "add_comment":    {"view_ticket": 0.25, "update_ticket": 0.20, "resolve_ticket": 0.15, "add_comment": 0.10, "assign_ticket": 0.10, "reply_ticket": 0.10, "close_ticket": 0.10},
        "resolve_ticket": {"view_ticket": 0.35, "create_ticket": 0.15, "add_comment": 0.15, "update_ticket": 0.10, "resolve_ticket": 0.05, "resolve_incident": 0.10, "close_ticket": 0.10},
    },
}


@dataclass
class AppSession:
    """A planned burst of activity within a single app."""
    app: str
    role: str                            # admin / operator / reader
    category: str                        # _APP_CATEGORY value
    target_size: int                     # events in this session
    workflow_id: Optional[str] = None    # links cross-app workflow steps
    workflow_step: int = 0


# ═══════════════════════════════════════════════════════════════════════════
# Layer 3: Cross-App Workflow Chains
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class WorkflowStep:
    """One step in a cross-app workflow."""
    app: str
    actions: List[str]             # ordered actions for this step
    delay_seconds_mean: float      # delay from previous step completion
    delay_seconds_std: float
    optional: bool = False


@dataclass
class WorkflowTemplate:
    """A reusable cross-app workflow pattern."""
    name: str
    steps: List[WorkflowStep]
    dept_affinity: List[str]       # departments likely to use this
    daily_probability: float       # P(this workflow triggers on a given day)


_WORKFLOW_TEMPLATES: List[WorkflowTemplate] = [
    WorkflowTemplate(
        name="meeting_notes",
        steps=[
            WorkflowStep("Zoom", ["join_meeting", "send_chat"], 0, 0),
            WorkflowStep("Google Workspace", ["create_document", "edit_document"], 120, 60),
            WorkflowStep("Slack", ["send_message"], 180, 60),
        ],
        dept_affinity=["Engineering", "Product", "Sales", "Marketing", "HR", "Finance", "IT", "Operations", "Executive"],
        daily_probability=0.25,
    ),
    WorkflowTemplate(
        name="code_review",
        steps=[
            WorkflowStep("GitHub", ["create_pull_request"], 0, 0),
            WorkflowStep("Slack", ["send_message"], 60, 30),
            WorkflowStep("Jira", ["transition_issue"], 300, 120),
        ],
        dept_affinity=["Engineering"],
        daily_probability=0.35,
    ),
    WorkflowTemplate(
        name="incident_response",
        steps=[
            WorkflowStep("PagerDuty", ["acknowledge_incident"], 0, 0),
            WorkflowStep("Datadog", ["view_dashboard", "run_query"], 60, 30),
            WorkflowStep("Slack", ["send_message"], 120, 60),
            WorkflowStep("Jira", ["create_issue"], 300, 120),
        ],
        dept_affinity=["Engineering", "IT", "Infrastructure", "Security"],
        daily_probability=0.10,
    ),
    WorkflowTemplate(
        name="sales_cycle",
        steps=[
            WorkflowStep("Salesforce", ["update_opportunity"], 0, 0),
            WorkflowStep("HubSpot", ["send_email"], 180, 90, optional=True),
            WorkflowStep("DocuSign", ["send_envelope"], 600, 300, optional=True),
        ],
        dept_affinity=["Sales"],
        daily_probability=0.20,
    ),
    WorkflowTemplate(
        name="hr_onboarding",
        steps=[
            WorkflowStep("Workday", ["complete_task"], 0, 0),
            WorkflowStep("Okta", ["request_access"], 300, 120),
            WorkflowStep("Slack", ["join_channel"], 600, 300),
        ],
        dept_affinity=["HR"],
        daily_probability=0.08,
    ),
    WorkflowTemplate(
        name="expense_report",
        steps=[
            WorkflowStep("Expensify", ["submit_expense", "upload_receipt"], 0, 0),
            WorkflowStep("Slack", ["send_message"], 120, 60),
        ],
        dept_affinity=["Engineering", "Sales", "Marketing", "HR", "Finance", "IT", "Operations", "Product", "Executive"],
        daily_probability=0.05,
    ),
    WorkflowTemplate(
        name="design_review",
        steps=[
            WorkflowStep("Figma", ["share_file"], 0, 0),
            WorkflowStep("Slack", ["send_message"], 60, 30),
            WorkflowStep("Confluence", ["create_page"], 300, 120, optional=True),
        ],
        dept_affinity=["Product", "Design", "Marketing"],
        daily_probability=0.12,
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# Layer 4: Per-App Temporal Profiles
# ═══════════════════════════════════════════════════════════════════════════

# Category-specific circadian overrides: {peaks_hours, kappa}
_CATEGORY_CIRCADIAN: Dict[str, Dict[str, Any]] = {
    "COMMUNICATION": {"peaks": [9.5, 11.0, 14.0, 16.0], "kappa": 1.5},
    "MEETING":       {"peaks": [10.0, 14.0, 15.0],       "kappa": 3.0},
    "SOURCE_CONTROL": {"peaks": [10.5, 15.0],            "kappa": 2.5},
    "PROJECT_MGMT":  {"peaks": [10.0, 14.5],             "kappa": 2.0},
    "IDENTITY":      {"peaks": [8.5, 13.0],              "kappa": 3.5},
    "HR":            {"peaks": [9.0],                     "kappa": 2.0},
    "FINANCE":       {"peaks": [9.5],                     "kappa": 2.0},
    "MONITORING":    {"peaks": [9.0, 14.0, 22.0],        "kappa": 2.0},
}

# Category-specific day-of-week weights: Mon(0)…Sun(6)
_CATEGORY_WEEKLY: Dict[str, List[float]] = {
    "HR":           [1.5, 0.9, 0.8, 0.8, 1.2, 0.05, 0.02],
    "FINANCE":      [1.4, 1.0, 0.9, 0.9, 1.3, 0.05, 0.02],
    "PROJECT_MGMT": [1.3, 1.1, 1.1, 1.0, 0.8, 0.10, 0.05],
    "MONITORING":   [1.0, 1.0, 1.0, 1.0, 1.0, 0.40, 0.30],
}


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string (no microseconds)."""
    return dt.replace(tzinfo=timezone.utc, microsecond=0).isoformat().replace("+00:00", "Z")


def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    """Select the appropriate people container (employees or workers)."""
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


def _event_target_kwargs(kind: str, person_id: str) -> Dict[str, Any]:
    """Get the appropriate kwargs for targeting a person."""
    if kind == "worker":
        return {"worker_id": person_id}
    return {"employee_id": person_id}


def _generate_resource_name(resource_type: str, rng: random.Random) -> str:
    """Generate a realistic resource name based on type."""
    templates = _RESOURCE_NAME_TEMPLATES.get(resource_type, _RESOURCE_NAME_TEMPLATES["default"])
    template = rng.choice(templates)
    return template.format(
        q=rng.randint(1, 4),
        year=rng.randint(2024, 2026),
        topic=rng.choice(_TOPICS),
        dept=rng.choice(_DEPARTMENTS),
        prefix=rng.choice(["PROJ", "ENG", "FEAT", "BUG", "TASK"]),
        num=rng.randint(100, 9999),
    )


def _generate_resource_id(resource_type: str, rng: random.Random) -> str:
    """Generate a resource ID."""
    prefixes = {
        "document": "doc", "spreadsheet": "sheet", "message": "msg",
        "channel": "ch", "issue": "issue", "pull_request": "pr",
        "ticket": "tkt", "incident": "inc", "dashboard": "dash",
    }
    prefix = prefixes.get(resource_type, "res")
    return f"{prefix}_{rng.randint(10000, 99999)}"


def _collect_person_app_roles(person: Person) -> Dict[str, str]:
    """Parse authorisations to extract {app: role_tier} mapping.

    Authorisations are stored as "AppName - role" strings.
    Roles are mapped to tiers: admin, operator, reader.
    """
    authorisations = person.get("authorisations") or []
    if not isinstance(authorisations, list):
        return {}
    result: Dict[str, str] = {}
    for auth in authorisations:
        if not isinstance(auth, str) or " - " not in auth:
            continue
        app_name, raw_role = auth.rsplit(" - ", 1)
        app_name = app_name.strip()
        raw_role = raw_role.strip().lower()
        if not app_name:
            continue
        tier = _ROLE_TIER_MAP.get(raw_role, "operator")
        # Keep the highest privilege if multiple authorisations for same app
        existing = result.get(app_name)
        if existing is None:
            result[app_name] = tier
        elif tier == "admin":
            result[app_name] = "admin"
        elif tier == "operator" and existing == "reader":
            result[app_name] = "operator"
    return result


def _filter_actions_for_role(
    actions: List[Dict[str, Any]], role: str,
) -> List[Dict[str, Any]]:
    """Filter actions to those allowed by the role tier."""
    allowed = _ROLE_ALLOWED_USAGE.get(role, {"read", "write"})
    return [a for a in actions if a.get("usage", "read") in allowed]


def _compute_app_weights(
    app_roles: Dict[str, str],
    department: str,
    rng: random.Random,
    company: Optional[Company] = None,
) -> List[Tuple[str, float]]:
    """Compute composite app weights combining Zipf rank, tier frequency, and dept affinity."""
    from .department_categories import get_app_affinity
    if not app_roles:
        return []

    max_known_rank = max(_APP_CENTRALITY_RANK.values()) if _APP_CENTRALITY_RANK else 12
    dept_affinities = get_app_affinity(department, company)

    ranked: List[Tuple[str, int]] = []
    offset = 1
    for app in app_roles:
        if app in _APP_CENTRALITY_RANK:
            ranked.append((app, _APP_CENTRALITY_RANK[app]))
        else:
            ranked.append((app, max_known_rank + offset))
            offset += 1

    ranked.sort(key=lambda x: x[1])

    weights: List[Tuple[str, float]] = []
    for i, (app, _rank) in enumerate(ranked):
        # Zipf component
        zipf_w = 1.0 / ((i + 1) ** 1.2)
        # Category tier sessions/day
        cat = _APP_CATEGORY.get(app, "PRODUCTIVITY")
        tier = _CATEGORY_TIERS.get(cat, _CATEGORY_TIERS["PRODUCTIVITY"])
        tier_w = tier.sessions_per_day_mean
        # Department affinity
        dept_w = dept_affinities.get(app, 1.0)
        weights.append((app, zipf_w * tier_w * dept_w))

    # Normalize
    total = sum(w for _, w in weights)
    if total > 0:
        weights = [(app, w / total) for app, w in weights]
    return weights


def _sample_log_normal_gap(
    rng: random.Random, mu: float = 4.0, sigma: float = 0.9,
) -> float:
    """Sample an intra-session time gap in seconds from a log-normal distribution."""
    return math.exp(rng.gauss(mu, sigma))


def _build_category_circadian(
    base_circadian: CircadianSampler, category: str,
) -> CircadianSampler:
    """Create a category-specific circadian sampler keeping the person's UTC offset."""
    overrides = _CATEGORY_CIRCADIAN.get(category)
    if not overrides:
        return base_circadian
    return CircadianSampler(
        peaks_hours=overrides["peaks"],
        kappa=overrides["kappa"],
        utc_offset=base_circadian.utc_offset,
    )


def _build_category_weekly(
    base_weekly: WeeklyCycleModulator, category: str,
) -> WeeklyCycleModulator:
    """Create a category-specific weekly modulator."""
    overrides = _CATEGORY_WEEKLY.get(category)
    if not overrides:
        return base_weekly
    return WeeklyCycleModulator(weights=overrides)


def _snap_meeting_time(ts: datetime) -> datetime:
    """Snap a timestamp to the nearest half-hour for meeting events."""
    minute = ts.minute
    if minute < 15:
        return ts.replace(minute=0, second=0)
    elif minute < 45:
        return ts.replace(minute=30, second=0)
    else:
        return (ts.replace(minute=0, second=0) + timedelta(hours=1))


def _pick_failure_reason(usage: str, rng: random.Random) -> str:
    """Pick a failure reason conditioned on usage type."""
    if usage == "admin":
        reasons = [("permission_denied", 50), ("validation_error", 30), ("timeout", 20)]
    elif usage == "write":
        reasons = [("rate_limited", 30), ("network_error", 25), ("validation_error", 25), ("timeout", 20)]
    else:
        reasons = [("network_error", 40), ("rate_limited", 30), ("resource_not_found", 20), ("timeout", 10)]
    names, ws = zip(*reasons)
    return rng.choices(list(names), weights=list(ws), k=1)[0]


# ═══════════════════════════════════════════════════════════════════════════
# Session Planning
# ═══════════════════════════════════════════════════════════════════════════

def _plan_sessions(
    target_events: int,
    app_weights: List[Tuple[str, float]],
    app_roles: Dict[str, str],
    rng: random.Random,
) -> List[AppSession]:
    """Distribute target_events into sessions across apps."""
    if target_events <= 0 or not app_weights:
        return []

    total_weight = sum(w for _, w in app_weights)
    if total_weight <= 0:
        return []

    # Allocate events to apps proportionally
    allocations: List[Tuple[str, int]] = []
    allocated = 0
    for i, (app, weight) in enumerate(app_weights):
        if i == len(app_weights) - 1:
            alloc = max(0, target_events - allocated)
        else:
            alloc = round(target_events * weight / total_weight)
        if alloc > 0:
            allocations.append((app, alloc))
            allocated += alloc

    # Divide each app's allocation into sessions
    sessions: List[AppSession] = []
    for app, alloc in allocations:
        cat = _APP_CATEGORY.get(app, "PRODUCTIVITY")
        tier = _CATEGORY_TIERS.get(cat, _CATEGORY_TIERS["PRODUCTIVITY"])
        role = app_roles.get(app, "operator")

        remaining = alloc
        while remaining > 0:
            max_size = min(tier.session_size_max, remaining)
            min_size = min(tier.session_size_min, max_size)
            if min_size >= max_size:
                size = max_size
            else:
                n = max_size - min_size + 1
                sizes = list(range(min_size, max_size + 1))
                ws = [1.0 / ((j + 1) ** tier.session_size_alpha) for j in range(n)]
                size = rng.choices(sizes, weights=ws, k=1)[0]
            sessions.append(AppSession(
                app=app, role=role, category=cat, target_size=size,
            ))
            remaining -= size

    return sessions


# ═══════════════════════════════════════════════════════════════════════════
# Session Event Generation
# ═══════════════════════════════════════════════════════════════════════════

def _get_adjusted_weights(
    actions: List[Dict[str, Any]], utc_hour: float,
) -> List[float]:
    """Get action weights with end-of-day adjustment."""
    weights = []
    for a in actions:
        w = float(a.get("weight", 1.0))
        if utc_hour >= 16.5:
            usage = a.get("usage", "read")
            if usage == "read":
                w *= 2.0
            elif usage in ("write", "admin"):
                w *= 0.5
        weights.append(w)
    return weights


def _pick_markov_action(
    rng: random.Random,
    prev_action: str,
    available: List[Dict[str, Any]],
    category: str,
    utc_hour: float,
) -> Dict[str, Any]:
    """Pick the next action using Markov transitions, with fallback to marginal."""
    transitions = _MARKOV_TRANSITIONS.get(category, {}).get(prev_action)
    if transitions:
        action_name_map = {a["action"]: a for a in available}
        filtered = {
            name: prob
            for name, prob in transitions.items()
            if name in action_name_map
        }
        if filtered:
            names = list(filtered.keys())
            probs = [filtered[n] for n in names]
            chosen_name = rng.choices(names, weights=probs, k=1)[0]
            return action_name_map[chosen_name]

    # Fallback: marginal weighted sampling
    weights = _get_adjusted_weights(available, utc_hour)
    return rng.choices(available, weights=weights, k=1)[0]


def _generate_session_events(
    session: AppSession,
    session_start: datetime,
    rng: random.Random,
    use_format_ts: bool,
) -> List[Dict[str, Any]]:
    """Generate events for a single session."""
    all_actions = _APP_ACTIONS.get(session.app, _DEFAULT_ACTIONS)
    available = _filter_actions_for_role(all_actions, session.role)
    if not available:
        return []

    cat = session.category
    tier = _CATEGORY_TIERS.get(cat, _CATEGORY_TIERS["PRODUCTIVITY"])

    events: List[Dict[str, Any]] = []
    current_ts = session_start
    prev_action_name: Optional[str] = None

    for i in range(session.target_size):
        utc_hour = current_ts.hour + current_ts.minute / 60.0

        # Pick action
        if i == 0 or prev_action_name is None:
            weights = _get_adjusted_weights(available, utc_hour)
            action_info = rng.choices(available, weights=weights, k=1)[0]
        else:
            action_info = _pick_markov_action(
                rng, prev_action_name, available, cat, utc_hour,
            )

        usage = action_info.get("usage", "read")

        # Failure model: usage-conditioned rates
        fail_rate = {"read": 0.005, "write": 0.02, "admin": 0.05}.get(usage, 0.01)
        success = rng.random() >= fail_rate

        resource_type = action_info.get("resource_type", "resource")
        ts_str = format_ts(current_ts) if use_format_ts else _format_ts(current_ts)

        event: Dict[str, Any] = {
            "ts": ts_str,
            "app": session.app,
            "action": action_info["action"],
            "usage": usage,
            "success": success,
            "resource_type": resource_type,
            "resource_id": _generate_resource_id(resource_type, rng),
            "resource_name": _generate_resource_name(resource_type, rng),
            "description": action_info.get("description", "Performed action"),
        }

        if not success:
            event["failure_reason"] = _pick_failure_reason(usage, rng)

        events.append(event)
        prev_action_name = action_info["action"]

        # Advance timestamp within session (strip microseconds for clean output)
        if i < session.target_size - 1:
            gap = _sample_log_normal_gap(rng, tier.intra_gap_mu, tier.intra_gap_sigma)
            current_ts = (current_ts + timedelta(seconds=gap)).replace(microsecond=0)

    return events


# ═══════════════════════════════════════════════════════════════════════════
# Workflow System
# ═══════════════════════════════════════════════════════════════════════════

def _expand_workflow(
    template: WorkflowTemplate,
    app_roles: Dict[str, str],
    rng: random.Random,
) -> List[AppSession]:
    """Expand a workflow template into AppSession objects."""
    workflow_id = f"wf_{rng.randint(10000, 99999)}"
    sessions: List[AppSession] = []

    for step_idx, step in enumerate(template.steps):
        if step.optional and rng.random() < 0.40:
            continue
        if step.app not in app_roles:
            if not step.optional:
                return []  # required app missing — skip entire workflow
            continue

        cat = _APP_CATEGORY.get(step.app, "PRODUCTIVITY")
        role = app_roles[step.app]
        sessions.append(AppSession(
            app=step.app,
            role=role,
            category=cat,
            target_size=len(step.actions),
            workflow_id=workflow_id,
            workflow_step=step_idx,
        ))

    return sessions


def _select_and_expand_workflows(
    person: Person,
    app_roles: Dict[str, str],
    target_events: int,
    rng: random.Random,
    company: Optional[Company] = None,
) -> Tuple[List[AppSession], int]:
    """Select and expand workflows for a person, returning (sessions, events_used)."""
    from .department_categories import get_workflow_affinity
    workflow_budget = int(target_events * rng.uniform(0.20, 0.30))
    if workflow_budget <= 0:
        return [], 0

    department = person.get("department", "")

    # Filter to eligible workflows
    eligible: List[Tuple[WorkflowTemplate, float]] = []
    for tmpl in _WORKFLOW_TEMPLATES:
        required_apps = [s.app for s in tmpl.steps if not s.optional]
        if not all(app in app_roles for app in required_apps):
            continue
        affinity = get_workflow_affinity(tmpl.name, department, company)
        weight = tmpl.daily_probability * affinity
        eligible.append((tmpl, weight))

    if not eligible:
        return [], 0

    sessions: List[AppSession] = []
    events_used = 0

    # Try to fill the workflow budget
    attempts = 0
    while events_used < workflow_budget and eligible and attempts < 20:
        attempts += 1
        templates_list, weights_list = zip(*eligible)
        chosen = rng.choices(list(templates_list), weights=list(weights_list), k=1)[0]
        expanded = _expand_workflow(chosen, app_roles, rng)
        if not expanded:
            continue
        events_in_wf = sum(s.target_size for s in expanded)
        if events_used + events_in_wf > workflow_budget * 1.5:
            break
        sessions.extend(expanded)
        events_used += events_in_wf

    return sessions, events_used


# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def generate_app_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = True,
    events_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    failure_rate: float = 0.02,
    generation_config: Optional[Dict[str, Any]] = None,
    burst_schedule: Optional[BurstSchedule] = None,
) -> Dict[str, int]:
    """
    Populate each person's recent_activity.app_events with realistic in-app
    activity events using session-based generation, Markov transitions,
    cross-app workflows, and per-category temporal profiles.

    Args:
        company: Company data dict
        seed: Base seed for deterministic generation
        replace_existing: If True, replace existing app events; if False, append
        events_multiplier: Multiplier for baseline app event rate (1.0 = normal)
        failure_rate: Legacy param (failure rates are now usage-conditioned)
        generation_config: Temporal model config dict
        burst_schedule: Optional burst schedule for scaling event counts

    Returns:
        Statistics dict with counts of generated events
    """
    people, container_kind = _select_people_container(company)

    stats: Dict[str, Any] = {
        "employees_total": len(people),
        "employees_with_events": 0,
        "employees_with_apps": 0,
        "events_requested": 0,
        "events_added": 0,
        "successful_events": 0,
        "failed_events": 0,
        "apps_used": defaultdict(int),
        "actions_by_type": defaultdict(int),
        "usage_by_type": defaultdict(int),
        "sessions_generated": 0,
        "workflow_sessions": 0,
    }

    gen_cfg = generation_config or company.get("_generation_config") or {}

    if not people or events_multiplier == 0:
        return _finalize_stats(stats)

    # Pre-compute window for temporal model
    window_start = window_end = None
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)
    if not window_start or not window_end:
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(days=30)

    use_format_ts = bool(gen_cfg)
    base_seed = seed or 0
    requested_total = 0

    for idx_person, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        # 1. Collect app roles
        app_roles = _collect_person_app_roles(person)
        if not app_roles:
            continue

        stats["employees_with_apps"] += 1

        ra = person.setdefault("recent_activity", {})
        if replace_existing:
            ra.pop("app_events", None)

        rng = random.Random(base_seed * 1013 + idx_person)

        # 2. Resolve event count from baselines, scaled by multiplier
        if gen_cfg:
            target_events = resolve_event_count(
                person, "app", _DEFAULT_APP_EVENTS, rng,
                scale_factor=events_multiplier,
                baseline_std_scale=baseline_std_scale,
            )
        else:
            target_events = max(0, round(vary_count(_DEFAULT_APP_EVENTS, rng) * events_multiplier))

        if not replace_existing:
            existing_events = ra.get("app_events")
            existing_count = len(existing_events) if isinstance(existing_events, list) else 0
            target_events = max(target_events - existing_count, 0)

        if target_events <= 0:
            continue

        # 3. Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_events = apply_burst_to_count(
                target_events, person_id, "app_events",
                burst_schedule, rng, window_start, window_end,
            )

        if target_events <= 0:
            continue

        # 4. Compute app weights
        department = person.get("department", "")
        app_weights = _compute_app_weights(app_roles, department, rng, company)
        if not app_weights:
            continue

        # 5. Build temporal samplers
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        requested_total += target_events

        # 6-7. Plan workflow sessions
        workflow_sessions, workflow_events = _select_and_expand_workflows(
            person, app_roles, target_events, rng, company,
        )

        # 8-9. Plan independent sessions for remaining budget
        remaining_budget = max(0, target_events - workflow_events)
        independent_sessions = _plan_sessions(
            remaining_budget, app_weights, app_roles, rng,
        )

        # 10. Merge all sessions
        all_sessions = workflow_sessions + independent_sessions
        if not all_sessions:
            continue

        stats["workflow_sessions"] += len(workflow_sessions)

        # 11. Generate events for each session
        events_for_person = 0
        # Track workflow step timing for chained workflows
        workflow_end_times: Dict[str, datetime] = {}

        for session in all_sessions:
            # a. Build category-specific temporal samplers
            if circadian:
                cat_circadian = _build_category_circadian(circadian, session.category)
            else:
                cat_circadian = None
            if weekly:
                cat_weekly = _build_category_weekly(weekly, session.category)
            else:
                cat_weekly = None

            # b. Sample session start time
            if cat_circadian and cat_weekly and window_start and window_end:
                session_start = sample_timestamp(
                    cat_circadian, cat_weekly, rng, window_start, window_end,
                )
            else:
                days_back = rng.randint(0, 29)
                hour = rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])
                session_start = datetime.now(timezone.utc) - timedelta(days=days_back)
                session_start = session_start.replace(
                    hour=hour, minute=rng.randint(0, 59),
                    second=rng.randint(0, 59), microsecond=0,
                )

            # c. Adjust workflow chain timing
            if session.workflow_id and session.workflow_step > 0:
                prev_end = workflow_end_times.get(session.workflow_id)
                if prev_end:
                    # Find the matching step to get delay parameters
                    for tmpl in _WORKFLOW_TEMPLATES:
                        steps_match = [
                            s for s in tmpl.steps
                            if s.app == session.app
                        ]
                        if steps_match:
                            step = steps_match[0]
                            delay = max(0, rng.gauss(step.delay_seconds_mean, step.delay_seconds_std))
                            session_start = (prev_end + timedelta(seconds=delay)).replace(microsecond=0)
                            break

            # d. Meeting snap-to-half-hour
            if session.category == "MEETING":
                session_start = _snap_meeting_time(session_start)

            # e. Generate events
            events = _generate_session_events(
                session, session_start, rng, use_format_ts,
            )

            # Track workflow end time
            if session.workflow_id and events:
                # Approximate session end as start + (n_events * median gap)
                tier = _CATEGORY_TIERS.get(session.category, _CATEGORY_TIERS["PRODUCTIVITY"])
                total_gap = sum(
                    _sample_log_normal_gap(rng, tier.intra_gap_mu, tier.intra_gap_sigma)
                    for _ in range(max(0, len(events) - 1))
                )
                workflow_end_times[session.workflow_id] = (
                    session_start + timedelta(seconds=total_gap)
                ).replace(microsecond=0)

            # f. Store events and update stats
            for event in events:
                add_app_event_logs(
                    company,
                    **_event_target_kwargs(container_kind, person_id),
                    log=event,
                )
                stats["events_added"] += 1
                stats["apps_used"][event["app"]] += 1
                stats["actions_by_type"][event["action"]] += 1
                stats["usage_by_type"][event["usage"]] += 1
                if event.get("success", True):
                    stats["successful_events"] += 1
                else:
                    stats["failed_events"] += 1
                events_for_person += 1

            stats["sessions_generated"] += 1

        if events_for_person:
            stats["employees_with_events"] += 1

    stats["events_requested"] = requested_total
    return _finalize_stats(stats)


def _finalize_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Convert defaultdicts to regular dicts for serialisation."""
    for key in ("apps_used", "actions_by_type", "usage_by_type"):
        if isinstance(stats.get(key), defaultdict):
            stats[key] = dict(stats[key])
    return stats
