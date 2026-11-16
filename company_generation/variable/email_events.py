from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .user_activity import add_email_event_logs, vary_count
from .temporal_model import (
    format_ts,
    get_window,
    resolve_event_count,
    resolve_person_temporal,
    sample_timestamp,
)
from .episodic_bursts import BurstSchedule, apply_burst_to_count

Person = Dict[str, Any]
Company = Dict[str, Any]

_LONG_TAIL_ALPHA = 1.35
_DEFAULT_EMAIL_EVENTS = 8

# Email subject templates by department context
_SUBJECT_TEMPLATES = {
    "Engineering": [
        "Code review request: {topic}",
        "Sprint planning notes",
        "Bug report: {topic}",
        "Architecture discussion: {topic}",
        "Deployment update for {topic}",
        "Technical spec review needed",
        "Testing results for {topic}",
    ],
    "Sales": [
        "Follow-up: {topic} meeting",
        "Proposal for {topic}",
        "Q{quarter} pipeline update",
        "Client feedback on {topic}",
        "Deal status: {topic}",
        "Pricing discussion",
        "Contract review needed",
    ],
    "HR": [
        "Interview feedback: {topic}",
        "Onboarding checklist",
        "Benefits enrollment reminder",
        "Performance review schedule",
        "Team training: {topic}",
        "Policy update notification",
        "Hiring update for {topic} role",
    ],
    "Finance": [
        "Budget review: {topic}",
        "Expense report approval",
        "Q{quarter} financial summary",
        "Invoice processing: {topic}",
        "Audit preparation",
        "Payment confirmation",
        "Forecast update",
    ],
    "IT": [
        "System maintenance notice",
        "Security update: {topic}",
        "Access request: {topic}",
        "IT ticket resolved: {topic}",
        "Software license renewal",
        "Network upgrade announcement",
        "Password reset required",
    ],
    "Marketing": [
        "Campaign results: {topic}",
        "Brand guidelines update",
        "Content review: {topic}",
        "Event planning: {topic}",
        "Social media metrics",
        "Press release draft",
        "Marketing materials ready",
    ],
    "Operations": [
        "Process improvement: {topic}",
        "Inventory update",
        "Logistics coordination: {topic}",
        "Quality report: {topic}",
        "Vendor communication",
        "Operational metrics review",
        "Facility update",
    ],
    "Customer service": [
        "Customer feedback summary",
        "Support ticket escalation: {topic}",
        "SLA review",
        "Training session notes",
        "Customer success update: {topic}",
        "Issue resolution: {topic}",
        "NPS scores review",
    ],
    "default": [
        "Weekly sync notes",
        "Project update: {topic}",
        "Meeting follow-up",
        "Quick question about {topic}",
        "FYI: {topic}",
        "Action items from meeting",
        "Status update",
    ],
}

# Content templates for email body descriptions
_CONTENT_TEMPLATES = {
    "Engineering": [
        "This email discusses the technical implementation details for {topic}. Key points include the proposed architecture changes and timeline estimates.",
        "Summary of code review findings for the {topic} feature. Several optimizations were suggested that could improve performance.",
        "Update on the deployment status. All tests passed and the release is scheduled for next week.",
        "Discussion about the bug reported in {topic}. Root cause analysis is attached along with proposed fixes.",
    ],
    "Sales": [
        "Follow-up from our meeting regarding {topic}. Attached is the proposal with pricing details as discussed.",
        "Pipeline update for this quarter. Key opportunities and their current status are summarized below.",
        "Client feedback on the {topic} demo was positive. They requested additional information about enterprise features.",
        "Contract terms have been reviewed by legal. Please see attached redlined version with our proposed changes.",
    ],
    "HR": [
        "Interview feedback for the {topic} candidate. Overall impressions were favorable and we recommend moving forward.",
        "Reminder about upcoming benefits enrollment deadline. Please review the attached summary of changes.",
        "Performance review documentation for this cycle. Managers should complete evaluations by end of month.",
        "Training schedule for {topic} has been finalized. Please confirm your attendance.",
    ],
    "Finance": [
        "Q{quarter} budget review summary. Key variances and action items are highlighted in the attached report.",
        "Expense reports pending approval are attached. Please review and approve or reject by Friday.",
        "Invoice processing status for {topic}. Payment is scheduled for next week pending final approval.",
        "Audit preparation materials requested. Please provide the documentation listed in the attachment.",
    ],
    "IT": [
        "Scheduled maintenance window for {topic} systems this weekend. Expected downtime is 2-4 hours.",
        "Security alert regarding {topic}. Please update your password and enable MFA if not already done.",
        "Access request for {topic} has been approved. Credentials are provided in the secure attachment.",
        "IT ticket #{topic} has been resolved. Please confirm the issue is fixed and close the ticket.",
    ],
    "Marketing": [
        "Campaign performance report for {topic} is attached. Key metrics exceeded targets by 15%.",
        "Content review needed for {topic} materials. Please provide feedback by end of week.",
        "Event planning update for {topic}. Venue is confirmed and speaker lineup is attached.",
        "Brand guidelines have been updated. Please review attached document for the latest standards.",
    ],
    "Operations": [
        "Process improvement recommendations for {topic}. Implementation would reduce cycle time by 20%.",
        "Inventory levels update. Some items are approaching reorder thresholds and require attention.",
        "Logistics coordination for {topic} shipment. Tracking information and delivery ETA are attached.",
        "Quality metrics for {topic} are attached. Overall scores improved compared to last period.",
    ],
    "Customer service": [
        "Customer feedback summary for {topic}. Common themes and suggested improvements are outlined.",
        "Escalated support ticket for {topic}. Customer is awaiting response and this is marked urgent.",
        "SLA performance review attached. Most metrics are within targets with a few exceptions noted.",
        "Customer success update for {topic} account. Renewal discussion is scheduled for next month.",
    ],
    "default": [
        "This email provides an update on {topic}. Please review the attached materials and let me know if you have questions.",
        "Follow-up from our recent discussion about {topic}. Action items are summarized below.",
        "Quick update on the status of {topic}. Everything is on track for the planned timeline.",
        "FYI - sharing information about {topic} that may be relevant to your current projects.",
    ],
}

# Topics for subject/content templating
_TOPICS = [
    "Q4 roadmap", "customer portal", "mobile app", "API integration",
    "security audit", "compliance review", "vendor contract", "team expansion",
    "product launch", "migration project", "cost optimization", "partner program",
    "analytics dashboard", "user feedback", "performance tuning", "infrastructure upgrade",
]

# External domains for external emails
_EXTERNAL_DOMAINS = [
    "partner.example.com", "vendor.example.net", "client.example.org",
    "consultant.example.com", "agency.example.net", "supplier.example.org",
]

# Benign URL templates for normal emails (categorised by type)
_BENIGN_URL_TEMPLATES = {
    "internal_portal": [
        "https://intranet.{domain}/news/{slug}",
        "https://wiki.{domain}/pages/{slug}",
        "https://hr.{domain}/benefits/{slug}",
        "https://jira.{domain}/browse/{slug}",
        "https://confluence.{domain}/display/{slug}",
    ],
    "saas_tool": [
        "https://app.slack.com/messages/{slug}",
        "https://teams.microsoft.com/l/message/{slug}",
        "https://docs.google.com/document/d/{slug}",
        "https://zoom.us/j/{slug}",
        "https://app.asana.com/0/{slug}",
        "https://notion.so/{slug}",
    ],
    "external_legitimate": [
        "https://www.linkedin.com/posts/{slug}",
        "https://github.com/org/{slug}",
        "https://stackoverflow.com/questions/{slug}",
        "https://medium.com/@author/{slug}",
        "https://docs.aws.amazon.com/{slug}",
    ],
}


def _generate_benign_url(company_domain: str, rng: random.Random) -> str:
    """Generate a benign URL for a normal email."""
    category = rng.choice(list(_BENIGN_URL_TEMPLATES.keys()))
    template = rng.choice(_BENIGN_URL_TEMPLATES[category])
    slug = hashlib.md5(f"{rng.random()}".encode()).hexdigest()[:10]
    return template.format(domain=company_domain, slug=slug)


def _get_company_id(company: Company) -> str:
    """Extract company_id from the company dict."""
    return (company.get("company") or {}).get("id", "")


def _primary_email(person: Person) -> Optional[str]:
    """Get the primary email for a person."""
    if "email" in person and person["email"]:
        return person["email"]
    emails = person.get("emails") or []
    for value in emails:
        if value:
            return value
    return None


def _select_people_container(company: Company) -> Tuple[List[Person], str]:
    """Select the appropriate people container (employees or workers)."""
    employees = company.get("employees")
    if isinstance(employees, list) and employees:
        return employees, "employee"
    workers = company.get("workers")
    if isinstance(workers, list) and workers:
        return workers, "worker"
    return [], "employee"


def _format_ts(dt: datetime) -> str:
    """Format datetime to ISO string."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _event_target_kwargs(kind: str, person_id: str) -> Dict[str, Any]:
    """Get the appropriate kwargs for targeting a person."""
    if kind == "worker":
        return {"worker_id": person_id}
    return {"employee_id": person_id}


def _long_tail_weights(count: int, alpha: float = _LONG_TAIL_ALPHA) -> List[float]:
    """Generate long-tail distribution weights."""
    if count <= 0:
        return []
    return [1.0 / ((idx + 1) ** alpha) for idx in range(count)]


def _generate_attachment_url(file_path: str, company_domain: str, rng: random.Random) -> str:
    """Generate an attachment URL for a file."""
    # Generate a unique attachment ID based on the file path
    attachment_id = hashlib.md5(file_path.encode()).hexdigest()[:12]
    return f"https://mail.{company_domain}/attachments/{attachment_id}"


def _generate_external_attachment_url(filename: str, rng: random.Random) -> str:
    """Generate a standalone attachment URL for external files."""
    domain = rng.choice(_EXTERNAL_DOMAINS)
    attachment_id = hashlib.md5(f"{filename}{rng.random()}".encode()).hexdigest()[:12]
    return f"https://files.{domain}/share/{attachment_id}/{filename}"


def _extract_filename(file_path: str) -> str:
    """Extract filename from a file path."""
    return Path(file_path).name


def _extract_file_type(file_path: str) -> str:
    """Extract file type extension from a file path."""
    suffix = Path(file_path).suffix.lower()
    return suffix[1:] if suffix else "bin"


def _generate_file_size(file_type: str, rng: random.Random) -> int:
    """Generate a realistic file size based on file type."""
    size_ranges = {
        "pdf": (50_000, 5_000_000),
        "docx": (20_000, 2_000_000),
        "xlsx": (30_000, 10_000_000),
        "pptx": (100_000, 50_000_000),
        "zip": (100_000, 100_000_000),
        "csv": (1_000, 50_000_000),
        "txt": (100, 500_000),
        "png": (10_000, 5_000_000),
        "jpg": (50_000, 10_000_000),
    }
    min_size, max_size = size_ranges.get(file_type, (10_000, 1_000_000))
    return rng.randint(min_size, max_size)


def _generate_subject(department: str, rng: random.Random, company: Optional[Company] = None) -> str:
    """Generate an email subject based on department."""
    from .department_categories import get_subject_templates
    templates = get_subject_templates(department, company)
    template = rng.choice(templates)
    topic = rng.choice(_TOPICS)
    quarter = rng.randint(1, 4)
    return template.format(topic=topic, quarter=quarter)


def _generate_content(department: str, rng: random.Random, company: Optional[Company] = None) -> str:
    """Generate email content based on department."""
    from .department_categories import get_content_templates
    templates = get_content_templates(department, company)
    template = rng.choice(templates)
    topic = rng.choice(_TOPICS)
    quarter = rng.randint(1, 4)
    return template.format(topic=topic, quarter=quarter)


def _select_recipients(
    sender: Person,
    all_people: List[Person],
    department_members: Dict[str, List[Person]],
    rng: random.Random,
    max_recipients: int = 3,
) -> Tuple[List[str], List[str], List[str]]:
    """Select email recipients (to, cc, bcc)."""
    sender_dept = (sender.get("department") or "").strip().lower()
    sender_id = sender.get("id")
    
    # Get potential recipients (exclude sender)
    candidates = [p for p in all_people if p.get("id") != sender_id and _primary_email(p)]
    if not candidates:
        return [], [], []
    
    # Bias toward same department (70% chance)
    same_dept = [p for p in candidates if (p.get("department") or "").strip().lower() == sender_dept]
    other_dept = [p for p in candidates if p not in same_dept]
    
    # Select primary recipients (1-3)
    num_to = rng.randint(1, min(max_recipients, len(candidates)))
    to_list: List[str] = []
    
    for _ in range(num_to):
        pool = same_dept if same_dept and rng.random() < 0.7 else (other_dept or candidates)
        if not pool:
            pool = candidates
        recipient = rng.choice(pool)
        email = _primary_email(recipient)
        if email and email not in to_list:
            to_list.append(email)
            # Remove from pools to avoid duplicates
            if recipient in same_dept:
                same_dept.remove(recipient)
            if recipient in other_dept:
                other_dept.remove(recipient)
            candidates.remove(recipient)
    
    # Optionally add CC (30% chance)
    cc_list: List[str] = []
    if rng.random() < 0.3 and candidates:
        num_cc = rng.randint(1, min(2, len(candidates)))
        for _ in range(num_cc):
            if not candidates:
                break
            recipient = rng.choice(candidates)
            email = _primary_email(recipient)
            if email and email not in to_list and email not in cc_list:
                cc_list.append(email)
                candidates.remove(recipient)
    
    # Optionally add BCC (10% chance)
    bcc_list: List[str] = []
    if rng.random() < 0.1 and candidates:
        recipient = rng.choice(candidates)
        email = _primary_email(recipient)
        if email and email not in to_list and email not in cc_list:
            bcc_list.append(email)
    
    return to_list, cc_list, bcc_list


def _select_attachments(
    files: List[Dict[str, Any]],
    company_domain: str,
    rng: random.Random,
    max_attachments: int = 2,
    include_company_files: bool = True,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Select attachments for an email.
    
    Returns tuple of (attachments list, attachment_types list).
    """
    attachments: List[Dict[str, Any]] = []
    attachment_types: List[str] = []
    
    # Decide if this email has attachments (40% chance)
    if rng.random() > 0.4:
        return [], []
    
    num_attachments = rng.randint(1, max_attachments)
    
    for _ in range(num_attachments):
        # 70% chance to use company file, 30% external
        use_company_file = include_company_files and files and rng.random() < 0.7
        
        if use_company_file:
            file_meta = rng.choice(files)
            file_path = file_meta.get("path", "")
            filename = _extract_filename(file_path)
            file_type = _extract_file_type(file_path)
            
            attachment = {
                "filename": filename,
                "url": _generate_attachment_url(file_path, company_domain, rng),
                "file_path": file_path,
                "size_bytes": _generate_file_size(file_type, rng),
            }
        else:
            # Generate standalone external attachment
            ext = rng.choice(["pdf", "docx", "xlsx", "zip", "csv"])
            filename = f"document_{rng.randint(1000, 9999)}.{ext}"
            
            attachment = {
                "filename": filename,
                "url": _generate_external_attachment_url(filename, rng),
                "size_bytes": _generate_file_size(ext, rng),
            }
            file_type = ext
        
        attachments.append(attachment)
        if file_type not in attachment_types:
            attachment_types.append(file_type)
    
    return attachments, attachment_types


def generate_email_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = True,
    events_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    max_attachments_per_email: int = 2,
    generation_config: Optional[Dict[str, Any]] = None,
    burst_schedule: Optional[BurstSchedule] = None,
) -> Dict[str, int]:
    """
    Populate each person's recent_activity.email_events with email events.

    Events include sender, recipients, subject, content, and optional attachments
    (both from company files and standalone URLs).

    Optimized for large companies (1000+ employees) with department-biased
    recipient selection and scalable generation.

    Args:
        company: Company data dict
        seed: Base seed for deterministic generation
        replace_existing: If True, replace existing email events; if False, append
        events_multiplier: Multiplier for baseline email event rate (1.0 = normal)
        max_attachments_per_email: Maximum attachments per email

    Returns:
        Statistics dict with counts of generated events
    """
    from .constants_loader import load_company_files
    people, container_kind = _select_people_container(company)
    files = load_company_files(_get_company_id(company))

    # Get company domain
    company_info = company.get("company", {})
    company_domain = company_info.get("domain", "example.com")

    stats = {
        "files_available": len(files),
        "employees_total": len(people),
        "employees_with_events": 0,
        "events_requested": 0,
        "events_added": 0,
        "sent_events": 0,
        "received_events": 0,
        "events_with_attachments": 0,
        "events_with_urls": 0,
        "url_clicks": 0,
        "internal_emails": 0,
        "external_emails": 0,
    }

    gen_cfg = generation_config or company.get("_generation_config") or {}

    if not people or events_multiplier == 0:
        return stats

    # Build department index
    department_members: Dict[str, List[Person]] = defaultdict(list)
    for p in people:
        dept_key = (p.get("department") or "").strip().lower()
        if dept_key:
            department_members[dept_key].append(p)

    # Pre-compute window for temporal model
    window_start = window_end = None
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)

    base_seed = seed or 0
    requested_total = 0

    for idx_person, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        person_email = _primary_email(person)
        if not person_email:
            continue

        department = person.get("department") or "default"

        ra = person.setdefault("recent_activity", {})
        if replace_existing:
            ra.pop("email_events", None)

        rng = random.Random(base_seed * 1009 + idx_person)

        # Use baseline-driven event count if available, scaled by multiplier
        if gen_cfg:
            target_events = resolve_event_count(
                person, "email", _DEFAULT_EMAIL_EVENTS, rng,
                scale_factor=events_multiplier,
                baseline_std_scale=baseline_std_scale,
            )
        else:
            target_events = max(0, round(vary_count(_DEFAULT_EMAIL_EVENTS, rng) * events_multiplier))

        if not replace_existing:
            existing_events = ra.get("email_events")
            existing_count = len(existing_events) if isinstance(existing_events, list) else 0
            target_events = max(target_events - existing_count, 0)

        if target_events <= 0:
            continue
        # Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_events = apply_burst_to_count(
                target_events, person_id, "email_events",
                burst_schedule, rng, window_start, window_end,
            )
        if target_events <= 0:
            continue

        # Build temporal samplers for this person
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        requested_total += target_events
        events_for_person = 0

        for event_idx in range(target_events):
            # Determine direction (60% sent, 40% received)
            direction = "sent" if rng.random() < 0.6 else "received"

            # Determine if external (20% chance)
            external = rng.random() < 0.2

            # Generate timestamp using temporal model
            if circadian and weekly and window_start and window_end:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            else:
                days_back = rng.randint(0, 29)
                hours_offset = rng.randint(-10, 10)
                ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back, hours=hours_offset)
                ts = _format_ts(ts_dt)
            
            # Build email event
            event: Dict[str, Any] = {
                "ts": ts,
                "direction": direction,
                "external": external,
            }
            
            if direction == "sent":
                event["from"] = person_email
                
                if external:
                    # External recipient
                    ext_domain = rng.choice(_EXTERNAL_DOMAINS)
                    event["to"] = [f"contact{rng.randint(1, 99)}@{ext_domain}"]
                    event["cc"] = []
                    event["bcc"] = []
                    stats["external_emails"] += 1
                else:
                    # Internal recipients
                    to_list, cc_list, bcc_list = _select_recipients(
                        person, people, department_members, rng, max_recipients=3
                    )
                    event["to"] = to_list
                    event["cc"] = cc_list
                    event["bcc"] = bcc_list
                    stats["internal_emails"] += 1
                
                stats["sent_events"] += 1
            else:
                # Received email
                if external:
                    ext_domain = rng.choice(_EXTERNAL_DOMAINS)
                    event["from"] = f"sender{rng.randint(1, 99)}@{ext_domain}"
                    stats["external_emails"] += 1
                else:
                    # Internal sender
                    other_people = [p for p in people if p.get("id") != person_id]
                    if other_people:
                        sender = rng.choice(other_people)
                        event["from"] = _primary_email(sender) or f"colleague@{company_domain}"
                    else:
                        event["from"] = f"system@{company_domain}"
                    stats["internal_emails"] += 1
                
                event["to"] = [person_email]
                event["cc"] = []
                event["bcc"] = []
                stats["received_events"] += 1
            
            # Generate subject and content
            event["subject"] = _generate_subject(department, rng, company)
            event["content"] = _generate_content(department, rng, company)
            
            # Add attachments
            attachments, attachment_types = _select_attachments(
                files, company_domain, rng,
                max_attachments=max_attachments_per_email,
                include_company_files=True,
            )
            
            if attachments:
                event["attachments"] = attachments
                event["attachment_types"] = attachment_types
                stats["events_with_attachments"] += 1
            else:
                event["attachment_types"] = []

            # Add URL (~30% of emails)
            if rng.random() < 0.3:
                event["contains_url"] = _generate_benign_url(company_domain, rng)
                stats["events_with_urls"] += 1
                if direction == "received":
                    # ~60% of received emails with URL get clicked
                    event["url_clicked"] = 1 if rng.random() < 0.6 else 0
                    if event["url_clicked"]:
                        stats["url_clicks"] += 1
                else:
                    # Sent emails: not applicable from sender perspective
                    event["url_clicked"] = None

            # Add the event
            add_email_event_logs(
                company,
                **_event_target_kwargs(container_kind, person_id),
                log=event,
            )
            
            stats["events_added"] += 1
            events_for_person += 1
        
        if events_for_person:
            stats["employees_with_events"] += 1
    
    stats["events_requested"] = requested_total
    return stats

