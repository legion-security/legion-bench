"""
Email scenario schema for multi-participant email thread generation.

This module defines the data structures for email scenarios - coherent
email threads/conversations that can be applied to company data with
slot filling for actual employee names, files, and other context.

Key concepts:
- EmailScenario: A complete conversation template with multiple emails
- EmailTemplate: A single email within a scenario
- ScenarioSlots: Values that get filled in when applying a scenario
- Participants are indexed (0, 1, 2, ...) allowing flexible multi-party threads
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional


@dataclass
class EmailTemplate:
    """A single email within a scenario/thread.

    Uses participant indices for flexible multi-party conversations:
    - sender_index: Which participant sends this email (0 = first, 1 = second, etc.)
    - recipient_indices: Who receives it (empty = all other participants)
    """
    offset_hours: float  # Hours after scenario start (can be fractional, e.g., 0.5)
    sender_index: int  # Index into participant list (0 = initiator/first participant)
    subject_template: str  # e.g., "Review needed: {file_name}"
    body_template: str  # With slots like {participant_0_name}, {file_description}

    # Optional fields
    recipient_indices: List[int] = field(default_factory=list)  # Empty = all others
    include_attachment: bool = False  # Whether to attach the scenario's file
    reply_to_previous: bool = False  # If True, use "Re: " + original subject
    cc_indices: List[int] = field(default_factory=list)  # Participants to CC
    is_external_sender: bool = False  # If True, sender is external (use external_sender_email)
    external_sender_email: Optional[str] = None  # For external senders


@dataclass
class EmailScenario:
    """A coherent email thread/conversation that can be applied to company data.

    Scenarios define:
    - How many participants are needed and their roles
    - Requirements (same department, needs file, needs manager, etc.)
    - The sequence of emails in the thread

    Participant slots are named:
    - {participant_0_name}, {participant_0_email} - First participant (initiator)
    - {participant_1_name}, {participant_1_email} - Second participant
    - etc.

    Additionally, role-based aliases are created from participant_roles:
    - If participant_roles = ["lead", "engineer", "pm"]
    - Then {lead_name} = {participant_0_name}, {engineer_name} = {participant_1_name}, etc.
    """
    id: str  # Unique identifier, e.g., "doc_review_thread"
    name: str  # Human-readable name, e.g., "Document Review Thread"
    description: str  # Brief description of the scenario

    # Participant requirements
    num_participants: int = 2  # Exact number of participants needed
    participant_roles: List[str] = field(default_factory=lambda: ["initiator", "responder"])
    same_department: bool = True  # Should participants be from same department?
    departments: List[str] = field(default_factory=list)  # Restrict to these depts (empty = any)
    requires_manager: bool = False  # Should one participant be the initiator's manager?
    cross_department: bool = False  # Should participants be from DIFFERENT departments?

    # File requirements
    requires_file: bool = False  # Does this scenario need a file attachment?
    file_types: List[str] = field(default_factory=list)  # Allowed extensions, e.g., ["pdf", "docx"]
    file_departments: List[str] = field(default_factory=list)  # Prefer files from these depts

    # External participants
    num_external: int = 0  # Number of external email participants
    external_domain: Optional[str] = None  # Domain for external emails, e.g., "client.example.com"

    # The email sequence
    emails: List[EmailTemplate] = field(default_factory=list)

    # Metadata for selection and weighting
    tags: List[str] = field(default_factory=list)  # e.g., ["collaboration", "review"]
    weight: float = 1.0  # For weighted random selection (higher = more likely)
    urgency: Literal["normal", "high", "critical"] = "normal"


@dataclass
class ScenarioSlots:
    """Container for all slot values when applying a scenario.

    Slots get filled with actual company data at generation time.
    Templates reference these using {slot_name} syntax.
    """
    # Participants (dynamic based on num_participants)
    # These are populated as participant_0_name, participant_0_email, etc.
    participants: List[dict] = field(default_factory=list)
    # Each participant dict has: name, email, department, title

    # Role aliases (maps role name to participant index)
    # e.g., {"lead": 0, "engineer": 1} so {lead_name} works
    role_aliases: dict = field(default_factory=dict)

    # File information
    file_path: str = ""
    file_name: str = ""
    file_description: str = ""
    file_type: str = ""
    file_category: str = ""

    # Company context
    company_name: str = ""
    company_domain: str = ""

    # Dynamic content (filled with random but consistent values)
    project_name: str = ""
    deadline: str = ""
    quarter: str = ""
    date_reference: str = ""
    meeting_day: str = ""
    meeting_time: str = ""

    # Department context
    department: str = ""  # Primary department for the scenario

    def get(self, key: str, default: str = "") -> str:
        """Get a slot value by key, supporting participant lookups.

        Supports:
        - Direct attributes: {project_name}, {file_path}
        - Participant indexed: {participant_0_name}, {participant_1_email}
        - Role aliases: {lead_name}, {engineer_email} (if roles defined)
        """
        # Check direct attributes first
        if hasattr(self, key) and not key.startswith("_"):
            val = getattr(self, key)
            if isinstance(val, str):
                return val

        # Check for participant_N_attr pattern
        if key.startswith("participant_"):
            parts = key.split("_", 2)  # ["participant", "N", "attr"]
            if len(parts) == 3:
                try:
                    idx = int(parts[1])
                    attr = parts[2]
                    if 0 <= idx < len(self.participants):
                        return self.participants[idx].get(attr, default)
                except (ValueError, IndexError):
                    pass

        # Check for role alias pattern (e.g., lead_name, engineer_email)
        for role, idx in self.role_aliases.items():
            if key.startswith(f"{role}_"):
                attr = key[len(role) + 1:]  # Extract attribute after role_
                if 0 <= idx < len(self.participants):
                    return self.participants[idx].get(attr, default)

        return default

    def render(self, template: str) -> str:
        """Render a template string by replacing all {slot} placeholders."""
        import re

        def replacer(match):
            key = match.group(1)
            return self.get(key, match.group(0))  # Keep original if not found

        return re.sub(r"\{(\w+)\}", replacer, template)


# Type alias for clarity
ScenarioList = List[EmailScenario]
