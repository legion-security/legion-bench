#!/usr/bin/env python3
"""
LLM prompt templates for generating additional email scenarios.

This module provides prompts that can be sent to an LLM to generate
new email scenarios in the correct JSON format. The generated scenarios
can then be saved to constants/email_scenarios.json.

Usage:
    # Print a prompt for a specific department
    python -m company_generation.variable.generate_scenarios_prompts --department Engineering

    # Print the generic prompt
    python -m company_generation.variable.generate_scenarios_prompts --generic

    # Generate prompt for cross-department scenarios
    python -m company_generation.variable.generate_scenarios_prompts --cross-department

    # Generate prompt for urgent/incident scenarios
    python -m company_generation.variable.generate_scenarios_prompts --urgent
"""

import argparse
import json


# =============================================================================
# JSON SCHEMA FOR OUTPUT
# =============================================================================

OUTPUT_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["id", "name", "description", "num_participants", "participant_roles", "emails"],
        "properties": {
            "id": {
                "type": "string",
                "description": "Unique snake_case identifier, e.g., 'doc_review_engineering'"
            },
            "name": {
                "type": "string",
                "description": "Human-readable name, e.g., 'Engineering Document Review'"
            },
            "description": {
                "type": "string",
                "description": "Brief description of the scenario"
            },
            "num_participants": {
                "type": "integer",
                "minimum": 2,
                "maximum": 6,
                "description": "Number of participants in the conversation"
            },
            "participant_roles": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Role names for each participant, e.g., ['author', 'reviewer', 'manager']"
            },
            "same_department": {
                "type": "boolean",
                "default": True,
                "description": "Whether participants should be from the same department"
            },
            "departments": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Restrict to specific departments, or empty for any"
            },
            "requires_manager": {
                "type": "boolean",
                "default": False,
                "description": "Whether a manager should be one of the participants"
            },
            "cross_department": {
                "type": "boolean",
                "default": False,
                "description": "Whether participants should be from different departments"
            },
            "requires_file": {
                "type": "boolean",
                "default": False,
                "description": "Whether this scenario involves sharing a file"
            },
            "file_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Allowed file extensions if requires_file is true, e.g., ['pdf', 'docx']"
            },
            "emails": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["offset_hours", "sender_index", "subject_template", "body_template"],
                    "properties": {
                        "offset_hours": {
                            "type": "number",
                            "description": "Hours after thread start (0 for first email, can be fractional)"
                        },
                        "sender_index": {
                            "type": "integer",
                            "description": "Index of sender in participant list (0 = first participant)"
                        },
                        "subject_template": {
                            "type": "string",
                            "description": "Email subject with {slot} placeholders"
                        },
                        "body_template": {
                            "type": "string",
                            "description": "Email body with {slot} placeholders"
                        },
                        "recipient_indices": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Indices of recipients (empty = all except sender)"
                        },
                        "include_attachment": {
                            "type": "boolean",
                            "default": False,
                            "description": "Whether to include the scenario's file as attachment"
                        },
                        "reply_to_previous": {
                            "type": "boolean",
                            "default": False,
                            "description": "Whether this is a reply (adds 'Re: ' prefix)"
                        },
                        "cc_indices": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Indices of CC recipients"
                        }
                    }
                }
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tags for categorization, e.g., ['review', 'engineering']"
            },
            "weight": {
                "type": "number",
                "default": 1.0,
                "description": "Selection weight (higher = more likely to be used)"
            },
            "urgency": {
                "type": "string",
                "enum": ["normal", "high", "critical"],
                "default": "normal"
            }
        }
    }
}


# =============================================================================
# AVAILABLE SLOTS DOCUMENTATION
# =============================================================================

SLOTS_DOCUMENTATION = """
## Available Template Slots

### Participant Slots (dynamic based on num_participants)
- {participant_0_name}, {participant_0_email} - First participant (index 0)
- {participant_1_name}, {participant_1_email} - Second participant (index 1)
- {participant_N_name}, {participant_N_email} - Nth participant

### Role-Based Aliases
Based on participant_roles, you can use role names instead of indices:
- If participant_roles = ["author", "reviewer", "manager"]
- Then {author_name} = {participant_0_name}
- And {reviewer_name} = {participant_1_name}
- And {manager_email} = {participant_2_email}

### File Slots (when requires_file = true)
- {file_path} - Full path to the file
- {file_name} - Just the filename
- {file_description} - Description of file contents
- {file_type} - File extension (pdf, docx, etc.)

### Context Slots
- {department} - Department name of the initiator
- {company_name} - Company name
- {company_domain} - Company email domain

### Dynamic Content (randomly selected)
- {project_name} - A project name (Phoenix, Atlas, Nova, etc.)
- {deadline} - A deadline phrase ("end of week", "next Monday", etc.)
- {quarter} - A quarter (Q1, Q2, Q3, Q4)
- {date_reference} - A date reference ("today", "yesterday", "this morning", etc.)
- {meeting_day} - A weekday name
- {meeting_time} - A meeting time ("10am", "2pm", etc.)
"""


# =============================================================================
# PROMPT TEMPLATES
# =============================================================================

def get_base_prompt() -> str:
    """Get the base instruction prompt for scenario generation."""
    return f"""You are generating email scenario templates for a company simulation system.

Each scenario represents a coherent email thread/conversation that could occur in a corporate environment.
The scenarios will be used to generate realistic email data by filling template slots with actual company data.

{SLOTS_DOCUMENTATION}

## Key Requirements

1. **Multi-participant conversations**: Scenarios should involve 2-6 participants actively exchanging emails
2. **Realistic timing**: Use offset_hours to show realistic response times (0.25 = 15 min, 1 = 1 hour, etc.)
3. **Natural conversation flow**: Each email should logically follow from the previous ones
4. **Professional tone**: Emails should sound like real workplace communications
5. **Use slots appropriately**: Reference participants by their role aliases in email bodies
6. **Vary email lengths**: Mix of brief acknowledgments and detailed responses

## Output Format

Output a JSON array of scenario objects matching this schema:

```json
{json.dumps(OUTPUT_SCHEMA, indent=2)}
```
"""


def get_department_prompt(department: str) -> str:
    """Get a prompt for generating department-specific scenarios."""
    department_contexts = {
        "Engineering": """
Focus on Engineering-specific workflows:
- Code reviews and pull requests
- Technical design discussions
- Bug reports and incident response
- Sprint planning and retrospectives
- Architecture decisions
- Deployment and release coordination
- Technical documentation reviews

Use appropriate technical terminology and references to:
- Code, PRs, branches, deployments
- Sprints, tickets, backlogs
- APIs, services, databases
- Testing, QA, staging environments
""",
        "Sales": """
Focus on Sales-specific workflows:
- Deal pipeline discussions
- Client proposal reviews
- Contract negotiations
- Pricing strategy discussions
- Territory planning
- Win/loss analysis
- Lead handoffs and qualification

Use appropriate sales terminology and references to:
- Deals, opportunities, pipeline
- Prospects, leads, accounts
- Proposals, contracts, SOWs
- Quotas, targets, forecasts
""",
        "HR": """
Focus on HR-specific workflows:
- Hiring and interview coordination
- Onboarding new employees
- Performance review cycles
- Policy updates and communications
- Benefits administration
- Training program coordination
- Employee relations matters

Use appropriate HR terminology and references to:
- Candidates, requisitions, offers
- Onboarding, orientation
- Reviews, feedback, development plans
- Policies, compliance, handbook
""",
        "Finance": """
Focus on Finance-specific workflows:
- Budget planning and reviews
- Expense approvals
- Financial reporting
- Audit preparation
- Forecasting discussions
- Vendor payments
- Investment decisions

Use appropriate finance terminology and references to:
- Budgets, forecasts, actuals
- P&L, balance sheet, cash flow
- Invoices, POs, expense reports
- Audits, compliance, controls
""",
        "Marketing": """
Focus on Marketing-specific workflows:
- Campaign planning and execution
- Content review and approval
- Brand guideline discussions
- Analytics and performance reviews
- Event coordination
- PR and communications
- Creative asset reviews

Use appropriate marketing terminology and references to:
- Campaigns, content, creative
- Leads, conversions, funnel
- Brand, messaging, positioning
- Analytics, metrics, ROI
""",
        "IT": """
Focus on IT-specific workflows:
- System maintenance and upgrades
- Security incidents and alerts
- Access request management
- Infrastructure planning
- Helpdesk escalations
- Software deployments
- Backup and recovery

Use appropriate IT terminology and references to:
- Systems, servers, infrastructure
- Security, access, permissions
- Tickets, incidents, changes
- Deployments, patches, updates
""",
        "Customer service": """
Focus on Customer Service-specific workflows:
- Customer escalation handling
- Issue resolution coordination
- SLA monitoring and reporting
- Customer feedback analysis
- Process improvement discussions
- Training and knowledge sharing
- Cross-team handoffs

Use appropriate support terminology and references to:
- Tickets, cases, escalations
- SLAs, response times, resolution
- Customer satisfaction, NPS
- Knowledge base, playbooks
""",
    }

    context = department_contexts.get(department, f"""
Focus on {department}-specific workflows and common scenarios that would occur in this department.
Use appropriate terminology and realistic situations.
""")

    return f"""{get_base_prompt()}

## Department: {department}

{context}

## Task

Generate 5 unique email scenarios specifically for the {department} department.

Each scenario should:
1. Feel authentic to someone who has worked in {department}
2. Involve 2-4 participants with realistic roles for this department
3. Have 2-5 emails showing natural conversation progression
4. Include at least one scenario that requires a file attachment
5. Vary in urgency (mostly normal, one or two high priority)

Output only valid JSON, no additional text or explanation.
"""


def get_cross_department_prompt() -> str:
    """Get a prompt for generating cross-department scenarios."""
    return f"""{get_base_prompt()}

## Cross-Department Scenarios

Generate scenarios that involve collaboration BETWEEN departments. These scenarios should:

1. Set `same_department: false` and `cross_department: true`
2. Involve participants from 2-3 different departments
3. Show realistic handoffs and coordination challenges
4. Reference department-specific concerns from each perspective

Common cross-department interactions to model:
- Engineering + Product: Feature requests, technical feasibility discussions
- Sales + Engineering: Custom requirements, technical questions for deals
- HR + All: Policy announcements, training coordination
- Finance + All: Budget approvals, expense processes
- Marketing + Sales: Lead handoffs, campaign coordination
- IT + All: Security training, system access, maintenance notices
- Legal + All: Contract reviews, compliance requirements
- Customer Service + Engineering: Bug escalations, feature requests from customers

## Task

Generate 8 cross-department scenarios that:
1. Involve exactly 2-3 different departments
2. Show natural collaboration patterns
3. Include realistic friction points and resolutions
4. Have 3-5 emails showing the back-and-forth

Output only valid JSON, no additional text or explanation.
"""


def get_urgent_prompt() -> str:
    """Get a prompt for generating urgent/incident scenarios."""
    return f"""{get_base_prompt()}

## Urgent & Incident Scenarios

Generate scenarios for time-sensitive situations. These scenarios should:

1. Set `urgency: "high"` or `urgency: "critical"`
2. Use short offset_hours (0.25 = 15min, 0.5 = 30min for rapid responses)
3. Include urgency markers in subject lines ([URGENT], [ACTION REQUIRED], etc.)
4. Show escalation patterns when appropriate

Types of urgent scenarios to model:
- Security incidents (breach detected, phishing attempt, compromised accounts)
- System outages (production down, data issues, service degradation)
- Client escalations (angry customer, contract at risk, SLA breach)
- Compliance deadlines (audit notice, regulatory requirement, legal deadline)
- HR emergencies (employee incident, policy violation, urgent staffing)
- Financial urgencies (payment deadline, budget freeze, audit finding)

## Task

Generate 6 urgent scenarios that:
1. Create a sense of urgency through timing and language
2. Show rapid response patterns (quick acknowledgments, status updates)
3. Include escalation to management where appropriate
4. Conclude with resolution or clear next steps
5. Have 3-5 emails in quick succession

Output only valid JSON, no additional text or explanation.
"""


def get_generic_prompt(count: int = 10) -> str:
    """Get a generic prompt for generating diverse scenarios."""
    return f"""{get_base_prompt()}

## Task

Generate {count} diverse email scenarios covering various workplace situations.

Requirements:
1. Include a mix of same-department and cross-department scenarios
2. Include at least 2 scenarios that require file attachments
3. Include at least 1 urgent scenario
4. Include scenarios with 2, 3, and 4+ participants
5. Cover different scenario types:
   - Approvals and reviews
   - Project coordination
   - Information sharing
   - Problem solving
   - Planning and scheduling
6. Vary the email thread lengths (2-5 emails)
7. Make conversations feel natural and realistic

Output only valid JSON, no additional text or explanation.
"""


# =============================================================================
# EXAMPLE SCENARIO
# =============================================================================

EXAMPLE_SCENARIO = {
    "id": "technical_design_review",
    "name": "Technical Design Review",
    "description": "Team reviews a technical design document with multiple rounds of feedback",
    "num_participants": 3,
    "participant_roles": ["author", "senior_engineer", "tech_lead"],
    "same_department": True,
    "departments": ["Engineering", "IT"],
    "requires_manager": False,
    "cross_department": False,
    "requires_file": True,
    "file_types": ["pdf", "docx"],
    "emails": [
        {
            "offset_hours": 0,
            "sender_index": 0,
            "subject_template": "Design Review: {project_name} - {file_name}",
            "body_template": """Hi {senior_engineer_name}, {tech_lead_name},

I've completed the technical design for {project_name}. {file_description}

Key decisions I'd like your input on:
1. Database schema for the new entities
2. API versioning approach
3. Caching strategy

Could you review by {deadline}? Happy to set up a call if easier.

Thanks,
{author_name}""",
            "include_attachment": True,
            "reply_to_previous": False
        },
        {
            "offset_hours": 4.5,
            "sender_index": 1,
            "subject_template": "Re: Design Review: {project_name} - {file_name}",
            "body_template": """Thanks for sharing, {author_name}.

Initial thoughts:
- Database schema looks solid, but consider adding an index on the status field
- For API versioning, I'd suggest URL versioning over header versioning for better discoverability
- Caching strategy needs more detail - what's the invalidation approach?

{tech_lead_name}, what do you think about the proposed architecture?

{senior_engineer_name}""",
            "reply_to_previous": True
        },
        {
            "offset_hours": 6.0,
            "sender_index": 2,
            "subject_template": "Re: Design Review: {project_name} - {file_name}",
            "body_template": """Good review {senior_engineer_name}.

{author_name}, a few additional points:
- Agree on the URL versioning recommendation
- For the caching invalidation, consider event-driven approach with our message queue
- Please add a section on error handling and retry logic
- The timeline seems aggressive - let's discuss resource allocation

Otherwise, this is heading in the right direction.

{tech_lead_name}""",
            "reply_to_previous": True
        },
        {
            "offset_hours": 7.0,
            "sender_index": 0,
            "subject_template": "Re: Design Review: {project_name} - {file_name}",
            "body_template": """Thank you both for the thorough feedback!

I'll update the design with:
- Index on status field
- URL versioning (v1/v2 prefix)
- Event-driven cache invalidation via message queue
- Error handling section with retry logic

{tech_lead_name}, I'll also revise the timeline and flag the resource concern.

Will have v2 ready by {deadline}.

{author_name}""",
            "reply_to_previous": True
        }
    ],
    "tags": ["engineering", "design", "review", "technical"],
    "weight": 1.5,
    "urgency": "normal"
}


def print_example() -> None:
    """Print an example scenario."""
    print("\n## Example Scenario Format\n")
    print("```json")
    print(json.dumps([EXAMPLE_SCENARIO], indent=2))
    print("```")


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate LLM prompts for creating email scenarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--department",
        type=str,
        choices=["Engineering", "Sales", "HR", "Finance", "Marketing", "IT", "Customer service"],
        help="Generate prompt for a specific department",
    )
    group.add_argument(
        "--cross-department",
        action="store_true",
        help="Generate prompt for cross-department scenarios",
    )
    group.add_argument(
        "--urgent",
        action="store_true",
        help="Generate prompt for urgent/incident scenarios",
    )
    group.add_argument(
        "--generic",
        action="store_true",
        help="Generate a generic prompt for diverse scenarios",
    )
    group.add_argument(
        "--example",
        action="store_true",
        help="Print an example scenario in JSON format",
    )
    group.add_argument(
        "--schema",
        action="store_true",
        help="Print the JSON schema for scenarios",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of scenarios to request (for --generic)",
    )

    args = parser.parse_args()

    if args.example:
        print_example()
    elif args.schema:
        print("\n## JSON Schema for Email Scenarios\n")
        print("```json")
        print(json.dumps(OUTPUT_SCHEMA, indent=2))
        print("```")
    elif args.department:
        print(get_department_prompt(args.department))
    elif args.cross_department:
        print(get_cross_department_prompt())
    elif args.urgent:
        print(get_urgent_prompt())
    elif args.generic:
        print(get_generic_prompt(args.count))


if __name__ == "__main__":
    main()
