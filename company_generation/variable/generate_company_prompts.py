"""
Company-aware LLM prompt templates for generating email scenarios and company files.

These prompts dynamically incorporate company information (name, domain, industry,
departments, roles) so the LLM generates content tailored to each company rather
than defaulting to a generic tech-company context.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .generate_scenarios_prompts import OUTPUT_SCHEMA, SLOTS_DOCUMENTATION


# =============================================================================
# COMPANY CONTEXT
# =============================================================================

@dataclass
class CompanyContext:
    """Holds company information extracted from the YAML config."""
    company_id: str
    name: str
    domain: str
    description: str
    employee_count: int
    departments: List[str]
    department_weights: Dict[str, float]
    role_distribution: Dict[str, Dict[str, float]]  # dept -> {role: weight}
    locations: List[str] = field(default_factory=list)

    def department_summary(self) -> str:
        """Human-readable department listing with roles."""
        lines = []
        for dept in self.departments:
            roles = list(self.role_distribution.get(dept, {}).keys())
            if roles:
                lines.append(f"- **{dept}** ({self.department_weights.get(dept, 0):.0%} of employees): {', '.join(roles)}")
            else:
                lines.append(f"- **{dept}** ({self.department_weights.get(dept, 0):.0%} of employees)")
        return "\n".join(lines)


def build_company_context(config: Dict[str, Any]) -> CompanyContext:
    """Build a CompanyContext from a parsed YAML config dict."""
    company = config.get("company", {})
    overall = config.get("overall", {})

    return CompanyContext(
        company_id=company.get("id", ""),
        name=company.get("name", ""),
        domain=company.get("domain", ""),
        description=company.get("description", ""),
        employee_count=overall.get("employees", 0),
        departments=list(overall.get("department_distribution", {}).keys()),
        department_weights=overall.get("department_distribution", {}),
        role_distribution=overall.get("role_distribution", {}),
        locations=company.get("locations", []),
    )


# =============================================================================
# BASE PROMPT (shared preamble)
# =============================================================================

def _get_base_prompt(ctx: CompanyContext) -> str:
    """Base instructions for all scenario generation prompts."""
    return f"""You are generating email scenario templates for a company simulation system.

## Company Profile
- **Name**: {ctx.name}
- **Domain**: {ctx.domain}
- **Description**: {ctx.description}
- **Size**: {ctx.employee_count} employees
- **Locations**: {', '.join(ctx.locations) if ctx.locations else 'Single location'}

## Departments and Roles
{ctx.department_summary()}

## Template Slot System
{SLOTS_DOCUMENTATION}

## Key Requirements

1. **Multi-participant conversations**: 2-6 participants actively exchanging emails
2. **Realistic timing**: Use offset_hours for realistic response times (0.25 = 15 min, 1 = 1 hour, etc.)
3. **Natural conversation flow**: Each email should logically follow from the previous
4. **Professional tone**: Emails should sound like real workplace communications for this specific industry
5. **Use slots appropriately**: Reference participants by their role aliases in email bodies
6. **Vary email lengths**: Mix of brief acknowledgments and detailed responses
7. **Industry-specific language**: Use terminology natural to {ctx.name}'s industry and department
8. **IMPORTANT**: The "departments" field in each scenario MUST use department names exactly as listed above

## Output Format

Output a JSON array of scenario objects matching this schema:

```json
{json.dumps(OUTPUT_SCHEMA, indent=2)}
```
"""


# =============================================================================
# EMAIL SCENARIO PROMPTS
# =============================================================================

def get_company_department_prompt(
    department: str,
    ctx: CompanyContext,
    existing_ids: Optional[List[str]] = None,
) -> str:
    """Generate prompt for department-specific email scenarios."""
    roles = list(ctx.role_distribution.get(department, {}).keys())
    roles_str = ", ".join(roles) if roles else "various roles"

    dedup_block = ""
    if existing_ids:
        dedup_block = f"""
## Deduplication
Do NOT generate scenarios with these IDs or covering these same topics:
{json.dumps(existing_ids)}
"""

    return f"""{_get_base_prompt(ctx)}

## Department: {department}

Roles in this department: {roles_str}

Generate 5 unique email scenarios specifically for the **{department}** department at {ctx.name}.

Each scenario should:
1. Feel authentic to someone who works in {department} at a company like {ctx.name}
2. Involve 2-4 participants with realistic roles from this department
3. Have 3-5 emails showing natural conversation progression
4. Include at least one scenario that requires a file attachment
5. Vary in urgency (mostly normal, one or two high priority)
6. Use industry-specific terminology and realistic situations for this department
7. Set "departments": ["{department}"] for each scenario
8. Prefix each scenario id with "{ctx.company_id}_"
{dedup_block}
Output only valid JSON, no additional text or explanation.
"""


def get_company_cross_department_prompt(
    ctx: CompanyContext,
    existing_ids: Optional[List[str]] = None,
) -> str:
    """Generate prompt for cross-department scenarios."""
    dept_pairs = []
    depts = ctx.departments
    for i in range(len(depts)):
        for j in range(i + 1, len(depts)):
            dept_pairs.append(f"- {depts[i]} + {depts[j]}")
    pairs_sample = "\n".join(dept_pairs[:15])  # Show up to 15 possible pairs

    dedup_block = ""
    if existing_ids:
        dedup_block = f"""
## Deduplication
Do NOT generate scenarios with these IDs or covering these same topics:
{json.dumps(existing_ids)}
"""

    return f"""{_get_base_prompt(ctx)}

## Cross-Department Scenarios for {ctx.name}

Generate 8 scenarios involving collaboration BETWEEN departments. These should:

1. Set `same_department: false` and `cross_department: true`
2. Involve participants from 2-3 different departments
3. Show realistic handoffs and coordination patterns specific to {ctx.name}'s industry
4. Reference department-specific concerns from each perspective
5. Have 3-5 emails showing back-and-forth
6. Prefix each scenario id with "{ctx.company_id}_"

Some possible department interactions:
{pairs_sample}

Choose interactions that make sense for {ctx.name}'s business. The "departments" field
should list the 2-3 departments involved (using exact names from the list above).
{dedup_block}
Output only valid JSON, no additional text or explanation.
"""


def get_company_urgent_prompt(
    ctx: CompanyContext,
    existing_ids: Optional[List[str]] = None,
) -> str:
    """Generate prompt for urgent/incident scenarios."""
    dedup_block = ""
    if existing_ids:
        dedup_block = f"""
## Deduplication
Do NOT generate scenarios with these IDs or covering these same topics:
{json.dumps(existing_ids)}
"""

    return f"""{_get_base_prompt(ctx)}

## Urgent & Incident Scenarios for {ctx.name}

Generate 6 urgent scenarios for time-sensitive situations at {ctx.name}. These should:

1. Set `urgency: "high"` or `urgency: "critical"`
2. Use short offset_hours (0.25 = 15min, 0.5 = 30min for rapid responses)
3. Include urgency markers in subject lines ([URGENT], [ACTION REQUIRED], etc.)
4. Show escalation patterns when appropriate
5. Be realistic for {ctx.name}'s industry
6. Prefix each scenario id with "{ctx.company_id}_"

Think about what kinds of urgent situations would arise at a company like {ctx.name}:
{ctx.description}

Consider incidents related to:
- Industry-specific emergencies (relevant to the company's core business)
- IT/security incidents (system outages, breaches)
- Compliance/regulatory urgencies
- Client/stakeholder escalations
- Employee safety or HR emergencies
- Financial urgencies
{dedup_block}
Output only valid JSON, no additional text or explanation.
"""


def get_company_generic_prompt(
    count: int,
    ctx: CompanyContext,
    existing_ids: Optional[List[str]] = None,
) -> str:
    """Generate prompt for generic diverse scenarios."""
    dedup_block = ""
    if existing_ids:
        dedup_block = f"""
## Deduplication
Do NOT generate scenarios with these IDs or covering these same topics:
{json.dumps(existing_ids)}
"""

    return f"""{_get_base_prompt(ctx)}

## Task

Generate {count} diverse email scenarios covering various workplace situations at {ctx.name}.

Requirements:
1. Include a mix of same-department and cross-department scenarios
2. Include at least 2 scenarios that require file attachments
3. Include at least 1 urgent scenario
4. Include scenarios with 2, 3, and 4+ participants
5. Cover different types: approvals, project coordination, information sharing, problem solving, planning
6. Vary thread lengths (2-5 emails)
7. Make conversations feel natural and specific to {ctx.name}'s industry
8. Prefix each scenario id with "{ctx.company_id}_"
9. Use department names exactly as listed in the company profile
{dedup_block}
Output only valid JSON, no additional text or explanation.
"""


# =============================================================================
# COMPANY FILES PROMPTS
# =============================================================================

COMPANY_FILE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["type", "content", "owner role", "created", "path"],
        "properties": {
            "type": {
                "type": "string",
                "enum": ["regular", "business", "confidential", "unlabeled"],
                "description": "Sensitivity classification"
            },
            "content": {
                "type": "string",
                "description": "1-2 sentence description of what this file contains"
            },
            "owner role": {
                "type": "string",
                "description": "Department - Role of the file owner, e.g. 'Finance - Senior Accountant'"
            },
            "created": {
                "type": "string",
                "description": "Creation date in YYYY-MM-DD format"
            },
            "path": {
                "type": "string",
                "description": "File path, e.g. /departments/finance/Reports/quarterly_report.pdf"
            }
        }
    }
}


def get_company_files_department_prompt(
    department: str,
    ctx: CompanyContext,
    count: int,
    existing_paths: Optional[List[str]] = None,
) -> str:
    """Generate prompt for department-specific company files."""
    roles = list(ctx.role_distribution.get(department, {}).keys())
    roles_with_dept = [f"{department} - {r}" for r in roles]
    dept_slug = department.lower().replace(" & ", "_").replace(" ", "_")

    dedup_block = ""
    if existing_paths:
        # Only show last 50 to stay within token limits
        shown = existing_paths[-50:]
        dedup_block = f"""
## Deduplication
Do NOT generate files at these paths (or very similar variations):
{json.dumps(shown)}
"""

    return f"""You are generating file metadata for a company simulation system.

## Company: {ctx.name}
{ctx.description}

## Department: {department}
Roles: {', '.join(roles_with_dept)}

## Task

Generate exactly {count} file entries for the **{department}** department.

Requirements:
1. Files should be realistic documents that people in {department} at {ctx.name} would create and use
2. Use the "owner role" field with format "Department - Role" using exact department and role names above
3. File paths should start with /departments/{dept_slug}/
4. Use realistic file extensions: .pdf, .docx, .xlsx, .pptx, .csv, .md
5. Include subdirectories for organization (e.g. /departments/{dept_slug}/Reports/, /departments/{dept_slug}/Projects/)
6. Mix of sensitivity types: ~45% business, ~30% regular, ~15% confidential, ~10% unlabeled
7. Dates should be between 2022-01-01 and 2025-03-31
8. Content descriptions should be 1-2 sentences explaining what the file contains
9. Make files industry-specific and realistic for {ctx.name}

## Output Format

```json
{json.dumps(COMPANY_FILE_SCHEMA, indent=2)}
```
{dedup_block}
Output only valid JSON array, no additional text or explanation.
"""


def get_company_files_shared_prompt(
    ctx: CompanyContext,
    count: int,
    existing_paths: Optional[List[str]] = None,
) -> str:
    """Generate prompt for shared/company-wide files."""
    dedup_block = ""
    if existing_paths:
        shown = existing_paths[-50:]
        dedup_block = f"""
## Deduplication
Do NOT generate files at these paths (or very similar variations):
{json.dumps(shown)}
"""

    return f"""You are generating file metadata for a company simulation system.

## Company: {ctx.name}
{ctx.description}

## Task

Generate exactly {count} company-wide shared files that would be accessible across departments.

These are files that live under /shared/ and are relevant to the entire company. Examples:
- Company policies (code of conduct, IT security policy, expense policy, travel policy)
- HR documents (employee handbook, onboarding guide, benefits overview)
- Brand materials (brand guidelines, logo usage guide, templates)
- Company communications (newsletters, all-hands meeting notes, org charts)
- Operational documents (emergency procedures, office floor plans)
- Compliance documents (regulatory guidelines, training materials)

Requirements:
1. Paths should start with /shared/ followed by a category (e.g. /shared/policies/, /shared/HR/, /shared/Marketing/)
2. Owner roles should use exact department and role names from the company
3. Mix of sensitivity types: ~50% business, ~30% regular, ~15% confidential, ~5% unlabeled
4. Dates between 2022-01-01 and 2025-03-31
5. Content descriptions should be specific to {ctx.name}'s industry
6. Include industry-specific compliance and regulatory documents

Available departments and roles:
{ctx.department_summary()}

## Output Format

```json
{json.dumps(COMPANY_FILE_SCHEMA, indent=2)}
```
{dedup_block}
Output only valid JSON array, no additional text or explanation.
"""
