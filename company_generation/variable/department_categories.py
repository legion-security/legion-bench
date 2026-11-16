"""
Department category classification system.

Maps department names to abstract behavioral categories so that event
generation (logins, processes, apps, emails) produces realistic data
for any company — not just NexusTech.

Categories are resolved in order:
1. Explicit mapping in company YAML (overall.department_categories)
2. Fuzzy keyword matching on department name
3. Fallback to 'business_operations'

Usage:
    from .department_categories import get_category, get_ip_weights, ...

    cat = get_category("Fulfillment & Warehouse", company)  # -> "business_operations"
    weights = get_ip_weights("Fulfillment & Warehouse", company)  # -> (0.60, 0.03)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

Person = Dict[str, Any]
Company = Dict[str, Any]

# =============================================================================
# CATEGORY CONSTANTS
# =============================================================================

TECH_ENGINEERING = "tech_engineering"
TECH_OPS = "tech_ops"
TECH_DATA = "tech_data"
BUSINESS_SALES = "business_sales"
BUSINESS_MARKETING = "business_marketing"
BUSINESS_FINANCE = "business_finance"
BUSINESS_OPERATIONS = "business_operations"
PEOPLE_HR = "people_hr"
PEOPLE_SUPPORT = "people_support"
PROFESSIONAL_LEGAL = "professional_legal"
PROFESSIONAL_CLINICAL = "professional_clinical"
PROFESSIONAL_TRADES = "professional_trades"
LEADERSHIP = "leadership"
FINANCE_SPECIALIZED = "finance_specialized"

DEFAULT_CATEGORY = BUSINESS_OPERATIONS


# =============================================================================
# FUZZY KEYWORD MATCHING (fallback when no YAML mapping)
# =============================================================================

# Order matters: first match wins.  More specific keywords go first.
_KEYWORD_TO_CATEGORY: List[Tuple[List[str], str]] = [
    # Leadership
    (["executive", "c-suite", "board"], LEADERSHIP),
    # Tech
    (["engineering", "software", "r&d", "development", "devops"], TECH_ENGINEERING),
    (["infrastructure", "security", "it & ot", "it&ot", "cybersec", "sre", "platform"], TECH_OPS),
    (["data science", "data & analytics", "analytics", "research & analytics", "bi ", "machine learning"], TECH_DATA),
    # Finance specialized
    (["trading", "investment bank", "wealth manage", "capital market", "portfolio"], FINANCE_SPECIALIZED),
    # Professional
    (["litigation", "corporate & m&a", "intellectual property", "real estate law",
      "employment law", "tax law", "compliance & risk", "risk & compliance"], PROFESSIONAL_LEGAL),
    (["clinical", "nursing", "pharmacy", "laboratory", "radiology", "medical", "patient"], PROFESSIONAL_CLINICAL),
    (["production", "manufacturing", "maintenance", "quality assurance", "quality control",
      "safety & env", "welding", "machining", "assembly"], PROFESSIONAL_TRADES),
    # Business
    (["sales", "partnership", "business develop", "client service", "account manage"], BUSINESS_SALES),
    (["marketing", "design", "brand", "creative", "content", "seo", "social media"], BUSINESS_MARKETING),
    (["finance", "accounting", "billing", "treasury", "audit", "tax"], BUSINESS_FINANCE),
    (["operation", "supply chain", "logistics", "fulfillment", "warehouse",
      "procurement", "facilities", "administration"], BUSINESS_OPERATIONS),
    # People
    (["human resource", " hr", "people ops", "recruiting", "talent"], PEOPLE_HR),
    (["customer support", "customer success", "customer service", "help desk",
      "patient service", "support"], PEOPLE_SUPPORT),
    # Legal (generic, after professional_legal for specific practice areas)
    (["legal", "compliance", "regulatory"], PROFESSIONAL_LEGAL),
    # IT (generic, after tech_ops for specific infra)
    (["it"], TECH_OPS),
]


def _fuzzy_match_category(department: str) -> str:
    """Match department name to category via keyword scanning."""
    dept_lower = f" {department.lower()} "  # pad for word-boundary matching
    for keywords, category in _KEYWORD_TO_CATEGORY:
        for kw in keywords:
            if kw in dept_lower:
                return category
    return DEFAULT_CATEGORY


# Per-company cache: {company_id: {dept: category}}
_CATEGORY_CACHE: Dict[str, Dict[str, str]] = {}


def get_category(department: str, company: Optional[Company] = None) -> str:
    """Resolve a department name to its behavioral category.

    Resolution order:
    1. Explicit mapping in company["overall"]["department_categories"]
    2. Fuzzy keyword match
    3. DEFAULT_CATEGORY
    """
    if not department:
        return DEFAULT_CATEGORY

    # Check company-level explicit mapping
    if company:
        company_id = (company.get("company") or {}).get("id", "")
        # Check cache
        if company_id and company_id in _CATEGORY_CACHE:
            cached = _CATEGORY_CACHE[company_id].get(department)
            if cached:
                return cached

        mapping = (company.get("overall") or {}).get("department_categories") or {}
        if department in mapping:
            cat = mapping[department]
            if company_id:
                _CATEGORY_CACHE.setdefault(company_id, {})[department] = cat
            return cat

    # Fuzzy match
    cat = _fuzzy_match_category(department)
    if company:
        company_id = (company.get("company") or {}).get("id", "")
        if company_id:
            _CATEGORY_CACHE.setdefault(company_id, {})[department] = cat
    return cat


# =============================================================================
# CATEGORY -> IP WEIGHTS  (office_pct, travel_pct)
# =============================================================================

CATEGORY_IP_WEIGHTS: Dict[str, Tuple[float, float]] = {
    TECH_ENGINEERING:       (0.65, 0.02),
    TECH_OPS:               (0.58, 0.02),
    TECH_DATA:              (0.60, 0.02),
    BUSINESS_SALES:         (0.35, 0.10),
    BUSINESS_MARKETING:     (0.55, 0.05),
    BUSINESS_FINANCE:       (0.65, 0.02),
    BUSINESS_OPERATIONS:    (0.60, 0.03),
    PEOPLE_HR:              (0.65, 0.02),
    PEOPLE_SUPPORT:         (0.45, 0.05),
    PROFESSIONAL_LEGAL:     (0.65, 0.02),
    PROFESSIONAL_CLINICAL:  (0.70, 0.01),
    PROFESSIONAL_TRADES:    (0.80, 0.01),
    LEADERSHIP:             (0.40, 0.08),
    FINANCE_SPECIALIZED:    (0.60, 0.03),
}

_DEFAULT_OFFICE_PCT = 0.55
_DEFAULT_TRAVEL_PCT = 0.03


def get_ip_weights(department: str, company: Optional[Company] = None) -> Tuple[float, float]:
    """Get (office_pct, travel_pct) for a department."""
    cat = get_category(department, company)
    return CATEGORY_IP_WEIGHTS.get(cat, (_DEFAULT_OFFICE_PCT, _DEFAULT_TRAVEL_PCT))


# =============================================================================
# CATEGORY -> LOGIN TIER CLASSIFICATION
# =============================================================================

# Categories where "ops" tier applies (higher login rates, admin tools)
OPS_CATEGORIES = {TECH_OPS}
# Categories where "eng" tier applies
ENG_CATEGORIES = {TECH_ENGINEERING, TECH_DATA}
# Categories where "sales" tier applies
SALES_CATEGORIES = {BUSINESS_SALES}
# Categories where "cs" tier applies
CS_CATEGORIES = {PEOPLE_SUPPORT}
# Everything else uses "general" tier
GENERAL_CATEGORIES = {
    BUSINESS_MARKETING, BUSINESS_FINANCE, BUSINESS_OPERATIONS,
    PEOPLE_HR, PROFESSIONAL_LEGAL, PROFESSIONAL_CLINICAL,
    PROFESSIONAL_TRADES, FINANCE_SPECIALIZED,
}


def classify_role_tier(person: Person, company: Optional[Company] = None) -> str:
    """Classify a person into a login rate tier based on their department category."""
    dept = person.get("department", "")
    title = (person.get("title") or "").lower()

    # Executive check (title-based, regardless of department)
    if any(t in title for t in ("ceo", "cto", "cfo", "coo", "ciso", "vp ", "vice president", "chief")):
        return "executive"

    cat = get_category(dept, company)

    if cat == LEADERSHIP:
        return "executive"

    if cat in OPS_CATEGORIES:
        if any(t in title for t in ("senior", "staff", "principal", "lead")):
            return "ops_senior"
        if any(t in title for t in ("manager", "director", "head of")):
            return "manager"
        return "ops_ic"

    if cat in ENG_CATEGORIES:
        if any(t in title for t in ("senior", "staff", "principal", "lead")):
            return "eng_senior"
        if any(t in title for t in ("manager", "director", "head of")):
            return "manager"
        return "eng_ic"

    if cat in SALES_CATEGORIES:
        if any(t in title for t in ("manager", "director", "head of", "lead")):
            return "manager"
        return "sales_ic"

    if cat in CS_CATEGORIES:
        if any(t in title for t in ("manager", "director", "head of", "lead")):
            return "manager"
        return "cs_ic"

    # General categories (business, professional, people_hr, etc.)
    if any(t in title for t in ("manager", "director", "head of", "lead", "partner", "chief")):
        return "manager"
    if any(t in title for t in ("senior", "staff", "principal")):
        return "general_senior"
    return "general_ic"


# =============================================================================
# CATEGORY -> PROCESS PROFILES
# =============================================================================

CATEGORY_PROCESS_PROFILES: Dict[str, List[Tuple[Dict[str, str], float]]] = {
    TECH_ENGINEERING: [
        ({"process_name": "code.exe",       "path": "C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\code.exe"}, 5.0),
        ({"process_name": "node.exe",       "path": "C:\\Program Files\\nodejs\\node.exe"},                                       4.0),
        ({"process_name": "python.exe",     "path": "C:\\Python311\\python.exe"},                                                   3.5),
        ({"process_name": "docker.exe",     "path": "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"},               2.5),
        ({"process_name": "git.exe",        "path": "C:\\Program Files\\Git\\cmd\\git.exe"},                                        3.0),
        ({"process_name": "npm.cmd",        "path": "C:\\Program Files\\nodejs\\npm.cmd"},                                          2.0),
        ({"process_name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},              2.0),
        ({"process_name": "cmd.exe",        "path": "C:\\Windows\\System32\\cmd.exe"},                                              1.5),
    ],
    TECH_DATA: [
        ({"process_name": "python.exe",     "path": "C:\\Python311\\python.exe"},                                                   5.0),
        ({"process_name": "jupyter.exe",    "path": "C:\\Python311\\Scripts\\jupyter.exe"},                                         3.5),
        ({"process_name": "code.exe",       "path": "C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\code.exe"}, 3.0),
        ({"process_name": "docker.exe",     "path": "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"},               2.0),
        ({"process_name": "git.exe",        "path": "C:\\Program Files\\Git\\cmd\\git.exe"},                                        2.0),
        ({"process_name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},              1.5),
    ],
    TECH_OPS: [
        ({"process_name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},              5.0),
        ({"process_name": "mmc.exe",        "path": "C:\\Windows\\System32\\mmc.exe"},                                              3.0),
        ({"process_name": "cmd.exe",        "path": "C:\\Windows\\System32\\cmd.exe"},                                              3.0),
        ({"process_name": "mstsc.exe",      "path": "C:\\Windows\\System32\\mstsc.exe"},                                            2.5),
        ({"process_name": "ssh.exe",        "path": "C:\\Windows\\System32\\OpenSSH\\ssh.exe"},                                     2.0),
        ({"process_name": "regedit.exe",    "path": "C:\\Windows\\regedit.exe"},                                                    1.0),
    ],
    BUSINESS_FINANCE: [
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             6.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.0),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   3.0),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         1.5),
        ({"process_name": "PBIDesktop.exe", "path": "C:\\Program Files\\Microsoft Power BI Desktop\\bin\\PBIDesktop.exe"},         1.5),
    ],
    FINANCE_SPECIALIZED: [
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             6.0),
        ({"process_name": "bloomberg.exe",   "path": "C:\\blp\\API\\bloomberg.exe"},                                                4.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           2.5),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   2.0),
        ({"process_name": "python.exe",     "path": "C:\\Python311\\python.exe"},                                                   2.0),
        ({"process_name": "PBIDesktop.exe", "path": "C:\\Program Files\\Microsoft Power BI Desktop\\bin\\PBIDesktop.exe"},         1.5),
    ],
    PROFESSIONAL_LEGAL: [
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           6.0),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   5.0),
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           4.0),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             2.0),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         1.5),
    ],
    PROFESSIONAL_CLINICAL: [
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.0),
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           4.0),
        ({"process_name": "chrome.exe",     "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},                  5.0),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   3.0),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             2.0),
    ],
    PROFESSIONAL_TRADES: [
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             4.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.0),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   3.0),
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           3.0),
        ({"process_name": "chrome.exe",     "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},                  2.0),
    ],
    BUSINESS_SALES: [
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           5.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.5),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             3.0),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         3.0),
        ({"process_name": "chrome.exe",     "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},                  2.0),
    ],
    BUSINESS_MARKETING: [
        ({"process_name": "chrome.exe",     "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},                  4.0),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         3.5),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.0),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   2.0),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             2.0),
    ],
    BUSINESS_OPERATIONS: [
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             4.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.5),
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           3.5),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   2.0),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         1.5),
    ],
    PEOPLE_HR: [
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           4.0),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             3.5),
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           4.0),
        ({"process_name": "AcroRd32.exe",   "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},   2.5),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         2.0),
    ],
    PEOPLE_SUPPORT: [
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           5.0),
        ({"process_name": "chrome.exe",     "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},                  4.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           2.5),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             2.0),
    ],
    LEADERSHIP: [
        ({"process_name": "OUTLOOK.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},           5.0),
        ({"process_name": "POWERPNT.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},         4.0),
        ({"process_name": "WINWORD.EXE",    "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},           3.0),
        ({"process_name": "EXCEL.EXE",      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},             2.5),
        ({"process_name": "chrome.exe",     "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},                  2.0),
    ],
}

_DEFAULT_PROCESS_PROFILE: List[Tuple[Dict[str, str], float]] = [
    ({"process_name": "WINWORD.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},    4.0),
    ({"process_name": "EXCEL.EXE",     "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},      3.0),
    ({"process_name": "OUTLOOK.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},    4.0),
    ({"process_name": "AcroRd32.exe",  "path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"}, 2.0),
    ({"process_name": "POWERPNT.EXE",  "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},  1.5),
    ({"process_name": "chrome.exe",    "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},           2.0),
]


def get_process_profile(
    department: str, company: Optional[Company] = None,
) -> List[Tuple[Dict[str, str], float]]:
    """Get process profile for a department."""
    cat = get_category(department, company)
    return CATEGORY_PROCESS_PROFILES.get(cat, _DEFAULT_PROCESS_PROFILE)


# =============================================================================
# CATEGORY -> APP AFFINITY
# =============================================================================

CATEGORY_APP_AFFINITY: Dict[str, Dict[str, float]] = {
    TECH_ENGINEERING:      {"GitHub": 3.0, "GitLab": 2.5, "Bitbucket": 2.0, "Jira": 2.0, "Confluence": 1.5, "AWS": 2.0, "Google Cloud Platform": 1.5, "Azure": 1.5, "Datadog": 2.0, "PagerDuty": 1.5},
    TECH_OPS:              {"Okta": 2.5, "1Password": 2.0, "ServiceNow": 2.0, "AWS": 1.5, "PagerDuty": 2.0, "Datadog": 1.5},
    TECH_DATA:             {"Snowflake": 2.5, "Tableau": 2.0, "Power BI": 1.5, "GitHub": 1.5},
    BUSINESS_SALES:        {"Salesforce": 3.0, "HubSpot": 2.0, "DocuSign": 2.0, "Zoom": 1.5},
    BUSINESS_MARKETING:    {"HubSpot": 2.0, "Canva": 2.5, "Figma": 1.5},
    BUSINESS_FINANCE:      {"QuickBooks": 3.0, "NetSuite": 2.5, "Expensify": 2.0, "Concur": 2.0},
    BUSINESS_OPERATIONS:   {"ServiceNow": 2.0, "Jira": 1.5},
    PEOPLE_HR:             {"Workday": 3.0, "BambooHR": 2.5, "DocuSign": 1.5},
    PEOPLE_SUPPORT:        {"Zendesk": 2.5, "Freshdesk": 2.0, "Salesforce": 1.5},
    PROFESSIONAL_LEGAL:    {"DocuSign": 2.5, "Dropbox": 2.0, "Box": 2.0},
    PROFESSIONAL_CLINICAL: {"Zoom": 1.5},
    PROFESSIONAL_TRADES:   {"ServiceNow": 1.5},
    LEADERSHIP:            {"Zoom": 1.5},
    FINANCE_SPECIALIZED:   {"Salesforce": 2.0, "DocuSign": 1.5},
}


def get_app_affinity(department: str, company: Optional[Company] = None) -> Dict[str, float]:
    """Get app affinity dict for a department."""
    cat = get_category(department, company)
    return CATEGORY_APP_AFFINITY.get(cat, {})


# =============================================================================
# CATEGORY -> WORKFLOW AFFINITY
# =============================================================================

# Maps workflow name -> list of categories that have high affinity
CATEGORY_WORKFLOW_AFFINITY: Dict[str, List[str]] = {
    "meeting_notes": [
        TECH_ENGINEERING, BUSINESS_SALES, BUSINESS_MARKETING, BUSINESS_FINANCE,
        BUSINESS_OPERATIONS, PEOPLE_HR, LEADERSHIP, TECH_DATA, TECH_OPS,
        PROFESSIONAL_LEGAL, PROFESSIONAL_CLINICAL, FINANCE_SPECIALIZED,
    ],
    "code_review": [TECH_ENGINEERING, TECH_DATA],
    "incident_response": [TECH_ENGINEERING, TECH_OPS],
    "sales_cycle": [BUSINESS_SALES, FINANCE_SPECIALIZED],
    "hr_onboarding": [PEOPLE_HR],
    "expense_report": [
        TECH_ENGINEERING, BUSINESS_SALES, BUSINESS_MARKETING, PEOPLE_HR,
        BUSINESS_FINANCE, TECH_OPS, BUSINESS_OPERATIONS, LEADERSHIP,
        PROFESSIONAL_LEGAL, FINANCE_SPECIALIZED,
    ],
    "design_review": [BUSINESS_MARKETING, TECH_ENGINEERING],
}


def get_workflow_affinity(workflow_name: str, department: str, company: Optional[Company] = None) -> float:
    """Get affinity multiplier for a workflow given a department.

    Returns 3.0 if the department's category is in the workflow's affinity list,
    1.0 otherwise.
    """
    cat = get_category(department, company)
    affinity_cats = CATEGORY_WORKFLOW_AFFINITY.get(workflow_name, [])
    return 3.0 if cat in affinity_cats else 1.0


# =============================================================================
# CATEGORY -> EMAIL TEMPLATES
# =============================================================================

CATEGORY_SUBJECT_TEMPLATES: Dict[str, List[str]] = {
    TECH_ENGINEERING: [
        "Code review request: {topic}",
        "Sprint planning notes",
        "Bug report: {topic}",
        "Architecture discussion: {topic}",
        "Deployment update for {topic}",
        "Technical spec review needed",
        "Testing results for {topic}",
    ],
    TECH_OPS: [
        "System maintenance notice",
        "Security update: {topic}",
        "Access request: {topic}",
        "IT ticket resolved: {topic}",
        "Software license renewal",
        "Network upgrade announcement",
        "Password reset required",
    ],
    TECH_DATA: [
        "Data pipeline status: {topic}",
        "Model performance review",
        "Dashboard update: {topic}",
        "Data quality alert: {topic}",
        "Analytics report: {topic}",
        "Dataset access request",
        "Experiment results: {topic}",
    ],
    BUSINESS_SALES: [
        "Follow-up: {topic} meeting",
        "Proposal for {topic}",
        "Q{quarter} pipeline update",
        "Client feedback on {topic}",
        "Deal status: {topic}",
        "Pricing discussion",
        "Contract review needed",
    ],
    BUSINESS_MARKETING: [
        "Campaign results: {topic}",
        "Brand guidelines update",
        "Content review: {topic}",
        "Event planning: {topic}",
        "Social media metrics",
        "Press release draft",
        "Marketing materials ready",
    ],
    BUSINESS_FINANCE: [
        "Budget review: {topic}",
        "Expense report approval",
        "Q{quarter} financial summary",
        "Invoice processing: {topic}",
        "Audit preparation",
        "Payment confirmation",
        "Forecast update",
    ],
    BUSINESS_OPERATIONS: [
        "Process improvement: {topic}",
        "Inventory update",
        "Logistics coordination: {topic}",
        "Quality report: {topic}",
        "Vendor communication",
        "Operational metrics review",
        "Facility update",
    ],
    PEOPLE_HR: [
        "Interview feedback: {topic}",
        "Onboarding checklist",
        "Benefits enrollment reminder",
        "Performance review schedule",
        "Team training: {topic}",
        "Policy update notification",
        "Hiring update for {topic} role",
    ],
    PEOPLE_SUPPORT: [
        "Customer feedback summary",
        "Support ticket escalation: {topic}",
        "SLA review",
        "Training session notes",
        "Customer success update: {topic}",
        "Issue resolution: {topic}",
        "NPS scores review",
    ],
    PROFESSIONAL_LEGAL: [
        "Case update: {topic}",
        "Contract review: {topic}",
        "Filing deadline reminder",
        "Document review: {topic}",
        "Compliance update: {topic}",
        "Legal research: {topic}",
        "Deposition preparation",
    ],
    PROFESSIONAL_CLINICAL: [
        "Patient care update: {topic}",
        "Lab results review: {topic}",
        "Staff scheduling: {topic}",
        "Protocol update: {topic}",
        "Compliance training reminder",
        "Equipment maintenance notice",
        "Department meeting notes",
    ],
    PROFESSIONAL_TRADES: [
        "Production schedule: {topic}",
        "Quality inspection report: {topic}",
        "Safety briefing: {topic}",
        "Equipment status: {topic}",
        "Shift handoff notes",
        "Maintenance request: {topic}",
        "Material shortage alert",
    ],
    LEADERSHIP: [
        "Q{quarter} strategy review",
        "Board meeting preparation",
        "Organizational update: {topic}",
        "Budget approval: {topic}",
        "Executive team sync",
        "Stakeholder communication",
        "Key initiative update: {topic}",
    ],
    FINANCE_SPECIALIZED: [
        "Portfolio review: {topic}",
        "Trade execution summary",
        "Risk assessment: {topic}",
        "Client portfolio update",
        "Market analysis: {topic}",
        "Compliance filing: {topic}",
        "Deal pipeline: {topic}",
    ],
}

_DEFAULT_SUBJECT_TEMPLATES: List[str] = [
    "Weekly sync notes",
    "Project update: {topic}",
    "Meeting follow-up",
    "Quick question about {topic}",
    "FYI: {topic}",
    "Action items from meeting",
    "Status update",
]


def get_subject_templates(department: str, company: Optional[Company] = None) -> List[str]:
    """Get email subject templates for a department."""
    cat = get_category(department, company)
    return CATEGORY_SUBJECT_TEMPLATES.get(cat, _DEFAULT_SUBJECT_TEMPLATES)


CATEGORY_CONTENT_TEMPLATES: Dict[str, List[str]] = {
    TECH_ENGINEERING: [
        "This email discusses the technical implementation details for {topic}. Key points include the proposed architecture changes and timeline estimates.",
        "Summary of code review findings for the {topic} feature. Several optimizations were suggested that could improve performance.",
        "Update on the deployment status. All tests passed and the release is scheduled for next week.",
        "Discussion about the bug reported in {topic}. Root cause analysis is attached along with proposed fixes.",
    ],
    TECH_OPS: [
        "Scheduled maintenance window for {topic} systems this weekend. Expected downtime is 2-4 hours.",
        "Security alert regarding {topic}. Please update your password and enable MFA if not already done.",
        "Access request for {topic} has been approved. Credentials are provided in the secure attachment.",
        "IT ticket #{topic} has been resolved. Please confirm the issue is fixed and close the ticket.",
    ],
    TECH_DATA: [
        "Data pipeline for {topic} completed successfully. Key metrics and anomalies are summarized below.",
        "Model retraining results for {topic} are attached. Accuracy improved by 3% over the previous version.",
        "Dashboard for {topic} has been updated with the latest data. Please review the new visualizations.",
        "Data quality issue detected in {topic}. Affected records and remediation steps are outlined below.",
    ],
    BUSINESS_SALES: [
        "Follow-up from our meeting regarding {topic}. Attached is the proposal with pricing details as discussed.",
        "Pipeline update for this quarter. Key opportunities and their current status are summarized below.",
        "Client feedback on the {topic} demo was positive. They requested additional information about enterprise features.",
        "Contract terms have been reviewed by legal. Please see attached redlined version with our proposed changes.",
    ],
    BUSINESS_MARKETING: [
        "Campaign performance report for {topic} is attached. Key metrics exceeded targets by 15%.",
        "Content review needed for {topic} materials. Please provide feedback by end of week.",
        "Event planning update for {topic}. Venue is confirmed and speaker lineup is attached.",
        "Brand guidelines have been updated. Please review attached document for the latest standards.",
    ],
    BUSINESS_FINANCE: [
        "Q{quarter} budget review summary. Key variances and action items are highlighted in the attached report.",
        "Expense reports pending approval are attached. Please review and approve or reject by Friday.",
        "Invoice processing status for {topic}. Payment is scheduled for next week pending final approval.",
        "Audit preparation materials requested. Please provide the documentation listed in the attachment.",
    ],
    BUSINESS_OPERATIONS: [
        "Process improvement recommendations for {topic}. Implementation would reduce cycle time by 20%.",
        "Inventory levels update. Some items are approaching reorder thresholds and require attention.",
        "Logistics coordination for {topic} shipment. Tracking information and delivery ETA are attached.",
        "Quality metrics for {topic} are attached. Overall scores improved compared to last period.",
    ],
    PEOPLE_HR: [
        "Interview feedback for the {topic} candidate. Overall impressions were favorable and we recommend moving forward.",
        "Reminder about upcoming benefits enrollment deadline. Please review the attached summary of changes.",
        "Performance review documentation for this cycle. Managers should complete evaluations by end of month.",
        "Training schedule for {topic} has been finalized. Please confirm your attendance.",
    ],
    PEOPLE_SUPPORT: [
        "Customer feedback summary for {topic}. Common themes and suggested improvements are outlined.",
        "Escalated support ticket for {topic}. Customer is awaiting response and this is marked urgent.",
        "SLA performance review attached. Most metrics are within targets with a few exceptions noted.",
        "Customer success update for {topic} account. Renewal discussion is scheduled for next month.",
    ],
    PROFESSIONAL_LEGAL: [
        "Case update for {topic}. Key developments and next steps are outlined below.",
        "Contract review for {topic} is complete. Redlined version with recommended changes is attached.",
        "Filing deadline for {topic} is approaching. Please ensure all documents are prepared and reviewed.",
        "Legal research on {topic} is attached. Summary of findings and risk assessment included.",
    ],
    PROFESSIONAL_CLINICAL: [
        "Protocol update for {topic}. New guidelines are effective immediately and training is scheduled.",
        "Lab results for {topic} are available. Please review and follow up with the care team.",
        "Staffing schedule for {topic} has been finalized. Please check your assignments and report conflicts.",
        "Equipment maintenance for {topic} is scheduled. Alternative procedures are outlined below.",
    ],
    PROFESSIONAL_TRADES: [
        "Production schedule for {topic} has been updated. Revised targets and shift assignments are attached.",
        "Quality inspection results for {topic}. Two items flagged for review — details in the report.",
        "Safety briefing for {topic}. All team members must review before the next shift.",
        "Maintenance request for {topic} has been submitted. Estimated downtime and workaround plan attached.",
    ],
    LEADERSHIP: [
        "Q{quarter} strategic review materials are attached. Key metrics and initiative updates are summarized.",
        "Board meeting agenda and preparation documents for {topic}. Please review before the session.",
        "Organizational update regarding {topic}. Details on the changes and timeline are outlined below.",
        "Budget approval request for {topic}. Business case and financial projections are attached.",
    ],
    FINANCE_SPECIALIZED: [
        "Portfolio performance review for {topic}. Returns and key attribution analysis are attached.",
        "Trade execution summary for today's session. All orders filled within target parameters.",
        "Risk assessment for {topic} is complete. Exposure levels and mitigation recommendations are attached.",
        "Client portfolio update for {topic}. Recommended rebalancing actions are outlined below.",
    ],
}

_DEFAULT_CONTENT_TEMPLATES: List[str] = [
    "This email provides an update on {topic}. Please review the attached materials and let me know if you have questions.",
    "Follow-up from our recent discussion about {topic}. Action items are summarized below.",
    "Quick update on the status of {topic}. Everything is on track for the planned timeline.",
    "FYI - sharing information about {topic} that may be relevant to your current projects.",
]


def get_content_templates(department: str, company: Optional[Company] = None) -> List[str]:
    """Get email content templates for a department."""
    cat = get_category(department, company)
    return CATEGORY_CONTENT_TEMPLATES.get(cat, _DEFAULT_CONTENT_TEMPLATES)
