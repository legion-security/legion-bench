"""
Process event log generation for company fixtures.

Generates realistic Windows EDR process events with:
- File-to-process correlation (e.g. .docx → WINWORD.EXE, .xlsx → EXCEL.EXE)
- App-to-process correlation (e.g. "Slack" → slack.exe 0-3 min before)
- Role-based process profiles (Engineering → code.exe, python.exe; Finance → EXCEL.EXE)
- Weighted background OS processes (svchost.exe dominates, realistic service groups)
- Process lifecycle pairing (start → stop with log-normal durations)
- Multi-level process trees (explorer→cmd→python, services→svchost→taskhostw)
- Full field population: command_line, hash, user_context for every event
- Scheduled task circadian profiles (Defender scans at 2AM, indexing at 3-4AM)
- Role-conditioned event counts (Engineering ~2.5/day, IT ~3.5/day, General ~0.8/day)
"""
from __future__ import annotations

import hashlib
import math
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import os

from .user_activity import (
    add_process_event_logs,
    _collect_person_apps,
    _collect_person_device_ids,
    vary_count,
)
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
from .department_categories import classify_role_tier

Person = Dict[str, Any]
Company = Dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1a. File extension → process mapping ────────────────────────────────────

_EXT_TO_PROCESS: Dict[str, Dict[str, str]] = {
    ".docx": {"process_name": "WINWORD.EXE", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},
    ".doc":  {"process_name": "WINWORD.EXE", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},
    ".xlsx": {"process_name": "EXCEL.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},
    ".xls":  {"process_name": "EXCEL.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},
    ".csv":  {"process_name": "EXCEL.EXE",   "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"},
    ".pptx": {"process_name": "POWERPNT.EXE","path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},
    ".ppt":  {"process_name": "POWERPNT.EXE","path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"},
    ".pdf":  {"process_name": "AcroRd32.exe","path": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"},
    ".txt":  {"process_name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
    ".log":  {"process_name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
    ".py":   {"process_name": "python.exe",  "path": "C:\\Python311\\python.exe"},
    ".js":   {"process_name": "node.exe",    "path": "C:\\Program Files\\nodejs\\node.exe"},
    ".json": {"process_name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
    ".yaml": {"process_name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
    ".yml":  {"process_name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
    ".md":   {"process_name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
    ".html": {"process_name": "chrome.exe",  "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
    ".htm":  {"process_name": "chrome.exe",  "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
}

# ── 1b. Weighted background processes ────────────────────────────────────────

_WEIGHTED_BACKGROUND_PROCESSES: List[Tuple[Dict[str, str], float]] = [
    ({"process_name": "svchost.exe",      "path": "C:\\Windows\\System32\\svchost.exe",                    "parent_process": "services.exe"},          40.0),
    ({"process_name": "MsMpEng.exe",      "path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe", "parent_process": "services.exe"}, 10.0),
    ({"process_name": "RuntimeBroker.exe","path": "C:\\Windows\\System32\\RuntimeBroker.exe",              "parent_process": "svchost.exe"},            8.0),
    ({"process_name": "dwm.exe",          "path": "C:\\Windows\\System32\\dwm.exe",                       "parent_process": "winlogon.exe"},           6.0),
    ({"process_name": "taskhostw.exe",    "path": "C:\\Windows\\System32\\taskhostw.exe",                  "parent_process": "svchost.exe"},            5.0),
    ({"process_name": "SearchHost.exe",   "path": "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe", "parent_process": "svchost.exe"}, 5.0),
    ({"process_name": "ctfmon.exe",       "path": "C:\\Windows\\System32\\ctfmon.exe",                     "parent_process": "svchost.exe"},            4.0),
    ({"process_name": "spoolsv.exe",      "path": "C:\\Windows\\System32\\spoolsv.exe",                   "parent_process": "services.exe"},           4.0),
    ({"process_name": "WmiPrvSE.exe",     "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",            "parent_process": "svchost.exe"},            3.5),
    ({"process_name": "conhost.exe",      "path": "C:\\Windows\\System32\\conhost.exe",                    "parent_process": "csrss.exe"},              3.0),
    ({"process_name": "lsass.exe",        "path": "C:\\Windows\\System32\\lsass.exe",                      "parent_process": "wininit.exe"},            2.5),
    ({"process_name": "csrss.exe",        "path": "C:\\Windows\\System32\\csrss.exe",                      "parent_process": "smss.exe"},               2.0),
    ({"process_name": "SecurityHealthSystray.exe", "path": "C:\\Windows\\System32\\SecurityHealthSystray.exe", "parent_process": "explorer.exe"},       2.0),
    ({"process_name": "sihost.exe",       "path": "C:\\Windows\\System32\\sihost.exe",                     "parent_process": "svchost.exe"},            2.0),
    ({"process_name": "explorer.exe",     "path": "C:\\Windows\\explorer.exe",                              "parent_process": "userinit.exe"},          2.0),
    ({"process_name": "audiodg.exe",      "path": "C:\\Windows\\System32\\audiodg.exe",                    "parent_process": "svchost.exe"},            1.0),
]
_BG_NAMES = [p[0]["process_name"] for p in _WEIGHTED_BACKGROUND_PROCESSES]
_BG_WEIGHTS = [p[1] for p in _WEIGHTED_BACKGROUND_PROCESSES]

# System-level processes (run as SYSTEM or NETWORK SERVICE)
_SYSTEM_PROCESSES = {
    "svchost.exe", "MsMpEng.exe", "lsass.exe", "csrss.exe", "services.exe",
    "smss.exe", "wininit.exe", "winlogon.exe", "System", "dwm.exe",
    "spoolsv.exe", "SearchHost.exe", "WmiPrvSE.exe", "taskhostw.exe",
    "audiodg.exe", "RuntimeBroker.exe",
}

_NETWORK_SERVICE_PROCESSES = {"WmiPrvSE.exe", "spoolsv.exe"}

# ── 1c. svchost.exe service group variants ───────────────────────────────────

_SVCHOST_SERVICE_GROUPS: List[str] = [
    "netsvcs", "LocalService", "NetworkService", "DcomLaunch",
    "LocalServiceNetworkRestricted", "LocalServiceNoNetwork",
    "LocalSystemNetworkRestricted", "UnistackSvcGroup",
    "appmodel", "ClipboardSvcGroup", "WbioSvcGroup", "termsvcs",
]

# NOTE: Role-based process profiles are now defined in department_categories.py
# via CATEGORY_PROCESS_PROFILES, accessed through get_process_profile().

# ── 1e. Process tree templates ───────────────────────────────────────────────

_PROCESS_TREE_TEMPLATES: Dict[str, List[List[str]]] = {
    "developer": [
        ["explorer.exe", "cmd.exe", "python.exe"],
        ["explorer.exe", "cmd.exe", "node.exe"],
        ["explorer.exe", "code.exe", "node.exe"],
        ["explorer.exe", "cmd.exe", "git.exe"],
        ["explorer.exe", "powershell.exe", "docker.exe"],
        ["explorer.exe", "cmd.exe", "npm.cmd"],
    ],
    "it_admin": [
        ["explorer.exe", "powershell.exe", "gpupdate.exe"],
        ["explorer.exe", "powershell.exe", "net.exe"],
        ["explorer.exe", "mmc.exe"],
        ["explorer.exe", "cmd.exe", "ipconfig.exe"],
        ["explorer.exe", "powershell.exe", "dsquery.exe"],
    ],
    "scheduled": [
        ["services.exe", "svchost.exe", "taskhostw.exe", "powershell.exe"],
        ["services.exe", "svchost.exe", "WmiPrvSE.exe"],
        ["services.exe", "svchost.exe", "taskhostw.exe"],
    ],
}

# Map process names to tree categories
_PROCESS_TO_TREE_CATEGORY: Dict[str, str] = {
    "python.exe": "developer", "node.exe": "developer", "git.exe": "developer",
    "npm.cmd": "developer", "docker.exe": "developer", "code.exe": "developer",
    "jupyter.exe": "developer", "kubectl.exe": "developer", "terraform.exe": "developer",
    "powershell.exe": "it_admin", "cmd.exe": "it_admin", "gpupdate.exe": "it_admin",
    "mmc.exe": "it_admin", "regedit.exe": "it_admin", "mstsc.exe": "it_admin",
    "ssh.exe": "it_admin", "nmap.exe": "it_admin", "wireshark.exe": "it_admin",
}

# ── 1f. Process duration profiles (log-normal parameters) ────────────────────

_DURATION_PROFILES: Dict[str, Tuple[float, float]] = {
    # (mu, sigma) for log-normal distribution in seconds
    # median = exp(mu), spread controlled by sigma
    "desktop_app":  (math.log(4680),  0.7),   # median ~1.3h, range 20m-6h
    "cli_tool":     (math.log(20),    1.2),   # median ~20s, range 2s-10m
    "background":   (math.log(21600), 0.8),   # median ~6h, range 45m-days
    "browser":      (math.log(7920),  0.6),   # median ~2.2h, range 50m-8h
    "ide":          (math.log(13320), 0.5),   # median ~3.7h, range 1.5h-10h
}

# Map process names to duration profiles
_PROCESS_DURATION_MAP: Dict[str, str] = {
    "WINWORD.EXE": "desktop_app", "EXCEL.EXE": "desktop_app", "POWERPNT.EXE": "desktop_app",
    "OUTLOOK.EXE": "desktop_app", "AcroRd32.exe": "desktop_app", "PBIDesktop.exe": "desktop_app",
    "Figma.exe": "ide", "Notion.exe": "desktop_app", "tableau.exe": "desktop_app",
    "chrome.exe": "browser", "Teams.exe": "browser", "Zoom.exe": "desktop_app",
    "slack.exe": "desktop_app", "1Password.exe": "desktop_app",
    "code.exe": "ide", "jupyter.exe": "ide",
    "python.exe": "cli_tool", "node.exe": "cli_tool", "git.exe": "cli_tool",
    "npm.cmd": "cli_tool", "docker.exe": "cli_tool", "cmd.exe": "cli_tool",
    "powershell.exe": "cli_tool", "kubectl.exe": "cli_tool", "terraform.exe": "cli_tool",
    "mmc.exe": "desktop_app", "mstsc.exe": "desktop_app", "regedit.exe": "cli_tool",
    "gpupdate.exe": "cli_tool", "ssh.exe": "cli_tool", "nmap.exe": "cli_tool",
    "wireshark.exe": "desktop_app",
    # Background / system
    "svchost.exe": "background", "MsMpEng.exe": "background", "lsass.exe": "background",
    "csrss.exe": "background", "dwm.exe": "background", "spoolsv.exe": "background",
    "WmiPrvSE.exe": "background", "taskhostw.exe": "background", "SearchHost.exe": "background",
    "RuntimeBroker.exe": "background", "ctfmon.exe": "background", "conhost.exe": "cli_tool",
    "explorer.exe": "background", "sihost.exe": "background", "audiodg.exe": "background",
    "SecurityHealthSystray.exe": "background",
}

# ── 1g. Process event count tiers ────────────────────────────────────────────

_DEFAULT_PROCESS_RATES: Dict[str, Tuple[float, float]] = {
    # (mean_events_per_day, std)
    "eng_ic":         (2.5, 0.8),
    "eng_senior":     (3.0, 1.0),
    "ops_ic":         (3.5, 1.0),
    "ops_senior":     (4.0, 1.5),
    "general_ic":     (0.8, 0.3),
    "general_senior": (1.0, 0.4),
    "sales_ic":       (1.0, 0.4),
    "cs_ic":          (1.0, 0.4),
    "manager":        (1.2, 0.5),
    "executive":      (0.5, 0.2),
}

# NOTE: Department-to-tier classification is now handled by
# department_categories.classify_role_tier().

# ── 1h. Scheduled task circadian profiles ────────────────────────────────────

_SCHEDULED_TASK_PROFILES: Dict[str, Dict[str, Any]] = {
    "MsMpEng.exe":  {"peaks": [2.0, 14.0], "kappa": 4.0},   # Defender scans at 2AM and 2PM
    "taskhostw.exe":{"peaks": [3.0],        "kappa": 5.0},   # Scheduled tasks at 3AM
    "WmiPrvSE.exe": {"peaks": [0.0, 6.0, 12.0, 18.0], "kappa": 3.0},  # Every 6h
    "spoolsv.exe":  {"peaks": [8.5],        "kappa": 4.0},   # Print spooler 8-9AM
    "SearchHost.exe":{"peaks": [3.5],       "kappa": 5.0},   # Indexing at 3-4AM
}

# ── App-to-process mappings (kept from original) ────────────────────────────

_APP_TO_PROCESS: Dict[str, List[Dict[str, str]]] = {
    "Slack": [
        {"process_name": "slack.exe", "path": "C:\\Program Files\\Slack\\slack.exe", "parent_process": "explorer.exe"},
    ],
    "Microsoft Teams": [
        {"process_name": "Teams.exe", "path": "C:\\Program Files\\Microsoft\\Teams\\Teams.exe", "parent_process": "explorer.exe"},
    ],
    "Zoom": [
        {"process_name": "Zoom.exe", "path": "C:\\Program Files\\Zoom\\Zoom.exe", "parent_process": "explorer.exe"},
    ],
    "Google Workspace": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Microsoft 365": [
        {"process_name": "WINWORD.EXE", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "parent_process": "explorer.exe"},
        {"process_name": "EXCEL.EXE", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "parent_process": "explorer.exe"},
        {"process_name": "OUTLOOK.EXE", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "parent_process": "explorer.exe"},
    ],
    "GitHub": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
        {"process_name": "git.exe", "path": "C:\\Program Files\\Git\\cmd\\git.exe", "parent_process": "cmd.exe"},
    ],
    "GitLab": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
        {"process_name": "git.exe", "path": "C:\\Program Files\\Git\\cmd\\git.exe", "parent_process": "cmd.exe"},
    ],
    "Bitbucket": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
        {"process_name": "git.exe", "path": "C:\\Program Files\\Git\\cmd\\git.exe", "parent_process": "cmd.exe"},
    ],
    "Jira": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Confluence": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Asana": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Trello": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Notion": [
        {"process_name": "Notion.exe", "path": "C:\\Program Files\\Notion\\Notion.exe", "parent_process": "explorer.exe"},
    ],
    "Salesforce": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "HubSpot": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "AWS": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
        {"process_name": "aws.exe", "path": "C:\\Program Files\\Amazon\\AWSCLI\\aws.exe", "parent_process": "cmd.exe"},
    ],
    "Google Cloud Platform": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
        {"process_name": "gcloud.exe", "path": "C:\\Program Files\\Google\\Cloud SDK\\gcloud.exe", "parent_process": "cmd.exe"},
    ],
    "Azure": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
        {"process_name": "az.exe", "path": "C:\\Program Files\\Microsoft\\Azure CLI\\az.exe", "parent_process": "cmd.exe"},
    ],
    "Snowflake": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Tableau": [
        {"process_name": "tableau.exe", "path": "C:\\Program Files\\Tableau\\tableau.exe", "parent_process": "explorer.exe"},
    ],
    "Power BI": [
        {"process_name": "PBIDesktop.exe", "path": "C:\\Program Files\\Microsoft Power BI Desktop\\bin\\PBIDesktop.exe", "parent_process": "explorer.exe"},
    ],
    "Figma": [
        {"process_name": "Figma.exe", "path": "C:\\Program Files\\Figma\\Figma.exe", "parent_process": "explorer.exe"},
    ],
    "Canva": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Okta": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "1Password": [
        {"process_name": "1Password.exe", "path": "C:\\Program Files\\1Password\\1Password.exe", "parent_process": "explorer.exe"},
    ],
    "Datadog": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Splunk": [
        {"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent_process": "explorer.exe"},
    ],
    "Dropbox": [
        {"process_name": "Dropbox.exe", "path": "C:\\Program Files\\Dropbox\\Dropbox.exe", "parent_process": "explorer.exe"},
    ],
    "Box": [
        {"process_name": "Box.exe", "path": "C:\\Program Files\\Box\\Box.exe", "parent_process": "explorer.exe"},
    ],
}

_BROWSER_PROCESS = {
    "process_name": "chrome.exe",
    "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "parent_process": "explorer.exe",
}


# ═══════════════════════════════════════════════════════════════════════════════
# 2. HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_username(person: Person) -> str:
    """Derive a Windows username from a person record."""
    email = person.get("email", "")
    if email and "@" in email:
        return email.split("@")[0]
    name = person.get("name", "unknown")
    parts = name.lower().split()
    if len(parts) >= 2:
        return parts[0][0] + parts[-1]
    return parts[0] if parts else "unknown"


def _get_file_extension(file_path: str) -> Optional[str]:
    """Extract file extension from various path formats (local, UNC, SharePoint URL, Google Drive)."""
    if not file_path:
        return None
    # For URLs, extract path component first
    if "://" in file_path:
        parsed = urlparse(file_path)
        path = parsed.path
    else:
        path = file_path
    # Get the extension from the last component
    _, ext = os.path.splitext(path)
    ext = ext.lower()
    return ext if ext else None


def _deterministic_hash(process_name: str) -> str:
    """Generate a deterministic SHA256 hash for a given process executable name."""
    return hashlib.sha256(f"nexustech-edr-{process_name}".encode()).hexdigest()


def _resolve_process_event_count(
    person: Person,
    rng: random.Random,
    *,
    window_days: int = 30,
    baseline_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    company: Optional[Company] = None,
) -> int:
    """Resolve total process event count for the generation window.

    Resolution order:
    1. person["behavior_baselines"]["process_event_baseline"]["avg_events_per_day"]
    2. Role tier from _DEFAULT_PROCESS_RATES

    The resolved rate is then scaled by ``baseline_multiplier`` (e.g. 2.0 = twice
    as many events).  This preserves the department-level differentiation at every
    activity level.
    """
    baselines = person.get("behavior_baselines") or {}
    bl = baselines.get("process_event_baseline")
    if isinstance(bl, dict) and "avg_events_per_day" in bl:
        avg_spec = bl["avg_events_per_day"]
        if isinstance(avg_spec, dict):
            mean_per_day = float(avg_spec.get("mean", 1.0))
            std_per_day = float(avg_spec.get("std", 0.5)) * baseline_std_scale
        else:
            mean_per_day = float(avg_spec)
            std_per_day = mean_per_day * 0.25 * baseline_std_scale
    else:
        tier = classify_role_tier(person, company)
        mean_per_day, std_per_day = _DEFAULT_PROCESS_RATES.get(tier, (0.8, 0.3))
        std_per_day = std_per_day * baseline_std_scale

    # Apply multiplier to both mean and std so the distribution shape is preserved
    mean_per_day *= baseline_multiplier
    std_per_day *= baseline_multiplier

    person_rate = max(0.0, rng.gauss(mean_per_day, std_per_day))
    total = person_rate * window_days
    return max(0, round(total))


def _generate_command_line(process_name: str, path: str, rng: random.Random, *, file_arg: str = "") -> str:
    """Generate a realistic command line for a user-mode process."""
    quoted_path = f'"{path}"'

    if file_arg:
        return f'{quoted_path} "{file_arg}"'

    if process_name == "git.exe":
        cmds = [
            "git pull", "git push", "git status", "git diff",
            'git commit -m "Update changes"', "git fetch origin",
            "git checkout -b feature/update", "git merge main",
            "git log --oneline -10", "git stash",
        ]
        return rng.choice(cmds)

    if process_name == "python.exe":
        cmds = [
            f'{quoted_path} manage.py runserver',
            f'{quoted_path} -m pytest tests/',
            f'{quoted_path} -m pip install -r requirements.txt',
            f'{quoted_path} scripts/deploy.py',
            f'{quoted_path} -m flask run',
            f'{quoted_path} setup.py install',
        ]
        return rng.choice(cmds)

    if process_name == "node.exe":
        cmds = [
            f'{quoted_path} server.js',
            f'{quoted_path} index.js',
            f'{quoted_path} node_modules/.bin/webpack --mode production',
            f'{quoted_path} scripts/build.js',
        ]
        return rng.choice(cmds)

    if process_name == "npm.cmd":
        cmds = ["npm install", "npm run build", "npm run test", "npm run dev", "npm start"]
        return rng.choice(cmds)

    if process_name == "docker.exe":
        cmds = [
            "docker build -t app:latest .",
            "docker-compose up -d",
            "docker ps",
            "docker pull nginx:latest",
            "docker logs --tail 100 app-container",
        ]
        return rng.choice(cmds)

    if process_name == "kubectl.exe":
        cmds = [
            "kubectl get pods -n production",
            "kubectl describe pod app-server-0 -n production",
            "kubectl logs -f deployment/api-server -n production",
            "kubectl apply -f deployment.yaml",
            "kubectl rollout status deployment/api-server -n production",
        ]
        return rng.choice(cmds)

    if process_name == "terraform.exe":
        cmds = [
            "terraform plan -out=tfplan",
            "terraform apply tfplan",
            "terraform init",
            "terraform state list",
        ]
        return rng.choice(cmds)

    if process_name == "powershell.exe":
        cmds = [
            f'{quoted_path} -Command "Get-Process"',
            f'{quoted_path} -Command "Get-Service | Where-Object Status -eq Running"',
            f'{quoted_path} -File "C:\\Scripts\\backup.ps1"',
            f'{quoted_path} -Command "Get-EventLog -LogName System -Newest 50"',
            f'{quoted_path} -Command "Test-NetConnection -ComputerName fileserver01 -Port 445"',
            f'{quoted_path} -Command "Get-ADUser -Filter * -SearchBase \\"OU=Users,DC=corp,DC=internal\\""',
        ]
        return rng.choice(cmds)

    if process_name == "cmd.exe":
        cmds = [
            f'{quoted_path} /c "dir C:\\Users"',
            f'{quoted_path} /c "ipconfig /all"',
            f'{quoted_path} /c "netstat -an"',
            f'{quoted_path} /c "ping fileserver01"',
        ]
        return rng.choice(cmds)

    if process_name == "ssh.exe":
        hosts = ["bastion01.corp.internal", "prod-web-01", "staging-db-01", "monitoring-01"]
        return f'{quoted_path} admin@{rng.choice(hosts)}'

    if process_name == "nmap.exe":
        cmds = [
            f'{quoted_path} -sV -p 1-1000 10.0.1.0/24',
            f'{quoted_path} -sn 10.0.0.0/16',
            f'{quoted_path} -A 10.0.1.50',
        ]
        return rng.choice(cmds)

    if process_name == "mstsc.exe":
        hosts = ["fileserver01", "dc01.corp.internal", "print-server-01", "app-server-02"]
        return f'{quoted_path} /v:{rng.choice(hosts)}'

    if process_name == "gpupdate.exe":
        return f'{quoted_path} /force'

    if process_name == "jupyter.exe":
        return f'{quoted_path} notebook --port={rng.randint(8888, 8899)}'

    # Default: just the quoted path
    return quoted_path


def _generate_bg_command_line(process_name: str, path: str, rng: random.Random) -> str:
    """Generate a realistic command line for a background/system process."""
    quoted_path = f'"{path}"'

    if process_name == "svchost.exe":
        group = rng.choice(_SVCHOST_SERVICE_GROUPS)
        return f'{quoted_path} -k {group}'

    if process_name == "taskhostw.exe":
        tasks = [
            "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            "\\Microsoft\\Windows\\Maintenance\\WinSAT",
            "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup",
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
        ]
        return f'{quoted_path} {rng.choice(tasks)}'

    if process_name == "MsMpEng.exe":
        return quoted_path  # Defender doesn't expose cmdline args

    if process_name == "WmiPrvSE.exe":
        return f'{quoted_path} -Embedding'

    # Default system process: just the path
    return quoted_path


def _resolve_user_context(process_name: str, username: str) -> str:
    """Determine the user context for a process event."""
    if process_name in _NETWORK_SERVICE_PROCESSES:
        return "NT AUTHORITY\\NETWORK SERVICE"
    if process_name in _SYSTEM_PROCESSES:
        return "NT AUTHORITY\\SYSTEM"
    return f"CORP\\{username}"


def _resolve_integrity_level(process_name: str) -> str:
    """Determine integrity level for a process."""
    if process_name in _SYSTEM_PROCESSES:
        return "system"
    if process_name in ("regedit.exe", "mmc.exe", "gpupdate.exe"):
        return "high"
    return "medium"


def _build_process_event(
    *,
    ts: str,
    process_name: str,
    action: str,
    path: str,
    parent_process: str,
    pid: int,
    username: str,
    rng: random.Random,
    device_id: Optional[str] = None,
    command_line: Optional[str] = None,
    file_arg: str = "",
    is_background: bool = False,
) -> Dict[str, Any]:
    """Central event builder that populates ALL schema fields."""
    if command_line is None:
        if is_background:
            command_line = _generate_bg_command_line(process_name, path, rng)
        else:
            command_line = _generate_command_line(process_name, path, rng, file_arg=file_arg)

    event: Dict[str, Any] = {
        "ts": ts,
        "process_name": process_name,
        "action": action,
        "parent_process": parent_process,
        "path": path,
        "pid": pid,
        "integrity_level": _resolve_integrity_level(process_name),
        "command_line": command_line,
        "hash": _deterministic_hash(process_name),
        "user_context": _resolve_user_context(process_name, username),
    }
    if device_id:
        event["device_id"] = device_id
    return event


def _build_lifecycle_stop(
    start_event: Dict[str, Any],
    rng: random.Random,
) -> Optional[Dict[str, Any]]:
    """Generate a paired stop event for a start event with log-normal duration."""
    process_name = start_event["process_name"]
    profile_key = _PROCESS_DURATION_MAP.get(process_name, "cli_tool")
    mu, sigma = _DURATION_PROFILES.get(profile_key, _DURATION_PROFILES["cli_tool"])

    duration_seconds = min(rng.lognormvariate(mu, sigma), 86400)  # cap at 24h

    try:
        start_ts = datetime.fromisoformat(start_event["ts"].replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

    stop_ts = start_ts + timedelta(seconds=duration_seconds)
    stop_event = dict(start_event)
    stop_event["ts"] = format_ts(stop_ts)
    stop_event["action"] = "stop"
    return stop_event


def _apply_process_tree(
    process_name: str,
    current_parent: str,
    rng: random.Random,
) -> str:
    """For CLI/developer processes, 40% chance to use a deeper parent chain."""
    category = _PROCESS_TO_TREE_CATEGORY.get(process_name)
    if not category:
        return current_parent
    if rng.random() > 0.4:
        return current_parent

    templates = _PROCESS_TREE_TEMPLATES.get(category, [])
    if not templates:
        return current_parent

    # Find templates where this process appears
    matching = [t for t in templates if process_name in t]
    if not matching:
        # Use any template from the category, return the second-to-last as parent
        chain = rng.choice(templates)
        return chain[-2] if len(chain) >= 2 else current_parent

    chain = rng.choice(matching)
    idx = chain.index(process_name)
    if idx > 0:
        return chain[idx - 1]
    return current_parent


def _weighted_choice(items: List[Tuple[Any, float]], rng: random.Random) -> Any:
    """Weighted random selection from (item, weight) pairs."""
    population = [item for item, _ in items]
    weights = [w for _, w in items]
    return rng.choices(population, weights=weights, k=1)[0]


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


def _emit_event(
    company: Company,
    container_kind: str,
    person_id: str,
    event: Dict[str, Any],
    stats: Dict[str, Any],
    *,
    category: str,
) -> None:
    """Emit a single process event and update stats."""
    add_process_event_logs(
        company,
        **_event_target_kwargs(container_kind, person_id),
        log=event,
    )
    stats["events_added"] += 1
    stats[f"{category}_events"] += 1
    stats["processes_used"][event["process_name"]] += 1


# ═══════════════════════════════════════════════════════════════════════════════
# 3. MAIN GENERATION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_process_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = True,
    baseline_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    background_ratio: float = 0.3,
    file_correlation_ratio: float = 0.5,
    generation_config: Optional[Dict[str, Any]] = None,
    burst_schedule: Optional[BurstSchedule] = None,
) -> Dict[str, int]:
    """
    Populate each person's recent_activity.process_events with realistic process events.

    Events are distributed across 4 buckets:
    - File-correlated (~25%): linked to file_events by extension (e.g. .docx → WINWORD.EXE)
    - App-correlated (~25%): linked to app_events (e.g. "Slack" → slack.exe)
    - Role-specific (~15-20%): department process profiles (Engineering → python.exe, code.exe)
    - Background (~30%): weighted OS processes with scheduled timing patterns

    Args:
        company: Company data dict
        seed: Base seed for deterministic generation
        replace_existing: If True, replace existing process events; if False, append
        baseline_multiplier: Scales the per-person baseline rate (1.0 = normal,
            2.0 = double, 0.5 = half).  Preserves department-level differentiation.
        background_ratio: Fraction of events that are background OS noise
        file_correlation_ratio: Fraction of eligible file events to correlate with processes
        generation_config: Temporal model configuration
        burst_schedule: Episodic burst schedule for count scaling

    Returns:
        Statistics dict with counts of generated events
    """
    people, container_kind = _select_people_container(company)

    stats: Dict[str, Any] = {
        "employees_total": len(people),
        "employees_with_events": 0,
        "events_requested": 0,
        "events_added": 0,
        "file_correlated_events": 0,
        "app_correlated_events": 0,
        "role_specific_events": 0,
        "background_events": 0,
        "lifecycle_stop_events": 0,
        "processes_used": defaultdict(int),
    }

    gen_cfg = generation_config or company.get("_generation_config") or {}

    if not people:
        stats["processes_used"] = dict(stats["processes_used"])
        return stats

    window_start = window_end = None
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)

    window_days = 30
    if gen_cfg:
        window_days = gen_cfg.get("temporal", {}).get("window_days", 30)

    base_seed = seed or 0

    for idx_person, person in enumerate(people):
        person_id = person.get("id")
        if not person_id:
            continue

        ra = person.setdefault("recent_activity", {})
        if replace_existing:
            ra.pop("process_events", None)

        rng = random.Random(base_seed * 1017 + idx_person)
        username = _extract_username(person)
        department = person.get("department", "")

        # ── Count resolution ─────────────────────────────────────────────
        target_events = _resolve_process_event_count(
            person, rng, window_days=window_days,
            baseline_multiplier=baseline_multiplier,
            baseline_std_scale=baseline_std_scale,
            company=company,
        )

        # Apply burst scaling
        if burst_schedule and burst_schedule.bursts and window_start and window_end:
            target_events = apply_burst_to_count(
                target_events, person_id, "process_events",
                burst_schedule, rng, window_start, window_end,
            )

        if target_events <= 0:
            continue

        stats["events_requested"] += target_events

        device_ids = _collect_person_device_ids(company, person)
        device_id = rng.choice(device_ids) if device_ids else None

        # ── Budget allocation ────────────────────────────────────────────
        n_file_correlated = max(0, round(target_events * 0.25))
        n_app_correlated = max(0, round(target_events * 0.25))
        n_role_specific = max(0, round(target_events * 0.18))
        n_background = target_events - n_file_correlated - n_app_correlated - n_role_specific

        events_generated = 0

        # Build temporal samplers
        circadian = weekly = None
        if gen_cfg:
            circadian, weekly = resolve_person_temporal(person, gen_cfg)

        # ── Bucket 1: File-correlated process events ─────────────────────
        file_events = ra.get("file_events")
        if isinstance(file_events, list) and file_events and n_file_correlated > 0:
            eligible = []
            for fe in file_events:
                action = fe.get("action", "")
                if action not in ("read", "modify", "open", "download"):
                    continue
                fp = fe.get("file_path", "") or fe.get("path", "")
                ext = _get_file_extension(fp)
                if ext and ext in _EXT_TO_PROCESS:
                    eligible.append((fe, ext))

            if eligible:
                # Sample a fraction of eligible file events
                n_to_correlate = min(
                    n_file_correlated,
                    max(1, round(len(eligible) * file_correlation_ratio)),
                )
                sampled = rng.sample(eligible, min(n_to_correlate, len(eligible)))

                for file_evt, ext in sampled:
                    fe_ts_str = file_evt.get("ts", "")
                    if not fe_ts_str:
                        continue
                    try:
                        fe_ts = datetime.fromisoformat(fe_ts_str.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        continue

                    # Process starts 0-30s before file event
                    offset_seconds = rng.randint(0, 30)
                    proc_ts = fe_ts - timedelta(seconds=offset_seconds)

                    proc_info = _EXT_TO_PROCESS[ext]
                    pname = proc_info["process_name"]
                    ppath = proc_info["path"]
                    parent = _apply_process_tree(pname, "explorer.exe", rng)
                    pid = rng.randint(1000, 65535)

                    file_arg = file_evt.get("file_path", "") or file_evt.get("path", "")

                    event = _build_process_event(
                        ts=format_ts(proc_ts),
                        process_name=pname,
                        action="start",
                        path=ppath,
                        parent_process=parent,
                        pid=pid,
                        username=username,
                        rng=rng,
                        device_id=device_id,
                        file_arg=file_arg,
                    )
                    _emit_event(company, container_kind, person_id, event, stats, category="file_correlated")
                    events_generated += 1

                    # Lifecycle stop
                    stop_event = _build_lifecycle_stop(event, rng)
                    if stop_event:
                        _emit_event(company, container_kind, person_id, stop_event, stats, category="lifecycle_stop")

        # ── Bucket 2: App-correlated process events ──────────────────────
        app_events = ra.get("app_events")
        if isinstance(app_events, list) and app_events and n_app_correlated > 0:
            sample_size = min(n_app_correlated, len(app_events))
            sampled_app_events = rng.sample(app_events, sample_size)

            for app_evt in sampled_app_events:
                app_name = app_evt.get("app", "")
                app_ts_str = app_evt.get("ts", "")
                if not app_ts_str:
                    continue

                try:
                    app_ts = datetime.fromisoformat(app_ts_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    continue

                offset_seconds = rng.randint(0, 180)
                proc_ts = app_ts - timedelta(seconds=offset_seconds)

                proc_options = _APP_TO_PROCESS.get(app_name)
                if not proc_options:
                    proc_info = dict(_BROWSER_PROCESS)
                else:
                    proc_info = dict(rng.choice(proc_options))

                pname = proc_info["process_name"]
                ppath = proc_info.get("path", "")
                parent = proc_info.get("parent_process", "explorer.exe")
                parent = _apply_process_tree(pname, parent, rng)
                pid = rng.randint(1000, 65535)

                event = _build_process_event(
                    ts=format_ts(proc_ts),
                    process_name=pname,
                    action="start",
                    path=ppath,
                    parent_process=parent,
                    pid=pid,
                    username=username,
                    rng=rng,
                    device_id=device_id,
                )
                _emit_event(company, container_kind, person_id, event, stats, category="app_correlated")
                events_generated += 1

                # Lifecycle stop for app-correlated events
                stop_event = _build_lifecycle_stop(event, rng)
                if stop_event:
                    _emit_event(company, container_kind, person_id, stop_event, stats, category="lifecycle_stop")

        # ── Bucket 3: Role-specific process events ───────────────────────
        from .department_categories import get_process_profile
        profile = get_process_profile(department, company)
        remaining_role = max(0, n_role_specific)

        for _ in range(remaining_role):
            proc_info = _weighted_choice(profile, rng)
            pname = proc_info["process_name"]
            ppath = proc_info["path"].replace("{user}", username)
            parent = _apply_process_tree(pname, "explorer.exe", rng)
            pid = rng.randint(1000, 65535)

            if circadian and weekly and window_start and window_end:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            else:
                days_back = rng.randint(0, 29)
                hour = rng.randint(7, 20)
                ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
                ts_dt = ts_dt.replace(
                    hour=hour, minute=rng.randint(0, 59),
                    second=rng.randint(0, 59), microsecond=0,
                )
                ts = format_ts(ts_dt)

            event = _build_process_event(
                ts=ts,
                process_name=pname,
                action="start",
                path=ppath,
                parent_process=parent,
                pid=pid,
                username=username,
                rng=rng,
                device_id=device_id,
            )
            _emit_event(company, container_kind, person_id, event, stats, category="role_specific")
            events_generated += 1

            # Lifecycle stop
            stop_event = _build_lifecycle_stop(event, rng)
            if stop_event:
                _emit_event(company, container_kind, person_id, stop_event, stats, category="lifecycle_stop")

        # ── Bucket 4: Background OS process events ───────────────────────
        remaining_bg = max(0, target_events - events_generated)
        # Ensure we generate at least the planned background count
        bg_count = max(n_background, remaining_bg)

        for _ in range(bg_count):
            bg_idx = rng.choices(range(len(_WEIGHTED_BACKGROUND_PROCESSES)), weights=_BG_WEIGHTS, k=1)[0]
            proc_info = dict(_WEIGHTED_BACKGROUND_PROCESSES[bg_idx][0])
            pname = proc_info["process_name"]
            ppath = proc_info["path"]
            parent = proc_info.get("parent_process", "services.exe")
            pid = rng.randint(4, 65535)

            # Use scheduled task circadian profile if available
            task_profile = _SCHEDULED_TASK_PROFILES.get(pname)
            if task_profile and window_start and window_end:
                bg_circadian = CircadianSampler(
                    peaks_hours=task_profile["peaks"],
                    kappa=task_profile["kappa"],
                    utc_offset=0.0,
                )
                bg_weekly = WeeklyCycleModulator(weights=[1.0] * 7)
                ts_dt = sample_timestamp(bg_circadian, bg_weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            elif circadian and weekly and window_start and window_end:
                ts_dt = sample_timestamp(circadian, weekly, rng, window_start, window_end)
                ts = format_ts(ts_dt)
            else:
                days_back = rng.randint(0, 29)
                hour = rng.randint(0, 23)
                ts_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
                ts_dt = ts_dt.replace(
                    hour=hour, minute=rng.randint(0, 59),
                    second=rng.randint(0, 59), microsecond=0,
                )
                ts = format_ts(ts_dt)

            event = _build_process_event(
                ts=ts,
                process_name=pname,
                action="start",
                path=ppath,
                parent_process=parent,
                pid=pid,
                username=username,
                rng=rng,
                device_id=device_id,
                is_background=True,
            )
            _emit_event(company, container_kind, person_id, event, stats, category="background")
            events_generated += 1

            # Background processes: lifecycle stop
            stop_event = _build_lifecycle_stop(event, rng)
            if stop_event:
                _emit_event(company, container_kind, person_id, stop_event, stats, category="lifecycle_stop")

        if events_generated:
            stats["employees_with_events"] += 1

    stats["processes_used"] = dict(stats["processes_used"])
    return stats
