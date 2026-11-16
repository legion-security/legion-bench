"""
Centralized loader for per-company constants (email scenarios, company files).

Each company gets its own directory under constants/{company_id}/ containing:
- email_scenarios.json  (email thread templates)
- company_files.json    (file metadata for file events)

Falls back to the legacy constants/ root directory when no company-specific
directory exists (backward compatibility).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .email_scenarios import EmailScenario, EmailTemplate

# Root of the constants directory (repo_root/constants/)
_CONSTANTS_ROOT = Path(__file__).resolve().parents[3] / "constants"

# Per-company caches
_COMPANY_FILES_CACHE: Dict[str, List[Dict[str, Any]]] = {}
_EMAIL_SCENARIOS_CACHE: Dict[str, List[EmailScenario]] = {}


def get_constants_dir(company_id: Optional[str] = None) -> Path:
    """Resolve constants directory for a given company.

    Looks up: constants/{company_id}/
    Falls back to: constants/ (for backward compatibility)
    """
    if company_id:
        company_dir = _CONSTANTS_ROOT / company_id
        if company_dir.is_dir():
            return company_dir
    return _CONSTANTS_ROOT


def load_company_files(company_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load company_files.json for the given company, with caching.

    Args:
        company_id: Company identifier (e.g. 'brightcart_inc').
                    None or empty falls back to legacy constants/.
    """
    cache_key = company_id or ""
    if cache_key in _COMPANY_FILES_CACHE:
        return _COMPANY_FILES_CACHE[cache_key]

    constants_dir = get_constants_dir(company_id)
    path = constants_dir / "company_files.json"

    if not path.exists():
        _COMPANY_FILES_CACHE[cache_key] = []
        return []

    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    if not isinstance(data, list):
        _COMPANY_FILES_CACHE[cache_key] = []
        return []

    _COMPANY_FILES_CACHE[cache_key] = data
    return data


def _load_scenarios_from_json(path: Path) -> List[EmailScenario]:
    """Load scenarios from a single JSON file."""
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        scenarios = []
        for item in data:
            emails = [EmailTemplate(**e) for e in item.pop("emails", [])]
            scenario = EmailScenario(**item, emails=emails)
            scenarios.append(scenario)
        return scenarios
    except Exception:
        return []


def load_email_scenarios(company_id: Optional[str] = None) -> List[EmailScenario]:
    """Load email scenarios for the given company, with caching.

    For company-specific dirs: loads email_scenarios.json
    For legacy fallback: loads email_scenarios.json + _2 + _burst
    """
    cache_key = company_id or ""
    if cache_key in _EMAIL_SCENARIOS_CACHE:
        return _EMAIL_SCENARIOS_CACHE[cache_key]

    constants_dir = get_constants_dir(company_id)
    scenarios: List[EmailScenario] = []

    if company_id and (constants_dir / "email_scenarios.json").exists():
        # Company-specific: single file
        scenarios = _load_scenarios_from_json(constants_dir / "email_scenarios.json")
    else:
        # Legacy fallback: multiple files in constants/
        for filename in [
            "email_scenarios.json",
            "email_scenarios_2.json",
            "email_scenarios_burst.json",
        ]:
            scenarios.extend(_load_scenarios_from_json(_CONSTANTS_ROOT / filename))

    _EMAIL_SCENARIOS_CACHE[cache_key] = scenarios
    return scenarios


def clear_caches() -> None:
    """Clear all caches (useful for testing)."""
    _COMPANY_FILES_CACHE.clear()
    _EMAIL_SCENARIOS_CACHE.clear()
