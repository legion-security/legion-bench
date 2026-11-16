"""Deterministic IOC matching for evaluation."""

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from evaluation.models import IOCCategoryResult, IOCResult


def normalize_ioc(value: str) -> str:
    """Normalize an IOC value for comparison.

    Lowercases, strips protocol prefixes, www., and trailing slashes.
    """
    v = value.lower().strip()
    v = re.sub(r"^https?://", "", v)
    v = re.sub(r"^www\.", "", v)
    v = v.rstrip("/")
    return v


def check_ioc_in_report(ioc: str, report_lower: str) -> bool:
    """Check whether a normalized IOC appears in the lowercased report."""
    normalized = normalize_ioc(ioc)
    return normalized in report_lower


_HEADER_PREFIX = r"(?:[#]{1,6}\s+|\*\*\s*)"
_HEADER_SUFFIX = r"(?:\s*\*\*)?\s*:?\s*$"

_IOCS_HEADER_RE = re.compile(
    rf"^\s*{_HEADER_PREFIX}(?:indicators? of compromise|iocs?)\b[^\n]*{_HEADER_SUFFIX}",
    re.IGNORECASE | re.MULTILINE,
)
_NEXT_HEADER_RE = re.compile(
    rf"^\s*{_HEADER_PREFIX}("
    r"findings|severity assessment|recommendations?|next steps?|"
    r"executive summary|timeline|affected entities|appendix|"
    r"tool calls? summary|conclusion"
    rf"){_HEADER_SUFFIX[:-1]}[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)

_IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s`)\]>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
_HASH_RE = re.compile(
    r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE
)

# File-extension hints used to recognize filename-shaped strings (e.g.
# ``mimikatz.exe``, ``backup.7z``, ``cert.pem``) that the domain regex would
# otherwise pick up. Kept disjoint from real TLDs so we don't misclassify
# legitimate domains like ``example.com`` or ``service.io``.
_FILE_EXTENSIONS: Set[str] = {
    # executables and scripts
    "exe", "dll", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "wsf", "wsh",
    "scr", "msi", "msp", "hta", "lnk", "pif", "cpl", "msc", "sh", "bash",
    "py", "pyc", "pyo", "rb", "pl", "jar", "class", "apk", "ipa", "appx",
    "bin", "elf", "ko", "sys", "drv",
    # archives
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "cab", "iso", "img",
    # documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods",
    "odp", "csv", "txt", "log", "md", "json", "yaml", "yml", "xml", "html",
    "htm",
    # crypto / certs
    "pem", "key", "crt", "cer", "pfx", "p12", "jks", "ppk", "asc", "gpg",
    # config / data
    "conf", "cfg", "ini", "properties", "env", "toml", "lock", "db", "sqlite",
    "mdb", "bak", "tmp", "swp", "old", "dat", "sav",
    # images
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp", "tif", "tiff",
}


def looks_like_hash(value: str) -> bool:
    """Return True for MD5/SHA1/SHA256-shaped hex tokens."""
    return bool(_HASH_RE.fullmatch(value))


def looks_like_filename(value: str) -> bool:
    """Return True when ``value`` looks like a filename (e.g. ``rubeus.exe``)
    rather than a domain. The check is purely on the rightmost extension."""
    if "/" in value or "@" in value or " " in value:
        return False
    if "." not in value:
        return False
    ext = value.rsplit(".", 1)[-1].lower()
    return ext in _FILE_EXTENSIONS


def extract_iocs_section(report: str) -> str:
    """Return only the **Indicators of Compromise** section. Falls back to the
    full report when no IOC header is present."""
    if not report:
        return report
    match = _IOCS_HEADER_RE.search(report)
    if not match:
        return report
    start = match.end()
    tail = report[start:]
    next_match = _NEXT_HEADER_RE.search(tail)
    end = start + next_match.start() if next_match else len(report)
    section = report[match.start():end].strip()
    return section or report


def extract_listed_iocs(text: str) -> Set[str]:
    """Pull every plausible IOC string out of a chunk of report text and
    return the set of normalized values. Domains living inside emails or URLs
    are deduplicated by normalization."""
    if not text:
        return set()
    iocs: Set[str] = set()
    for m in _IPV4_RE.finditer(text):
        iocs.add(m.group(0))
    for m in _URL_RE.finditer(text):
        iocs.add(normalize_ioc(m.group(0).rstrip(".,;")))
    for m in _EMAIL_RE.finditer(text):
        iocs.add(m.group(0).lower())
    for m in _DOMAIN_RE.finditer(text):
        token = m.group(0).lower()
        if any(token in e for e in iocs if "@" in e):
            continue
        iocs.add(token)
    for m in _HASH_RE.finditer(text):
        iocs.add(m.group(0).lower())
    return iocs


def build_known_ioc_index(
    known_iocs: Optional[Iterable[str]],
) -> Tuple[Set[str], List[str]]:
    """Split a flat IoC value list into (exact_values, prefix_values).

    Values ending in ``.`` are treated as IPv4 prefixes (e.g. ``185.234.72.``)
    so that a full IP an agent writes (``185.234.72.41``) still counts as
    "known". Everything else is matched as an exact normalized string.
    Unresolved templates (containing ``{``) are dropped.
    """
    exact: Set[str] = set()
    prefixes: List[str] = []
    for value in known_iocs or ():
        if not isinstance(value, str) or not value or "{" in value:
            continue
        normalized = normalize_ioc(value).lower()
        if not normalized:
            continue
        if normalized.endswith("."):
            prefixes.append(normalized)
        else:
            exact.add(normalized)
    return exact, prefixes


def compute_ioc_precision(
    report: str,
    expected_iocs: Dict[str, List[str]],
    known_iocs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Of the IOCs the agent listed in the IOC section, how many are real?

    ``known_iocs`` is an optional flat list of every attack-ground-truth IoC
    value (across all 19 IoC types, not just the 4 evaluated categories).
    Extracted IoCs that match a known value are counted as ``neutral`` —
    excluded from both the matched count and the false-positive denominator
    so that surfacing a real-but-unevaluated indicator (e.g. ``mimikatz.exe``,
    a miner pool, a known C2 host) does not punish precision.

    Hash-shaped tokens and filename-shaped tokens (extension-based detection)
    are also treated as neutral unconditionally — none of the scenarios
    declare ``expected_iocs.hashes`` and the four-category schema has no
    natural home for filenames, so the agent should not be penalized for
    surfacing them.

    Returns a dict with: ``listed_count``, ``matched_count``, ``neutral_count``,
    ``unmatched`` (the genuine false positives), and ``precision`` (None when
    no scoreable IOCs were listed).
    """
    section = extract_iocs_section(report)
    listed = extract_listed_iocs(section)

    truth: Set[str] = set()
    for vals in (expected_iocs or {}).values():
        for v in vals:
            truth.add(normalize_ioc(v).lower())

    known_exact, known_prefixes = build_known_ioc_index(known_iocs)

    def _is_known(value: str) -> bool:
        lv = value.lower()
        if lv in known_exact:
            return True
        return any(lv.startswith(p) for p in known_prefixes)

    matched = {v for v in listed if v.lower() in truth}

    def _embedded_hosts(value: str) -> Set[str]:
        """Return every domain/IP token embedded in ``value``.

        A URL like ``analytics-tracking-api.net/stage1.ps1`` carries a host
        that may be the matched indicator itself. Treating such derivatives
        as separate false positives double-counts the same IoC.
        """
        hosts: Set[str] = set()
        for m in _DOMAIN_RE.finditer(value):
            hosts.add(m.group(0).lower())
        for m in _IPV4_RE.finditer(value):
            hosts.add(m.group(0))
        # Don't treat the value itself as its own embedded host.
        hosts.discard(value.lower())
        return hosts

    def _is_derivative(value: str) -> bool:
        """A listed value is a 'derivative' when it contains an embedded host
        that matches an evaluated indicator or a known indicator. Such forms
        (URLs/emails wrapping a known domain or IP) are not new false
        positives — they are alternate renderings of the same IoC."""
        for h in _embedded_hosts(value):
            if h in truth or _is_known(h):
                return True
        return False

    neutral = {
        v for v in listed - matched
        if _is_known(v)
        or looks_like_hash(v)
        or looks_like_filename(v)
        or _is_derivative(v)
    }
    unmatched = sorted(listed - matched - neutral)

    listed_count = len(listed)
    scored = listed_count - len(neutral)
    precision = (len(matched) / scored) if scored > 0 else None

    return {
        "listed_count": listed_count,
        "matched_count": len(matched),
        "neutral_count": len(neutral),
        "unmatched": unmatched,
        "precision": precision,
    }


def evaluate_iocs(report: str, expected_iocs: Dict[str, List[str]]) -> IOCResult:
    """Evaluate IOC recall by checking each expected IOC against the report.

    Args:
        report: The agent's investigation report text.
        expected_iocs: Dict mapping category names to lists of expected IOC values.

    Returns:
        IOCResult with per-category and overall recall.
    """
    report_lower = report.lower()
    categories: Dict[str, IOCCategoryResult] = {}
    total_found = 0
    total_expected = 0

    for category, ioc_list in expected_iocs.items():
        found = []
        missed = []
        for ioc in ioc_list:
            if check_ioc_in_report(ioc, report_lower):
                found.append(ioc)
            else:
                missed.append(ioc)

        cat_recall = len(found) / len(ioc_list) if ioc_list else 1.0
        categories[category] = IOCCategoryResult(
            expected=ioc_list,
            found=found,
            missed=missed,
            recall=cat_recall,
        )
        total_found += len(found)
        total_expected += len(ioc_list)

    overall_recall = total_found / total_expected if total_expected > 0 else 1.0

    return IOCResult(
        categories=categories,
        overall_recall=overall_recall,
        total_found=total_found,
        total_expected=total_expected,
    )