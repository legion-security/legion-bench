"""Execution context for a golden-workflow run.

Holds the alert, the running list of tool-call results, and a handful of
extraction helpers (employee_id from a prior lookup_user, distinct IPs
from sign-in logs, etc.) that workflow steps lean on.

Keeping the helpers on the context (not on each step) means the
workflow definitions stay declarative — they describe *what* to call,
not *how* to derive parameters.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from agents.base import ToolCallRecord

logger = logging.getLogger(__name__)


# ISO-8601 timestamp with a Z suffix, optionally fractional seconds.
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)")

# Private / internal IPv4 ranges to filter out before TI lookups.
_PRIVATE_RANGES = (
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
)


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in _PRIVATE_RANGES)


def _walk(obj: Any) -> Iterable[Any]:
    """Yield every dict / list element in a nested structure (DFS)."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


class ExecutionContext:
    """Mutable state shared across the steps of one workflow run."""

    def __init__(self, scenario: dict):
        self.scenario = scenario
        self.alert: dict = scenario.get("alert") or {}
        self.results: list[ToolCallRecord] = []
        # Each entry tracks the originating step label so report
        # rendering can group calls by analyst-facing intent.
        self.step_labels: list[str] = []

    # ------------------------------------------------------------------
    # Alert / scenario extraction
    # ------------------------------------------------------------------

    @property
    def email(self) -> str | None:
        for ind in self.alert.get("initial_indicators", []) or []:
            if ind.get("type") == "email":
                return ind.get("value")
        # Fallback: first email-shaped string in the title.
        m = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", self.alert.get("title", ""))
        return m.group(0) if m else None

    @property
    def alert_ts(self) -> datetime | None:
        text = " ".join(
            str(self.alert.get(k, "")) for k in ("description", "title")
        )
        m = _TS_RE.search(text)
        if not m:
            return None
        raw = m.group(1).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def time_window(
        self,
        days_back: float = 2.0,
        days_forward: float = 1.0,
    ) -> tuple[str | None, str | None]:
        """Return ISO-8601 (start, end) bracketing the alert timestamp.

        If the alert has no parsable timestamp, returns (None, None) and
        callers should pass through unbounded queries.
        """
        ts = self.alert_ts
        if ts is None:
            return None, None
        start = ts - timedelta(days=days_back)
        end = ts + timedelta(days=days_forward)
        return self._iso(start), self._iso(end)

    @staticmethod
    def _iso(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------------------
    # Result accumulator
    # ------------------------------------------------------------------

    def record(self, step_label: str, call: ToolCallRecord) -> None:
        self.results.append(call)
        self.step_labels.append(step_label)

    def calls_for(self, function_name: str) -> list[ToolCallRecord]:
        """All recorded calls for a given tool function."""
        return [r for r in self.results if r.function_name == function_name]

    def first_result(self, function_name: str) -> Any:
        for r in self.calls_for(function_name):
            if r.error is None and r.result is not None:
                return r.result
        return None

    def all_results(self, function_name: str) -> list[Any]:
        return [
            r.result
            for r in self.calls_for(function_name)
            if r.error is None and r.result is not None
        ]

    # ------------------------------------------------------------------
    # Derived identifiers
    # ------------------------------------------------------------------

    @property
    def employee_id(self) -> str | None:
        """Read employee_id from a prior entra_lookup_user call."""
        user = self.first_result("entra_lookup_user")
        if isinstance(user, dict):
            return user.get("id")
        return None

    @property
    def device_ids(self) -> list[str]:
        """Distinct device_ids seen in sign-in logs and process events."""
        ids: set[str] = set()
        for source in (
            "entra_sign_in_logs",
            "cs_get_process_tree",
            "cs_get_device_events",
        ):
            for result in self.all_results(source):
                for node in _walk(result):
                    val = node.get("device_id") if isinstance(node, dict) else None
                    if val and isinstance(val, str) and val != "unknown":
                        ids.add(val)
        return sorted(ids)

    # ------------------------------------------------------------------
    # IOC extraction from prior tool results
    # ------------------------------------------------------------------

    def collect_ips(
        self,
        from_functions: tuple[str, ...] = ("entra_sign_in_logs",),
        exclude_private: bool = True,
    ) -> list[str]:
        ips: set[str] = set()
        for fn in from_functions:
            for result in self.all_results(fn):
                for node in _walk(result):
                    if not isinstance(node, dict):
                        continue
                    for key in (
                        "ip", "source_ip", "destination_ip", "client_ip", "src_ip"
                    ):
                        val = node.get(key)
                        if isinstance(val, str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
                            if exclude_private and _is_private_ip(val):
                                continue
                            ips.add(val)
        return sorted(ips)

    def collect_domains(
        self,
        from_functions: tuple[str, ...] = ("defender_search_emails",),
    ) -> list[str]:
        domains: set[str] = set()
        for fn in from_functions:
            for result in self.all_results(fn):
                for node in _walk(result):
                    if not isinstance(node, dict):
                        continue
                    for key in ("contains_url", "url", "destination", "domain"):
                        val = node.get(key)
                        if not isinstance(val, str):
                            continue
                        for d in self._extract_domains(val):
                            domains.add(d)
                    sender = node.get("sender") or node.get("from")
                    if isinstance(sender, str) and "@" in sender:
                        dom = sender.rsplit("@", 1)[-1].strip().lower()
                        if dom:
                            domains.add(dom)
        return sorted(domains)

    @staticmethod
    def _extract_domains(text: str) -> list[str]:
        """Pull bare domains out of a URL or freeform string."""
        out: list[str] = []
        for m in re.finditer(r"https?://([^/\s,]+)", text):
            out.append(m.group(1).lower())
        # Bare domain heuristic
        for m in re.finditer(r"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)\b", text.lower()):
            d = m.group(1)
            if "." in d and not re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
                out.append(d)
        return out

    def collect_urls(
        self,
        from_functions: tuple[str, ...] = ("defender_search_emails",),
    ) -> list[str]:
        urls: set[str] = set()
        for fn in from_functions:
            for result in self.all_results(fn):
                for node in _walk(result):
                    if not isinstance(node, dict):
                        continue
                    val = node.get("contains_url") or node.get("url")
                    if isinstance(val, str) and val.startswith(("http://", "https://")):
                        urls.add(val)
        return sorted(urls)

    def collect_hashes(
        self,
        from_functions: tuple[str, ...] = (
            "cs_get_process_tree",
            "defender_search_emails",
            "defender_get_email_attachments",
        ),
    ) -> list[str]:
        hashes: set[str] = set()
        for fn in from_functions:
            for result in self.all_results(fn):
                for node in _walk(result):
                    if not isinstance(node, dict):
                        continue
                    for key in ("hash", "sha256", "file_hash"):
                        val = node.get(key)
                        if isinstance(val, str) and re.match(r"^[a-fA-F0-9]{32,128}$", val):
                            hashes.add(val.lower())
        return sorted(hashes)

    def collect_external_senders(
        self,
        from_functions: tuple[str, ...] = ("defender_search_emails",),
        own_domain_hint: str | None = None,
    ) -> list[str]:
        """Distinct external sender addresses (excluding our own domain)."""
        # Best-effort own domain: derive from the alert email indicator.
        if own_domain_hint is None and self.email:
            own_domain_hint = self.email.rsplit("@", 1)[-1].lower()

        senders: set[str] = set()
        for fn in from_functions:
            for result in self.all_results(fn):
                for node in _walk(result):
                    if not isinstance(node, dict):
                        continue
                    sender = node.get("sender") or node.get("from")
                    is_external = node.get("external")
                    if not isinstance(sender, str) or "@" not in sender:
                        continue
                    sender = sender.strip().lower()
                    if is_external is False:
                        continue
                    if own_domain_hint and sender.endswith("@" + own_domain_hint):
                        continue
                    senders.add(sender)
        return sorted(senders)

    def collect_filenames(
        self,
        from_functions: tuple[str, ...] = (
            "defender_search_emails",
            "defender_get_email_attachments",
        ),
    ) -> list[str]:
        names: set[str] = set()
        for fn in from_functions:
            for result in self.all_results(fn):
                for node in _walk(result):
                    if not isinstance(node, dict):
                        continue
                    for key in ("filename", "attachment_name", "file_name"):
                        val = node.get(key)
                        if isinstance(val, str) and val.strip():
                            names.add(val.strip())
                    # email_events has an `attachments` field that may be a
                    # JSON-serialized list of dicts.
                    atts = node.get("attachments")
                    if isinstance(atts, list):
                        for a in atts:
                            if isinstance(a, dict):
                                fn_val = a.get("filename") or a.get("name")
                                if isinstance(fn_val, str) and fn_val.strip():
                                    names.add(fn_val.strip())
        return sorted(names)
