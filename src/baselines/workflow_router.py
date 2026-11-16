"""Deterministic ticket → golden-workflow router.

Maps an alert ticket (as produced by the scenario YAMLs) to one of four
golden investigation workflows used as a baseline:

    - AccountTakeover
    - Malware
    - DLP
    - Phishing

The mapping is driven primarily by `alert.source` (the SOC tool that fired
the alert), with a small title-prefix disambiguator for `splunk_es` because
that source covers a broad mix of identity / cloud / supply-chain anomalies.

Empirical alignment on the 98 ticket fixtures in
`results/isolated/meridian/soc_runbook_deterministic/_tmp/`:

    purview        → DLP                 (9/9   = 100%)
    crowdstrike    → Malware             (31/31 = 100%)
    defender_o365  → Phishing            (17/17 = 100%)
    entra_id       → AccountTakeover     (3/3   = 100%)
    splunk_es      → AccountTakeover/    (38)
                     Malware (supply chain title)

A handful of "structural" misroutes are documented in
`audit_routing.py` rather than papered over, because the right answer is
defined by *what the ticket says*, not the underlying ground-truth attack:
e.g. a `personal_email_exfil` ticket fired by `defender_o365` is routed to
Phishing because the analyst sees an outbound-email DLP alert from the
mail gateway, and the workflow is responsible for surfacing the exfil.
"""
from __future__ import annotations

from typing import Literal

GoldenWorkflow = Literal["AccountTakeover", "Malware", "DLP", "Phishing"]

ALL_WORKFLOWS: tuple[GoldenWorkflow, ...] = (
    "AccountTakeover",
    "Malware",
    "DLP",
    "Phishing",
)

# alert.source values seen in the benchmark fixtures.
_SOURCE_TO_WORKFLOW: dict[str, GoldenWorkflow] = {
    "purview": "DLP",
    "crowdstrike": "Malware",
    "defender_o365": "Phishing",
    "entra_id": "AccountTakeover",
}

# splunk_es title prefixes that indicate identity-anomaly framing
# (the SIEM rule the analyst would respond to). Lowercased substring match.
_SPLUNK_ATO_TITLE_KEYS: tuple[str, ...] = (
    "credential-related",
    "anomalous sign-in",
    "anomalous authentication",
    "multiple failed authentications",
    "unusual mfa",
    "suspicious authentication",
    "privilege-related",
    "security configuration change",
)

# splunk_es title prefixes that indicate endpoint / supply-chain framing.
_SPLUNK_MALWARE_TITLE_KEYS: tuple[str, ...] = (
    "supply chain",
)


def pick_golden_workflow(alert: dict) -> GoldenWorkflow:
    """Return the golden workflow to run for a given alert dict.

    `alert` is the `alert:` block from a scenario YAML — at minimum it must
    have `source` and `title` fields.
    """
    source = (alert.get("source") or "").lower()
    title = (alert.get("title") or "").lower()

    direct = _SOURCE_TO_WORKFLOW.get(source)
    if direct is not None:
        return direct

    if source == "splunk_es":
        if any(k in title for k in _SPLUNK_MALWARE_TITLE_KEYS):
            return "Malware"
        if any(k in title for k in _SPLUNK_ATO_TITLE_KEYS):
            return "AccountTakeover"
        # Cloud-admin / cloud-API anomalies are identity-driven from the
        # analyst's perspective: someone authenticated then did something
        # weird in a cloud admin plane.
        if "cloud" in title:
            return "AccountTakeover"
        return "AccountTakeover"

    # Unknown source: fall back to AccountTakeover since the bulk of
    # "generic suspicious activity" tickets are identity-shaped in this
    # benchmark.
    return "AccountTakeover"


def _load_yaml(path: str) -> dict:
    import yaml

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> None:
    """CLI: `python -m baselines.workflow_router <ticket.yaml>`."""
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Pick the golden workflow for a ticket.")
    ap.add_argument("ticket_yaml", help="Path to a scenario/ticket YAML file.")
    ap.add_argument(
        "--explain",
        action="store_true",
        help="Print the alert source/title alongside the chosen workflow.",
    )
    args = ap.parse_args()

    scenario = _load_yaml(args.ticket_yaml)
    alert = scenario.get("alert") or {}
    workflow = pick_golden_workflow(alert)

    if args.explain:
        print(f"source: {alert.get('source')}")
        print(f"title:  {alert.get('title')}")
        print(f"workflow: {workflow}")
    else:
        print(workflow)

    sys.exit(0)


if __name__ == "__main__":
    main()
