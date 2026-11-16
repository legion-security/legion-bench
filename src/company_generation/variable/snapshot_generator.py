import argparse
import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import random


@dataclass
class GenerationConfig:
    days: int
    hourly: bool
    seed: int
    max_events_per_stream: int = 400


def _poisson(rng: random.Random, lam: float) -> int:
    # Simple Poisson using Knuth's algorithm for small lam; clamp for stability
    lam = max(0.1, float(lam))
    L = math.exp(-lam)
    k = 0
    p = 1.0
    while p > L and k < 10000:
        k += 1
        p *= rng.random()
    return max(0, k - 1)


def _window_for(hour_start: datetime) -> Tuple[str, str]:
    start = hour_start.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    end_dt = hour_start + timedelta(minutes=59, seconds=59)
    end = end_dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return start, end


def _baseline_processes(os_name: str) -> List[str]:
    if os_name == "Windows":
        return ["explorer.exe", "outlook.exe", "chrome.exe", "teams.exe"]
    if os_name == "macOS":
        return ["Finder", "Mail", "Google Chrome", "Slack"]
    return ["bash", "sshd", "chrome", "vim"]


def _endpoint_events_for_hour(device: Dict[str, Any], hour: datetime, rng: random.Random) -> Dict[str, List[Dict[str, Any]]]:
    os_name = device.get("os", "Windows")
    events: Dict[str, List[Dict[str, Any]]] = {k: [] for k in ["process", "file", "netflow", "dns", "auth", "persistence", "detections"]}

    # Diurnal scaling based on local hours; assume UTC and bump during work hours 08-19
    scale = 1.0 + (0.8 if 8 <= hour.hour <= 19 else 0.2)

    # Processes
    base = _baseline_processes(os_name)
    proc_count = min(30, _poisson(rng, lam=6 * scale))
    for _ in range(proc_count):
        name = rng.choice(base)
        pid = rng.randint(100, 6000)
        ts = hour + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        events["process"].append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "pid": pid,
            "ppid": rng.randint(50, 5000),
            "image": name,
            "cmdline": name,
            "userId": device.get("owner_user_id"),
            "signed": True,
            "integrity": rng.choice(["low", "medium", "high"]),
        })

    # Occasional suspicious process
    if os_name == "Windows" and rng.random() < 0.05:
        ts = hour + timedelta(minutes=rng.randint(0, 59))
        events["process"].append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "pid": rng.randint(2000, 9000),
            "ppid": rng.randint(100, 1000),
            "image": "powershell.exe",
            "cmdline": "powershell -nop -w hidden -e <b64>",
            "userId": device.get("owner_user_id"),
            "signed": True,
            "integrity": "high",
        })

    # Netflow/DNS
    net_count = min(50, _poisson(rng, lam=10 * scale))
    common_hosts = [
        ("142.250.64.78", 443, "googleapis.com"),
        ("20.112.52.29", 443, "microsoft.com"),
        ("140.82.121.3", 443, "api.github.com"),
        ("151.101.1.69", 443, "slack.com"),
    ]
    for _ in range(net_count):
        ip, port, host = rng.choice(common_hosts)
        ts = hour + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        pid = rng.randint(100, 6000)
        events["netflow"].append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "pid": pid,
            "dstIp": ip,
            "dstPort": port,
            "protocol": "tcp",
            "bytesOut": rng.randint(500, 150000),
            "bytesIn": rng.randint(500, 150000),
            "sni": host,
        })
        if rng.random() < 0.6:
            events["dns"].append({
                "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
                "q": host,
                "a": ip,
            })

    # Auth
    if rng.random() < 0.2:
        ts = hour + timedelta(minutes=rng.randint(0, 59))
        events["auth"].append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "type": rng.choice(["console", "ssh", "rdp"]),
            "userId": device.get("owner_user_id", "unknown"),
            "success": rng.random() > 0.05,
            "fromIp": f"73.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        })

    # Persistence and detections rare
    if rng.random() < 0.02:
        ts = hour + timedelta(minutes=rng.randint(0, 59))
        events["persistence"].append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "type": rng.choice(["scheduledTask", "service", "cron"]),
            "name": rng.choice(["Updater", "Helper", "Cleanup"]),
            "createdBy": device.get("owner_user_id", "unknown"),
        })
    if rng.random() < 0.03:
        ts = hour + timedelta(minutes=rng.randint(0, 59))
        events["detections"].append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "product": "TwinEDR",
            "ruleId": rng.choice(["T1059.001", "T1105", "T1547"]),
            "severity": rng.choice(["low", "medium", "high"]),
            "action": rng.choice(["allow", "block", "quarantine"]),
            "reason": "simulated",
        })

    # Trim to cap
    for k in events:
        if len(events[k]) > 400:
            events[k] = events[k][:400]
    return events


def _cloud_api_events_for_hour(provider: str, hour: datetime, rng: random.Random) -> List[Dict[str, Any]]:
    verbs = {
        "aws": ["ec2:DescribeInstances", "s3:GetObject", "sts:AssumeRole", "iam:ListUsers"],
        "azure": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Storage/storageAccounts/listKeys/action"],
        "gcp": ["compute.instances.list", "storage.objects.get", "iam.serviceAccounts.get"]
    }
    count = min(40, _poisson(rng, lam=4.0))
    events: List[Dict[str, Any]] = []
    for _ in range(count):
        ts = hour + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        events.append({
            "ts": ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            "provider": provider,
            "actor": rng.choice(["role/app", "user/admin", "svc/principal"]),
            "action": rng.choice(verbs.get(provider, ["unknown"])),
            "target": rng.choice(["ec2", "s3", "vm", "disk", "bucket", "project"]),
            "status": rng.choice(["success", "success", "success", "failure"]),
            "sourceIp": f"198.51.{rng.randint(0,255)}.{rng.randint(1,254)}",
        })
    return events


def _snapshot(entity_type: str, entity_id: str, hour: datetime, events: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    start, end = _window_for(hour)
    return {
        "snapshotId": f"sn-{entity_type}-{entity_id}-{hour.strftime('%Y%m%d%H')}",
        "window": {"start": start, "end": end},
        "entity": {"type": entity_type, "id": entity_id},
        "events": events,
    }


def _iter_hours(baseline_date: str, days: int) -> Iterable[datetime]:
    base = datetime.strptime(baseline_date, "%Y-%m-%d").replace(tzinfo=None)
    for d in range(days):
        day = base + timedelta(days=d)
        for h in range(24):
            yield day.replace(hour=h, minute=0, second=0, microsecond=0)


def generate_snapshots(company: Dict[str, Any], out_dir: Path, baseline_date: str, cfg: GenerationConfig) -> None:
    rng = random.Random(cfg.seed)
    devices: List[Dict[str, Any]] = company.get("devices", [])
    cloud = company.get("cloud", {})
    instances: List[Dict[str, Any]] = cloud.get("instances", [])
    containers: List[Dict[str, Any]] = cloud.get("containers", [])

    for hour in _iter_hours(baseline_date, cfg.days):
        day_dir = out_dir / hour.strftime("%Y-%m-%d") / hour.strftime("%H")
        day_dir.mkdir(parents=True, exist_ok=True)

        # Devices
        for dev in devices:
            events = _endpoint_events_for_hour(dev, hour, rng)
            snap = _snapshot("device", dev["id"], hour, events)
            path = day_dir / f"device_{dev['id']}.jsonl"
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(snap))
                f.write("\n")

        # Cloud instances
        for inst in instances:
            provider = inst.get("provider", "aws")
            api_events = _cloud_api_events_for_hour(provider, hour, rng)
            events: Dict[str, List[Dict[str, Any]]] = {"cloudApi": api_events}
            snap = _snapshot("cloudInstance", inst["instanceId"], hour, events)
            path = day_dir / f"cloudInstance_{inst['instanceId']}.jsonl"
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(snap))
                f.write("\n")

        # Containers (lightweight for now)
        for ctr in containers:
            provider = ctr.get("provider", "aws")
            api_events = _cloud_api_events_for_hour(provider, hour, rng)
            events = {"cloudApi": api_events[: max(0, len(api_events) // 2)]}
            snap = _snapshot("container", ctr["id"], hour, events)
            path = day_dir / f"container_{ctr['id']}.jsonl"
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(snap))
                f.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate hourly snapshots for endpoints and cloud workloads")
    parser.add_argument("--company", required=True, help="Path to company JSON fixture")
    parser.add_argument("--out-dir", required=True, help="Output base directory for timelines")
    parser.add_argument("--baseline-date", default="2025-10-01", help="Baseline date (YYYY-MM-DD)")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    with open(args.company, "r", encoding="utf-8") as f:
        company = json.load(f)

    out_dir = Path(args.out_dir)
    cfg = GenerationConfig(days=args.days, hourly=True, seed=args.seed)
    generate_snapshots(company, out_dir, args.baseline_date, cfg)
    print(f"Wrote snapshots under {out_dir}")


if __name__ == "__main__":
    main()


