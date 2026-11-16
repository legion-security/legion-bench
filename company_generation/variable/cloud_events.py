"""
Cloud API event log generation for company fixtures.

Generates realistic cloud API audit logs (analogous to AWS CloudTrail,
Azure Activity Log, GCP Cloud Audit Log) stored in company["cloud"]["events"].

Key design:
- Instance-role affinity: each instance's (tags.app, tags.env) determines which
  API actions it can generate.
- Session-based generation: events come in bursts of 3-15 causally ordered API
  calls driven by a Markov chain per profile.
- Provider-specific translation: generic actions are translated to the correct
  event_source/event_name tuples for AWS, Azure, and GCP.
- Identity type distribution varies by environment (prod/stage/dev).
"""
from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .temporal_model import (
    CircadianSampler,
    WeeklyCycleModulator,
    format_ts,
    get_window,
    sample_timestamp,
)

Person = Dict[str, Any]
Company = Dict[str, Any]


# ---------------------------------------------------------------------------
# Provider-specific action translation
# ---------------------------------------------------------------------------

# Maps generic action names to (event_source, event_name) per provider
_ACTION_TRANSLATION: Dict[str, Dict[str, Tuple[str, str]]] = {
    "describe_target_health": {
        "aws": ("elasticloadbalancing.amazonaws.com", "DescribeTargetHealth"),
        "azure": ("Microsoft.Network", "GetLoadBalancerHealthStatus"),
        "gcp": ("compute.googleapis.com", "healthChecks.get"),
    },
    "put_metric_data": {
        "aws": ("monitoring.amazonaws.com", "PutMetricData"),
        "azure": ("Microsoft.Insights", "PutMetricValues"),
        "gcp": ("monitoring.googleapis.com", "timeSeries.create"),
    },
    "put_log_events": {
        "aws": ("logs.amazonaws.com", "PutLogEvents"),
        "azure": ("Microsoft.OperationalInsights", "PostData"),
        "gcp": ("logging.googleapis.com", "entries.write"),
    },
    "get_secret_value": {
        "aws": ("secretsmanager.amazonaws.com", "GetSecretValue"),
        "azure": ("Microsoft.KeyVault", "GetSecret"),
        "gcp": ("secretmanager.googleapis.com", "versions.access"),
    },
    "get_object": {
        "aws": ("s3.amazonaws.com", "GetObject"),
        "azure": ("Microsoft.Storage", "GetBlob"),
        "gcp": ("storage.googleapis.com", "objects.get"),
    },
    "put_object": {
        "aws": ("s3.amazonaws.com", "PutObject"),
        "azure": ("Microsoft.Storage", "PutBlob"),
        "gcp": ("storage.googleapis.com", "objects.insert"),
    },
    "list_objects": {
        "aws": ("s3.amazonaws.com", "ListObjectsV2"),
        "azure": ("Microsoft.Storage", "ListBlobs"),
        "gcp": ("storage.googleapis.com", "objects.list"),
    },
    "assume_role": {
        "aws": ("sts.amazonaws.com", "AssumeRole"),
        "azure": ("Microsoft.Authorization", "ElevateAccess"),
        "gcp": ("iam.googleapis.com", "serviceAccounts.signJwt"),
    },
    "batch_write_item": {
        "aws": ("dynamodb.amazonaws.com", "BatchWriteItem"),
        "azure": ("Microsoft.DocumentDB", "BatchWrite"),
        "gcp": ("datastore.googleapis.com", "commit"),
    },
    "get_item": {
        "aws": ("dynamodb.amazonaws.com", "GetItem"),
        "azure": ("Microsoft.DocumentDB", "ReadDocument"),
        "gcp": ("datastore.googleapis.com", "lookup"),
    },
    "put_item": {
        "aws": ("dynamodb.amazonaws.com", "PutItem"),
        "azure": ("Microsoft.DocumentDB", "CreateDocument"),
        "gcp": ("datastore.googleapis.com", "commit"),
    },
    "receive_message": {
        "aws": ("sqs.amazonaws.com", "ReceiveMessage"),
        "azure": ("Microsoft.ServiceBus", "ReceiveMessages"),
        "gcp": ("pubsub.googleapis.com", "subscriptions.pull"),
    },
    "send_message": {
        "aws": ("sqs.amazonaws.com", "SendMessage"),
        "azure": ("Microsoft.ServiceBus", "SendMessage"),
        "gcp": ("pubsub.googleapis.com", "topics.publish"),
    },
    "invoke_function": {
        "aws": ("lambda.amazonaws.com", "Invoke"),
        "azure": ("Microsoft.Web", "InvokeFunction"),
        "gcp": ("cloudfunctions.googleapis.com", "functions.call"),
    },
    "create_training_job": {
        "aws": ("sagemaker.amazonaws.com", "CreateTrainingJob"),
        "azure": ("Microsoft.MachineLearningServices", "CreateJob"),
        "gcp": ("aiplatform.googleapis.com", "customJobs.create"),
    },
    "describe_training_job": {
        "aws": ("sagemaker.amazonaws.com", "DescribeTrainingJob"),
        "azure": ("Microsoft.MachineLearningServices", "GetJob"),
        "gcp": ("aiplatform.googleapis.com", "customJobs.get"),
    },
    "describe_instances": {
        "aws": ("ec2.amazonaws.com", "DescribeInstances"),
        "azure": ("Microsoft.Compute", "GetVirtualMachine"),
        "gcp": ("compute.googleapis.com", "instances.get"),
    },
    "start_query": {
        "aws": ("athena.amazonaws.com", "StartQueryExecution"),
        "azure": ("Microsoft.Sql", "ExecuteQuery"),
        "gcp": ("bigquery.googleapis.com", "jobs.insert"),
    },
    "get_query_results": {
        "aws": ("athena.amazonaws.com", "GetQueryResults"),
        "azure": ("Microsoft.Sql", "GetQueryResults"),
        "gcp": ("bigquery.googleapis.com", "jobs.getQueryResults"),
    },
}

# Event category mapping for generic actions
_ACTION_CATEGORY: Dict[str, Tuple[str, bool]] = {
    # action -> (category, read_only)
    "describe_target_health": ("management", True),
    "put_metric_data": ("monitoring", False),
    "put_log_events": ("monitoring", False),
    "get_secret_value": ("data", True),
    "get_object": ("data", True),
    "put_object": ("data", False),
    "list_objects": ("data", True),
    "assume_role": ("auth", False),
    "batch_write_item": ("data", False),
    "get_item": ("data", True),
    "put_item": ("data", False),
    "receive_message": ("data", True),
    "send_message": ("data", False),
    "invoke_function": ("management", False),
    "create_training_job": ("management", False),
    "describe_training_job": ("management", True),
    "describe_instances": ("management", True),
    "start_query": ("data", False),
    "get_query_results": ("data", True),
}


# ---------------------------------------------------------------------------
# Instance behavior profiles
# ---------------------------------------------------------------------------

@dataclass
class InstanceBehaviorProfile:
    """Defines the expected behavior pattern for an instance type."""
    app_tag: str
    events_per_day_mean: int
    events_per_day_std: int
    # Circadian peaks as hours (24h format)
    circadian_peaks: List[float]
    circadian_kappa: float
    # Weekly weights Mon=0..Sun=6
    weekly_weights: List[float]
    # Top actions with weights (Markov starting distribution)
    action_weights: List[Tuple[str, float]]
    # Markov transitions: action -> [(next_action, weight), ...]
    transitions: Dict[str, List[Tuple[str, float]]]
    # Error rate (fraction)
    error_rate: float = 0.005


_PROFILES: Dict[str, InstanceBehaviorProfile] = {
    "web": InstanceBehaviorProfile(
        app_tag="web",
        events_per_day_mean=220,
        events_per_day_std=50,
        circadian_peaks=[3.0, 9.0, 14.0, 20.0],  # 24/7 with slight biz-hours bump
        circadian_kappa=0.8,  # low concentration = spread across day
        weekly_weights=[1.0, 1.0, 1.0, 1.0, 1.0, 0.7, 0.6],
        action_weights=[
            ("describe_target_health", 30),
            ("put_metric_data", 25),
            ("put_log_events", 25),
            ("get_secret_value", 10),
            ("get_object", 5),
            ("describe_instances", 5),
        ],
        transitions={
            "describe_target_health": [("put_metric_data", 40), ("put_log_events", 30), ("describe_target_health", 20), ("get_secret_value", 10)],
            "put_metric_data": [("put_log_events", 40), ("describe_target_health", 30), ("put_metric_data", 20), ("get_object", 10)],
            "put_log_events": [("describe_target_health", 30), ("put_metric_data", 30), ("put_log_events", 20), ("get_secret_value", 10), ("get_object", 10)],
            "get_secret_value": [("describe_target_health", 40), ("get_object", 30), ("put_log_events", 30)],
            "get_object": [("put_log_events", 40), ("put_metric_data", 30), ("describe_target_health", 30)],
            "describe_instances": [("describe_target_health", 50), ("put_metric_data", 30), ("put_log_events", 20)],
        },
        error_rate=0.005,
    ),
    "etl": InstanceBehaviorProfile(
        app_tag="etl",
        events_per_day_mean=170,
        events_per_day_std=50,
        circadian_peaks=[2.0, 6.0, 14.0],  # Periodic batch peaks
        circadian_kappa=2.0,
        weekly_weights=[1.0, 1.0, 1.0, 1.0, 1.0, 0.4, 0.3],
        action_weights=[
            ("get_object", 20),
            ("put_object", 15),
            ("assume_role", 10),
            ("batch_write_item", 15),
            ("put_log_events", 15),
            ("list_objects", 10),
            ("start_query", 8),
            ("get_query_results", 7),
        ],
        transitions={
            "assume_role": [("get_secret_value", 40), ("get_object", 30), ("list_objects", 20), ("start_query", 10)],
            "get_secret_value": [("get_object", 40), ("list_objects", 30), ("start_query", 30)],
            "get_object": [("put_object", 30), ("batch_write_item", 25), ("put_log_events", 20), ("get_object", 15), ("get_query_results", 10)],
            "put_object": [("put_log_events", 30), ("get_object", 25), ("batch_write_item", 25), ("put_object", 20)],
            "batch_write_item": [("put_log_events", 35), ("batch_write_item", 25), ("get_object", 20), ("put_object", 20)],
            "list_objects": [("get_object", 50), ("start_query", 30), ("put_log_events", 20)],
            "put_log_events": [("get_object", 30), ("assume_role", 20), ("batch_write_item", 20), ("put_object", 15), ("put_log_events", 15)],
            "start_query": [("get_query_results", 70), ("put_log_events", 30)],
            "get_query_results": [("put_object", 30), ("batch_write_item", 30), ("put_log_events", 20), ("start_query", 20)],
        },
        error_rate=0.01,
    ),
    "billing": InstanceBehaviorProfile(
        app_tag="billing",
        events_per_day_mean=140,
        events_per_day_std=40,
        circadian_peaks=[9.0, 14.0],  # Business hours
        circadian_kappa=2.5,
        weekly_weights=[1.0, 1.0, 1.0, 1.0, 1.0, 0.15, 0.08],
        action_weights=[
            ("receive_message", 20),
            ("get_item", 20),
            ("put_item", 15),
            ("send_message", 15),
            ("invoke_function", 10),
            ("put_log_events", 10),
            ("get_secret_value", 5),
            ("get_object", 5),
        ],
        transitions={
            "receive_message": [("get_item", 35), ("invoke_function", 25), ("put_log_events", 20), ("get_secret_value", 10), ("send_message", 10)],
            "get_item": [("put_item", 35), ("send_message", 25), ("put_log_events", 20), ("get_item", 20)],
            "put_item": [("send_message", 30), ("put_log_events", 25), ("receive_message", 25), ("get_item", 20)],
            "send_message": [("receive_message", 30), ("put_log_events", 25), ("get_item", 25), ("invoke_function", 20)],
            "invoke_function": [("put_log_events", 30), ("get_item", 25), ("send_message", 25), ("receive_message", 20)],
            "put_log_events": [("receive_message", 30), ("get_item", 25), ("invoke_function", 20), ("get_object", 15), ("put_log_events", 10)],
            "get_secret_value": [("get_item", 40), ("invoke_function", 30), ("receive_message", 30)],
            "get_object": [("put_log_events", 40), ("get_item", 30), ("send_message", 30)],
        },
        error_rate=0.008,
    ),
    "ml": InstanceBehaviorProfile(
        app_tag="ml",
        events_per_day_mean=300,
        events_per_day_std=80,
        circadian_peaks=[4.0, 10.0, 16.0, 22.0],  # Long sessions, runs weekends
        circadian_kappa=0.6,  # very spread out
        weekly_weights=[1.0, 1.0, 1.0, 1.0, 1.0, 0.8, 0.7],  # runs weekends too
        action_weights=[
            ("create_training_job", 5),
            ("describe_training_job", 15),
            ("put_metric_data", 25),
            ("get_object", 20),
            ("put_object", 15),
            ("put_log_events", 15),
            ("get_secret_value", 5),
        ],
        transitions={
            "create_training_job": [("describe_training_job", 50), ("put_log_events", 30), ("put_metric_data", 20)],
            "describe_training_job": [("put_metric_data", 30), ("describe_training_job", 25), ("get_object", 20), ("put_log_events", 15), ("put_object", 10)],
            "put_metric_data": [("describe_training_job", 25), ("put_log_events", 25), ("get_object", 20), ("put_metric_data", 15), ("put_object", 15)],
            "get_object": [("put_log_events", 25), ("put_metric_data", 25), ("get_object", 20), ("put_object", 15), ("describe_training_job", 15)],
            "put_object": [("put_log_events", 30), ("put_metric_data", 25), ("get_object", 25), ("describe_training_job", 20)],
            "put_log_events": [("describe_training_job", 25), ("put_metric_data", 25), ("get_object", 20), ("put_object", 15), ("create_training_job", 5), ("put_log_events", 10)],
            "get_secret_value": [("create_training_job", 30), ("get_object", 40), ("put_log_events", 30)],
        },
        error_rate=0.008,
    ),
}

# Dev environment override
_DEV_OVERRIDE = {
    "events_per_day_mean": 85,
    "events_per_day_std": 25,
    "error_rate": 0.05,
}


# ---------------------------------------------------------------------------
# Identity type distribution by environment
# ---------------------------------------------------------------------------

_IDENTITY_TYPE_WEIGHTS: Dict[str, List[Tuple[str, float]]] = {
    "prod": [("service_role", 95), ("assumed_role", 5)],
    "stage": [("service_role", 80), ("assumed_role", 15), ("human", 5)],
    "dev": [("service_role", 40), ("assumed_role", 30), ("human", 30)],
}


# ---------------------------------------------------------------------------
# User agents by provider
# ---------------------------------------------------------------------------

_USER_AGENTS: Dict[str, List[str]] = {
    "aws": [
        "aws-sdk-python/1.28.0",
        "aws-sdk-java/2.20.100",
        "aws-sdk-go/1.44.300",
        "aws-cli/2.13.0",
        "Boto3/1.28.40",
    ],
    "azure": [
        "azsdk-python-identity/1.14.0",
        "azsdk-java-azure-core/1.42.0",
        "azsdk-net-Azure.Core/1.35.0",
        "Azure-CLI/2.52.0",
    ],
    "gcp": [
        "google-cloud-sdk/445.0.0",
        "gcloud-python/2.12.0",
        "google-api-python-client/2.97.0",
        "google-cloud-java/3.25.0",
    ],
}

# Error codes by provider
_ERROR_CODES: Dict[str, List[Tuple[str, str]]] = {
    "aws": [
        ("AccessDenied", "Access Denied"),
        ("ThrottlingException", "Rate exceeded"),
        ("ResourceNotFoundException", "Resource not found"),
        ("ValidationException", "Invalid parameter"),
    ],
    "azure": [
        ("AuthorizationFailed", "Authorization failed"),
        ("TooManyRequests", "Rate limit exceeded"),
        ("ResourceNotFound", "Resource not found"),
        ("InvalidRequest", "Invalid request parameters"),
    ],
    "gcp": [
        ("PERMISSION_DENIED", "Permission denied"),
        ("RESOURCE_EXHAUSTED", "Rate limit exceeded"),
        ("NOT_FOUND", "Resource not found"),
        ("INVALID_ARGUMENT", "Invalid argument"),
    ],
}


# ---------------------------------------------------------------------------
# Helper: Markov chain session generation
# ---------------------------------------------------------------------------

def _sample_action(weights: List[Tuple[str, float]], rng: random.Random) -> str:
    """Weighted random choice from (action, weight) pairs."""
    actions, w = zip(*weights)
    return rng.choices(actions, weights=w, k=1)[0]


def _next_action(
    current: str,
    profile: InstanceBehaviorProfile,
    rng: random.Random,
) -> str:
    """Pick next action from Markov transitions, with fallback."""
    transitions = profile.transitions.get(current)
    if transitions:
        return _sample_action(transitions, rng)
    # Fallback: pick from starting distribution
    return _sample_action(profile.action_weights, rng)


def _sample_session_size(rng: random.Random) -> int:
    """Sample session size from bounded Zipf-like distribution [3, 15]."""
    # Use geometric distribution to approximate Zipf, bounded
    size = 3
    while size < 15 and rng.random() < 0.55:
        size += 1
    return size


def _sample_intra_session_gap(rng: random.Random) -> float:
    """Sample gap between events within a session (seconds).

    Log-normal with mu=2.0, sigma=0.8 → median ~7 seconds.
    """
    return min(300.0, rng.lognormvariate(2.0, 0.8))


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_cloud_event_logs(
    company: Company,
    *,
    seed: int = 1337,
    replace_existing: bool = True,
    events_multiplier: float = 1.0,
    baseline_std_scale: float = 1.0,
    generation_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, int]:
    """
    Generate cloud API event logs for all cloud instances.

    Events are stored in company["cloud"]["events"] as a flat list sorted
    by timestamp.

    Args:
        company: Company data dict to modify in-place
        seed: Base seed for deterministic generation
        replace_existing: If True, replace existing cloud events
        events_multiplier: Scale factor for event volume
        generation_config: Optional temporal configuration

    Returns:
        Statistics dict with counts from generation
    """
    stats: Dict[str, Any] = {
        "instances_total": 0,
        "instances_with_events": 0,
        "events_added": 0,
        "events_by_provider": defaultdict(int),
        "events_by_profile": defaultdict(int),
        "events_by_identity_type": defaultdict(int),
        "events_by_category": defaultdict(int),
        "errors": 0,
        "sessions": 0,
    }

    cloud = company.get("cloud")
    if not cloud:
        stats["events_by_provider"] = dict(stats["events_by_provider"])
        stats["events_by_profile"] = dict(stats["events_by_profile"])
        stats["events_by_identity_type"] = dict(stats["events_by_identity_type"])
        stats["events_by_category"] = dict(stats["events_by_category"])
        return stats

    instances = cloud.get("instances", [])
    stats["instances_total"] = len(instances)

    if not instances:
        stats["events_by_provider"] = dict(stats["events_by_provider"])
        stats["events_by_profile"] = dict(stats["events_by_profile"])
        stats["events_by_identity_type"] = dict(stats["events_by_identity_type"])
        stats["events_by_category"] = dict(stats["events_by_category"])
        return stats

    if replace_existing:
        cloud["events"] = []

    gen_cfg = generation_config or company.get("_generation_config") or {}

    # Resolve time window
    if gen_cfg:
        window_start, window_end = get_window(gen_cfg)
    else:
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(days=30)

    window_days = max(1, (window_end - window_start).days)

    # Collect human employees for human-identity events
    human_candidates = _collect_human_candidates(company)
    employee_lookup = _build_employee_lookup(company)

    all_events: List[Dict[str, Any]] = list(cloud.get("events", []))

    event_counter = len(all_events)

    for idx, instance in enumerate(instances):
        rng = random.Random(seed * 1021 + idx)
        provider = instance.get("provider", "aws")
        tags = instance.get("tags", {})
        app_tag = tags.get("app", "web")
        env_tag = tags.get("env", "prod")
        instance_id = instance.get("instanceId", f"unknown-{idx}")

        # Resolve profile
        profile = _PROFILES.get(app_tag)
        if not profile:
            profile = _PROFILES["web"]

        # Apply dev override
        if env_tag == "dev":
            mean = _DEV_OVERRIDE["events_per_day_mean"]
            std = _DEV_OVERRIDE["events_per_day_std"]
            error_rate = _DEV_OVERRIDE["error_rate"]
            # Dev instances only generate during business hours
            circadian = CircadianSampler(peaks_hours=[9.0, 14.0], kappa=2.5)
            weekly = WeeklyCycleModulator(weights=[1.0, 1.0, 1.0, 1.0, 1.0, 0.15, 0.08])
        else:
            mean = profile.events_per_day_mean
            std = profile.events_per_day_std
            error_rate = profile.error_rate
            circadian = CircadianSampler(
                peaks_hours=list(profile.circadian_peaks),
                kappa=profile.circadian_kappa,
            )
            weekly = WeeklyCycleModulator(weights=list(profile.weekly_weights))

        # Compute total events for the window
        daily_rate = max(0.0, rng.gauss(mean, std * baseline_std_scale))
        daily_rate = max(mean * 0.3, min(daily_rate, mean * 2.5))
        total_events = round(daily_rate * window_days * events_multiplier)

        if total_events <= 0:
            continue

        # Compute session count
        avg_session_size = 6.0
        session_count = max(1, round(total_events / avg_session_size))

        # Resolve identity components
        iam_info = instance.get("iam", {})
        iam_identity = iam_info.get("role") or iam_info.get("servicePrincipal") or f"unknown-{instance_id}"
        account_id = (
            instance.get("accountId")
            or instance.get("subscriptionId")
            or instance.get("projectId")
            or "unknown"
        )
        region = instance.get("region", "unknown")
        private_ip = instance.get("network", {}).get("privateIp", "10.0.0.1")

        # Identity type weights for this environment
        id_type_weights = _IDENTITY_TYPE_WEIGHTS.get(env_tag, _IDENTITY_TYPE_WEIGHTS["prod"])

        events_for_instance = 0

        for _ in range(session_count):
            session_size = _sample_session_size(rng)

            # Sample session start time
            session_start = sample_timestamp(circadian, weekly, rng, window_start, window_end)

            # Pick identity type for this session
            identity_type = _sample_action(id_type_weights, rng)

            # Resolve source IP and identity based on identity type
            human_email = None  # set when identity_type == "human"
            if identity_type == "human" and human_candidates:
                human = rng.choice(human_candidates)
                source_ip = human.get("ip", private_ip)
                identity_name = human.get("email", iam_identity)
                human_email = human.get("email")
                user_agent = rng.choice(["aws-cli/2.13.0", "Azure-CLI/2.52.0", "google-cloud-sdk/445.0.0"])
            elif identity_type == "assumed_role":
                source_ip = private_ip
                identity_name = f"assumed/{iam_identity}"
                user_agent = rng.choice(_USER_AGENTS.get(provider, ["sdk/unknown"]))
            else:
                source_ip = private_ip
                identity_name = iam_identity
                user_agent = rng.choice(_USER_AGENTS.get(provider, ["sdk/unknown"]))

            # Generate Markov chain of actions
            current_action = _sample_action(profile.action_weights, rng)
            current_ts = session_start

            for event_idx in range(session_size):
                if events_for_instance >= total_events:
                    break

                # Translate action to provider-specific names
                translation = _ACTION_TRANSLATION.get(current_action, {})
                provider_specific = translation.get(provider)
                if not provider_specific:
                    # Fallback: use generic names
                    event_source = f"{provider}.generic.api"
                    event_name = current_action
                else:
                    event_source, event_name = provider_specific

                # Category and read_only
                cat_info = _ACTION_CATEGORY.get(current_action, ("management", True))
                event_category, read_only = cat_info

                # Determine success/failure
                is_error = rng.random() < error_rate
                if is_error:
                    error_choices = _ERROR_CODES.get(provider, [("Error", "Unknown error")])
                    error_code, error_message = rng.choice(error_choices)
                    response_status = "AccessDenied" if "denied" in error_code.lower() or "Denied" in error_code else "Failed"
                else:
                    response_status = "Success"
                    error_code = None
                    error_message = None

                event_counter += 1
                event: Dict[str, Any] = {
                    "event_id": f"cev-{event_counter:08d}",
                    "ts": format_ts(current_ts),
                    "provider": provider,
                    "instance_id": instance_id,
                    "region": region,
                    "account_id": account_id,
                    "identity": identity_name,
                    "identity_type": identity_type,
                    "event_source": event_source,
                    "event_name": event_name,
                    "event_category": event_category,
                    "read_only": read_only,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "request_parameters": "{}",
                    "response_status": response_status,
                    "error_code": error_code,
                    "error_message": error_message,
                    "resources": "[]",
                }
                all_events.append(event)
                events_for_instance += 1

                # Link human-identity events to the employee's recent_activity
                if human_email and human_email in employee_lookup:
                    emp = employee_lookup[human_email]
                    ra = emp.setdefault("recent_activity", {})
                    ra.setdefault("cloud_events", []).append(event)

                # Stats
                stats["events_by_provider"][provider] += 1
                stats["events_by_profile"][app_tag] += 1
                stats["events_by_identity_type"][identity_type] += 1
                stats["events_by_category"][event_category] += 1
                if is_error:
                    stats["errors"] += 1

                # Advance timestamp within session
                gap = _sample_intra_session_gap(rng)
                current_ts = current_ts + timedelta(seconds=gap)

                # Next action via Markov chain
                current_action = _next_action(current_action, profile, rng)

            stats["sessions"] += 1

        if events_for_instance > 0:
            stats["instances_with_events"] += 1
            stats["events_added"] += events_for_instance

    # Sort all events by timestamp and store
    all_events.sort(key=lambda e: e.get("ts", ""))
    cloud["events"] = all_events

    # Convert defaultdicts to regular dicts for JSON serialization
    stats["events_by_provider"] = dict(stats["events_by_provider"])
    stats["events_by_profile"] = dict(stats["events_by_profile"])
    stats["events_by_identity_type"] = dict(stats["events_by_identity_type"])
    stats["events_by_category"] = dict(stats["events_by_category"])

    return stats


def _collect_human_candidates(company: Company) -> List[Dict[str, str]]:
    """Collect IT/Engineering employees with IPs for human-identity events.

    Returns list of dicts with keys: id, email, ip.
    """
    candidates = []
    employees = company.get("employees", [])
    devices = company.get("devices", [])

    # Build device IP lookup
    device_ip_map: Dict[str, str] = {}
    for d in devices:
        if isinstance(d, dict) and d.get("id") and d.get("ip_address"):
            owner = d.get("owner_user_id")
            if owner:
                device_ip_map[owner] = d["ip_address"]

    for emp in employees:
        if not isinstance(emp, dict):
            continue
        dept = (emp.get("department") or "").lower()
        if dept not in ("it", "engineering", "information technology", "devops", "infrastructure", "platform"):
            continue
        emp_id = emp.get("id", "")
        email = emp.get("email", "")
        ip = device_ip_map.get(emp_id, "10.0.1.100")
        candidates.append({"id": emp_id, "email": email, "ip": ip})

    # If no IT/Engineering employees found, use any employees (limited)
    if not candidates:
        for emp in employees[:10]:
            if not isinstance(emp, dict):
                continue
            emp_id = emp.get("id", "")
            email = emp.get("email", "")
            ip = device_ip_map.get(emp_id, "10.0.1.100")
            candidates.append({"id": emp_id, "email": email, "ip": ip})

    return candidates


def _build_employee_lookup(company: Company) -> Dict[str, Dict[str, Any]]:
    """Build email → employee dict for linking human events."""
    lookup: Dict[str, Dict[str, Any]] = {}
    for emp in company.get("employees", []):
        if isinstance(emp, dict) and emp.get("email"):
            lookup[emp["email"]] = emp
    return lookup
