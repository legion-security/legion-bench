"""
Temporal model for role-conditioned stochastic event generation.

Provides circadian sampling (von Mises), weekly cycle modulation,
timezone-aware timestamps, and role-based event count resolution.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Circadian sampler (von Mises on the 24-hour circle)
# ---------------------------------------------------------------------------

@dataclass
class CircadianSampler:
    """Sample hours of day from a mixture of von Mises distributions.

    Each peak hour range (e.g. "08:00-10:00") becomes a component centred
    at the midpoint of that range.  ``kappa`` controls concentration
    (higher = more peaked around the centres).
    """

    peaks_hours: List[float] = field(default_factory=lambda: [9.0, 14.0])
    kappa: float = 2.5
    utc_offset: float = 0.0  # hours east of UTC

    # ── public API ──────────────────────────────────────────────────────

    def sample_local_hour(self, rng: random.Random) -> float:
        """Return a sampled hour in *local* time [0, 24)."""
        peak = rng.choice(self.peaks_hours)
        # von Mises: convert peak hour → radians, sample, convert back
        mu = (peak / 24.0) * 2 * math.pi
        angle = _sample_von_mises(rng, mu, self.kappa)
        hour = (angle / (2 * math.pi)) * 24.0
        return hour % 24.0

    def sample_utc_hour(self, rng: random.Random) -> float:
        """Return a sampled hour in UTC [0, 24)."""
        local = self.sample_local_hour(rng)
        return (local - self.utc_offset) % 24.0

    # ── factory ─────────────────────────────────────────────────────────

    @classmethod
    def from_baseline(
        cls,
        hours_spec: List[str],
        location: str,
        kappa: float,
        tz_map: Dict[str, float],
    ) -> "CircadianSampler":
        """Build from a baseline hours spec like ["08:00-10:00", "14:00-17:00"].

        Each range is converted to a single peak at the midpoint.
        """
        peaks: List[float] = []
        for spec in hours_spec:
            if "-" in spec:
                parts = spec.split("-", 1)
                start_h = _hhmm_to_hours(parts[0])
                end_h = _hhmm_to_hours(parts[1])
                # Handle overnight ranges (e.g. "22:00-03:00")
                if end_h < start_h:
                    end_h += 24.0
                mid = (start_h + end_h) / 2.0
                peaks.append(mid % 24.0)
            else:
                peaks.append(_hhmm_to_hours(spec))
        if not peaks:
            peaks = [9.0, 14.0]
        utc_offset = tz_map.get(location, 0.0)
        return cls(peaks_hours=peaks, kappa=kappa, utc_offset=utc_offset)


# ---------------------------------------------------------------------------
# Weekly cycle modulator
# ---------------------------------------------------------------------------

@dataclass
class WeeklyCycleModulator:
    """Seven weights for Mon(0)…Sun(6).  Default is typical office worker."""

    weights: List[float] = field(
        default_factory=lambda: [1.0, 1.0, 1.0, 1.0, 1.0, 0.15, 0.08]
    )

    def weight_for_day(self, day_of_week: int) -> float:
        """Return the weight for a given day (0=Monday, 6=Sunday)."""
        if 0 <= day_of_week < len(self.weights):
            return self.weights[day_of_week]
        return 1.0

    @classmethod
    def from_config(
        cls,
        department: str,
        generation_config: Dict[str, Any],
    ) -> "WeeklyCycleModulator":
        """Resolve weekly weights for a department from generation_config."""
        weekly_cfg = (
            generation_config.get("temporal", {}).get("weekly_weights", {})
        )
        # Normalise department name for lookup (lowercase, underscores)
        dept_key = department.lower().replace(" ", "_")
        weights = weekly_cfg.get(dept_key) or weekly_cfg.get("default")
        if weights and isinstance(weights, list) and len(weights) == 7:
            return cls(weights=list(weights))
        return cls()


# ---------------------------------------------------------------------------
# Timestamp sampling
# ---------------------------------------------------------------------------

def sample_timestamp(
    circadian: CircadianSampler,
    weekly: WeeklyCycleModulator,
    rng: random.Random,
    window_start: datetime,
    window_end: datetime,
    *,
    max_attempts: int = 50,
) -> datetime:
    """Sample a single UTC timestamp within the window.

    Uses accept/reject on the weekly weight to respect day-of-week patterns.
    """
    span_days = max(1, (window_end - window_start).days)

    for _ in range(max_attempts):
        day_offset = rng.randint(0, span_days - 1)
        candidate_date = window_start + timedelta(days=day_offset)
        dow = candidate_date.weekday()  # 0=Mon
        w = weekly.weight_for_day(dow)
        if rng.random() > w:
            continue  # reject this day
        utc_hour = circadian.sample_utc_hour(rng)
        hour_int = int(utc_hour)
        frac = utc_hour - hour_int
        minute = int(frac * 60)
        second = rng.randint(0, 59)
        ts = candidate_date.replace(
            hour=hour_int % 24,
            minute=minute,
            second=second,
            microsecond=0,
            tzinfo=timezone.utc,
        )
        return ts

    # Fallback: accept any day if we exhaust attempts
    day_offset = rng.randint(0, span_days - 1)
    candidate_date = window_start + timedelta(days=day_offset)
    utc_hour = circadian.sample_utc_hour(rng)
    hour_int = int(utc_hour)
    frac = utc_hour - hour_int
    minute = int(frac * 60)
    second = rng.randint(0, 59)
    return candidate_date.replace(
        hour=hour_int % 24,
        minute=minute,
        second=second,
        microsecond=0,
        tzinfo=timezone.utc,
    )


def format_ts(dt: datetime) -> str:
    """Format a datetime as ISO 8601 UTC string with Z suffix."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Event count resolution from baselines
# ---------------------------------------------------------------------------

def resolve_event_count(
    person: Dict[str, Any],
    event_type: str,
    fallback_count: int,
    rng: random.Random,
    *,
    window_days: int = 30,
    scale_factor: float = 1.0,
    baseline_std_scale: float = 1.0,
) -> int:
    """Resolve how many events a person should generate.

    Reads from ``person["behavior_baselines"]["{event_type}_baseline"]["avg_events_per_day"]``
    and multiplies by ``window_days``.  Falls back to ``fallback_count`` if
    no baseline is present.

    ``scale_factor`` is applied to the final count regardless of whether the
    baseline or fallback path was used (e.g. 2.0 doubles the count).

    ``baseline_std_scale`` multiplies the std deviation used when sampling
    per-person rates (e.g. 2.0 = wider spread around the mean).
    """
    baselines = person.get("behavior_baselines") or {}
    baseline_key = f"{event_type}_baseline"
    bl = baselines.get(baseline_key)
    if isinstance(bl, dict) and "avg_events_per_day" in bl:
        avg_spec = bl["avg_events_per_day"]
        if isinstance(avg_spec, dict):
            mean_per_day = float(avg_spec.get("mean", 1.0))
            std_per_day = float(avg_spec.get("std", 0.5)) * baseline_std_scale
        else:
            mean_per_day = float(avg_spec)
            std_per_day = mean_per_day * 0.25 * baseline_std_scale
        # Sample per-person rate then multiply by window
        person_rate = max(0.0, rng.gauss(mean_per_day, std_per_day))
        total = person_rate * window_days
        return max(0, round(total * scale_factor))
    # Fallback: use the provided count (legacy behavior)
    return max(0, round(_vary_count(fallback_count, rng, cv=0.25 * baseline_std_scale) * scale_factor))


def _vary_count(mean: int, rng: random.Random, cv: float = 0.25) -> int:
    """Duplicate of user_activity.vary_count for internal use."""
    if mean <= 1:
        return max(0, mean)
    std = cv * mean
    value = rng.gauss(mean, std)
    return max(0, min(round(value), 2 * mean))


# ---------------------------------------------------------------------------
# Person temporal resolution
# ---------------------------------------------------------------------------

def resolve_person_temporal(
    person: Dict[str, Any],
    generation_config: Dict[str, Any],
) -> Tuple[CircadianSampler, WeeklyCycleModulator]:
    """Build temporal samplers for a person from their baselines and location."""
    baselines = person.get("behavior_baselines") or {}
    location = person.get("location", "")
    department = person.get("department", "")

    temporal_cfg = generation_config.get("temporal", {})
    kappa = temporal_cfg.get("circadian", {}).get("concentration", 2.5)
    tz_map = generation_config.get("location_timezones", {})

    # Build circadian sampler from login baseline hours
    login_bl = baselines.get("login_baseline") or {}
    hours_spec = login_bl.get("hours", ["08:00-10:00", "13:00-17:00"])
    circadian = CircadianSampler.from_baseline(hours_spec, location, kappa, tz_map)

    # Build weekly modulator from department
    weekly = WeeklyCycleModulator.from_config(department, generation_config)

    return circadian, weekly


def get_window(generation_config: Dict[str, Any]) -> Tuple[datetime, datetime]:
    """Return (window_start, window_end) based on generation_config.temporal.window_days."""
    window_days = (
        generation_config.get("temporal", {}).get("window_days", 30)
    )
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(days=window_days)
    return window_start, window_end


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hhmm_to_hours(s: str) -> float:
    """Convert "HH:MM" string to fractional hours."""
    s = s.strip()
    parts = s.split(":")
    h = int(parts[0])
    m = int(parts[1]) if len(parts) > 1 else 0
    return h + m / 60.0


def _sample_von_mises(rng: random.Random, mu: float, kappa: float) -> float:
    """Sample from von Mises distribution using rejection sampling.

    Returns an angle in [0, 2*pi).
    """
    if kappa < 1e-6:
        return rng.uniform(0, 2 * math.pi)

    # Use the Best-Fisher algorithm for von Mises sampling
    tau = 1.0 + math.sqrt(1.0 + 4.0 * kappa * kappa)
    rho = (tau - math.sqrt(2.0 * tau)) / (2.0 * kappa)
    r = (1.0 + rho * rho) / (2.0 * rho)

    for _ in range(1000):
        u1 = rng.random()
        z = math.cos(math.pi * u1)
        f = (1.0 + r * z) / (r + z)
        c = kappa * (r - f)
        u2 = rng.random()
        if c * (2.0 - c) > u2 or math.log(c / u2) + 1.0 >= c:
            u3 = rng.random()
            theta = mu + math.copysign(math.acos(f), u3 - 0.5)
            return theta % (2 * math.pi)

    # Fallback (should never reach here)
    return rng.uniform(0, 2 * math.pi)
