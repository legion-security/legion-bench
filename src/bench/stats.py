"""Confidence intervals for aggregate benchmark metrics.

Every headline number in a report is a mean over runs, and runs are not
independent: in isolated mode the same base scenario is attacked with several
victims, and every agent is measured on the same scenario set. Treating runs as
iid understates the uncertainty, because two runs of the same scenario tell you
less than two runs of different scenarios.

So the default here is a **cluster bootstrap over base scenarios**: resample
scenarios with replacement, pool the runs belonging to the drawn scenarios, and
take the mean. The spread of those resampled means is the sampling distribution
the interval comes from. It needs no normality assumption and — being a
percentile method — can never report a bound outside the data's own range, which
matters for recall metrics that pile up at 0 and 1.

A ``normal`` method is also provided (mean ± z·SEM over runs, ignoring
clustering) because ``scripts/make_metrics_figure.py`` uses that convention for
the paper figure. Prefer ``cluster_bootstrap`` for new work.

Bootstrap draws come from a seeded generator, so a given results directory always
produces identical intervals.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

import numpy as np

DEFAULT_CONFIDENCE = 0.95
DEFAULT_RESAMPLES = 10_000
DEFAULT_SEED = 20260728

# Metrics bounded on [0, 1]; used only to sanity-check, never to widen an interval.
_UNIT_INTERVAL_HINT = ("recall", "precision", "f1", "score")


@dataclass(frozen=True)
class MeanCI:
    """A mean with a confidence interval and the sample size behind it."""

    mean: Optional[float]
    lo: Optional[float]
    hi: Optional[float]
    n: int                      # number of observations (runs)
    n_clusters: Optional[int]   # number of independent units resampled
    method: str
    confidence: float

    @property
    def has_interval(self) -> bool:
        return self.lo is not None and self.hi is not None

    @property
    def half_width(self) -> Optional[float]:
        """Half the interval width — the '±' figure, for symmetric-ish reporting."""
        if not self.has_interval:
            return None
        return (self.hi - self.lo) / 2.0

    def as_dict(self) -> dict:
        return {
            "mean": self.mean,
            "ci_lo": self.lo,
            "ci_hi": self.hi,
            "n": self.n,
            "n_clusters": self.n_clusters,
            "ci_method": self.method,
            "ci_confidence": self.confidence,
        }


_EMPTY = MeanCI(None, None, None, 0, None, "none", DEFAULT_CONFIDENCE)


def _clean(values: Iterable[Any], clusters: Optional[Sequence[Any]]):
    """Drop non-finite observations, keeping cluster labels aligned."""
    vals = np.asarray(list(values), dtype="float64")
    if clusters is None:
        return vals[np.isfinite(vals)], None
    clus = np.asarray(list(clusters), dtype=object)
    if len(clus) != len(vals):
        raise ValueError(f"values ({len(vals)}) and clusters ({len(clus)}) length mismatch")
    keep = np.isfinite(vals)
    return vals[keep], clus[keep]


def mean_ci(
    values: Iterable[Any],
    *,
    clusters: Optional[Sequence[Any]] = None,
    method: str = "cluster_bootstrap",
    confidence: float = DEFAULT_CONFIDENCE,
    n_resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
) -> MeanCI:
    """Mean of ``values`` with a confidence interval.

    Args:
        values: Per-run metric values. Non-finite entries (None/NaN) are dropped.
        clusters: Independent-unit label per value — normally the base scenario
            id. Required by ``cluster_bootstrap``; when omitted each observation
            is its own cluster, i.e. a plain iid bootstrap.
        method: ``cluster_bootstrap`` (default) or ``normal`` (mean ± z·SEM).
        confidence: Coverage, e.g. 0.95.
        n_resamples: Bootstrap resample count.
        seed: Seed for the bootstrap generator, so intervals are reproducible.

    Returns:
        A MeanCI. With fewer than 2 independent units the mean is still
        reported but ``lo``/``hi`` are None — there is nothing to estimate
        spread from, and a zero-width interval would be a lie.
    """
    vals, clus = _clean(values, clusters)
    n = int(vals.size)
    if n == 0:
        return MeanCI(None, None, None, 0, None, method, confidence)

    mean = float(vals.mean())

    if method == "normal":
        if n < 2:
            return MeanCI(mean, None, None, n, None, method, confidence)
        sem = float(vals.std(ddof=1) / math.sqrt(n))
        z = _z_for(confidence)
        return MeanCI(mean, mean - z * sem, mean + z * sem, n, None, method, confidence)

    if method != "cluster_bootstrap":
        raise ValueError(f"Unknown CI method: {method!r}")

    if clus is None:
        clus = np.arange(n, dtype=object)

    uniq, inv = np.unique(clus.astype(str), return_inverse=True)
    n_clusters = int(uniq.size)
    if n_clusters < 2:
        return MeanCI(mean, None, None, n, n_clusters, method, confidence)

    # Resample whole clusters, then take the pooled mean of the drawn runs.
    # Pooling by sums/counts keeps unequal cluster sizes weighted correctly —
    # this is the mean over runs, not the mean of per-cluster means.
    sums = np.bincount(inv, weights=vals, minlength=n_clusters)
    counts = np.bincount(inv, minlength=n_clusters).astype("float64")

    rng = np.random.default_rng(seed)
    draw = rng.integers(0, n_clusters, size=(n_resamples, n_clusters))
    boot = sums[draw].sum(axis=1) / counts[draw].sum(axis=1)

    alpha = (1.0 - confidence) / 2.0
    lo, hi = np.quantile(boot, [alpha, 1.0 - alpha])
    return MeanCI(mean, float(lo), float(hi), n, n_clusters, method, confidence)


def _z_for(confidence: float) -> float:
    """Normal quantile for a two-sided interval, without a scipy dependency."""
    table = {0.80: 1.2816, 0.90: 1.6449, 0.95: 1.9600, 0.98: 2.3263, 0.99: 2.5758}
    key = round(confidence, 2)
    if key in table:
        return table[key]
    # Acklam's inverse-normal approximation; plenty accurate for CI bounds.
    p = 1.0 - (1.0 - confidence) / 2.0
    a = [-3.969683028665376e01, 2.209460984245205e02, -2.759285104469687e02,
         1.383577518672690e02, -3.066479806614716e01, 2.506628277459239e00]
    b = [-5.447609879822406e01, 1.615858368580409e02, -1.556989798598866e02,
         6.680131188771972e01, -1.328068155288572e01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e00,
         -2.549732539343734e00, 4.374664141464968e00, 2.938163982698783e00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e00,
         3.754408661907416e00]
    plow, phigh = 0.02425, 1 - 0.02425
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p > phigh:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
                ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    q = p - 0.5
    r = q * q
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
           (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)


def fmt_ci(ci: MeanCI, *, pct: bool = False, decimals: int = 2) -> str:
    """Render as ``mean [lo-hi]`` for a Markdown table cell.

    Falls back to the bare mean when no interval could be estimated, and to
    ``-`` when there is no data at all.
    """
    if ci.mean is None:
        return "-"
    if pct:
        centre = f"{ci.mean:.0%}"
        if not ci.has_interval:
            return centre
        return f"{centre} [{ci.lo * 100:.0f}-{ci.hi * 100:.0f}]"
    centre = f"{ci.mean:.{decimals}f}"
    if not ci.has_interval:
        return centre
    return f"{centre} [{ci.lo:.{decimals}f}-{ci.hi:.{decimals}f}]"


def series_ci(
    frame,
    column: str,
    *,
    cluster_column: Optional[str] = "base_scenario_id",
    **kwargs,
) -> MeanCI:
    """``mean_ci`` for a DataFrame column, clustering on ``cluster_column``.

    Missing columns and all-null columns yield an empty MeanCI rather than an
    error, matching how the report tables treat absent metrics.
    """
    if column not in frame.columns or frame.empty:
        return _EMPTY
    clusters = None
    if cluster_column and cluster_column in frame.columns:
        clusters = frame[cluster_column].astype(str).tolist()
    return mean_ci(frame[column].tolist(), clusters=clusters, **kwargs)


def methods_note(confidence: float = DEFAULT_CONFIDENCE) -> str:
    """One-line description of the interval, for the report header."""
    return (
        f"Bracketed ranges are {confidence:.0%} confidence intervals from a cluster "
        f"bootstrap ({DEFAULT_RESAMPLES:,} resamples, seed {DEFAULT_SEED}) that "
        f"resamples base scenarios rather than individual runs, so repeated "
        f"victims of one scenario are not counted as independent evidence. "
        f"A cell shows no interval when fewer than 2 scenarios contribute."
    )
