"""Historical baseline / recurrence detection.

Bits AI SRE answered the test9 incident correctly partly because it
looked at 12+ hours of historical data and noticed the latency spike
was recurring every 3–5 hours — that pattern alone disqualified the
"one-time deployment caused this" hypothesis. Our agent stayed inside
the alert window and missed this.

This module computes simple statistics over a long-window metric
series and exposes whether the alert window's spike fits a recurring
pattern. No fancy time-series modeling — just median+MAD spike
detection on the raw points.

Design intent:
- Cheap to compute (one Datadog query, pure-python aggregation)
- Output is a structured summary suitable for prompt injection
- Conservative: only flags recurrence if multiple distinct spike
  events are found, to avoid false-positives on noisy metrics
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from src.models.incident import MetricSeries

logger = logging.getLogger(__name__)


@dataclass
class SpikeEvent:
    """A single spike event — a contiguous run of points above threshold."""

    start: datetime
    end: datetime
    peak_value: float
    duration_seconds: float


@dataclass
class RecurrenceAnalysis:
    """Result of historical baseline analysis on a single metric."""

    metric_name: str = ""
    baseline_median: float = 0.0
    baseline_mad: float = 0.0  # median absolute deviation (robust spread)
    threshold_value: float = 0.0
    spike_events: list[SpikeEvent] = field(default_factory=list)
    is_recurring: bool = False
    period_estimate_minutes: float = 0.0
    # Whether the most recent (current) spike is the only one — i.e., novel
    is_novel_event: bool = False

    def summary(self) -> str:
        """One-paragraph summary suitable for prompt injection."""
        if not self.metric_name:
            return "Historical baseline: no metric data available."
        if not self.spike_events:
            return (
                f"Historical baseline ({self.metric_name}): "
                f"no spikes above {self.threshold_value:.2f} detected in lookback window. "
                f"This may be a novel anomaly or the metric may not be the right one."
            )
        if self.is_recurring:
            times = ", ".join(
                e.start.strftime("%H:%M UTC") for e in self.spike_events[-5:]
            )
            return (
                f"Historical baseline ({self.metric_name}): "
                f"baseline median {self.baseline_median:.2f}, threshold {self.threshold_value:.2f}. "
                f"RECURRING PATTERN: {len(self.spike_events)} spike events in lookback "
                f"window (last 5: {times}). "
                f"Estimated period: ~{self.period_estimate_minutes:.0f} minutes. "
                f"INTERPRETATION: This is a recurring issue — a one-time deployment "
                f"or config change is UNLIKELY to be the root cause. Look for "
                f"periodic processes, autoscaler churn, traffic-driven capacity gaps, "
                f"or scheduled jobs with matching cadence."
            )
        return (
            f"Historical baseline ({self.metric_name}): "
            f"baseline median {self.baseline_median:.2f}, threshold {self.threshold_value:.2f}. "
            f"{len(self.spike_events)} spike event(s) detected — current event "
            f"appears novel relative to recent history."
        )


def _median_absolute_deviation(values: list[float], median: float) -> float:
    """Robust spread measure — median of |x - median(x)|."""
    if not values:
        return 0.0
    abs_devs = [abs(v - median) for v in values]
    return statistics.median(abs_devs)


def detect_recurrence(
    series: MetricSeries,
    threshold_factor: float = 3.0,
    min_spike_duration_seconds: float = 60.0,
    max_gap_seconds: float = 300.0,
    min_spikes_for_recurring: int = 3,
) -> RecurrenceAnalysis:
    """Detect spike events in a long-window metric series.

    A point is a "spike" if it exceeds (median + threshold_factor * MAD).
    Contiguous spike points (with gaps <= max_gap_seconds) are grouped
    into a single SpikeEvent; events shorter than min_spike_duration are
    discarded as noise. If at least min_spikes_for_recurring distinct
    events are found, the pattern is flagged as recurring.

    Conservative defaults: threshold_factor=3 (high bar), min_spikes=3
    (avoid flagging two-event noise). Tune via args.
    """
    result = RecurrenceAnalysis()
    if not series or not series.points:
        return result

    result.metric_name = series.metric_name
    values = [p.value for p in series.points]

    if len(values) < 10:
        # Not enough data to compute a meaningful baseline
        return result

    median = statistics.median(values)
    mad = _median_absolute_deviation(values, median)
    # If MAD is essentially zero (constant metric), use a small fraction of
    # the median as the deviation floor to avoid divide-by-zero spike detection.
    if mad < 1e-9:
        mad = max(abs(median) * 0.1, 1e-6)

    threshold = median + threshold_factor * mad
    result.baseline_median = median
    result.baseline_mad = mad
    result.threshold_value = threshold

    # Walk points and group spikes
    sorted_points = sorted(series.points, key=lambda p: p.timestamp)
    events: list[SpikeEvent] = []
    current_start: datetime | None = None
    current_end: datetime | None = None
    current_peak = 0.0
    last_spike_ts: datetime | None = None

    for p in sorted_points:
        is_spike = p.value > threshold
        if is_spike:
            if current_start is None:
                current_start = p.timestamp
                current_peak = p.value
            else:
                # Continue the current event if within max_gap
                if (
                    last_spike_ts
                    and (p.timestamp - last_spike_ts).total_seconds() > max_gap_seconds
                ):
                    # Gap too big — close out current event, start new one
                    if current_start and current_end:
                        events.append(SpikeEvent(
                            start=current_start,
                            end=current_end,
                            peak_value=current_peak,
                            duration_seconds=(current_end - current_start).total_seconds(),
                        ))
                    current_start = p.timestamp
                    current_peak = p.value
            current_end = p.timestamp
            current_peak = max(current_peak, p.value)
            last_spike_ts = p.timestamp
        else:
            # Below threshold — close out current event if any
            if current_start and current_end:
                events.append(SpikeEvent(
                    start=current_start,
                    end=current_end,
                    peak_value=current_peak,
                    duration_seconds=(current_end - current_start).total_seconds(),
                ))
            current_start = None
            current_end = None
            current_peak = 0.0

    # Flush trailing event
    if current_start and current_end:
        events.append(SpikeEvent(
            start=current_start,
            end=current_end,
            peak_value=current_peak,
            duration_seconds=(current_end - current_start).total_seconds(),
        ))

    # Filter out events shorter than the min duration (single-point noise)
    events = [e for e in events if e.duration_seconds >= min_spike_duration_seconds]
    result.spike_events = events

    if len(events) >= min_spikes_for_recurring:
        result.is_recurring = True
        # Estimate period as median gap between consecutive event starts
        if len(events) >= 2:
            gaps = [
                (events[i + 1].start - events[i].start).total_seconds() / 60.0
                for i in range(len(events) - 1)
            ]
            result.period_estimate_minutes = statistics.median(gaps)
    elif len(events) <= 1:
        result.is_novel_event = True

    return result


def detect_recurrence_from_alert_metric(
    series: MetricSeries,
    incident_start: datetime,
    incident_end: datetime,
) -> RecurrenceAnalysis:
    """Convenience: run detect_recurrence and annotate whether the current
    incident window contains one of the detected spike events.

    This helps the prompt say "the alert spike at 08:25 is the 4th in 24h".
    """
    analysis = detect_recurrence(series)

    # Mark whether the incident window overlaps any detected spike
    if analysis.spike_events:
        for ev in analysis.spike_events:
            if ev.start <= incident_end and ev.end >= incident_start:
                # Found the current spike — confirm it's part of a recurring pattern
                if analysis.is_recurring and len(analysis.spike_events) > 1:
                    analysis.is_novel_event = False
                break

    return analysis
