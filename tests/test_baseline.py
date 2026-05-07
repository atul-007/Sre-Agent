"""Tests for historical baseline / recurrence detection."""

from datetime import datetime, timedelta

from src.correlation.baseline import (
    detect_recurrence,
    detect_recurrence_from_alert_metric,
)
from src.models.incident import MetricDataPoint, MetricSeries

NOW = datetime(2026, 5, 7, 12, 0, 0)


def _series(values_at_minutes: list[tuple[int, float]], name: str = "p95.latency") -> MetricSeries:
    """Build a MetricSeries from (minutes_before_now, value) tuples."""
    return MetricSeries(
        metric_name=name,
        display_name=name,
        points=[
            MetricDataPoint(
                timestamp=NOW - timedelta(minutes=minutes_before),
                value=value,
            )
            for minutes_before, value in values_at_minutes
        ],
    )


class TestRecurrence:
    """Detection of repeated spike events."""

    def test_recurring_pattern_detected(self):
        # 4 spike events at 30-min intervals, each 5 minutes long, baseline 100, peak 500
        # Build as a dict keyed by minute so spikes overwrite baseline (no dup timestamps).
        by_minute = {m: 100 + (m % 7) for m in range(720, 0, -1)}
        for spike_minute in [540, 360, 180, 5]:
            for offset in range(5):
                by_minute[spike_minute - offset] = 500 + offset
        points = sorted(by_minute.items(), reverse=True)
        series = _series(points)
        result = detect_recurrence(series, threshold_factor=3.0)
        assert result.is_recurring
        assert len(result.spike_events) >= 3
        assert result.period_estimate_minutes > 0

    def test_single_spike_is_not_recurring(self):
        # 12h of baseline + 1 spike → novel event, not recurring
        by_minute = {m: 100 + (m % 5) for m in range(720, 0, -1)}
        for offset in range(5):
            by_minute[offset] = 500
        points = sorted(by_minute.items(), reverse=True)
        series = _series(points)
        result = detect_recurrence(series)
        assert not result.is_recurring
        assert result.is_novel_event

    def test_constant_metric_does_not_spike(self):
        # All values identical → no spikes
        points = [(m, 100.0) for m in range(720, 0, -1)]
        series = _series(points)
        result = detect_recurrence(series)
        assert not result.is_recurring
        assert len(result.spike_events) == 0


class TestEdgeCases:
    """Defensive behavior."""

    def test_empty_series(self):
        series = MetricSeries(metric_name="x", display_name="x", points=[])
        result = detect_recurrence(series)
        assert not result.is_recurring
        assert result.metric_name == ""

    def test_too_few_points(self):
        # < 10 points: no analysis
        points = [(m, float(m)) for m in range(5)]
        series = _series(points)
        result = detect_recurrence(series)
        assert not result.is_recurring
        assert result.baseline_median == 0.0  # default, not computed


class TestSummary:
    """Prompt-friendly summary output."""

    def test_recurring_summary_calls_out_period(self):
        by_minute = {m: 100 + (m % 5) for m in range(720, 0, -1)}
        for spike_minute in [540, 360, 180, 5]:
            for offset in range(5):
                by_minute[spike_minute - offset] = 500
        points = sorted(by_minute.items(), reverse=True)
        series = _series(points)
        result = detect_recurrence(series)
        s = result.summary()
        assert "RECURRING PATTERN" in s
        assert "Estimated period" in s
        assert "deployment" in s.lower()  # interpretation mentions deployment is unlikely

    def test_novel_event_summary(self):
        by_minute = {m: 100 + (m % 5) for m in range(720, 0, -1)}
        for offset in range(5):
            by_minute[offset] = 500
        points = sorted(by_minute.items(), reverse=True)
        series = _series(points)
        result = detect_recurrence(series)
        s = result.summary()
        assert "novel" in s.lower() or "appears novel" in s.lower()


class TestAlertMetricHelper:
    """Convenience helper that maps the spike to the incident window."""

    def test_marks_current_event_as_part_of_pattern(self):
        # Build a recurring pattern where the most recent spike sits inside the
        # incident window — should set is_novel_event=False.
        by_minute = {m: 100 + (m % 5) for m in range(720, 0, -1)}
        for spike_minute in [540, 360, 180, 5]:
            for offset in range(5):
                by_minute[spike_minute - offset] = 500
        points = sorted(by_minute.items(), reverse=True)
        series = _series(points)
        incident_start = NOW - timedelta(minutes=10)
        incident_end = NOW
        result = detect_recurrence_from_alert_metric(series, incident_start, incident_end)
        assert result.is_recurring
        assert not result.is_novel_event
