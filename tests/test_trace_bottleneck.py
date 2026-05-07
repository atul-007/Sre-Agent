"""Tests for trace bottleneck analysis (self-time vs downstream-time)."""

from datetime import datetime

import pytest

from src.correlation.trace_bottleneck import (
    compute_trace_bottleneck,
    is_downstream_bound,
    is_self_bound,
)
from src.models.incident import TraceSpan

NOW = datetime(2026, 5, 7, 10, 0, 0)


def _span(
    trace_id: str,
    span_id: str,
    service: str,
    duration_ms: float,
    parent_id: str = "",
) -> TraceSpan:
    return TraceSpan(
        trace_id=trace_id,
        span_id=span_id,
        parent_id=parent_id,
        service=service,
        operation="op",
        resource="r",
        duration_ns=int(duration_ms * 1_000_000),
        start_time=NOW,
        status="ok",
    )


class TestSelfTimeBottleneck:
    """When the alerted service is internally bottlenecked."""

    def test_dominant_self_time_marks_self_bound(self):
        # Root in primary service: 10s. One downstream child: 100ms.
        # Self-time = 9.9s = ~99% of root duration.
        spans = [
            _span("t1", "s1", "search", 10_000),
            _span("t1", "s2", "items", 100, parent_id="s1"),
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        assert result.slow_traces_analyzed == 1
        assert result.dominant_location == "self"
        assert result.dominant_service == "search"
        assert result.primary_self_time_ratio > 0.95
        assert is_self_bound(result)
        assert not is_downstream_bound(result)

    def test_aggregates_self_time_across_traces(self):
        spans = []
        for i in range(5):
            spans.append(_span(f"t{i}", f"r{i}", "search", 5_000))
            spans.append(_span(f"t{i}", f"c{i}", "items", 50, parent_id=f"r{i}"))
        result = compute_trace_bottleneck(spans, primary_service="search")
        assert result.slow_traces_analyzed == 5
        assert result.dominant_service == "search"
        assert result.dominant_location == "self"
        # Aggregate self-time for search ~ 5 * 4950 ≈ 24750ms
        assert result.self_time_by_service["search"] > 20_000


class TestDownstreamBottleneck:
    """When a downstream service is the actual bottleneck."""

    def test_dominant_downstream_marks_downstream_bound(self):
        # Root span 5s, but child in downstream takes 4.9s.
        spans = [
            _span("t1", "s1", "search", 5_000),
            _span("t1", "s2", "items", 4_900, parent_id="s1"),
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        assert result.slow_traces_analyzed == 1
        assert result.dominant_location == "downstream"
        assert result.dominant_service == "items"
        assert is_downstream_bound(result)
        assert not is_self_bound(result)

    def test_chain_of_downstream_bottlenecks(self):
        # search -> items -> spanner; spanner is the actual slow one
        spans = [
            _span("t1", "s1", "search", 6_000),
            _span("t1", "s2", "items", 5_900, parent_id="s1"),
            _span("t1", "s3", "spanner", 5_800, parent_id="s2"),
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        assert result.dominant_service == "spanner"
        assert result.dominant_location == "downstream"


class TestEdgeCases:
    """Defensive behavior on degenerate inputs."""

    def test_empty_spans(self):
        result = compute_trace_bottleneck([], primary_service="search")
        assert result.slow_traces_analyzed == 0
        assert result.dominant_location == "unknown"

    def test_only_fast_traces_ignored(self):
        # All traces under threshold — none counted as slow.
        spans = [
            _span("t1", "s1", "search", 100),
            _span("t1", "s2", "items", 50, parent_id="s1"),
        ]
        result = compute_trace_bottleneck(
            spans, primary_service="search", slow_threshold_ms=1000
        )
        assert result.slow_traces_analyzed == 0
        assert result.dominant_location == "unknown"

    def test_mixed_no_clear_winner(self):
        # Two services contribute roughly equally — should be "mixed".
        spans = [
            _span("t1", "s1", "search", 4_000),
            _span("t1", "s2", "items", 1_900, parent_id="s1"),
            # search self-time ≈ 2100, items self-time = 1900 → ~52/48 split
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        assert result.dominant_location == "mixed"

    def test_orphan_spans_treated_as_root(self):
        # span with parent_id pointing to a span not in the set should be
        # treated as a root (common when fetching only the slow part of a trace).
        spans = [
            _span("t1", "s99", "search", 5_000, parent_id="missing-parent"),
            _span("t1", "s2", "items", 100, parent_id="s99"),
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        assert result.slow_traces_analyzed == 1
        assert result.dominant_location == "self"


class TestSummary:
    """Human-readable summary suitable for prompts."""

    def test_summary_self_bound_calls_out_internal_cause(self):
        spans = [
            _span("t1", "s1", "search", 10_000),
            _span("t1", "s2", "items", 50, parent_id="s1"),
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        summary = result.summary()
        assert "internally bottlenecked" in summary.lower()
        assert "downstream-cause hypotheses are likely wrong" in summary.lower()

    def test_summary_downstream_bound_names_culprit(self):
        spans = [
            _span("t1", "s1", "search", 5_000),
            _span("t1", "s2", "items", 4_900, parent_id="s1"),
        ]
        result = compute_trace_bottleneck(spans, primary_service="search")
        summary = result.summary()
        assert "items" in summary
        assert "downstream service" in summary.lower()

    def test_summary_no_data(self):
        result = compute_trace_bottleneck([], primary_service="search")
        assert "insufficient" in result.summary().lower()
