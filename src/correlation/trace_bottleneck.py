"""Trace bottleneck analysis — self-time vs downstream-time per trace.

This is the analysis Bits AI SRE uses to distinguish "service X is slow
because downstream Y is slow" from "service X is slow internally and
downstream is fine." Without this, an investigation can look at error
logs from a downstream service that happen to fire during the alert
window and incorrectly conclude downstream caused the issue, when in
reality the alerted service is internally bottlenecked (goroutine
contention, GC, lock contention, slow code path) and downstream
returns in milliseconds.

Algorithm:
  For each trace, group spans by trace_id and build the parent->child
  tree. self_time(span) = duration - sum(child durations). Aggregate
  self_time per service across all slow traces. The service with the
  largest aggregate self_time is the dominant bottleneck.

Output is a structured `TraceBottleneckAnalysis` ready to inject into
prompts and to gate downstream-cause hypotheses in rules.py.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from src.models.incident import TraceSpan

logger = logging.getLogger(__name__)


@dataclass
class TraceBottleneckAnalysis:
    """Result of self-time vs downstream-time analysis across traces."""

    total_traces_analyzed: int = 0
    slow_traces_analyzed: int = 0
    # Aggregate self-time (ms) per service across all slow traces
    self_time_by_service: dict[str, float] = field(default_factory=dict)
    # Total downstream time (ms) per service across all slow traces
    downstream_time_by_service: dict[str, float] = field(default_factory=dict)
    # For the primary service: ratio of self-time to total time across slow traces
    primary_self_time_ratio: float = 0.0
    # The service whose aggregate self-time is largest — the dominant bottleneck
    dominant_service: str = ""
    # "self" if primary service IS the bottleneck; "downstream" if some other
    # service is; "mixed" if no clear winner; "unknown" if no trace data
    dominant_location: str = "unknown"
    # Top 5 services by self-time, ranked
    ranked_bottlenecks: list[tuple[str, float]] = field(default_factory=list)
    # Max single-trace self-time observed for the primary service (ms)
    primary_max_self_time_ms: float = 0.0

    def summary(self) -> str:
        """One-paragraph summary suitable for prompt injection."""
        if self.dominant_location == "unknown" or self.slow_traces_analyzed == 0:
            return "Trace bottleneck analysis: insufficient trace data."

        lines = [
            f"Analyzed {self.slow_traces_analyzed} slow traces "
            f"(of {self.total_traces_analyzed} total).",
            f"Primary service self-time ratio: {self.primary_self_time_ratio:.0%} "
            f"(max single-trace self-time: {self.primary_max_self_time_ms:.0f}ms).",
            f"Dominant bottleneck: {self.dominant_service} "
            f"({self.dominant_location.upper()}).",
        ]
        if self.ranked_bottlenecks:
            top = ", ".join(
                f"{svc}={ms:.0f}ms" for svc, ms in self.ranked_bottlenecks[:5]
            )
            lines.append(f"Top contributors by self-time: {top}.")

        if self.dominant_location == "self":
            lines.append(
                "INTERPRETATION: The alerted service is internally bottlenecked. "
                "Downstream-cause hypotheses are LIKELY WRONG — investigate "
                "internal causes (goroutine contention, GC, lock contention, "
                "slow code path, capacity gap)."
            )
        elif self.dominant_location == "downstream":
            lines.append(
                f"INTERPRETATION: A downstream service ({self.dominant_service}) "
                f"is the actual bottleneck. Investigate further into that service."
            )

        return " ".join(lines)


def compute_trace_bottleneck(
    spans: list[TraceSpan],
    primary_service: str,
    slow_threshold_ms: float = 1000.0,
    min_dominance_ratio: float = 0.6,
) -> TraceBottleneckAnalysis:
    """Compute per-service self-time across all slow traces.

    A trace is "slow" if its root span duration exceeds slow_threshold_ms.
    A service is the "dominant" bottleneck if its share of total self-time
    across all slow traces exceeds min_dominance_ratio.

    Returns a TraceBottleneckAnalysis. Safe on empty input — returns
    a default-filled analysis with dominant_location="unknown".
    """
    result = TraceBottleneckAnalysis()
    if not spans:
        return result

    # 1. Group spans by trace_id
    by_trace: dict[str, list[TraceSpan]] = defaultdict(list)
    for span in spans:
        by_trace[span.trace_id].append(span)

    result.total_traces_analyzed = len(by_trace)

    self_time_agg: dict[str, float] = defaultdict(float)
    downstream_time_agg: dict[str, float] = defaultdict(float)
    primary_self_time_total = 0.0
    primary_total_time = 0.0
    primary_max_self_time = 0.0

    for trace_id, trace_spans in by_trace.items():
        # 2. Find root span — span with empty parent_id, or with a parent_id
        # not present in this trace's span set
        span_ids = {s.span_id for s in trace_spans}
        roots = [
            s for s in trace_spans
            if not s.parent_id or s.parent_id not in span_ids
        ]
        if not roots:
            continue
        root = max(roots, key=lambda s: s.duration_ns)
        root_duration_ms = root.duration_ns / 1_000_000.0
        if root_duration_ms < slow_threshold_ms:
            continue

        result.slow_traces_analyzed += 1

        # 3. Build parent->children map for this trace, compute self-time
        children_by_parent: dict[str, list[TraceSpan]] = defaultdict(list)
        for s in trace_spans:
            if s.parent_id:
                children_by_parent[s.parent_id].append(s)

        for s in trace_spans:
            child_duration_ns = sum(c.duration_ns for c in children_by_parent.get(s.span_id, []))
            self_ns = max(s.duration_ns - child_duration_ns, 0)
            self_ms = self_ns / 1_000_000.0
            self_time_agg[s.service] += self_ms

            # If this span calls out to a different service via children,
            # accumulate that as downstream time on the parent's service.
            for child in children_by_parent.get(s.span_id, []):
                if child.service != s.service:
                    downstream_time_agg[s.service] += child.duration_ns / 1_000_000.0

            if s.service == primary_service:
                primary_self_time_total += self_ms
                primary_total_time += s.duration_ns / 1_000_000.0
                if self_ms > primary_max_self_time:
                    primary_max_self_time = self_ms

    if result.slow_traces_analyzed == 0:
        return result

    result.self_time_by_service = dict(self_time_agg)
    result.downstream_time_by_service = dict(downstream_time_agg)
    result.primary_max_self_time_ms = primary_max_self_time

    if primary_total_time > 0:
        result.primary_self_time_ratio = primary_self_time_total / primary_total_time

    # Rank services by aggregate self-time
    ranked = sorted(self_time_agg.items(), key=lambda kv: -kv[1])
    result.ranked_bottlenecks = ranked

    if ranked:
        total_self_time = sum(self_time_agg.values())
        top_service, top_self_time = ranked[0]
        top_share = top_self_time / total_self_time if total_self_time > 0 else 0.0

        result.dominant_service = top_service
        if top_share >= min_dominance_ratio:
            result.dominant_location = (
                "self" if top_service == primary_service else "downstream"
            )
        else:
            result.dominant_location = "mixed"

    return result


def is_self_bound(analysis: TraceBottleneckAnalysis, threshold: float = 0.6) -> bool:
    """Convenience: True if the primary service is the dominant bottleneck."""
    return (
        analysis.dominant_location == "self"
        and analysis.primary_self_time_ratio >= threshold
    )


def is_downstream_bound(analysis: TraceBottleneckAnalysis) -> bool:
    """Convenience: True if a downstream service is the dominant bottleneck."""
    return analysis.dominant_location == "downstream"
