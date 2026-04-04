"""Signal correlation engine — aligns metrics, logs, traces, and events on a unified timeline."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean, stdev

from src.models.incident import (
    IncidentQuery,
    IncidentSeverity,
    LogEntry,
    MetricSeries,
    ObservabilityData,
    TimelineEvent,
    TraceSpan,
)

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Correlates observability signals into a unified investigation context."""

    def __init__(self, correlation_window_seconds: int = 300) -> None:
        self.window = timedelta(seconds=correlation_window_seconds)

    def build_timeline(
        self, incident: IncidentQuery, data: ObservabilityData
    ) -> list[TimelineEvent]:
        """Build a unified, time-ordered timeline of all significant events."""
        events: list[TimelineEvent] = []

        # 1. Metric anomalies
        events.extend(self._detect_metric_anomalies(data.metrics))

        # 2. Error logs
        events.extend(self._extract_log_events(data.logs))

        # 3. Trace errors / slow spans
        events.extend(self._extract_trace_events(data.traces))

        # 4. Deployment events
        for evt in data.deployment_events:
            events.append(
                TimelineEvent(
                    timestamp=evt.timestamp,
                    event_type="deployment",
                    source=evt.source,
                    description=f"Deployment: {evt.title}",
                    severity=IncidentSeverity.HIGH,
                    evidence={"text": evt.text, "tags": evt.tags},
                )
            )

        # 5. Monitor alerts
        for mon in data.monitors:
            if mon.status in ("Alert", "Warn"):
                events.append(
                    TimelineEvent(
                        timestamp=mon.last_triggered or incident.start_time,
                        event_type="monitor_alert",
                        source=f"monitor:{mon.monitor_id}",
                        description=f"Monitor '{mon.name}' in {mon.status} state",
                        severity=(
                            IncidentSeverity.CRITICAL
                            if mon.status == "Alert"
                            else IncidentSeverity.HIGH
                        ),
                        evidence={"monitor_id": mon.monitor_id, "message": mon.message},
                    )
                )

        # 6. General events
        for evt in data.events:
            events.append(
                TimelineEvent(
                    timestamp=evt.timestamp,
                    event_type="event",
                    source=evt.source,
                    description=evt.title,
                    severity=IncidentSeverity.MEDIUM,
                    evidence={"text": evt.text},
                )
            )

        events.sort(key=lambda e: e.timestamp)
        return events

    def correlate_services(self, data: ObservabilityData) -> dict:
        """Map error propagation across services using traces and service map."""
        service_errors: dict[str, list[dict]] = defaultdict(list)

        # Group trace errors by service
        for span in data.traces:
            if span.status == "error":
                service_errors[span.service].append(
                    {
                        "trace_id": span.trace_id,
                        "operation": span.operation,
                        "error_type": span.error_type,
                        "error_message": span.error_message,
                        "timestamp": span.start_time.isoformat(),
                        "duration_ms": span.duration_ns / 1e6,
                    }
                )

        # Build propagation graph from service map
        propagation: list[dict] = []
        for node in data.service_map:
            for dep in node.dependencies:
                if dep.error_rate > 0.01:  # >1% error rate
                    propagation.append(
                        {
                            "from": dep.source_service,
                            "to": dep.target_service,
                            "error_rate": dep.error_rate,
                            "avg_latency_ms": dep.avg_latency_ms,
                            "call_type": dep.call_type,
                        }
                    )

        # Cross-reference: find traces that span multiple erroring services
        cross_service_traces: list[dict] = []
        trace_groups: dict[str, list[TraceSpan]] = defaultdict(list)
        for span in data.traces:
            trace_groups[span.trace_id].append(span)

        for trace_id, spans in trace_groups.items():
            error_services = {s.service for s in spans if s.status == "error"}
            if len(error_services) > 1:
                cross_service_traces.append(
                    {
                        "trace_id": trace_id,
                        "error_services": list(error_services),
                        "span_count": len(spans),
                        "total_errors": sum(1 for s in spans if s.status == "error"),
                    }
                )

        return {
            "service_errors": dict(service_errors),
            "error_propagation": propagation,
            "cross_service_traces": cross_service_traces,
        }

    def compute_anomaly_summary(self, data: ObservabilityData) -> dict:
        """Compute summary statistics and anomalies for the investigation context."""
        summary: dict = {
            "metric_anomalies": [],
            "error_log_count": 0,
            "warn_log_count": 0,
            "error_trace_count": 0,
            "slow_trace_count": 0,
            "top_error_messages": [],
            "affected_resources": [],
        }

        # Metric anomalies
        for series in data.metrics:
            anomaly = self._check_metric_anomaly(series)
            if anomaly:
                summary["metric_anomalies"].append(anomaly)

        # Log stats
        error_msgs: dict[str, int] = defaultdict(int)
        for log in data.logs:
            if log.status == "error":
                summary["error_log_count"] += 1
                # Normalize error messages for grouping
                msg_key = log.message[:200] if log.message else "unknown"
                error_msgs[msg_key] += 1
            elif log.status == "warn":
                summary["warn_log_count"] += 1

        summary["top_error_messages"] = sorted(
            [{"message": k, "count": v} for k, v in error_msgs.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        # Trace stats
        resources_affected: set[str] = set()
        for span in data.traces:
            if span.status == "error":
                summary["error_trace_count"] += 1
                resources_affected.add(f"{span.service}:{span.resource}")
            if span.duration_ns > 1_000_000_000:  # >1s
                summary["slow_trace_count"] += 1
                resources_affected.add(f"{span.service}:{span.resource}")

        summary["affected_resources"] = list(resources_affected)[:20]

        return summary

    # ── Private helpers ──────────────────────────────────────────────

    def _detect_metric_anomalies(self, metrics: list[MetricSeries]) -> list[TimelineEvent]:
        """Detect anomalies in metric series using z-score method."""
        events: list[TimelineEvent] = []
        for series in metrics:
            if len(series.points) < 10:
                continue

            values = [p.value for p in series.points]
            mu = mean(values)
            sigma = stdev(values) if len(values) > 1 else 0

            if sigma == 0:
                continue

            for pt in series.points:
                z = abs(pt.value - mu) / sigma
                if z > 3.0:  # 3-sigma anomaly
                    events.append(
                        TimelineEvent(
                            timestamp=pt.timestamp,
                            event_type="metric_anomaly",
                            source=series.metric_name,
                            description=(
                                f"Anomaly in {series.display_name}: "
                                f"value={pt.value:.2f} (z-score={z:.1f}, mean={mu:.2f})"
                            ),
                            severity=(
                                IncidentSeverity.CRITICAL if z > 5.0 else IncidentSeverity.HIGH
                            ),
                            evidence={
                                "metric": series.metric_name,
                                "value": pt.value,
                                "z_score": z,
                                "mean": mu,
                                "stddev": sigma,
                            },
                        )
                    )
        return events

    def _extract_log_events(self, logs: list[LogEntry]) -> list[TimelineEvent]:
        """Extract significant log events."""
        events: list[TimelineEvent] = []
        for log in logs:
            if log.status != "error":
                continue
            events.append(
                TimelineEvent(
                    timestamp=log.timestamp,
                    event_type="error_log",
                    source=f"{log.service}:{log.host}",
                    description=log.message[:500],
                    severity=IncidentSeverity.HIGH,
                    evidence={
                        "service": log.service,
                        "host": log.host,
                        "trace_id": log.trace_id,
                    },
                )
            )
        return events

    def _extract_trace_events(self, traces: list[TraceSpan]) -> list[TimelineEvent]:
        """Extract significant trace events (errors and slow spans)."""
        events: list[TimelineEvent] = []
        for span in traces:
            if span.status == "error":
                events.append(
                    TimelineEvent(
                        timestamp=span.start_time,
                        event_type="trace_error",
                        source=f"{span.service}:{span.operation}",
                        description=(
                            f"Error in {span.service}/{span.resource}: "
                            f"{span.error_type} - {span.error_message[:300]}"
                        ),
                        severity=IncidentSeverity.HIGH,
                        evidence={
                            "trace_id": span.trace_id,
                            "service": span.service,
                            "duration_ms": span.duration_ns / 1e6,
                            "error_type": span.error_type,
                        },
                    )
                )
            elif span.duration_ns > 1_000_000_000:  # >1s
                events.append(
                    TimelineEvent(
                        timestamp=span.start_time,
                        event_type="slow_trace",
                        source=f"{span.service}:{span.operation}",
                        description=(
                            f"Slow span in {span.service}/{span.resource}: "
                            f"{span.duration_ns / 1e6:.0f}ms"
                        ),
                        severity=IncidentSeverity.MEDIUM,
                        evidence={
                            "trace_id": span.trace_id,
                            "service": span.service,
                            "duration_ms": span.duration_ns / 1e6,
                        },
                    )
                )
        return events

    def _check_metric_anomaly(self, series: MetricSeries):
        """Check if a metric series has anomalous behavior."""
        if len(series.points) < 10:
            return None

        values = [p.value for p in series.points]
        mu = mean(values)
        sigma = stdev(values) if len(values) > 1 else 0

        if sigma == 0:
            return None

        max_z = max(abs(v - mu) / sigma for v in values)
        if max_z > 3.0:
            return {
                "metric": series.metric_name,
                "display_name": series.display_name,
                "mean": mu,
                "stddev": sigma,
                "max_z_score": max_z,
                "max_value": max(values),
                "min_value": min(values),
            }
        return None
