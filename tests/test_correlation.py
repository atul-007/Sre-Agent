"""Tests for the correlation engine."""

from datetime import datetime, timedelta

import pytest

from src.correlation.engine import CorrelationEngine
from src.models.incident import (
    DatadogEvent,
    IncidentQuery,
    LogEntry,
    MetricDataPoint,
    MetricSeries,
    MonitorStatus,
    ObservabilityData,
    ServiceDependency,
    ServiceNode,
    SymptomType,
    TraceSpan,
)

NOW = datetime(2026, 4, 4, 14, 0, 0)


@pytest.fixture
def engine():
    return CorrelationEngine(correlation_window_seconds=300)


@pytest.fixture
def incident():
    return IncidentQuery(
        raw_query="Why did test-service latency spike?",
        service="test-service",
        symptom_type=SymptomType.LATENCY,
        start_time=NOW - timedelta(hours=1),
        end_time=NOW,
    )


def _make_metric(name: str, values: list[float]) -> MetricSeries:
    return MetricSeries(
        metric_name=name,
        display_name=name,
        points=[
            MetricDataPoint(timestamp=NOW - timedelta(minutes=len(values) - i), value=v)
            for i, v in enumerate(values)
        ],
    )


class TestBuildTimeline:
    def test_metric_anomaly_detected(self, engine, incident):
        # 20 normal values + 1 extreme outlier
        values = [10.0] * 20 + [500.0]
        data = ObservabilityData(metrics=[_make_metric("latency", values)])
        timeline = engine.build_timeline(incident, data)
        anomalies = [e for e in timeline if e.event_type == "metric_anomaly"]
        assert len(anomalies) >= 1
        assert anomalies[0].evidence["z_score"] > 3.0

    def test_error_logs_in_timeline(self, engine, incident):
        data = ObservabilityData(
            logs=[
                LogEntry(
                    timestamp=NOW - timedelta(minutes=5),
                    message="Connection refused",
                    service="test-service",
                    status="error",
                )
            ]
        )
        timeline = engine.build_timeline(incident, data)
        error_events = [e for e in timeline if e.event_type == "error_log"]
        assert len(error_events) == 1

    def test_deployment_events_in_timeline(self, engine, incident):
        data = ObservabilityData(
            deployment_events=[
                DatadogEvent(
                    timestamp=NOW - timedelta(minutes=10),
                    title="Deploy v2.0",
                    text="New version",
                    source="deploy",
                )
            ]
        )
        timeline = engine.build_timeline(incident, data)
        deploy_events = [e for e in timeline if e.event_type == "deployment"]
        assert len(deploy_events) == 1

    def test_timeline_sorted_chronologically(self, engine, incident):
        data = ObservabilityData(
            logs=[
                LogEntry(
                    timestamp=NOW - timedelta(minutes=1),
                    message="Error B",
                    service="test-service",
                    status="error",
                ),
                LogEntry(
                    timestamp=NOW - timedelta(minutes=10),
                    message="Error A",
                    service="test-service",
                    status="error",
                ),
            ]
        )
        timeline = engine.build_timeline(incident, data)
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps)


class TestCorrelateServices:
    def test_cross_service_errors_detected(self, engine):
        data = ObservabilityData(
            traces=[
                TraceSpan(
                    trace_id="t1",
                    span_id="s1",
                    service="svc-a",
                    operation="call",
                    resource="/api",
                    duration_ns=1000,
                    start_time=NOW,
                    status="error",
                    error_message="fail",
                    error_type="Err",
                ),
                TraceSpan(
                    trace_id="t1",
                    span_id="s2",
                    parent_id="s1",
                    service="svc-b",
                    operation="handler",
                    resource="/handler",
                    duration_ns=900,
                    start_time=NOW,
                    status="error",
                    error_message="upstream fail",
                    error_type="Err",
                ),
            ],
            service_map=[
                ServiceNode(
                    name="svc-a",
                    dependencies=[
                        ServiceDependency(
                            source_service="svc-a",
                            target_service="svc-b",
                            call_type="http",
                            error_rate=0.5,
                        )
                    ],
                )
            ],
        )
        result = engine.correlate_services(data)
        assert len(result["cross_service_traces"]) == 1
        assert set(result["cross_service_traces"][0]["error_services"]) == {"svc-a", "svc-b"}
        assert len(result["error_propagation"]) == 1


class TestAnomalySummary:
    def test_counts_errors_and_warns(self, engine):
        data = ObservabilityData(
            logs=[
                LogEntry(timestamp=NOW, message="err1", service="s", status="error"),
                LogEntry(timestamp=NOW, message="err2", service="s", status="error"),
                LogEntry(timestamp=NOW, message="warn1", service="s", status="warn"),
            ],
            traces=[
                TraceSpan(
                    trace_id="t1",
                    span_id="s1",
                    service="s",
                    operation="op",
                    resource="r",
                    duration_ns=100,
                    start_time=NOW,
                    status="error",
                    error_message="",
                    error_type="",
                ),
            ],
        )
        summary = engine.compute_anomaly_summary(data)
        assert summary["error_log_count"] == 2
        assert summary["warn_log_count"] == 1
        assert summary["error_trace_count"] == 1
