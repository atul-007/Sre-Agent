"""Demo script that runs a full investigation with mock Datadog data.

This demonstrates the complete pipeline without needing live Datadog access.
Requires: ANTHROPIC_API_KEY environment variable.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from config.settings import AgentConfig
from src.core.orchestrator import SREAgent
from src.models.incident import (
    DatadogEvent,
    LogEntry,
    MetricDataPoint,
    MetricSeries,
    MonitorStatus,
    ObservabilityData,
    ServiceDependency,
    ServiceNode,
    TraceSpan,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# ── Mock Data ────────────────────────────────────────────────────────

NOW = datetime(2026, 4, 4, 14, 30, 0)
INCIDENT_START = NOW - timedelta(hours=1)


def _make_metric_points(
    base: float, spike_at: int, spike_value: float, count: int = 60
) -> list[MetricDataPoint]:
    points = []
    for i in range(count):
        ts = INCIDENT_START + timedelta(minutes=i)
        val = spike_value if i == spike_at else base + (i % 5) * 0.1
        points.append(MetricDataPoint(timestamp=ts, value=val))
    return points


MOCK_DATA = ObservabilityData(
    metrics=[
        MetricSeries(
            metric_name="trace.http.request.duration",
            display_name="checkout-service p99 latency",
            points=_make_metric_points(base=120.0, spike_at=30, spike_value=4500.0),
            unit="ms",
        ),
        MetricSeries(
            metric_name="trace.http.request.errors",
            display_name="checkout-service error count",
            points=_make_metric_points(base=2.0, spike_at=31, spike_value=350.0),
            unit="count",
        ),
        MetricSeries(
            metric_name="system.cpu.user",
            display_name="checkout-service CPU",
            points=_make_metric_points(base=35.0, spike_at=29, spike_value=98.0),
            unit="percent",
        ),
        MetricSeries(
            metric_name="trace.http.request.duration",
            display_name="payments-db p99 latency",
            points=_make_metric_points(base=5.0, spike_at=28, spike_value=3200.0),
            unit="ms",
        ),
    ],
    logs=[
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=28),
            message="Connection pool exhausted for payments-db: max connections (100) reached",
            service="checkout-service",
            status="error",
            host="checkout-prod-01",
            trace_id="abc123",
        ),
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=28, seconds=5),
            message="Slow query detected: SELECT * FROM orders WHERE user_id = ? took 3200ms (threshold: 500ms)",
            service="payments-db",
            status="error",
            host="db-prod-primary",
            trace_id="abc124",
        ),
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=29),
            message="Query plan changed after index rebuild: full table scan on orders.user_id",
            service="payments-db",
            status="warn",
            host="db-prod-primary",
        ),
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=30),
            message="Timeout waiting for database response after 5000ms",
            service="checkout-service",
            status="error",
            host="checkout-prod-01",
            trace_id="abc125",
        ),
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=30, seconds=10),
            message="HTTP 503 returned to client: upstream service unavailable",
            service="api-gateway",
            status="error",
            host="gateway-prod-01",
            trace_id="abc126",
        ),
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=25),
            message="Scheduled maintenance: index rebuild started on orders table",
            service="payments-db",
            status="info",
            host="db-prod-primary",
        ),
        LogEntry(
            timestamp=INCIDENT_START + timedelta(minutes=31),
            message="Circuit breaker OPEN for payments-db: 50% error rate exceeded threshold",
            service="checkout-service",
            status="error",
            host="checkout-prod-02",
        ),
    ],
    traces=[
        TraceSpan(
            trace_id="abc123",
            span_id="span1",
            service="api-gateway",
            operation="http.request",
            resource="POST /api/checkout",
            duration_ns=5_200_000_000,
            start_time=INCIDENT_START + timedelta(minutes=30),
            status="error",
            error_message="upstream timeout",
            error_type="TimeoutError",
        ),
        TraceSpan(
            trace_id="abc123",
            span_id="span2",
            parent_id="span1",
            service="checkout-service",
            operation="checkout.process",
            resource="POST /checkout",
            duration_ns=5_100_000_000,
            start_time=INCIDENT_START + timedelta(minutes=30),
            status="error",
            error_message="database timeout after 5000ms",
            error_type="DatabaseTimeoutError",
        ),
        TraceSpan(
            trace_id="abc123",
            span_id="span3",
            parent_id="span2",
            service="payments-db",
            operation="db.query",
            resource="SELECT orders",
            duration_ns=5_000_000_000,
            start_time=INCIDENT_START + timedelta(minutes=30),
            status="error",
            error_message="query execution exceeded timeout: full table scan detected",
            error_type="QueryTimeoutError",
        ),
        TraceSpan(
            trace_id="abc124",
            span_id="span4",
            service="checkout-service",
            operation="checkout.validate",
            resource="POST /checkout",
            duration_ns=3_500_000_000,
            start_time=INCIDENT_START + timedelta(minutes=31),
            status="error",
            error_message="circuit breaker open",
            error_type="CircuitBreakerError",
        ),
    ],
    service_map=[
        ServiceNode(
            name="checkout-service",
            service_type="web",
            dependencies=[
                ServiceDependency(
                    source_service="checkout-service",
                    target_service="payments-db",
                    call_type="db",
                    avg_latency_ms=2800.0,
                    error_rate=0.45,
                    calls_per_minute=1200.0,
                ),
                ServiceDependency(
                    source_service="checkout-service",
                    target_service="inventory-service",
                    call_type="http",
                    avg_latency_ms=50.0,
                    error_rate=0.01,
                    calls_per_minute=800.0,
                ),
            ],
            dependents=[
                ServiceDependency(
                    source_service="api-gateway",
                    target_service="checkout-service",
                    call_type="http",
                    avg_latency_ms=4200.0,
                    error_rate=0.35,
                    calls_per_minute=500.0,
                ),
            ],
        ),
        ServiceNode(
            name="payments-db",
            service_type="db",
            dependencies=[],
            dependents=[
                ServiceDependency(
                    source_service="checkout-service",
                    target_service="payments-db",
                    call_type="db",
                    avg_latency_ms=2800.0,
                    error_rate=0.45,
                    calls_per_minute=1200.0,
                ),
            ],
        ),
    ],
    events=[],
    monitors=[
        MonitorStatus(
            monitor_id=12345,
            name="checkout-service p99 latency > 500ms",
            status="Alert",
            message="P99 latency at 4500ms, threshold 500ms",
            tags=["service:checkout-service", "env:production"],
            last_triggered=INCIDENT_START + timedelta(minutes=30),
        ),
        MonitorStatus(
            monitor_id=12346,
            name="checkout-service error rate > 5%",
            status="Alert",
            message="Error rate at 45%, threshold 5%",
            tags=["service:checkout-service", "env:production"],
            last_triggered=INCIDENT_START + timedelta(minutes=31),
        ),
    ],
    deployment_events=[
        DatadogEvent(
            timestamp=INCIDENT_START + timedelta(minutes=20),
            title="payments-db: scheduled index maintenance v2.4.1",
            text="Automated index rebuild on orders table (REINDEX CONCURRENTLY)",
            source="deploy",
            tags=["service:payments-db", "env:production", "team:data-platform"],
        ),
    ],
)


async def main() -> None:
    config = AgentConfig()
    agent = SREAgent(config)

    # Patch the fetcher to return mock data instead of hitting real Datadog
    with patch.object(agent.fetcher, "fetch_all", new=AsyncMock(return_value=MOCK_DATA)):
        report_md = await agent.investigate_and_format(
            query="Why did checkout-service latency spike at 2pm today?",
            output_format="markdown",
        )

    print(report_md)
    await agent.close()


if __name__ == "__main__":
    asyncio.run(main())
