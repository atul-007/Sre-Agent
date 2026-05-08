"""Tests for building IncidentQuery from Slack alert context."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models.incident import SymptomType
from src.slack.incident_builder import (
    _classify_symptom,
    _extract_service_from_query,
    build_incident_from_alert,
)
from src.slack.parser import SlackAlertContext


class TestClassifySymptom:
    def test_cpu_saturation(self):
        assert _classify_symptom("kubernetes.cpu.usage.total") == SymptomType.SATURATION

    def test_memory_saturation(self):
        assert _classify_symptom("system.mem.used") == SymptomType.SATURATION

    def test_latency(self):
        assert _classify_symptom("trace.http.request.duration") == SymptomType.LATENCY

    def test_error_rate(self):
        assert _classify_symptom("trace.http.request.errors") == SymptomType.ERROR_RATE

    def test_throughput(self):
        assert _classify_symptom("trace.http.request.hits") == SymptomType.THROUGHPUT

    def test_unknown(self):
        assert _classify_symptom("custom.metric.foobar") == SymptomType.UNKNOWN

    def test_from_name(self):
        assert _classify_symptom("", "P99 Latency Alert") == SymptomType.LATENCY


class TestExtractServiceFromQuery:
    def test_extract(self):
        query = "avg:trace.http.request.duration{service:checkout-service}"
        assert _extract_service_from_query(query) == "checkout-service"

    def test_no_service(self):
        query = "avg:system.cpu.user{host:web-01}"
        assert _extract_service_from_query(query) is None


@pytest.mark.asyncio
class TestBuildIncidentFromAlert:
    async def test_full_context(self):
        alert = SlackAlertContext(
            monitor_id=12345,
            monitor_url="https://app.datadoghq.com/monitors/12345",
            group_tags={
                "container_name": "flink-main-container",
                "kube_deployment": "mk-sp-event-log-router",
                "pod_name": "mk-sp-event-log-router-58f87f4fb6-xmq8f",
            },
            from_ts=datetime(2026, 4, 3, 18, 0, 0, tzinfo=timezone.utc),
            to_ts=datetime(2026, 4, 3, 19, 0, 0, tzinfo=timezone.utc),
            alert_title="K8s pod CPU usage",
            threshold="92.51",
            raw_text="CPU usage alert",
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "K8s pod CPU usage on mk-sp-event-log-router",
            "query": "avg:kubernetes.cpu.usage.total{service:mk-sp-event-log-router}",
            "tags": ["service:mk-sp-event-log-router", "env:production"],
            "options": {"thresholds": {"critical": 80}},
        }

        incident = await build_incident_from_alert(alert, mock_client)

        assert incident.service == "mk-sp-event-log-router"
        assert incident.symptom_type == SymptomType.SATURATION
        assert incident.start_time == datetime(2026, 4, 3, 18, 0, 0, tzinfo=timezone.utc)
        assert incident.end_time == datetime(2026, 4, 3, 19, 0, 0, tzinfo=timezone.utc)
        assert incident.environment == "production"
        assert incident.monitor_id == 12345
        assert "kubernetes.cpu.usage.total" in incident.monitor_query
        assert incident.source_tags["kube_deployment"] == "mk-sp-event-log-router"

    async def test_fallback_to_kube_deployment(self):
        """When no service tag exists, fall back to kube_deployment."""
        alert = SlackAlertContext(
            monitor_id=999,
            monitor_url="https://app.datadoghq.com/monitors/999",
            group_tags={"kube_deployment": "my-deployment"},
            alert_title="CPU alert",
            raw_text="alert text",
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "CPU alert",
            "query": "avg:kubernetes.cpu.usage.total{kube_namespace:prod}",
            "tags": [],
            "options": {},
        }

        incident = await build_incident_from_alert(alert, mock_client)
        assert incident.service == "my-deployment"

    async def test_monitor_fetch_failure(self):
        """Should still build incident when monitor fetch fails."""
        alert = SlackAlertContext(
            monitor_id=999,
            monitor_url="https://app.datadoghq.com/monitors/999",
            group_tags={"kube_deployment": "my-service"},
            from_ts=datetime(2026, 4, 3, 18, 0, 0, tzinfo=timezone.utc),
            to_ts=datetime(2026, 4, 3, 19, 0, 0, tzinfo=timezone.utc),
            alert_title="CPU spike alert",
            raw_text="cpu usage high",
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.side_effect = Exception("API error")

        incident = await build_incident_from_alert(alert, mock_client)
        assert incident.service == "my-service"
        assert incident.monitor_id == 999

    async def test_default_time_window(self):
        """When no timestamps in URL, defaults to (now - 1h, now)."""
        alert = SlackAlertContext(
            monitor_id=100,
            monitor_url="https://app.datadoghq.com/monitors/100",
            group_tags={"service": "web-api"},
            alert_title="Error rate spike",
            raw_text="errors",
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "Error rate alert",
            "query": "sum:trace.http.request.errors{service:web-api}.as_count()",
            "tags": ["service:web-api"],
            "options": {},
        }

        incident = await build_incident_from_alert(alert, mock_client)
        assert incident.service == "web-api"
        assert incident.symptom_type == SymptomType.ERROR_RATE
        # Should have a reasonable time window
        diff = (incident.end_time - incident.start_time).total_seconds()
        # 1h before trigger + up to 10min after = 60–70min total
        assert 3500 < diff <= 4300

    async def test_anchor_on_alert_text_triggered_at(self):
        """When URL has no timestamps but alert body has 'At ... UTC', anchor on it."""
        triggered = datetime(2026, 5, 6, 8, 41, 53, tzinfo=timezone.utc)
        alert = SlackAlertContext(
            monitor_id=200,
            monitor_url="https://app.datadoghq.com/monitors/200",
            group_tags={"service": "search-api"},
            alert_title="Latency",
            raw_text="At 2026-05-06 08:41:53 UTC, a latency alert was triggered",
            triggered_at=triggered,
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "P95 Latency",
            "query": "avg:trace.grpc.server.duration{service:search-api}",
            "tags": ["service:search-api"],
            "options": {},
        }

        incident = await build_incident_from_alert(alert, mock_client)
        assert incident.start_time == triggered - timedelta(hours=1)
        # end_time is min(triggered + 10min, now); since triggered is in the
        # past, expect triggered + 10min
        assert incident.end_time == triggered + timedelta(minutes=10)

    async def test_anchor_on_monitor_state_modified(self):
        """When URL and text have no timestamps, fall back to monitor's state_modified."""
        modified_epoch = 1746520913  # 2026-05-06 08:41:53 UTC
        alert = SlackAlertContext(
            monitor_id=300,
            monitor_url="https://app.datadoghq.com/monitors/300",
            group_tags={"service": "auth"},
            alert_title="Auth errors",
            raw_text="errors elevated",
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "Auth error rate",
            "query": "sum:trace.http.request.errors{service:auth}.as_count()",
            "tags": ["service:auth"],
            "options": {},
            "overall_state_modified": modified_epoch,
        }

        incident = await build_incident_from_alert(alert, mock_client)
        expected_anchor = datetime.fromtimestamp(modified_epoch, tz=timezone.utc)
        assert incident.start_time == expected_anchor - timedelta(hours=1)
        assert incident.end_time == expected_anchor + timedelta(minutes=10)

    async def test_anchor_on_slack_message_ts(self):
        """When no other anchor available, use the parent Slack message ts."""
        message_ts = datetime(2026, 5, 6, 8, 41, 53, tzinfo=timezone.utc)
        alert = SlackAlertContext(
            monitor_id=400,
            monitor_url="https://app.datadoghq.com/monitors/400",
            group_tags={"service": "checkout"},
            alert_title="Latency",
            raw_text="latency high",
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "Checkout latency",
            "query": "avg:trace.http.request.duration{service:checkout}",
            "tags": ["service:checkout"],
            "options": {},
        }

        incident = await build_incident_from_alert(
            alert, mock_client, message_ts=message_ts
        )
        assert incident.start_time == message_ts - timedelta(hours=1)
        assert incident.end_time == message_ts + timedelta(minutes=10)

    async def test_anchor_priority_alert_text_over_message_ts(self):
        """Alert-text triggered_at wins over message_ts."""
        text_triggered = datetime(2026, 5, 6, 8, 41, 53, tzinfo=timezone.utc)
        # Slack message arrives slightly later than Datadog reports trigger
        message_ts = datetime(2026, 5, 6, 8, 42, 30, tzinfo=timezone.utc)
        alert = SlackAlertContext(
            monitor_id=500,
            monitor_url="https://app.datadoghq.com/monitors/500",
            group_tags={"service": "api"},
            alert_title="Latency",
            raw_text="At 2026-05-06 08:41:53 UTC, alert triggered",
            triggered_at=text_triggered,
        )

        mock_client = AsyncMock()
        mock_client.get_monitor.return_value = {
            "name": "API latency",
            "query": "avg:trace.http.request.duration{service:api}",
            "tags": ["service:api"],
            "options": {},
        }

        incident = await build_incident_from_alert(
            alert, mock_client, message_ts=message_ts
        )
        # Should use text_triggered, not message_ts
        assert incident.start_time == text_triggered - timedelta(hours=1)
        assert incident.end_time == text_triggered + timedelta(minutes=10)
