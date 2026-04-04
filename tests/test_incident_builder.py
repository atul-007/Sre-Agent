"""Tests for building IncidentQuery from Slack alert context."""

from datetime import datetime, timezone
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
        assert diff == pytest.approx(3600, abs=60)  # ~1 hour
