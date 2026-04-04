"""Tests for metric/tag discovery and dashboard mining functionality."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

from config.settings import AgentConfig, DatadogConfig
from src.datadog.client import DatadogClient
from src.models.incident import (
    DiscoveredContext,
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    SymptomType,
)
from src.investigation.engine import InvestigationEngine


# ── DiscoveredContext Model Tests ────────────────────────────────────


class TestDiscoveredContext:
    def test_defaults(self):
        ctx = DiscoveredContext()
        assert ctx.available_metrics == []
        assert ctx.resolved_namespace == ""
        assert ctx.resolved_tags == {}
        assert ctx.dashboard_metrics == []
        assert ctx.infra_metrics == []
        assert ctx.container_metrics == []
        assert ctx.apm_metrics == []
        assert ctx.custom_metrics == []

    def test_with_data(self):
        ctx = DiscoveredContext(
            available_metrics=["kubernetes.cpu.usage.total", "container.cpu.usage"],
            resolved_namespace="my-ns-prod",
            resolved_tags={"kube_namespace": "my-ns-prod", "kube_container_name": "main"},
            dashboard_metrics=["flink.task.numRecordsIn"],
            infra_metrics=["kubernetes.cpu.usage.total"],
            container_metrics=["container.cpu.usage"],
        )
        assert len(ctx.available_metrics) == 2
        assert ctx.resolved_namespace == "my-ns-prod"
        assert "kube_namespace" in ctx.resolved_tags


class TestInvestigationStateWithDiscovery:
    def test_has_discovered_context_field(self):
        state = InvestigationState()
        assert state.discovered_context is None

    def test_with_discovered_context(self):
        ctx = DiscoveredContext(resolved_namespace="prod-ns")
        state = InvestigationState(discovered_context=ctx)
        assert state.discovered_context.resolved_namespace == "prod-ns"


# ── Dashboard Metric Extraction Tests ────────────────────────────────


class TestExtractMetricsFromDashboard:
    def test_extracts_from_timeseries(self):
        dashboard = {
            "widgets": [
                {
                    "definition": {
                        "requests": [
                            {"q": "avg:system.cpu.user{service:my-svc}"}
                        ]
                    }
                }
            ]
        }
        metrics = DatadogClient.extract_metrics_from_dashboard(dashboard)
        assert "system.cpu.user" in metrics

    def test_extracts_from_nested_queries(self):
        dashboard = {
            "widgets": [
                {
                    "definition": {
                        "requests": [
                            {
                                "queries": [
                                    {"query": "avg:flink.task.numRecordsIn{service:router}"},
                                    {"query": "sum:flink.task.numRecordsOut{service:router}"},
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        metrics = DatadogClient.extract_metrics_from_dashboard(dashboard)
        assert "flink.task.numRecordsIn" in metrics
        assert "flink.task.numRecordsOut" in metrics

    def test_extracts_from_nested_widgets(self):
        dashboard = {
            "widgets": [
                {
                    "definition": {
                        "widgets": [
                            {
                                "definition": {
                                    "requests": [
                                        {"q": "max:kubernetes.cpu.usage.total{ns:prod}"}
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
        metrics = DatadogClient.extract_metrics_from_dashboard(dashboard)
        assert "kubernetes.cpu.usage.total" in metrics

    def test_handles_empty_dashboard(self):
        metrics = DatadogClient.extract_metrics_from_dashboard({"widgets": []})
        assert metrics == []

    def test_deduplicates(self):
        dashboard = {
            "widgets": [
                {
                    "definition": {
                        "requests": [
                            {"q": "avg:system.cpu.user{*}"},
                            {"q": "max:system.cpu.user{host:a}"},
                        ]
                    }
                }
            ]
        }
        metrics = DatadogClient.extract_metrics_from_dashboard(dashboard)
        assert metrics.count("system.cpu.user") == 1

    def test_multiple_aggregations(self):
        dashboard = {
            "widgets": [
                {
                    "definition": {
                        "requests": [
                            {"q": "avg:metric.a{*}, sum:metric.b{*}, count:metric.c{*}"}
                        ]
                    }
                }
            ]
        }
        metrics = DatadogClient.extract_metrics_from_dashboard(dashboard)
        assert "metric.a" in metrics
        assert "metric.b" in metrics
        assert "metric.c" in metrics


# ── Namespace Candidate Generation Tests ─────────────────────────────


class TestNamespaceCandidateGeneration:
    def test_basic_generation(self):
        candidates = InvestigationEngine._generate_namespace_candidates(
            "production", "mk-sp-event-log-router", {}
        )
        assert "mk-sp-event-log-router" in candidates
        # Should generate prefix-based candidates with env suffixes
        assert any("mk-sp-prod" in c or "mk-sp-production" in c for c in candidates)

    def test_respects_source_tags(self):
        candidates = InvestigationEngine._generate_namespace_candidates(
            "production", "my-svc", {"kube_namespace": "exact-ns"}
        )
        assert candidates[0] == "exact-ns"

    def test_namespace_hint_with_suffixes(self):
        candidates = InvestigationEngine._generate_namespace_candidates(
            "production", "my-svc", {"namespace": "mercari-search-platform"}
        )
        assert "mercari-search-platform-prod" in candidates
        assert "mercari-search-platform-production" in candidates
        assert "mercari-search-platform" in candidates

    def test_deduplicates(self):
        candidates = InvestigationEngine._generate_namespace_candidates(
            "production", "a-b-c", {}
        )
        assert len(candidates) == len(set(candidates))

    def test_staging_suffixes(self):
        candidates = InvestigationEngine._generate_namespace_candidates(
            "staging", "my-svc", {"namespace": "my-ns"}
        )
        assert "my-ns-staging" in candidates
        assert "my-ns-stg" in candidates


# ── Build Queries From Discovered Tests ──────────────────────────────


class TestBuildQueriesFromDiscovered:
    def _make_engine(self):
        config = AgentConfig()
        dd = MagicMock()
        reasoning = MagicMock()
        correlation = MagicMock()
        return InvestigationEngine(dd, reasoning, correlation, config)

    def test_prioritizes_dashboard_metrics(self):
        engine = self._make_engine()
        ctx = DiscoveredContext(
            dashboard_metrics=["flink.task.numRecordsIn", "flink.jvm.cpu.load"],
            resolved_tags={"kube_namespace": "my-ns"},
        )
        queries = engine._build_queries_from_discovered(ctx, "my-svc")
        # Dashboard metrics should be first
        assert any("flink.task.numRecordsIn" in q for q in queries)
        assert any("kube_namespace:my-ns" in q for q in queries)

    def test_uses_service_tag_when_no_resolved(self):
        engine = self._make_engine()
        ctx = DiscoveredContext(
            dashboard_metrics=["some.metric"],
        )
        queries = engine._build_queries_from_discovered(ctx, "my-svc")
        assert any("service:my-svc" in q for q in queries)

    def test_includes_container_metrics(self):
        engine = self._make_engine()
        ctx = DiscoveredContext(
            container_metrics=["container.cpu.usage", "container.memory.usage"],
            resolved_tags={"kube_namespace": "ns"},
        )
        queries = engine._build_queries_from_discovered(ctx, "svc")
        assert any("container.cpu" in q for q in queries)

    def test_includes_custom_metrics(self):
        engine = self._make_engine()
        ctx = DiscoveredContext(
            custom_metrics=["my_app.queue_depth", "my_app.processing_time"],
            resolved_tags={},
        )
        queries = engine._build_queries_from_discovered(ctx, "svc")
        assert any("my_app.queue_depth" in q for q in queries)

    def test_empty_context_returns_empty(self):
        engine = self._make_engine()
        ctx = DiscoveredContext()
        queries = engine._build_queries_from_discovered(ctx, "svc")
        assert queries == []


# ── DISCOVER_CONTEXT Action Type Tests ────────────────────────────────


class TestDiscoverContextActionType:
    def test_enum_value(self):
        assert InvestigationActionType.DISCOVER_CONTEXT.value == "discover_context"

    def test_in_action_to_signals(self):
        from src.investigation.rules import ACTION_TO_SIGNALS
        assert "discover_context" in ACTION_TO_SIGNALS


# ── Integration-style Discovery Tests (mocked HTTP) ──────────────────


class TestDiscoverServiceContextIntegration:
    def _make_engine(self):
        config = AgentConfig()
        dd = AsyncMock(spec=DatadogClient)
        reasoning = MagicMock()
        correlation = MagicMock()
        engine = InvestigationEngine(dd, reasoning, correlation, config)
        engine.state = InvestigationState()
        return engine, dd

    def _make_incident(self):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="CPU alert for my-svc",
            service="mk-sp-event-log-router",
            symptom_type=SymptomType.SATURATION,
            start_time=now - timedelta(hours=1),
            end_time=now,
            environment="production",
            source_tags={"namespace": "mercari-search-platform"},
        )

    @pytest.mark.asyncio
    async def test_discovers_metrics(self):
        engine, dd = self._make_engine()
        incident = self._make_incident()

        # Mock metric search returning results
        dd.search_metrics = AsyncMock(return_value=[
            "flink.taskmanager.jvm.cpu.load",
            "container.cpu.usage",
            "kubernetes.cpu.usage.total",
        ])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])
        dd.find_dashboards_for_service = AsyncMock(return_value=[])
        dd.search_hosts_by_tag = AsyncMock(return_value=[])

        ctx = await engine._discover_service_context(incident)

        assert len(ctx.available_metrics) == 3
        assert "container.cpu.usage" in ctx.container_metrics
        assert "kubernetes.cpu.usage.total" in ctx.infra_metrics

    @pytest.mark.asyncio
    async def test_resolves_namespace_with_suffix(self):
        engine, dd = self._make_engine()
        incident = self._make_incident()

        dd.search_metrics = AsyncMock(return_value=[])
        dd.find_dashboards_for_service = AsyncMock(return_value=[])
        dd.search_hosts_by_tag = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])

        # Namespace probe: fail for base, succeed for -prod
        call_count = 0
        async def mock_query_metrics(query, start, end):
            nonlocal call_count
            call_count += 1
            if "mercari-search-platform-prod" in query:
                # Return a non-empty result
                from src.models.incident import MetricSeries, MetricDataPoint
                return [MetricSeries(
                    metric_name="kubernetes.cpu.usage.total",
                    display_name="cpu",
                    points=[MetricDataPoint(timestamp=start, value=0.5)],
                )]
            return []

        dd.query_metrics = mock_query_metrics

        ctx = await engine._discover_service_context(incident)
        assert ctx.resolved_namespace == "mercari-search-platform-prod"
        assert ctx.resolved_tags.get("kube_namespace") == "mercari-search-platform-prod"

    @pytest.mark.asyncio
    async def test_mines_dashboards(self):
        engine, dd = self._make_engine()
        incident = self._make_incident()

        dd.search_metrics = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])
        dd.search_hosts_by_tag = AsyncMock(return_value=[])

        # Mock dashboard mining
        dd.find_dashboards_for_service = AsyncMock(return_value=[
            {
                "id": "dash-1",
                "title": "Event Log Router Overview",
                "widgets": [
                    {
                        "definition": {
                            "requests": [
                                {"q": "avg:flink.task.numRecordsIn{service:mk-sp-event-log-router}"},
                                {"q": "sum:flink.task.numRecordsOut{service:mk-sp-event-log-router}"},
                            ]
                        }
                    }
                ]
            }
        ])

        ctx = await engine._discover_service_context(incident)
        assert "flink.task.numRecordsIn" in ctx.dashboard_metrics
        assert "flink.task.numRecordsOut" in ctx.dashboard_metrics
        assert "dash-1" in ctx.dashboard_ids

    @pytest.mark.asyncio
    async def test_falls_back_to_host_tags(self):
        engine, dd = self._make_engine()
        incident = self._make_incident()

        dd.search_metrics = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])
        dd.find_dashboards_for_service = AsyncMock(return_value=[])

        # Host tag lookup returns useful tags
        dd.search_hosts_by_tag = AsyncMock(return_value=[
            {
                "tags_by_source": {
                    "datadog": [
                        "kube_namespace:mercari-search-platform-prod",
                        "kube_cluster_name:prod-cluster",
                        "env:production",
                    ]
                }
            }
        ])

        ctx = await engine._discover_service_context(incident)
        assert ctx.resolved_tags.get("kube_namespace") == "mercari-search-platform-prod"
        assert ctx.resolved_tags.get("env") == "production"

    @pytest.mark.asyncio
    async def test_handles_all_failures_gracefully(self):
        engine, dd = self._make_engine()
        incident = self._make_incident()

        # Everything fails
        dd.search_metrics = AsyncMock(side_effect=Exception("API error"))
        dd.query_metrics = AsyncMock(side_effect=Exception("API error"))
        dd.find_dashboards_for_service = AsyncMock(side_effect=Exception("API error"))
        dd.search_hosts_by_tag = AsyncMock(side_effect=Exception("API error"))

        ctx = await engine._discover_service_context(incident)
        # Should return empty context, not crash
        assert ctx.available_metrics == []
        assert ctx.resolved_namespace == ""
