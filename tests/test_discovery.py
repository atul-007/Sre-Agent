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
from src.investigation.discovery import DiscoveryPhase
from src.investigation.analysis import AnalysisPhase
from src.models.incident import TrackedHypothesis, HypothesisStatus


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
        candidates = DiscoveryPhase.generate_namespace_candidates(
            "production", "mk-sp-event-log-router", {}
        )
        assert "mk-sp-event-log-router" in candidates
        # Should generate prefix-based candidates with env suffixes
        assert any("mk-sp-prod" in c or "mk-sp-production" in c for c in candidates)

    def test_respects_source_tags(self):
        candidates = DiscoveryPhase.generate_namespace_candidates(
            "production", "my-svc", {"kube_namespace": "exact-ns"}
        )
        assert candidates[0] == "exact-ns"

    def test_namespace_hint_with_suffixes(self):
        candidates = DiscoveryPhase.generate_namespace_candidates(
            "production", "my-svc", {"namespace": "search-platform"}
        )
        assert "search-platform-prod" in candidates
        assert "search-platform-production" in candidates
        assert "search-platform" in candidates

    def test_deduplicates(self):
        candidates = DiscoveryPhase.generate_namespace_candidates(
            "production", "a-b-c", {}
        )
        assert len(candidates) == len(set(candidates))

    def test_staging_suffixes(self):
        candidates = DiscoveryPhase.generate_namespace_candidates(
            "staging", "my-svc", {"namespace": "my-ns"}
        )
        assert "my-ns-staging" in candidates
        assert "my-ns-stg" in candidates


# ── Build Queries From Discovered Tests ──────────────────────────────


class TestBuildQueriesFromDiscovered:
    def test_prioritizes_dashboard_metrics(self):
        ctx = DiscoveredContext(
            dashboard_metrics=["flink.task.numRecordsIn", "flink.jvm.cpu.load"],
            resolved_tags={"kube_namespace": "my-ns"},
        )
        queries = DiscoveryPhase.build_queries_from_discovered(ctx, "my-svc")
        assert any("flink.task.numRecordsIn" in q for q in queries)
        assert any("kube_namespace:my-ns" in q for q in queries)

    def test_uses_service_tag_when_no_resolved(self):
        ctx = DiscoveredContext(
            dashboard_metrics=["some.metric"],
        )
        queries = DiscoveryPhase.build_queries_from_discovered(ctx, "my-svc")
        assert any("service:my-svc" in q for q in queries)

    def test_includes_container_metrics(self):
        ctx = DiscoveredContext(
            container_metrics=["container.cpu.usage", "container.memory.usage"],
            resolved_tags={"kube_namespace": "ns"},
        )
        queries = DiscoveryPhase.build_queries_from_discovered(ctx, "svc")
        assert any("container.cpu" in q for q in queries)

    def test_includes_custom_metrics(self):
        ctx = DiscoveredContext(
            custom_metrics=["my_app.queue_depth", "my_app.processing_time"],
            resolved_tags={},
        )
        queries = DiscoveryPhase.build_queries_from_discovered(ctx, "svc")
        assert any("my_app.queue_depth" in q for q in queries)

    def test_empty_context_returns_empty(self):
        ctx = DiscoveredContext()
        queries = DiscoveryPhase.build_queries_from_discovered(ctx, "svc")
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
    def _make_discovery(self):
        config = AgentConfig()
        dd = AsyncMock(spec=DatadogClient)
        discovery = DiscoveryPhase(dd, config)
        return discovery, dd

    def _make_incident(self):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="CPU alert for my-svc",
            service="mk-sp-event-log-router",
            symptom_type=SymptomType.SATURATION,
            start_time=now - timedelta(hours=1),
            end_time=now,
            environment="production",
            source_tags={"namespace": "search-platform"},
        )

    @pytest.mark.asyncio
    async def test_discovers_metrics(self):
        discovery, dd = self._make_discovery()
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
        dd.search_monitors = AsyncMock(return_value=[])

        ctx = await discovery.discover(incident)

        assert len(ctx.available_metrics) == 3
        assert "container.cpu.usage" in ctx.container_metrics
        assert "kubernetes.cpu.usage.total" in ctx.infra_metrics

    @pytest.mark.asyncio
    async def test_resolves_namespace_with_suffix(self):
        discovery, dd = self._make_discovery()
        incident = self._make_incident()

        dd.search_metrics = AsyncMock(return_value=[])
        dd.find_dashboards_for_service = AsyncMock(return_value=[])
        dd.search_hosts_by_tag = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])
        dd.search_monitors = AsyncMock(return_value=[])

        # Namespace probe: fail for base, succeed for -prod
        call_count = 0
        async def mock_query_metrics(query, start, end):
            nonlocal call_count
            call_count += 1
            if "search-platform-prod" in query:
                # Return a non-empty result
                from src.models.incident import MetricSeries, MetricDataPoint
                return [MetricSeries(
                    metric_name="kubernetes.cpu.usage.total",
                    display_name="cpu",
                    points=[MetricDataPoint(timestamp=start, value=0.5)],
                )]
            return []

        dd.query_metrics = mock_query_metrics

        ctx = await discovery.discover(incident)
        assert ctx.resolved_namespace == "search-platform-prod"
        assert ctx.resolved_tags.get("kube_namespace") == "search-platform-prod"

    @pytest.mark.asyncio
    async def test_mines_dashboards(self):
        discovery, dd = self._make_discovery()
        incident = self._make_incident()

        dd.search_metrics = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])
        dd.search_hosts_by_tag = AsyncMock(return_value=[])
        dd.search_monitors = AsyncMock(return_value=[])

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

        ctx = await discovery.discover(incident)
        assert "flink.task.numRecordsIn" in ctx.dashboard_metrics
        assert "flink.task.numRecordsOut" in ctx.dashboard_metrics
        assert "dash-1" in ctx.dashboard_ids

    @pytest.mark.asyncio
    async def test_falls_back_to_host_tags(self):
        discovery, dd = self._make_discovery()
        incident = self._make_incident()

        dd.search_metrics = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_metric_tag_values = AsyncMock(return_value=[])
        dd.find_dashboards_for_service = AsyncMock(return_value=[])
        dd.search_monitors = AsyncMock(return_value=[])

        # Host tag lookup returns useful tags
        dd.search_hosts_by_tag = AsyncMock(return_value=[
            {
                "tags_by_source": {
                    "datadog": [
                        "kube_namespace:search-platform-prod",
                        "kube_cluster_name:prod-cluster",
                        "env:production",
                    ]
                }
            }
        ])

        ctx = await discovery.discover(incident)
        assert ctx.resolved_tags.get("kube_namespace") == "search-platform-prod"
        assert ctx.resolved_tags.get("env") == "production"

    @pytest.mark.asyncio
    async def test_handles_all_failures_gracefully(self):
        discovery, dd = self._make_discovery()
        incident = self._make_incident()

        # Everything fails
        dd.search_metrics = AsyncMock(side_effect=Exception("API error"))
        dd.query_metrics = AsyncMock(side_effect=Exception("API error"))
        dd.find_dashboards_for_service = AsyncMock(side_effect=Exception("API error"))
        dd.search_hosts_by_tag = AsyncMock(side_effect=Exception("API error"))

        dd.search_monitors = AsyncMock(side_effect=Exception("API error"))

        ctx = await discovery.discover(incident)
        # Should return empty context, not crash
        assert ctx.available_metrics == []
        assert ctx.resolved_namespace == ""


# ── Hypothesis Matching Tests ────────────────────────────────────────


class TestHypothesisMatching:
    def _make_state(self):
        return InvestigationState()

    def test_exact_id_match(self):
        state = self._make_state()
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1", description="CPU saturation due to high request rate"
        )
        result = AnalysisPhase._find_matching_hypothesis("h1", "whatever", state)
        assert result == "h1"

    def test_description_similarity_match(self):
        state = self._make_state()
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1", description="CPU saturation caused by high request rate"
        )
        result = AnalysisPhase._find_matching_hypothesis("h99", "CPU saturation from high request rate", state)
        assert result == "h1"

    def test_no_match_for_different_hypothesis(self):
        state = self._make_state()
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1", description="CPU saturation caused by high request rate"
        )
        result = AnalysisPhase._find_matching_hypothesis("h99", "Memory leak in connection pool", state)
        assert result is None

    def test_next_hypothesis_id(self):
        state = self._make_state()
        assert AnalysisPhase._next_hypothesis_id(state) == "h1"

        state.hypotheses["h1"] = TrackedHypothesis(id="h1", description="test")
        assert AnalysisPhase._next_hypothesis_id(state) == "h2"

        state.hypotheses["h5"] = TrackedHypothesis(id="h5", description="test")
        assert AnalysisPhase._next_hypothesis_id(state) == "h6"


# ── Monitor Metric Extraction Tests ──────────────────────────────────


class TestExtractMetricsFromMonitors:
    def test_extracts_from_query(self):
        monitors = [
            {"query": "avg(last_5m):avg:system.cpu.user{service:my-svc} > 90"},
            {"query": "avg(last_5m):sum:trace.http.request.errors{service:my-svc}.as_count() > 10"},
        ]
        metrics = DatadogClient.extract_metrics_from_monitors(monitors)
        assert "system.cpu.user" in metrics
        assert "trace.http.request.errors" in metrics

    def test_handles_empty(self):
        assert DatadogClient.extract_metrics_from_monitors([]) == []

    def test_handles_complex_query(self):
        monitors = [
            {"query": "avg(last_10m):avg:kubernetes.cpu.usage.total{kube_namespace:prod} / avg:kubernetes.cpu.limits{kube_namespace:prod} * 100 > 80"},
        ]
        metrics = DatadogClient.extract_metrics_from_monitors(monitors)
        assert "kubernetes.cpu.usage.total" in metrics
        assert "kubernetes.cpu.limits" in metrics
