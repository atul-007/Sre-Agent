"""Tests for depth-first investigation phase."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

from config.settings import AgentConfig
from src.investigation.rules import (
    classify_hypothesis,
    build_depth_queries,
    get_alternative_signal,
    DEPTH_QUERIES,
)
from src.investigation.depth import DepthPhase
from src.investigation.analysis import AnalysisPhase
from src.investigation.execution import ActionExecutor
from src.models.incident import (
    DataGap,
    IncidentQuery,
    InvestigationState,
    InvestigationTrace,
    ObservabilityData,
    SymptomType,
    TrackedHypothesis,
    HypothesisStatus,
)


# ── Hypothesis Classification Tests ──────────────────────────────────


class TestClassifyHypothesis:
    def test_hot_pod(self):
        assert classify_hypothesis("Single hot pod receiving disproportionate traffic") == "hot_pod"

    def test_hot_pod_with_uneven(self):
        assert classify_hypothesis("Uneven load distribution across pods") == "hot_pod"

    def test_deployment_regression(self):
        assert classify_hypothesis("Latency increased after recent deployment") == "deployment_regression"

    def test_dependency_failure(self):
        assert classify_hypothesis("Upstream service timeout causing cascade") == "dependency_failure"

    def test_resource_exhaustion(self):
        assert classify_hypothesis("OOM kill due to memory limit reached") == "resource_exhaustion"

    def test_traffic_spike(self):
        assert classify_hypothesis("Sudden traffic spike overwhelmed the service") == "traffic_spike"

    def test_unknown(self):
        assert classify_hypothesis("Something completely unrelated happened") == "unknown"

    def test_empty(self):
        assert classify_hypothesis("") == "unknown"


# ── Depth Query Building Tests ───────────────────────────────────────


class TestBuildDepthQueries:
    def test_hot_pod_generates_queries(self):
        queries = build_depth_queries(
            "hot_pod",
            "my-service",
            {"kube_namespace": "my-ns"},
            pod="my-pod-abc123",
        )
        assert len(queries) > 0
        # Should have per-pod CPU query
        assert any("pod_name" in q["query"] for q in queries)
        # Should have the tag filter
        assert any("kube_namespace:my-ns" in q["query"] for q in queries)

    def test_hot_pod_with_pod_substitution(self):
        queries = build_depth_queries(
            "hot_pod",
            "svc",
            {"service": "svc"},
            pod="specific-pod-xyz",
        )
        pod_queries = [q for q in queries if "specific-pod-xyz" in q["query"]]
        assert len(pod_queries) > 0

    def test_unknown_category_returns_empty(self):
        queries = build_depth_queries("unknown", "svc", {})
        assert queries == []

    def test_uses_service_tag_when_no_tags(self):
        queries = build_depth_queries("resource_exhaustion", "my-svc", {})
        assert any("service:my-svc" in q["query"] for q in queries)

    def test_all_categories_have_queries(self):
        for category in DEPTH_QUERIES:
            queries = build_depth_queries(category, "svc", {"service": "svc"})
            assert len(queries) > 0, f"Category '{category}' generated no queries"

    def test_query_types_are_valid(self):
        for category in DEPTH_QUERIES:
            queries = build_depth_queries(category, "svc", {"service": "svc"})
            for q in queries:
                assert q["type"] in ("metric", "log"), f"Invalid type: {q['type']}"
                assert q["signal"], "Missing signal name"
                assert q["query"], "Missing query string"


# ── Signal Alternatives Tests ────────────────────────────────────────


class TestSignalAlternatives:
    def test_traces_alternative(self):
        assert get_alternative_signal("traces") == "error_logs"

    def test_request_rate_alternative(self):
        assert get_alternative_signal("request_rate") == "error_logs"

    def test_latency_alternative(self):
        assert get_alternative_signal("latency") == "traces"

    def test_no_alternative(self):
        assert get_alternative_signal("deployments") is None


# ── DepthPhase Integration Tests ─────────────────────────────────────


class TestDepthPhase:
    def _make_depth_phase(self):
        config = AgentConfig()
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        reasoning.query_dynamic = AsyncMock(return_value='{"supports": true, "mechanism": "GC pause", "evidence_summary": "GC pauses at 200ms", "confidence_delta": 0.1, "next_query_suggestion": ""}')
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)
        return depth, dd

    def _make_incident(self):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="pod_name:my-pod-xyz CPU alert",
            service="my-service",
            symptom_type=SymptomType.SATURATION,
            start_time=now - timedelta(hours=1),
            end_time=now,
            source_tags={"pod_name": "my-pod-xyz"},
        )

    def _make_state_with_hypothesis(self, desc: str, confidence: float = 0.3):
        state = InvestigationState()
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1",
            description=desc,
            status=HypothesisStatus.INVESTIGATING,
            confidence=confidence,
            supporting_evidence=["CPU at 93%"],
        )
        return state

    @pytest.mark.asyncio
    async def test_runs_depth_for_hot_pod(self):
        depth, dd = self._make_depth_phase()
        incident = self._make_incident()
        state = self._make_state_with_hypothesis("Hot pod receiving disproportionate traffic")
        trace = InvestigationTrace()
        data = ObservabilityData()

        # Mock metric queries returning data
        from src.models.incident import MetricSeries, MetricDataPoint
        dd.query_metrics = AsyncMock(return_value=[
            MetricSeries(metric_name="cpu", display_name="cpu",
                        points=[MetricDataPoint(timestamp=incident.start_time, value=0.9)])
        ])

        await depth.run(incident, trace, state, data)

        assert trace.total_steps > 0
        assert state.depth_steps_taken > 0
        # Hypothesis should have been updated
        assert state.hypotheses["h1"].confidence > 0.3

    @pytest.mark.asyncio
    async def test_skips_low_confidence(self):
        depth, dd = self._make_depth_phase()
        incident = self._make_incident()
        state = self._make_state_with_hypothesis("Weak hypothesis", confidence=0.05)
        trace = InvestigationTrace()
        data = ObservabilityData()

        await depth.run(incident, trace, state, data)
        assert trace.total_steps == 0

    @pytest.mark.asyncio
    async def test_skips_unknown_category(self):
        depth, dd = self._make_depth_phase()
        incident = self._make_incident()
        state = self._make_state_with_hypothesis("Something completely random and unclassifiable")
        trace = InvestigationTrace()
        data = ObservabilityData()

        await depth.run(incident, trace, state, data)
        assert trace.total_steps == 0

    @pytest.mark.asyncio
    async def test_records_data_gap_on_empty(self):
        depth, dd = self._make_depth_phase()
        incident = self._make_incident()
        state = self._make_state_with_hypothesis("Hot pod with uneven load")
        trace = InvestigationTrace()
        data = ObservabilityData()

        # Return empty data
        dd.query_metrics = AsyncMock(return_value=[])
        dd.search_logs = AsyncMock(return_value=[])

        await depth.run(incident, trace, state, data)
        assert len(state.data_gaps) > 0

    @pytest.mark.asyncio
    async def test_respects_max_depth_steps(self):
        config = AgentConfig(max_depth_steps=2)
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        reasoning.query_dynamic = AsyncMock(return_value='{"supports": true, "mechanism": "", "evidence_summary": "data", "confidence_delta": 0.05}')
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)

        incident = self._make_incident()
        state = self._make_state_with_hypothesis("Hot pod with uneven load")
        trace = InvestigationTrace()
        data = ObservabilityData()

        from src.models.incident import MetricSeries, MetricDataPoint
        dd.query_metrics = AsyncMock(return_value=[
            MetricSeries(metric_name="cpu", display_name="cpu",
                        points=[MetricDataPoint(timestamp=incident.start_time, value=0.5)])
        ])

        await depth.run(incident, trace, state, data)
        assert state.depth_steps_taken <= 2

    @pytest.mark.asyncio
    async def test_extracts_pod_from_source_tags(self):
        depth, dd = self._make_depth_phase()
        incident = self._make_incident()
        state = self._make_state_with_hypothesis("Hot pod issue")

        pod = depth._extract_pod_from_context(incident, state)
        assert pod == "my-pod-xyz"

    @pytest.mark.asyncio
    async def test_no_hypothesis_skips(self):
        depth, dd = self._make_depth_phase()
        incident = self._make_incident()
        state = InvestigationState()  # no hypotheses
        trace = InvestigationTrace()
        data = ObservabilityData()

        await depth.run(incident, trace, state, data)
        assert trace.total_steps == 0
