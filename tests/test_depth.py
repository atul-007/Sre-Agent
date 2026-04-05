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


# ── Cross-Service Investigation Tests ──────────────────────────────


class TestExtractServicesFromEvidence:
    """Tests for DepthPhase._extract_services_from_evidence."""

    def _make_incident(self, service="my-service"):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="Circuit breaker alert",
            service=service,
            symptom_type=SymptomType.AVAILABILITY,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )

    def test_extracts_from_service_tag(self):
        """Should extract downstream service from circuit breaker from-service tag."""
        incident = self._make_incident("mercari-product-search-jp")
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="Downstream dependency failure via circuit breaker",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=[
                "Circuit breaker opened for from-service:mercari-searchx-jp to search-service:triton-text-embeddings-ruri-small-v2-ft",
                "Stable throughput at primary service",
            ],
            contradicting_evidence=[],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        service_names = [s["service_name"] for s in result]
        assert "mercari-searchx-jp" in service_names or "triton-text-embeddings-ruri-small-v2-ft" in service_names

    def test_extracts_k8s_endpoint(self):
        """Should extract service and namespace from Kubernetes service endpoints."""
        incident = self._make_incident()
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="Downstream timeout",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=[
                "Error connecting to triton-text-embeddings-ruri-small-v2.mercari-embeddings-jp-prod.svc.cluster.local:8001",
            ],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        assert len(result) > 0
        svc = result[0]
        assert svc["service_name"] == "triton-text-embeddings-ruri-small-v2"
        assert svc["likely_k8s_namespace"] == "mercari-embeddings-jp-prod"

    def test_ignores_primary_service(self):
        """Should not return the primary service being investigated."""
        incident = self._make_incident("my-service")
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="Dependency failure",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=[
                "from-service:my-service had errors",
                "search-service:downstream-svc was unavailable",
            ],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        service_names = [s["service_name"] for s in result]
        assert "my-service" not in service_names
        assert "downstream-svc" in service_names

    def test_no_services_found(self):
        """Should return empty when no downstream services in evidence."""
        incident = self._make_incident()
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="Generic issue",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=["CPU is high", "Memory is fine"],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        assert len(result) == 0

    def test_rejects_english_words(self):
        """Should NOT extract common English words like 'pairs', 'issue', 'failure'."""
        incident = self._make_incident("mercari-product-search-jp")
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="Downstream dependency failure",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=[
                "from-service and search-service pairs triggered the circuit breaker",
                "The downstream failure caused cascading issues",
                "Still investigating the service map dependency",
            ],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        service_names = [s["service_name"] for s in result]
        # None of these common English words should be extracted
        for bad in ["pairs", "issue", "failure", "failures", "service", "services", "Still", "search"]:
            assert bad not in service_names, f"'{bad}' should not be extracted as service name"


class TestBuildDownstreamQueries:
    """Tests for DepthPhase._build_downstream_queries."""

    def _make_incident(self):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="alert",
            service="primary-svc",
            symptom_type=SymptomType.AVAILABILITY,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )

    def test_generates_queries(self):
        incident = self._make_incident()
        queries = DepthPhase._build_downstream_queries(
            "triton-text-embeddings", "mercari-embeddings-prod", incident,
        )
        assert len(queries) >= 4
        signals = [q["signal"] for q in queries]
        assert any("error_logs" in s for s in signals)
        assert any("mentions" in s for s in signals)
        assert any("restarts" in s for s in signals)
        assert any("cpu" in s for s in signals)

    def test_uses_namespace_in_queries(self):
        incident = self._make_incident()
        queries = DepthPhase._build_downstream_queries(
            "triton-svc", "my-namespace", incident,
        )
        # Namespace should be used in log and metric queries
        ns_queries = [q for q in queries if "my-namespace" in q["query"]]
        assert len(ns_queries) >= 2

    def test_no_namespace_uses_service_tag(self):
        incident = self._make_incident()
        queries = DepthPhase._build_downstream_queries(
            "downstream-svc", "", incident,
        )
        # Without namespace, should use service tag
        svc_queries = [q for q in queries if "service:downstream-svc" in q["query"]]
        assert len(svc_queries) >= 1

    def test_includes_probe_failures_with_namespace(self):
        incident = self._make_incident()
        queries = DepthPhase._build_downstream_queries(
            "triton-svc", "my-namespace", incident,
        )
        probe_queries = [q for q in queries if "probe" in q["query"].lower() or "SIGTERM" in q["query"]]
        assert len(probe_queries) >= 1


class TestDepthPhaseDependencyFailure:
    """Tests for cross-service depth investigation."""

    def _make_depth_phase(self, max_depth_steps=10):
        config = AgentConfig(max_depth_steps=max_depth_steps)
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        reasoning.query_dynamic = AsyncMock(return_value='{"supports": true, "is_source": true, "root_cause": "Pod crash", "mechanism": "SIGTERM during model load", "evidence_summary": "Pod restarted", "confidence_delta": 0.15, "further_downstream": "", "further_downstream_reason": "", "downstream_services": []}')
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)
        return depth, dd, reasoning

    def _make_incident(self):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="Circuit breaker open for product-search",
            service="product-search",
            symptom_type=SymptomType.AVAILABILITY,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )

    @pytest.mark.asyncio
    async def test_classifies_dependency_failure(self):
        """Hypothesis with circuit breaker/downstream keywords should classify as dependency_failure."""
        assert classify_hypothesis("Downstream service timeout causing circuit breaker to open") == "dependency_failure"
        assert classify_hypothesis("Circuit breaker opened due to cascade failure") == "dependency_failure"

    @pytest.mark.asyncio
    async def test_cross_service_runs_for_dependency(self):
        """Depth phase should investigate downstream services for dependency_failure."""
        depth, dd, reasoning = self._make_depth_phase()
        incident = self._make_incident()
        state = InvestigationState()
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1",
            description="Downstream service timeout causing circuit breaker cascade",
            status=HypothesisStatus.INVESTIGATING,
            confidence=0.35,
            supporting_evidence=[
                "Circuit breaker opened for from-service:searchx-jp to search-service:triton-embeddings",
            ],
        )
        trace = InvestigationTrace()
        data = ObservabilityData()

        from src.models.incident import LogEntry
        dd.query_metrics = AsyncMock(return_value=[])
        dd.search_logs = AsyncMock(return_value=[
            LogEntry(timestamp=incident.start_time, message="error", service="triton", status="error"),
        ])
        dd.get_events = AsyncMock(return_value=[])
        dd.get_triggered_monitors = AsyncMock(return_value=[])

        await depth.run(incident, trace, state, data)

        # Should have run depth steps investigating the downstream service
        assert trace.total_steps > 0
        assert state.depth_steps_taken > 0
        # Should have investigated triton-embeddings or searchx-jp
        data_sources = [s.data_source for s in trace.steps]
        assert any(ds != "product-search" for ds in data_sources), \
            f"Expected downstream service investigation, got: {data_sources}"

    @pytest.mark.asyncio
    async def test_respects_max_depth_across_services(self):
        """Max depth steps should be respected even during cross-service investigation."""
        depth, dd, reasoning = self._make_depth_phase(max_depth_steps=3)
        incident = self._make_incident()
        state = InvestigationState()
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1",
            description="Downstream circuit breaker cascade failure",
            status=HypothesisStatus.INVESTIGATING,
            confidence=0.35,
            supporting_evidence=[
                "from-service:caller to search-service:downstream-a",
            ],
        )
        trace = InvestigationTrace()
        data = ObservabilityData()

        dd.query_metrics = AsyncMock(return_value=[])
        dd.search_logs = AsyncMock(return_value=[])
        dd.get_events = AsyncMock(return_value=[])
        dd.get_triggered_monitors = AsyncMock(return_value=[])

        await depth.run(incident, trace, state, data)
        assert state.depth_steps_taken <= 3


# ── gRPC Protobuf Service Name Extraction ──────────────────────────


class TestProtobufServiceExtraction:
    """Tests for gRPC protobuf service name pattern extraction."""

    def _make_incident(self, service="mercari-home-jp"):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="Error logs alert",
            service=service,
            symptom_type=SymptomType.ERROR_RATE,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )

    def test_extracts_grpc_protobuf_service(self):
        """Should extract gRPC protobuf service names like mercari.platform.home.ddui.v1.ComponentService."""
        incident = self._make_incident()
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="ComponentService failure causing errors",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=[
                "rpc error: code = Internal desc = failed to get components on service call to mercari.platform.home.ddui.v1.ComponentService",
            ],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        service_names = [s["service_name"] for s in result]
        assert "mercari.platform.home.ddui.v1.ComponentService" in service_names

    def test_protobuf_service_has_high_priority(self):
        """gRPC protobuf services should have high investigation priority."""
        incident = self._make_incident()
        state = InvestigationState()
        hyp = TrackedHypothesis(
            id="h1",
            description="Service failure",
            status=HypothesisStatus.INVESTIGATING,
            supporting_evidence=[
                "Method call to service mercari.platform.search.v2.SearchService returned Internal",
            ],
        )
        result = DepthPhase._extract_services_from_evidence(hyp, state, incident)
        proto_services = [s for s in result if "." in s["service_name"]]
        assert len(proto_services) > 0
        assert proto_services[0]["investigation_priority"] == "high"
        assert proto_services[0]["source"] == "gRPC protobuf service name"


# ── can_conclude Traces Requirement Tests ──────────────────────────


class TestCanConcludeTracesRequirement:
    """Tests for can_conclude requiring traces for dependency hypotheses."""

    def test_blocks_conclude_when_traces_unchecked_and_dependency_hypothesis(self):
        """Should block conclusion when traces aren't checked and leading hypothesis is about dependency."""
        from src.investigation.rules import can_conclude, build_signal_checklist
        from src.models.incident import SignalCheckResult

        state = InvestigationState(
            signal_checklist=build_signal_checklist("error_rate"),
        )
        # Mark most signals as checked except traces
        for sig in state.signal_checklist:
            if sig != "traces":
                state.signal_checklist[sig].checked = True
                state.signal_checklist[sig].data_found = True

        # Add a dependency failure hypothesis
        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1",
            description="ComponentService dependency failure causing cascading errors",
            status=HypothesisStatus.CONFIRMED,
            confidence=0.90,
            supporting_evidence=["Service returned Internal errors"],
        )

        ok, reason = can_conclude(state)
        assert not ok
        assert "traces" in reason.lower()

    def test_allows_conclude_when_traces_checked(self):
        """Should allow conclusion when traces ARE checked, even with dependency hypothesis."""
        from src.investigation.rules import can_conclude, build_signal_checklist

        state = InvestigationState(
            signal_checklist=build_signal_checklist("error_rate"),
        )
        for sig in state.signal_checklist:
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_found = True

        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1",
            description="Downstream service timeout causing cascade",
            status=HypothesisStatus.CONFIRMED,
            confidence=0.90,
            supporting_evidence=["Service timed out"],
        )

        ok, reason = can_conclude(state)
        assert ok

    def test_allows_conclude_without_dependency_hypothesis(self):
        """Should allow conclusion without traces when hypothesis is NOT about dependencies."""
        from src.investigation.rules import can_conclude, build_signal_checklist

        state = InvestigationState(
            signal_checklist=build_signal_checklist("error_rate"),
        )
        for sig in state.signal_checklist:
            if sig != "traces":
                state.signal_checklist[sig].checked = True
                state.signal_checklist[sig].data_found = True

        state.hypotheses["h1"] = TrackedHypothesis(
            id="h1",
            description="CPU saturation caused OOM kills on hot pod",
            status=HypothesisStatus.CONFIRMED,
            confidence=0.80,
            supporting_evidence=["CPU at 95%"],
        )

        ok, reason = can_conclude(state)
        assert ok
