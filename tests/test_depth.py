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
    LogEntry,
    ObservabilityData,
    SymptomType,
    TraceSpan,
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

    def test_internal_resource_constraint(self):
        """Vague 'internal resource constraint' should match dependency_failure."""
        assert classify_hypothesis("Internal resource constraint causing latency") == "dependency_failure"

    def test_resource_constraint_fallback(self):
        """'resource constraint' alone should match via keyword."""
        assert classify_hypothesis("Resource constraint in backend service") == "dependency_failure"

    def test_deadline_exceeded(self):
        """gRPC DeadlineExceeded should match dependency_failure."""
        assert classify_hypothesis("DeadlineExceeded errors propagating from downstream") == "dependency_failure"

    def test_thread_pool_saturation(self):
        """Thread pool saturation should match resource_exhaustion."""
        assert classify_hypothesis("Thread pool saturation causing request queuing") == "resource_exhaustion"

    def test_vague_latency_spike_fallback(self):
        """Vague 'latency spike' with no specific keywords should fallback to dependency_failure."""
        result = classify_hypothesis("Latency spike in service processing")
        assert result != "unknown"  # Should not be unknown — infra hint fallback

    def test_vague_error_fallback(self):
        """Vague error description should fallback to dependency_failure via infra hints."""
        result = classify_hypothesis("Service experiencing intermittent errors")
        assert result != "unknown"

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
        assert any("error_traces" in s for s in signals)
        assert any("error_logs" in s for s in signals)
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

    def _make_depth_phase(self, max_depth_steps=10, max_downstream_steps=15):
        config = AgentConfig(max_depth_steps=max_depth_steps, max_downstream_steps=max_downstream_steps)
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
        """Max downstream steps should be respected during cross-service investigation."""
        depth, dd, reasoning = self._make_depth_phase(max_depth_steps=10, max_downstream_steps=3)
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
        assert state.downstream_steps_taken <= 3


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


# ── Early Exit Tests ─────────────────────────────────────────────────


class TestEarlyExitOnVictim:
    """Tests for adaptive per-service budget with early exit."""

    def _make_depth_phase(self, max_downstream_steps=15):
        config = AgentConfig(max_downstream_steps=max_downstream_steps)
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)
        return depth, dd, reasoning

    def _make_incident(self):
        now = datetime.now(timezone.utc)
        return IncidentQuery(
            raw_query="Error rate spike",
            service="my-service",
            symptom_type=SymptomType.ERROR_RATE,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )

    @pytest.mark.asyncio
    async def test_early_exit_on_victim_service(self):
        """Victim service (context canceled) should cost 1 step, not 5."""
        depth, dd, reasoning = self._make_depth_phase()

        dd.search_traces = AsyncMock(return_value=[
            TraceSpan(
                trace_id="abc", span_id="s1", service="downstream-svc",
                operation="grpc.server", resource="GetData",
                duration_ns=5_000_000, start_time=datetime.now(timezone.utc),
                status="error", error_message="context canceled",
                meta={"error.handling": "handled"},
            ),
        ])
        dd.search_logs = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_triggered_monitors = AsyncMock(return_value=[])

        reasoning.query_dynamic = AsyncMock(return_value='{"is_source": false, "root_cause": "", "mechanism": "context canceled from upstream timeout propagation", "evidence_summary": "All errors are context cancellations", "confidence_delta": -0.05, "further_downstream": "", "further_downstream_reason": ""}')

        incident = self._make_incident()
        state = InvestigationState()
        leading = TrackedHypothesis(
            id="h1", description="Dependency failure",
            status=HypothesisStatus.INVESTIGATING, confidence=0.4,
        )
        state.hypotheses["h1"] = leading
        trace = InvestigationTrace()
        data = ObservabilityData()

        initial = state.downstream_steps_taken
        await depth._investigate_downstream_service(
            "downstream-svc", "", incident, trace, state, data, leading, "dependency_failure",
        )
        # Should have taken only 1 step (traces), not 5
        assert state.downstream_steps_taken - initial == 1
        # Should have early-exit evidence
        assert any("early-exit" in e for e in leading.contradicting_evidence)

    @pytest.mark.asyncio
    async def test_no_early_exit_on_source_service(self):
        """Source service (is_source=True) should run all queries."""
        depth, dd, reasoning = self._make_depth_phase()

        dd.search_traces = AsyncMock(return_value=[
            TraceSpan(
                trace_id="abc", span_id="s1", service="downstream-svc",
                operation="grpc.server", resource="GetData",
                duration_ns=5_000_000, start_time=datetime.now(timezone.utc),
                status="error", error_message="internal server error",
            ),
        ])
        dd.search_logs = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_triggered_monitors = AsyncMock(return_value=[])

        reasoning.query_dynamic = AsyncMock(return_value='{"is_source": true, "root_cause": "OOM kill", "mechanism": "Memory exhaustion causing pod restart", "evidence_summary": "Pod OOM killed", "confidence_delta": 0.2, "further_downstream": "", "further_downstream_reason": ""}')

        incident = self._make_incident()
        state = InvestigationState()
        leading = TrackedHypothesis(
            id="h1", description="Dependency failure",
            status=HypothesisStatus.INVESTIGATING, confidence=0.4,
        )
        state.hypotheses["h1"] = leading
        trace = InvestigationTrace()
        data = ObservabilityData()

        initial = state.downstream_steps_taken
        await depth._investigate_downstream_service(
            "downstream-svc", "", incident, trace, state, data, leading, "dependency_failure",
        )
        # Should have taken more than 1 step (full investigation)
        assert state.downstream_steps_taken - initial >= 4

    @pytest.mark.asyncio
    async def test_no_early_exit_on_empty_traces(self):
        """Empty first query should not trigger early exit — continue investigating."""
        depth, dd, reasoning = self._make_depth_phase()

        dd.search_traces = AsyncMock(return_value=[])
        dd.search_logs = AsyncMock(return_value=[
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                message="connection refused",
                service="downstream-svc",
                status="error",
            ),
        ])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_triggered_monitors = AsyncMock(return_value=[])

        reasoning.query_dynamic = AsyncMock(return_value='{"is_source": true, "root_cause": "Connection refused", "mechanism": "Service crashed", "evidence_summary": "Connection refused errors", "confidence_delta": 0.1, "further_downstream": "", "further_downstream_reason": ""}')

        incident = self._make_incident()
        state = InvestigationState()
        leading = TrackedHypothesis(
            id="h1", description="Dependency failure",
            status=HypothesisStatus.INVESTIGATING, confidence=0.4,
        )
        state.hypotheses["h1"] = leading
        trace = InvestigationTrace()
        data = ObservabilityData()

        initial = state.downstream_steps_taken
        await depth._investigate_downstream_service(
            "downstream-svc", "", incident, trace, state, data, leading, "dependency_failure",
        )
        # Should have continued past the empty first query
        assert state.downstream_steps_taken - initial >= 2


# ── Separate Budget Tests ────────────────────────────────────────────


class TestSeparateDownstreamBudget:
    """Tests for separate depth vs downstream budgets."""

    @pytest.mark.asyncio
    async def test_downstream_uses_separate_budget(self):
        """Downstream investigation should use max_downstream_steps, not max_depth_steps."""
        config = AgentConfig(max_depth_steps=3, max_downstream_steps=10)
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        reasoning.query_dynamic = AsyncMock(return_value='{"is_source": true, "root_cause": "Crash", "mechanism": "OOM kill", "evidence_summary": "Pod crashed", "confidence_delta": 0.1, "further_downstream": "", "further_downstream_reason": "", "downstream_services": []}')
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)

        now = datetime.now(timezone.utc)
        incident = IncidentQuery(
            raw_query="Error spike",
            service="my-svc",
            symptom_type=SymptomType.ERROR_RATE,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )
        state = InvestigationState()
        leading = TrackedHypothesis(
            id="h1", description="Downstream dependency timeout cascade",
            status=HypothesisStatus.INVESTIGATING, confidence=0.4,
            supporting_evidence=["from-service:caller to search-service:downstream-a"],
        )
        state.hypotheses["h1"] = leading
        trace = InvestigationTrace()
        data = ObservabilityData()

        dd.search_traces = AsyncMock(return_value=[])
        dd.search_logs = AsyncMock(return_value=[])
        dd.query_metrics = AsyncMock(return_value=[])
        dd.get_events = AsyncMock(return_value=[])
        dd.get_triggered_monitors = AsyncMock(return_value=[])

        await depth.run(incident, trace, state, data)

        # downstream_steps_taken should be <= max_downstream_steps
        assert state.downstream_steps_taken <= 10
        # Standard depth queries should have run (trace-follow + 2 standard)
        # even though max_depth_steps=3
        assert state.depth_steps_taken >= 3


# ── LLM Ranking Tests ───────────────────────────────────────────────


class TestLLMRanking:
    """Tests for LLM-based downstream service ranking."""

    @pytest.mark.asyncio
    async def test_ranking_reorders_services(self):
        """LLM ranking should reorder services by root-cause likelihood."""
        config = AgentConfig()
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)

        now = datetime.now(timezone.utc)
        incident = IncidentQuery(
            raw_query="Error spike",
            service="my-svc",
            symptom_type=SymptomType.ERROR_RATE,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )
        leading = TrackedHypothesis(
            id="h1", description="Dependency failure causing errors",
            status=HypothesisStatus.INVESTIGATING, confidence=0.5,
            supporting_evidence=["SearchClient.GetItems failed with Internal error"],
        )
        data = ObservabilityData()

        candidates = [
            {"service_name": "campaign-svc", "source": "trace span", "likely_k8s_namespace": "", "investigation_priority": "high"},
            {"service_name": "search-svc", "source": "trace span", "likely_k8s_namespace": "", "investigation_priority": "high"},
            {"service_name": "comments-svc", "source": "trace span", "likely_k8s_namespace": "", "investigation_priority": "medium"},
            {"service_name": "analytics-svc", "source": "trace span", "likely_k8s_namespace": "", "investigation_priority": "low"},
        ]

        # Claude ranks search-svc first (matches error pattern)
        reasoning.query_dynamic = AsyncMock(return_value='{"ranked_services": [{"service_name": "search-svc", "reason": "SearchClient error points here"}, {"service_name": "campaign-svc", "reason": "Secondary"}]}')

        ranked = await depth._rank_downstream_services(candidates, incident, leading, data)
        assert ranked is not None
        assert ranked[0]["service_name"] == "search-svc"
        assert ranked[1]["service_name"] == "campaign-svc"

    @pytest.mark.asyncio
    async def test_ranking_fallback_on_parse_failure(self):
        """LLM ranking should return None on parse failure, triggering fallback."""
        config = AgentConfig()
        dd = AsyncMock()
        correlation = MagicMock()
        executor = ActionExecutor(dd, correlation, config)
        reasoning = MagicMock()
        analysis = AnalysisPhase(reasoning, correlation, config)
        depth = DepthPhase(executor, analysis, reasoning, config)

        now = datetime.now(timezone.utc)
        incident = IncidentQuery(
            raw_query="Error spike",
            service="my-svc",
            symptom_type=SymptomType.ERROR_RATE,
            start_time=now - timedelta(hours=1),
            end_time=now,
        )
        leading = TrackedHypothesis(
            id="h1", description="Dependency failure",
            status=HypothesisStatus.INVESTIGATING, confidence=0.5,
        )
        data = ObservabilityData()

        candidates = [
            {"service_name": "svc-a", "source": "trace", "likely_k8s_namespace": "", "investigation_priority": "high"},
            {"service_name": "svc-b", "source": "trace", "likely_k8s_namespace": "", "investigation_priority": "medium"},
        ]

        # Claude returns garbage
        reasoning.query_dynamic = AsyncMock(return_value="not valid json at all")

        ranked = await depth._rank_downstream_services(candidates, incident, leading, data)
        assert ranked is None  # should fallback

    @pytest.mark.asyncio
    async def test_trace_tree_summary(self):
        """Trace tree summary should show parent-child relationships."""
        now = datetime.now(timezone.utc)
        data = ObservabilityData()
        data.traces = [
            TraceSpan(
                trace_id="t1", span_id="root", parent_id="",
                service="home-jp", operation="grpc.server",
                resource="/GetComponents", duration_ns=50_000_000,
                start_time=now, status="error",
            ),
            TraceSpan(
                trace_id="t1", span_id="child1", parent_id="root",
                service="search-adapter", operation="grpc.client",
                resource="SearchComponents", duration_ns=40_000_000,
                start_time=now, status="error",
            ),
            TraceSpan(
                trace_id="t1", span_id="child2", parent_id="root",
                service="campaign-jp", operation="grpc.client",
                resource="GetCampaigns", duration_ns=20_000_000,
                start_time=now, status="ok",
            ),
        ]

        result = DepthPhase._build_trace_tree_summary(data, "home-jp")
        assert "home-jp" in result
        assert "search-adapter" in result
        assert "campaign-jp" in result
        assert "Trace t1" in result


# ── Service Name Resolution Tests ──────────────────────────────────

from src.investigation.depth import _derive_service_name_candidates, _derive_namespace_candidates


class TestDeriveServiceNameCandidates:
    """Test protobuf/component name → Datadog service name derivation."""

    def test_protobuf_to_service_names(self):
        """Protobuf name should generate hyphenated service name candidates."""
        candidates = _derive_service_name_candidates(
            "mercari.platform.searchtagjp.api.v2.TagSuggestService",
            "mercari-searchadapter-jp",
        )
        # Should include mercari-searchtagjp-jp (prefix-core-suffix from primary)
        assert "mercari-searchtagjp-jp" in candidates
        # Should include mercari-searchtagjp
        assert "mercari-searchtagjp" in candidates
        # Should include just the core
        assert "searchtagjp" in candidates

    def test_protobuf_camelcase_to_hyphen(self):
        """CamelCase RPC class should be converted to hyphenated form."""
        candidates = _derive_service_name_candidates(
            "mercari.platform.search.v1.SearchService",
            "mercari-home-jp",
        )
        assert "search-service" in candidates

    def test_component_name_underscore(self):
        """Component names with underscores should generate hyphenated variants."""
        candidates = _derive_service_name_candidates(
            "query_suggest_component",
            "mercari-searchadapter-jp",
        )
        assert "query_suggest_component" in candidates
        assert "query-suggest-component" in candidates
        # Should strip _component suffix
        assert "query_suggest" in candidates
        assert "query-suggest" in candidates

    def test_already_valid_service_name(self):
        """Already-valid hyphenated names should be returned as-is."""
        candidates = _derive_service_name_candidates(
            "mercari-searchx-jp",
            "mercari-searchadapter-jp",
        )
        assert candidates == ["mercari-searchx-jp"]

    def test_excludes_primary_service(self):
        """Primary service name should not appear in candidates."""
        candidates = _derive_service_name_candidates(
            "mercari.platform.searchadapter.api.v2.SearchService",
            "mercari-searchadapter-jp",
        )
        assert "mercari-searchadapter-jp" not in candidates

    def test_short_names_excluded(self):
        """Names shorter than 3 chars should be excluded."""
        candidates = _derive_service_name_candidates("ab", "my-service")
        assert len(candidates) == 0

    def test_empty_name(self):
        """Empty name should return empty list."""
        candidates = _derive_service_name_candidates("", "my-service")
        assert len(candidates) == 0

    def test_protobuf_skips_platform(self):
        """Domain parts should try skipping 'platform' namespace."""
        candidates = _derive_service_name_candidates(
            "mercari.platform.searchx.api.v1.Service",
            "mercari-home-jp",
        )
        assert "mercari-searchx" in candidates


class TestDeriveNamespaceCandidates:
    """Test namespace derivation from service names."""

    def test_generates_env_suffixed_candidates(self):
        """Should generate namespace candidates with env suffixes."""
        candidates = _derive_namespace_candidates(
            "mercari.platform.searchtagjp.api.v2.TagSuggestService",
            "mercari-searchadapter-jp",
        )
        assert any("prod" in c for c in candidates)
        assert any("searchtagjp" in c for c in candidates)

    def test_uses_service_candidates_as_base(self):
        """Namespace candidates should be based on service name candidates."""
        candidates = _derive_namespace_candidates(
            "query_suggest_component",
            "mercari-searchadapter-jp",
        )
        assert any("query-suggest" in c or "query_suggest" in c for c in candidates)


class TestBuildDownstreamQueriesExtended:
    """Test that downstream queries include k8s events and monitors."""

    def test_includes_k8s_events(self):
        """Downstream queries should include Kubernetes event query."""
        queries = DepthPhase._build_downstream_queries(
            "mercari-searchx-jp", "mercari-searchx-jp-prod",
            IncidentQuery(
                service="mercari-searchadapter-jp",
                symptom_type=SymptomType.LATENCY,
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                raw_query="test",
            ),
        )
        signals = [q["signal"] for q in queries]
        assert any("k8s_events" in s for s in signals)
        assert any("monitors" in s for s in signals)

    def test_includes_monitors(self):
        """Downstream queries should include triggered monitors."""
        queries = DepthPhase._build_downstream_queries(
            "searchx-jp", "",
            IncidentQuery(
                service="mercari-searchadapter-jp",
                symptom_type=SymptomType.LATENCY,
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                raw_query="test",
            ),
        )
        types = [q["type"] for q in queries]
        assert "event" in types
        assert "monitors" in types
