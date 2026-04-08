"""Tests for the investigation rule engine (signal checklists, confidence calibration, conclusion guards)."""

import pytest

from src.investigation.rules import (
    REQUIRED_SIGNALS,
    build_signal_checklist,
    calibrate_confidence,
    can_conclude,
    format_signal_coverage,
    get_forced_next_action,
    get_tag_fallbacks,
    get_unchecked_signals,
    mark_signals_checked,
)
from src.models.incident import (
    HypothesisStatus,
    InvestigationState,
    SignalCheckResult,
    SymptomType,
    TrackedHypothesis,
)


class TestBuildSignalChecklist:
    def test_saturation_checklist(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        assert "cpu_usage" in checklist
        assert "cpu_limits" in checklist
        assert "cpu_throttling" in checklist
        assert "request_rate" in checklist
        assert "memory" in checklist
        assert "deployments" in checklist
        assert len(checklist) == 8

    def test_latency_checklist(self):
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        assert "latency" in checklist
        assert "traces" in checklist
        assert "dependencies" in checklist

    def test_unknown_symptom_fallback(self):
        checklist = build_signal_checklist("nonexistent")
        assert checklist == build_signal_checklist(SymptomType.UNKNOWN.value)

    def test_all_signals_start_unchecked(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        for result in checklist.values():
            assert result.checked is False
            assert result.data_found is False


class TestMarkSignalsChecked:
    def test_marks_correct_signals(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        mark_signals_checked(checklist, "fetch_infra_metrics", step_number=1, data_found=True)
        assert checklist["cpu_usage"].checked is True
        assert checklist["cpu_limits"].checked is True
        assert checklist["cpu_throttling"].checked is True
        assert checklist["memory"].checked is True
        # Unrelated signals stay unchecked
        assert checklist["request_rate"].checked is False

    def test_marks_data_found(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        mark_signals_checked(checklist, "fetch_metrics", step_number=1, data_found=False)
        assert checklist["cpu_usage"].checked is True
        assert checklist["cpu_usage"].data_found is False

    def test_data_found_sticky(self):
        """Once data_found is True, subsequent empty checks don't reset it."""
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        mark_signals_checked(checklist, "fetch_metrics", step_number=1, data_found=True)
        mark_signals_checked(checklist, "fetch_metrics", step_number=2, data_found=False)
        assert checklist["cpu_usage"].data_found is True


class TestGetUncheckedSignals:
    def test_all_unchecked_initially(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        unchecked = get_unchecked_signals(checklist)
        assert len(unchecked) == 8

    def test_reduces_after_check(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        mark_signals_checked(checklist, "fetch_infra_metrics", step_number=1, data_found=True)
        unchecked = get_unchecked_signals(checklist)
        # cpu_usage, cpu_limits, cpu_throttling, memory are now checked
        assert "cpu_usage" not in unchecked
        assert "request_rate" in unchecked


class TestGetForcedNextAction:
    def test_generates_valid_action(self):
        action = get_forced_next_action("cpu_throttling", "my-service")
        assert action["action"] == "fetch_infra_metrics"
        assert "[FORCED]" in action["reason"]
        assert action["data_source"] == "my-service"

    def test_fallback_for_unknown_signal(self):
        action = get_forced_next_action("unknown_signal", "my-service")
        assert action["action"] == "fetch_metrics"


class TestGetTagFallbacks:
    def test_generates_alternatives(self):
        fallbacks = get_tag_fallbacks({"service": "my-svc"})
        assert len(fallbacks) > 0
        # Should try kube_service, app, etc.
        alt_keys = [list(f.keys())[0] for f in fallbacks]
        assert "kube_service" in alt_keys or "app" in alt_keys

    def test_max_three(self):
        fallbacks = get_tag_fallbacks({"service": "svc", "namespace": "ns"})
        assert len(fallbacks) <= 3


class TestCalibrateConfidence:
    def _make_state(self, empty=0, total=10, hypotheses=None):
        state = InvestigationState()
        state.empty_fetches = empty
        state.total_fetches = total
        state.hypotheses = hypotheses or {}
        return state

    def test_caps_when_all_fetches_empty(self):
        """All fetches empty should cap confidence at 0.20."""
        state = self._make_state(empty=6, total=6)
        result = calibrate_confidence(0.8, state)
        assert result <= 0.20

    def test_caps_moderately_with_one_non_empty(self):
        """Only 1 non-empty fetch should cap at sparse threshold."""
        state = self._make_state(empty=5, total=6)
        result = calibrate_confidence(0.8, state)
        assert result <= 0.40

    def test_no_cap_with_some_data(self):
        """2+ non-empty fetches should NOT cap, even if >50% empty."""
        state = self._make_state(empty=4, total=6)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.INVESTIGATING,
                confidence=0.7,
                supporting_evidence=["evidence1", "evidence2"],
            )
        }
        result = calibrate_confidence(0.7, state)
        assert result == 0.7

    def test_no_cap_on_good_data(self):
        """Less than 50% empty fetches should not cap."""
        state = self._make_state(empty=3, total=10)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.INVESTIGATING,
                confidence=0.7,
                supporting_evidence=["evidence1", "evidence2"],
            )
        }
        result = calibrate_confidence(0.7, state)
        assert result == 0.7

    def test_caps_without_direct_evidence(self):
        """No supporting evidence should cap at 0.60."""
        state = self._make_state(empty=2, total=10)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.INVESTIGATING,
                confidence=0.7,
            )
        }
        result = calibrate_confidence(0.75, state)
        assert result <= 0.60

    def test_high_confidence_gate(self):
        """Confidence >0.80 requires 2+ supporting and 0 contradicting."""
        state = self._make_state(empty=1, total=10)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.CONFIRMED,
                confidence=0.9,
                supporting_evidence=["e1"],  # only 1
            )
        }
        result = calibrate_confidence(0.9, state)
        assert result <= 0.80

    def test_allows_high_confidence_with_evidence(self):
        """Confidence >0.80 allowed with 2+ supporting, 0 contradicting."""
        state = self._make_state(empty=1, total=10)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.CONFIRMED,
                confidence=0.9,
                supporting_evidence=["e1", "e2"],
                contradicting_evidence=[],
            )
        }
        result = calibrate_confidence(0.9, state)
        assert result == 0.9

    def test_high_confidence_with_minor_contradictions(self):
        """Confidence >0.80 allowed if supporting >> contradicting."""
        state = self._make_state(empty=1, total=10)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.CONFIRMED,
                confidence=0.9,
                supporting_evidence=[f"e{i}" for i in range(10)],
                contradicting_evidence=["c1", "c2", "c3"],
            )
        }
        result = calibrate_confidence(0.9, state)
        assert result == 0.9  # 3 contradicting < 10//2=5, so allowed

    def test_high_confidence_blocked_with_major_contradictions(self):
        """Confidence >0.80 blocked if contradicting > half of supporting."""
        state = self._make_state(empty=1, total=10)
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.CONFIRMED,
                confidence=0.9,
                supporting_evidence=["e1", "e2", "e3", "e4"],
                contradicting_evidence=["c1", "c2", "c3"],
            )
        }
        result = calibrate_confidence(0.9, state)
        assert result <= 0.80  # 3 contradicting > 4//2=2, so blocked


class TestCanConclude:
    def test_cannot_with_low_coverage(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
        )
        # Nothing checked
        ok, reason = can_conclude(state, min_coverage=0.7)
        assert ok is False
        assert "Missing" in reason

    def test_can_with_full_coverage(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
        )
        # Mark all checked with data_found=True (v3 requirement)
        for sig in state.signal_checklist:
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_found = True
        # Need at least one hypothesis with evidence
        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.CONFIRMED,
                supporting_evidence=["evidence"],
            )
        }
        ok, reason = can_conclude(state, min_coverage=0.7)
        assert ok is True

    def test_cannot_without_evidence(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
        )
        for sig in state.signal_checklist:
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_found = True
        state.hypotheses = {
            "h1": TrackedHypothesis(id="h1", description="test")
        }
        ok, reason = can_conclude(state, min_coverage=0.7)
        assert ok is False
        assert "evidence" in reason.lower()

    def test_can_with_empty_checklist(self):
        state = InvestigationState()
        ok, _ = can_conclude(state)
        assert ok is True


class TestFormatSignalCoverage:
    def test_format_output(self):
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        mark_signals_checked(checklist, "fetch_infra_metrics", step_number=1, data_found=True)
        output = format_signal_coverage(checklist)
        assert "[x] cpu_usage" in output
        assert "data found" in output
        assert "[ ]" in output
        assert "NOT YET CHECKED" in output


class TestEvidenceDeduplication:
    """Test that evidence deduplication works in hypothesis merging."""

    def test_duplicate_evidence_filtered(self):
        """Duplicate evidence strings should not be added twice."""
        h = TrackedHypothesis(
            id="h1", description="test",
            status=HypothesisStatus.INVESTIGATING,
            confidence=0.5,
            supporting_evidence=["CPU at 62%"],
            contradicting_evidence=["Missing traces"],
        )
        state = InvestigationState()
        state.hypotheses = {"h1": h}

        # Simulate what merge_hypotheses does internally
        update = {
            "supporting_evidence": ["CPU at 62%", "No throttling"],
            "contradicting_evidence": ["Missing traces", "No gRPC data"],
        }
        existing_support = set(h.supporting_evidence)
        for e in update.get("supporting_evidence", []):
            if e not in existing_support:
                h.supporting_evidence.append(e)
                existing_support.add(e)
        existing_contra = set(h.contradicting_evidence)
        for e in update.get("contradicting_evidence", []):
            if e not in existing_contra:
                h.contradicting_evidence.append(e)
                existing_contra.add(e)

        assert h.supporting_evidence == ["CPU at 62%", "No throttling"]
        assert h.contradicting_evidence == ["Missing traces", "No gRPC data"]

    def test_evidence_preserves_order(self):
        """New evidence should be appended after existing, preserving order."""
        h = TrackedHypothesis(
            id="h1", description="test",
            status=HypothesisStatus.INVESTIGATING,
            confidence=0.5,
            supporting_evidence=["first", "second"],
        )
        new_evidence = ["second", "third", "first", "fourth"]
        existing = set(h.supporting_evidence)
        for e in new_evidence:
            if e not in existing:
                h.supporting_evidence.append(e)
                existing.add(e)

        assert h.supporting_evidence == ["first", "second", "third", "fourth"]


class TestCustomMetricSignalInference:
    """Test that query_custom_metric actions mark the right signals as checked."""

    def test_trace_latency_query_marks_signals(self):
        """Querying trace.grpc.server.duration should mark latency but NOT traces.

        trace.* metrics are aggregate metrics derived from APM, not actual trace spans.
        The 'traces' signal requires span-level data to follow request flows.
        """
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=1, data_found=True,
            query="avg:trace.grpc.server.duration{service:my-svc} by {resource_name}",
        )
        assert checklist["latency"].checked is True
        assert checklist["latency"].data_found is True
        # trace.* metrics should NOT satisfy the 'traces' signal
        assert checklist["traces"].checked is False

    def test_error_query_marks_error_rate(self):
        """Querying trace.*.errors should mark error_rate."""
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=1, data_found=True,
            query="sum:trace.grpc.server.errors{service:my-svc}.as_count()",
        )
        assert checklist["error_rate"].checked is True
        assert checklist["error_rate"].data_found is True

    def test_hits_query_marks_request_rate(self):
        """Querying trace.*.hits should mark request_rate."""
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=1, data_found=True,
            query="sum:trace.grpc.server.hits{service:my-svc}.as_count()",
        )
        assert checklist["request_rate"].checked is True

    def test_cpu_query_marks_cpu_usage(self):
        """Querying cpu.usage should mark cpu_usage."""
        checklist = build_signal_checklist(SymptomType.SATURATION.value)
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=1, data_found=True,
            query="avg:system.cpu.usage{host:my-host}",
        )
        assert checklist["cpu_usage"].checked is True

    def test_no_query_no_inference(self):
        """query_custom_metric without a query string should not mark anything."""
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=1, data_found=True,
        )
        unchecked = get_unchecked_signals(checklist)
        assert len(unchecked) == len(checklist)

    def test_non_custom_action_ignores_query(self):
        """fetch_metrics should use ACTION_TO_SIGNALS, not query inference."""
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        mark_signals_checked(
            checklist, "fetch_metrics", step_number=1, data_found=True,
            query="avg:trace.grpc.server.duration{service:my-svc}",
        )
        # fetch_metrics marks its own set of signals from ACTION_TO_SIGNALS
        assert checklist["latency"].checked is True
        assert checklist["cpu_usage"].checked is True

    def test_data_found_sticky_with_custom_metric(self):
        """data_found should remain True even if a later custom query returns empty."""
        checklist = build_signal_checklist(SymptomType.LATENCY.value)
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=1, data_found=True,
            query="avg:trace.http.request.duration{service:my-svc}",
        )
        mark_signals_checked(
            checklist, "query_custom_metric", step_number=2, data_found=False,
            query="avg:trace.http.request.errors{service:my-svc}",
        )
        assert checklist["latency"].data_found is True
