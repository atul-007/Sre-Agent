"""Tests for signal quality tracking and data gap handling."""

import pytest
from datetime import datetime, timezone

from src.investigation.rules import (
    build_signal_checklist,
    calibrate_confidence,
    can_conclude,
    mark_signals_checked,
)
from src.models.incident import (
    DataGap,
    InvestigationState,
    SignalCheckResult,
    SymptomType,
    TrackedHypothesis,
    HypothesisStatus,
)


class TestSignalQualityFields:
    def test_default_quality_fields(self):
        result = SignalCheckResult(signal_type="cpu_usage")
        assert result.data_quality == 0.0
        assert result.diagnostic_value == 0.0
        assert result.queries_attempted == []
        assert result.retry_count == 0

    def test_quality_fields_set(self):
        result = SignalCheckResult(
            signal_type="cpu_usage",
            checked=True,
            data_found=True,
            data_quality=1.0,
            diagnostic_value=0.8,
            queries_attempted=["avg:cpu{service:svc}"],
            retry_count=2,
        )
        assert result.data_quality == 1.0
        assert result.diagnostic_value == 0.8
        assert len(result.queries_attempted) == 1


class TestDataGapModel:
    def test_basic(self):
        gap = DataGap(
            signal="request_rate",
            queries_attempted=["avg:trace.request{service:svc}", "avg:http.requests{service:svc}"],
            failure_reason="No metrics matched any tag combination",
            recommendation="Verify service is instrumented with Datadog APM",
            impact="Cannot determine if traffic spike caused the issue",
        )
        assert gap.signal == "request_rate"
        assert len(gap.queries_attempted) == 2
        assert "APM" in gap.recommendation

    def test_defaults(self):
        gap = DataGap(signal="traces")
        assert gap.queries_attempted == []
        assert gap.failure_reason == ""


class TestCanConcludeWithDataQuality:
    def test_blocks_when_no_data_found(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
        )
        # All checked but none have data
        for sig in state.signal_checklist:
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_found = False

        ok, reason = can_conclude(state, min_coverage=0.7)
        assert ok is False
        assert "0%" in reason or "data" in reason.lower()

    def test_allows_when_majority_have_data(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
        )
        signals = list(state.signal_checklist.keys())
        # 6 out of 8 have data = 75% > 50%
        for i, sig in enumerate(signals):
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_found = i < 6

        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.INVESTIGATING,
                supporting_evidence=["evidence"],
            )
        }

        ok, reason = can_conclude(state, min_coverage=0.7)
        assert ok is True

    def test_blocks_when_minority_have_data(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
        )
        signals = list(state.signal_checklist.keys())
        # Only 2 out of 8 have data = 25% < 50%
        for i, sig in enumerate(signals):
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_found = i < 2

        ok, reason = can_conclude(state, min_coverage=0.7)
        assert ok is False


class TestCalibrateConfidenceWithQuality:
    def test_low_data_quality_caps_confidence(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
            total_fetches=5,
            empty_fetches=0,
        )
        # All checked but low quality
        for sig in state.signal_checklist:
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_quality = 0.1

        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.INVESTIGATING,
                supporting_evidence=["evidence"],
            )
        }

        result = calibrate_confidence(0.7, state)
        assert result <= 0.45

    def test_good_data_quality_allows_confidence(self):
        state = InvestigationState(
            signal_checklist=build_signal_checklist(SymptomType.SATURATION.value),
            total_fetches=5,
            empty_fetches=1,
        )
        for sig in state.signal_checklist:
            state.signal_checklist[sig].checked = True
            state.signal_checklist[sig].data_quality = 0.8

        state.hypotheses = {
            "h1": TrackedHypothesis(
                id="h1", description="test",
                status=HypothesisStatus.INVESTIGATING,
                supporting_evidence=["evidence 1", "evidence 2"],
            )
        }

        result = calibrate_confidence(0.6, state)
        assert result == 0.6  # No caps should apply


class TestInvestigationStateDataGaps:
    def test_data_gaps_default_empty(self):
        state = InvestigationState()
        assert state.data_gaps == []

    def test_data_gaps_accumulate(self):
        state = InvestigationState()
        state.data_gaps.append(DataGap(signal="traces", failure_reason="APM not enabled"))
        state.data_gaps.append(DataGap(signal="request_rate", failure_reason="No metrics"))
        assert len(state.data_gaps) == 2

    def test_phase_tracking(self):
        state = InvestigationState()
        assert state.phase == "discovery"
        state.phase = "breadth"
        assert state.phase == "breadth"

    def test_depth_steps_tracking(self):
        state = InvestigationState()
        assert state.depth_steps_taken == 0
        state.depth_steps_taken = 3
        assert state.depth_steps_taken == 3
