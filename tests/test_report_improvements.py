"""Tests for v3 report improvements."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from typing import Optional

from src.formatters.report import ReportFormatter
from src.models.incident import (
    DataGap,
    Hypothesis,
    IncidentQuery,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    RCAReport,
    SignalCheckResult,
    SymptomType,
    TrackedHypothesis,
    HypothesisStatus,
    InvestigationActionType,
)


def _make_report(
    confidence: float = 0.5,
    report_type: str = "rca",
    data_gaps: Optional[list] = None,
    next_steps: Optional[list] = None,
    signal_checklist: Optional[dict] = None,
):
    now = datetime.now(timezone.utc)
    incident = IncidentQuery(
        raw_query="CPU alert for my-service",
        service="my-service",
        symptom_type=SymptomType.SATURATION,
        start_time=now - timedelta(hours=1),
        end_time=now,
    )

    state = InvestigationState()
    if signal_checklist:
        state.signal_checklist = signal_checklist

    trace = InvestigationTrace(
        steps=[
            InvestigationStep(
                step_number=1,
                action=InvestigationActionType.FETCH_METRICS,
                reason="Check CPU",
                data_source="my-service",
                confidence=confidence,
            )
        ],
        total_steps=1,
        total_duration_ms=5000,
        concluded=True,
        conclusion_reason="root_cause_found",
        investigation_state=state,
    )

    return RCAReport(
        incident=incident,
        summary="CPU saturation on my-service",
        root_cause=Hypothesis(
            id="h1",
            description="Hot pod scenario",
            confidence=confidence,
            supporting_evidence=["Pod X at 93%"],
            is_root_cause=True,
        ),
        timeline=[],
        affected_services=["my-service"],
        blast_radius="Low",
        remediation_steps=["Restart pod"],
        confidence_score=confidence,
        evidence_chain=["Pod X at 93%"],
        investigation_trace=trace,
        data_gaps=data_gaps or [],
        report_type=report_type,
        recommended_next_steps=next_steps or [],
    )


class TestMarkdownReportType:
    def test_rca_header(self):
        report = _make_report(confidence=0.6, report_type="rca")
        md = ReportFormatter.to_markdown(report)
        assert "# Incident Investigation Report" in md
        assert "Investigation Summary" not in md

    def test_investigation_summary_header(self):
        report = _make_report(confidence=0.2, report_type="investigation_summary")
        md = ReportFormatter.to_markdown(report)
        assert "# Investigation Summary" in md
        assert "did not reach sufficient confidence" in md


class TestMarkdownDataQuality:
    def test_renders_data_quality_table(self):
        checklist = {
            "cpu_usage": SignalCheckResult(
                signal_type="cpu_usage", checked=True, data_found=True,
                data_quality=1.0, step_number=1, notes="5 series found",
            ),
            "request_rate": SignalCheckResult(
                signal_type="request_rate", checked=True, data_found=False,
                data_quality=0.0, step_number=2, notes="No gRPC metrics",
            ),
            "traces": SignalCheckResult(signal_type="traces"),
        }
        report = _make_report(signal_checklist=checklist)
        md = ReportFormatter.to_markdown(report)

        assert "### Data Quality" in md
        assert "| Signal | Status | Quality | Data Found | Notes |" in md
        assert "cpu_usage" in md
        assert "request_rate" in md
        assert "Not checked" in md


class TestMarkdownDataGaps:
    def test_renders_data_gaps(self):
        gaps = [
            DataGap(
                signal="request_rate",
                queries_attempted=["avg:trace.request{service:svc}"],
                failure_reason="No metrics matched any tag combination",
                recommendation="Verify APM instrumentation",
                impact="Cannot determine if traffic spike caused issue",
            ),
        ]
        report = _make_report(data_gaps=gaps)
        md = ReportFormatter.to_markdown(report)

        assert "### What We Don't Know" in md
        assert "request_rate" in md
        assert "Cannot determine" in md
        assert "Verify APM" in md

    def test_no_gaps_no_section(self):
        report = _make_report(data_gaps=[])
        md = ReportFormatter.to_markdown(report)
        assert "What We Don't Know" not in md


class TestMarkdownNextSteps:
    def test_renders_next_steps(self):
        steps = [
            "Check pod JVM metrics (GC, heap)",
            "Verify gRPC instrumentation",
        ]
        report = _make_report(next_steps=steps)
        md = ReportFormatter.to_markdown(report)

        assert "### Recommended Next Steps" in md
        assert "Check pod JVM" in md
        assert "Verify gRPC" in md

    def test_no_steps_no_section(self):
        report = _make_report(next_steps=[])
        md = ReportFormatter.to_markdown(report)
        assert "Recommended Next Steps" not in md


class TestSlackReportType:
    def test_rca_header(self):
        report = _make_report(confidence=0.6, report_type="rca")
        blocks = ReportFormatter.to_slack_blocks(report)
        header = blocks[0]["text"]["text"]
        assert "RCA:" in header

    def test_summary_header(self):
        report = _make_report(confidence=0.2, report_type="investigation_summary")
        blocks = ReportFormatter.to_slack_blocks(report)
        header = blocks[0]["text"]["text"]
        assert "Investigation Summary:" in header


class TestSlackDataGaps:
    def test_includes_data_gaps_block(self):
        gaps = [
            DataGap(
                signal="traces",
                failure_reason="APM not enabled",
                recommendation="Enable DD APM",
            ),
        ]
        report = _make_report(data_gaps=gaps)
        blocks = ReportFormatter.to_slack_blocks(report)

        gap_blocks = [b for b in blocks if b.get("type") == "section" and "Data Gaps" in b.get("text", {}).get("text", "")]
        assert len(gap_blocks) == 1
        assert "traces" in gap_blocks[0]["text"]["text"]

    def test_includes_next_steps_block(self):
        report = _make_report(next_steps=["Check GC metrics", "Verify APM"])
        blocks = ReportFormatter.to_slack_blocks(report)

        step_blocks = [b for b in blocks if b.get("type") == "section" and "Recommended Next Steps" in b.get("text", {}).get("text", "")]
        assert len(step_blocks) == 1
