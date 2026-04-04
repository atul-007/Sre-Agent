"""Tests for the report formatter."""

from datetime import datetime

import pytest

from src.formatters.report import ReportFormatter
from src.models.incident import (
    Hypothesis,
    IncidentQuery,
    IncidentSeverity,
    RCAReport,
    SymptomType,
    TimelineEvent,
)

NOW = datetime(2026, 4, 4, 14, 0, 0)


@pytest.fixture
def sample_report():
    return RCAReport(
        incident=IncidentQuery(
            raw_query="Why did checkout-service latency spike?",
            service="checkout-service",
            symptom_type=SymptomType.LATENCY,
            start_time=NOW,
            end_time=NOW,
        ),
        summary="Root cause: database connection pool exhaustion",
        root_cause=Hypothesis(
            id="h1",
            description="Database connection pool exhaustion caused by slow queries",
            confidence=0.85,
            supporting_evidence=["Connection pool at 100%", "Query latency >3s"],
            is_root_cause=True,
        ),
        contributing_factors=[
            Hypothesis(
                id="h2",
                description="Missing index on orders table",
                confidence=0.7,
                cascading_from="h1",
            ),
        ],
        timeline=[
            TimelineEvent(
                timestamp=NOW,
                event_type="metric_anomaly",
                source="latency",
                description="Latency spike to 4500ms",
                severity=IncidentSeverity.CRITICAL,
            ),
        ],
        affected_services=["checkout-service", "api-gateway"],
        blast_radius="Medium: 2 of 10 services affected",
        remediation_steps=["Increase connection pool size", "Add missing index"],
        confidence_score=0.85,
        evidence_chain=["Connection pool at 100%", "Slow queries detected"],
        raw_reasoning="Detailed analysis...",
    )


class TestMarkdownFormat:
    def test_contains_key_sections(self, sample_report):
        md = ReportFormatter.to_markdown(sample_report)
        assert "# Incident Investigation Report" in md
        assert "## Root Cause" in md
        assert "## Contributing Factors" in md
        assert "## Remediation Steps" in md
        assert "## Blast Radius" in md
        assert "checkout-service" in md

    def test_contains_evidence(self, sample_report):
        md = ReportFormatter.to_markdown(sample_report)
        assert "Connection pool at 100%" in md
        assert "85%" in md


class TestSlackFormat:
    def test_returns_valid_blocks(self, sample_report):
        blocks = ReportFormatter.to_slack_blocks(sample_report)
        assert len(blocks) >= 3
        assert blocks[0]["type"] == "header"


class TestCompactFormat:
    def test_returns_single_line(self, sample_report):
        compact = ReportFormatter.to_compact(sample_report)
        assert "85%" in compact
        assert "checkout-service" in compact
        assert len(compact) < 500
