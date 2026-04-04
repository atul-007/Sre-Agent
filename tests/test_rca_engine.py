"""Tests for the RCA engine."""

import json
from unittest.mock import AsyncMock

import pytest

from src.correlation.engine import CorrelationEngine
from src.models.incident import Hypothesis
from src.rca.engine import RCAEngine


class TestParseHypotheses:
    def setup_method(self):
        self.engine = RCAEngine(
            reasoning=AsyncMock(),
            correlation=CorrelationEngine(),
        )

    def test_parses_valid_json(self):
        raw = json.dumps(
            {
                "hypotheses": [
                    {
                        "id": "h1",
                        "description": "Database connection pool exhausted",
                        "confidence": 0.85,
                        "supporting_evidence": ["High connection count"],
                        "is_root_cause": True,
                    },
                    {
                        "id": "h2",
                        "description": "Traffic spike",
                        "confidence": 0.3,
                        "supporting_evidence": ["Request count increased"],
                        "is_root_cause": False,
                        "cascading_from": "h1",
                    },
                ]
            }
        )
        result = self.engine._parse_hypotheses(raw)
        assert len(result) == 2
        assert result[0].confidence == 0.85
        assert result[0].is_root_cause is True
        assert result[1].cascading_from == "h1"

    def test_fallback_on_invalid_json(self):
        result = self.engine._parse_hypotheses("No JSON here, just plain text analysis")
        assert len(result) == 1
        assert result[0].confidence == 0.5

    def test_extracts_json_from_mixed_text(self):
        raw = 'Here is my analysis:\n\n{"hypotheses": [{"id": "h1", "description": "test", "confidence": 0.9}]}'
        result = self.engine._parse_hypotheses(raw)
        assert len(result) == 1
        assert result[0].description == "test"


class TestSelectRootCause:
    def setup_method(self):
        self.engine = RCAEngine(
            reasoning=AsyncMock(),
            correlation=CorrelationEngine(),
        )

    def test_prefers_marked_root_cause(self):
        hypotheses = [
            Hypothesis(id="h1", description="A", confidence=0.9, is_root_cause=False),
            Hypothesis(id="h2", description="B", confidence=0.6, is_root_cause=True),
        ]
        result = self.engine._select_root_cause(hypotheses)
        assert result.id == "h2"

    def test_falls_back_to_highest_confidence(self):
        hypotheses = [
            Hypothesis(id="h1", description="A", confidence=0.3),
            Hypothesis(id="h2", description="B", confidence=0.9),
        ]
        result = self.engine._select_root_cause(hypotheses)
        assert result.id == "h2"


class TestParseRemediation:
    def setup_method(self):
        self.engine = RCAEngine(
            reasoning=AsyncMock(),
            correlation=CorrelationEngine(),
        )

    def test_extracts_numbered_steps(self):
        text = "1. Restart the service\n2. Scale up pods\n3. Fix the query"
        result = self.engine._parse_remediation(text)
        assert len(result) == 3
        assert "Restart the service" in result[0]

    def test_extracts_bullet_steps(self):
        text = "- Roll back deployment\n- Add circuit breaker\n- Tune connection pool"
        result = self.engine._parse_remediation(text)
        assert len(result) == 3
