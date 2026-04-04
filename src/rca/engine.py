"""Root Cause Analysis engine — orchestrates the full investigation pipeline."""

from __future__ import annotations

import json
import logging
import re

from src.claude.reasoning import ClaudeReasoning
from src.correlation.engine import CorrelationEngine
from src.models.incident import (
    Hypothesis,
    IncidentQuery,
    ObservabilityData,
    RCAReport,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class RCAEngine:
    """Orchestrates multi-pass reasoning to produce a root cause analysis."""

    def __init__(
        self,
        reasoning: ClaudeReasoning,
        correlation: CorrelationEngine,
    ) -> None:
        self.reasoning = reasoning
        self.correlation = correlation

    async def investigate(
        self, incident: IncidentQuery, data: ObservabilityData
    ) -> RCAReport:
        """Run full RCA investigation pipeline."""
        logger.info("Starting RCA investigation for %s", incident.service)

        # Step 1: Correlate all signals
        timeline = self.correlation.build_timeline(incident, data)
        service_correlation = self.correlation.correlate_services(data)
        anomaly_summary = self.correlation.compute_anomaly_summary(data)

        timeline_dicts = [evt.model_dump() for evt in timeline]
        monitor_dicts = [m.model_dump() for m in data.monitors]
        deploy_dicts = [d.model_dump() for d in data.deployment_events]

        incident_context = {
            "service": incident.service,
            "symptom_type": incident.symptom_type.value,
            "start_time": incident.start_time.isoformat(),
            "end_time": incident.end_time.isoformat(),
            "raw_query": incident.raw_query,
        }

        # Step 2: Claude Phase 1 — Initial Analysis
        logger.info("Phase 1: Initial analysis...")
        initial_analysis = await self.reasoning.initial_analysis(
            incident_context=incident_context,
            anomaly_summary=anomaly_summary,
            timeline=timeline_dicts,
            service_correlation=service_correlation,
            monitors=monitor_dicts,
            deployments=deploy_dicts,
        )

        # Step 3: Claude Phase 2 — Hypothesis Generation
        logger.info("Phase 2: Hypothesis generation...")
        hypotheses_raw = await self.reasoning.generate_hypotheses(
            initial_analysis=initial_analysis,
            top_errors=anomaly_summary.get("top_error_messages", []),
            cross_service_traces=service_correlation.get("cross_service_traces", []),
            metric_anomalies=anomaly_summary.get("metric_anomalies", []),
            service_map=[n.model_dump() for n in data.service_map],
        )

        # Step 4: Claude Phase 3 — Causal Reasoning
        logger.info("Phase 3: Causal reasoning...")
        causal_analysis = await self.reasoning.causal_reasoning(
            hypotheses=hypotheses_raw,
            timeline=timeline_dicts,
            metric_anomalies=anomaly_summary.get("metric_anomalies", []),
            error_patterns=anomaly_summary.get("top_error_messages", []),
            error_propagation=service_correlation.get("error_propagation", []),
            service_dependencies=[n.model_dump() for n in data.service_map],
            deployments=deploy_dicts,
        )

        # Step 5: Extract structured hypothesis data
        hypotheses = self._parse_hypotheses(hypotheses_raw)
        root_cause = self._select_root_cause(hypotheses)
        contributing = [h for h in hypotheses if not h.is_root_cause and h.confidence > 0.3]

        affected_services = list(
            {
                span.service
                for span in data.traces
                if span.status == "error"
            }
        )

        # Step 6: Claude Phase 4 — Remediation
        logger.info("Phase 4: Remediation...")
        remediation_text = await self.reasoning.generate_remediation(
            root_cause=root_cause.description,
            contributing_factors="\n".join(f"- {h.description}" for h in contributing),
            affected_services=affected_services,
            causal_chain=causal_analysis,
        )

        remediation_steps = self._parse_remediation(remediation_text)

        # Build final report
        return RCAReport(
            incident=incident,
            summary=self._build_summary(root_cause, affected_services),
            root_cause=root_cause,
            contributing_factors=contributing,
            timeline=timeline,
            affected_services=affected_services,
            blast_radius=self._compute_blast_radius(data, affected_services),
            remediation_steps=remediation_steps,
            confidence_score=root_cause.confidence,
            evidence_chain=root_cause.supporting_evidence,
            raw_reasoning=causal_analysis,
        )

    @staticmethod
    def _flatten_evidence(evidence: list) -> list[str]:
        """Flatten evidence items to strings -- Claude may return dicts or strings."""
        result = []
        for item in evidence:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                # Join all string values from the dict
                parts = [str(v) for v in item.values() if v]
                result.append(" — ".join(parts) if parts else str(item))
            else:
                result.append(str(item))
        return result

    def _parse_hypotheses(self, raw: str) -> list[Hypothesis]:
        """Parse Claude's hypothesis JSON output into structured objects."""
        # Try to extract JSON from the response
        json_match = re.search(r"\{[\s\S]*\}", raw)
        if not json_match:
            logger.warning("Could not parse hypotheses JSON, creating fallback")
            return [
                Hypothesis(
                    id="h1",
                    description=raw[:500],
                    confidence=0.5,
                    supporting_evidence=["Parsed from unstructured reasoning"],
                )
            ]

        try:
            data = json.loads(json_match.group())
            hypotheses_data = data.get("hypotheses", [data])
            return [
                Hypothesis(
                    id=h.get("id", f"h{i}"),
                    description=h.get("description", h.get("hypothesis", "Unknown")),
                    confidence=float(h.get("confidence", h.get("confidence_score", 0.5))),
                    supporting_evidence=self._flatten_evidence(h.get("supporting_evidence", [])),
                    contradicting_evidence=self._flatten_evidence(h.get("contradicting_evidence", [])),
                    is_root_cause=h.get("is_root_cause", False),
                    cascading_from=h.get("cascading_from"),
                )
                for i, h in enumerate(hypotheses_data)
            ]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning("Failed to parse hypotheses: %s", e)
            return [
                Hypothesis(
                    id="h1",
                    description=raw[:500],
                    confidence=0.5,
                    supporting_evidence=["Parsed from unstructured reasoning"],
                )
            ]

    def _select_root_cause(self, hypotheses: list[Hypothesis]) -> Hypothesis:
        """Select the most likely root cause from hypotheses."""
        # Prefer hypotheses explicitly marked as root cause
        root_causes = [h for h in hypotheses if h.is_root_cause]
        if root_causes:
            return max(root_causes, key=lambda h: h.confidence)

        # Otherwise, pick highest confidence
        return max(hypotheses, key=lambda h: h.confidence)

    def _parse_remediation(self, text: str) -> list[str]:
        """Extract remediation steps from Claude's response."""
        steps: list[str] = []
        for line in text.split("\n"):
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith("-") or line.startswith("•")):
                cleaned = re.sub(r"^[\d\.\-\•\*]+\s*", "", line).strip()
                if cleaned:
                    steps.append(cleaned)
        return steps if steps else [text[:500]]

    def _build_summary(self, root_cause: Hypothesis, affected_services: list[str]) -> str:
        """Build a concise summary for the RCA report."""
        svc_str = ", ".join(affected_services[:5])
        if len(affected_services) > 5:
            svc_str += f" and {len(affected_services) - 5} more"
        return (
            f"Root cause identified with {root_cause.confidence:.0%} confidence: "
            f"{root_cause.description}. "
            f"Affected services: {svc_str}."
        )

    def _compute_blast_radius(
        self, data: ObservabilityData, affected_services: list[str]
    ) -> str:
        """Compute and describe the blast radius of the incident."""
        total_services = {n.name for n in data.service_map}
        affected_set = set(affected_services)
        ratio = len(affected_set) / max(len(total_services), 1)

        if ratio > 0.5:
            severity = "Critical"
        elif ratio > 0.2:
            severity = "High"
        elif ratio > 0.05:
            severity = "Medium"
        else:
            severity = "Low"

        return (
            f"{severity} blast radius: {len(affected_set)} of "
            f"{len(total_services)} services affected ({ratio:.0%})"
        )
