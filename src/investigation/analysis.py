"""Analysis phase — Claude interpretation of data, hypothesis management, report generation."""

from __future__ import annotations

import logging
from typing import Any, Optional

from config.settings import AgentConfig
from src.claude.prompts import (
    INVESTIGATION_ANALYSIS_PROMPT,
    INVESTIGATION_CONCLUSION_PROMPT,
)
from src.claude.reasoning import ClaudeReasoning
from src.correlation.engine import CorrelationEngine
from src.investigation.helpers import (
    ensure_str_list,
    format_current_hypotheses,
    format_data_summary,
    format_full_trace,
    format_raw_data,
    parse_json_response,
)
from src.investigation.rules import (
    calibrate_confidence,
    format_signal_coverage,
)
from src.models.incident import (
    DataGap,
    Hypothesis,
    HypothesisStatus,
    IncidentQuery,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    ObservabilityData,
    RCAReport,
    TrackedHypothesis,
)

logger = logging.getLogger(__name__)


class AnalysisPhase:
    """Handles Claude-based analysis of investigation data and hypothesis management."""

    def __init__(
        self,
        reasoning: ClaudeReasoning,
        correlation: CorrelationEngine,
        config: AgentConfig,
    ) -> None:
        self.reasoning = reasoning
        self.correlation = correlation
        self.config = config

    # ── Step analysis ─────────────────────────────────────────────────

    async def analyze_findings(
        self,
        step: InvestigationStep,
        raw_data: Any,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
    ) -> tuple[str, list[str], str, float]:
        """Ask Claude to analyze the data from a step."""
        data_content = format_raw_data(raw_data, step.action)

        previous_findings = "\n".join(
            f"Step {s.step_number}: {s.findings}" for s in trace.steps
        ) or "No previous findings."

        if state.hypotheses:
            current_hypotheses = self.format_tracked_hypotheses(state)
        else:
            current_hypotheses = format_current_hypotheses(trace) or "No hypotheses yet."

        prompt = INVESTIGATION_ANALYSIS_PROMPT.format(
            step_number=step.step_number,
            action=step.action.value,
            reason=step.reason,
            data_source=step.data_source,
            data_content=data_content,
            previous_findings=previous_findings,
            current_hypotheses=current_hypotheses,
        )

        response = await self.reasoning.query_dynamic(prompt)
        parsed = parse_json_response(response, fallback={
            "findings": response[:500],
            "hypothesis_updates": [],
            "hypotheses": [],
            "decision": "Continue investigation",
            "confidence": 0.0,
        })

        # Merge structured hypothesis updates into state
        self.merge_hypotheses(parsed, step.step_number, state)

        # Build legacy hypotheses list for backward compat
        hypotheses_str = parsed.get("hypotheses", [])
        if not hypotheses_str and state.hypotheses:
            hypotheses_str = [
                f"[{h.status.value.upper()}] {h.description} ({h.confidence:.0%})"
                for h in state.hypotheses.values()
            ]

        return (
            parsed.get("findings", ""),
            hypotheses_str,
            parsed.get("decision", ""),
            min(max(float(parsed.get("confidence", 0.0)), 0.0), 1.0),
        )

    # ── Report generation ─────────────────────────────────────────────

    async def generate_final_report(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        accumulated_data: ObservabilityData,
        state: InvestigationState,
    ) -> RCAReport:
        """Generate the final RCA report from the investigation trace."""
        full_trace_str = format_full_trace(trace)
        data_summary = format_data_summary(accumulated_data)

        extra_context = ""
        if state:
            extra_context = (
                f"\n\n**Signal Coverage:**\n{format_signal_coverage(state.signal_checklist)}"
                f"\n\n**Tracked Hypotheses:**\n{self.format_tracked_hypotheses(state)}"
                f"\n\n**Data Gaps:** {len(state.data_gap_log)} empty fetches out of "
                f"{state.total_fetches} total"
            )

        prompt = INVESTIGATION_CONCLUSION_PROMPT.format(
            step_count=trace.total_steps,
            incident_summary=(
                f"Service: {incident.service}, Symptom: {incident.symptom_type.value}, "
                f"Time: {incident.start_time} to {incident.end_time}, "
                f"Query: {incident.raw_query}"
                + extra_context
            ),
            full_trace=full_trace_str,
            all_data_summary=data_summary,
        )

        response = await self.reasoning.query_dynamic(prompt)
        parsed = parse_json_response(response, fallback={})

        # Build root cause hypothesis
        root_cause_data = parsed.get("root_cause", {})
        rc_supporting = ensure_str_list(root_cause_data.get("supporting_evidence", []))
        rc_contradicting = ensure_str_list(root_cause_data.get("contradicting_evidence", []))
        if state.hypotheses:
            top_hyp = max(state.hypotheses.values(), key=lambda h: h.confidence, default=None)
            if top_hyp:
                rc_supporting = list(set(rc_supporting + top_hyp.supporting_evidence))
                rc_contradicting = list(set(rc_contradicting + top_hyp.contradicting_evidence))

        root_cause = Hypothesis(
            id="h1",
            description=root_cause_data.get("description", "Unable to determine root cause"),
            confidence=min(max(float(root_cause_data.get("confidence", 0.5)), 0.0), 1.0),
            supporting_evidence=rc_supporting,
            contradicting_evidence=rc_contradicting,
            is_root_cause=True,
        )

        # Calibrate final confidence
        root_cause.confidence = calibrate_confidence(
            root_cause.confidence,
            state,
            confidence_cap_sparse=self.config.confidence_cap_on_sparse_data,
            confidence_cap_no_evidence=self.config.confidence_cap_no_direct_evidence,
        )

        contributing = []
        for i, factor in enumerate(parsed.get("contributing_factors", [])):
            if isinstance(factor, dict):
                contributing.append(Hypothesis(
                    id=f"cf{i+1}",
                    description=factor.get("description", ""),
                    confidence=min(max(float(factor.get("confidence", 0.3)), 0.0), 1.0),
                ))
            elif isinstance(factor, str):
                contributing.append(Hypothesis(
                    id=f"cf{i+1}",
                    description=factor,
                    confidence=0.3,
                ))

        timeline = self.correlation.build_timeline(incident, accumulated_data)

        # v3: Determine report type and populate new fields
        report_type = "rca" if root_cause.confidence >= 0.30 else "investigation_summary"

        # Build signal quality summary
        signal_quality_summary = {}
        for signal, check in state.signal_checklist.items():
            signal_quality_summary[signal] = {
                "checked": check.checked,
                "data_found": check.data_found,
                "data_quality": check.data_quality,
                "queries_attempted": check.queries_attempted,
            }

        # v3: Get recommended next steps for low-confidence investigations
        recommended_next_steps: list[str] = []
        if root_cause.confidence < 0.50:
            recommended_next_steps = self._build_next_steps(state, incident)

        return RCAReport(
            incident=incident,
            summary=parsed.get("summary", root_cause.description),
            root_cause=root_cause,
            contributing_factors=contributing,
            timeline=timeline,
            affected_services=parsed.get("affected_services", [incident.service]),
            blast_radius=parsed.get("blast_radius", "Unknown"),
            remediation_steps=parsed.get("remediation_steps", []),
            confidence_score=root_cause.confidence,
            evidence_chain=parsed.get("evidence_chain", root_cause.supporting_evidence),
            raw_reasoning=parsed.get("causal_chain", ""),
            investigation_trace=trace,
            # v3 fields
            data_gaps=list(state.data_gaps),
            signal_quality_summary=signal_quality_summary,
            report_type=report_type,
            recommended_next_steps=recommended_next_steps,
        )

    # ── Hypothesis management ─────────────────────────────────────────

    def merge_hypotheses(self, parsed: dict, step_number: int, state: InvestigationState) -> None:
        """Merge Claude's hypothesis updates into the tracked state."""
        # Try structured format first (v2 prompt)
        updates = parsed.get("hypothesis_updates", [])
        if updates and isinstance(updates, list):
            for update in updates:
                if not isinstance(update, dict):
                    continue
                h_id = update.get("id", "")
                description = update.get("description", "")

                matched_id = self._find_matching_hypothesis(h_id, description, state)

                if matched_id:
                    h = state.hypotheses[matched_id]
                    status_str = update.get("status", h.status.value)
                    try:
                        h.status = HypothesisStatus(status_str)
                    except ValueError:
                        pass
                    if "confidence" in update:
                        h.confidence = min(max(float(update["confidence"]), 0.0), 1.0)
                    if description and len(description) > len(h.description):
                        h.description = description
                    h.supporting_evidence.extend(update.get("supporting_evidence", []))
                    h.contradicting_evidence.extend(update.get("contradicting_evidence", []))
                    h.last_updated_step = step_number
                else:
                    new_id = self._next_hypothesis_id(state)
                    status_str = update.get("status", "pending")
                    try:
                        status = HypothesisStatus(status_str)
                    except ValueError:
                        status = HypothesisStatus.PENDING

                    state.hypotheses[new_id] = TrackedHypothesis(
                        id=new_id,
                        description=description,
                        status=status,
                        confidence=min(max(float(update.get("confidence", 0.0)), 0.0), 1.0),
                        supporting_evidence=update.get("supporting_evidence", []),
                        contradicting_evidence=update.get("contradicting_evidence", []),
                        created_at_step=step_number,
                        last_updated_step=step_number,
                    )
            return

        # Fallback: parse old-style hypotheses list (list[str])
        old_hyps = parsed.get("hypotheses", [])
        if old_hyps and isinstance(old_hyps, list):
            for i, hyp_str in enumerate(old_hyps):
                if not isinstance(hyp_str, str):
                    continue
                status = HypothesisStatus.PENDING
                lower = hyp_str.lower()
                if "confirmed" in lower:
                    status = HypothesisStatus.CONFIRMED
                elif "rejected" in lower:
                    status = HypothesisStatus.REJECTED
                elif "investigating" in lower or "unvalidated" in lower:
                    status = HypothesisStatus.INVESTIGATING
                elif "inconclusive" in lower:
                    status = HypothesisStatus.INCONCLUSIVE

                matched_id = self._find_matching_hypothesis("", hyp_str[:200], state)
                if matched_id:
                    state.hypotheses[matched_id].status = status
                    state.hypotheses[matched_id].description = hyp_str[:200]
                    state.hypotheses[matched_id].last_updated_step = step_number
                else:
                    new_id = self._next_hypothesis_id(state)
                    state.hypotheses[new_id] = TrackedHypothesis(
                        id=new_id,
                        description=hyp_str[:200],
                        status=status,
                        created_at_step=step_number,
                        last_updated_step=step_number,
                    )

    @staticmethod
    def _find_matching_hypothesis(
        h_id: str, description: str, state: InvestigationState
    ) -> str | None:
        """Find an existing hypothesis matching by ID or description similarity."""
        if h_id and h_id != "new" and h_id in state.hypotheses:
            return h_id

        if description:
            desc_lower = description.lower()
            desc_words = set(desc_lower.split())
            stop_words = {
                "the", "a", "an", "is", "are", "was", "were", "be", "been",
                "in", "on", "at", "to", "for", "of", "with", "by", "from",
                "may", "might", "could", "would", "should", "can", "will",
                "this", "that", "these", "those", "it", "its", "and", "or",
            }
            desc_keywords = desc_words - stop_words

            best_match = None
            best_overlap = 0

            for existing_id, existing in state.hypotheses.items():
                existing_lower = existing.description.lower()
                existing_words = set(existing_lower.split()) - stop_words

                if not existing_words or not desc_keywords:
                    continue

                overlap = len(desc_keywords & existing_words)
                min_size = min(len(desc_keywords), len(existing_words))
                if min_size > 0 and overlap / min_size > 0.5 and overlap > best_overlap:
                    best_match = existing_id
                    best_overlap = overlap

            if best_match:
                return best_match

        return None

    @staticmethod
    def _next_hypothesis_id(state: InvestigationState) -> str:
        """Generate a unique hypothesis ID."""
        max_num = 0
        for h_id in state.hypotheses:
            if h_id.startswith("h") and h_id[1:].isdigit():
                max_num = max(max_num, int(h_id[1:]))
        return f"h{max_num + 1}"

    # ── Formatting ────────────────────────────────────────────────────

    @staticmethod
    def format_tracked_hypotheses(state: InvestigationState) -> str:
        """Format tracked hypotheses for prompts."""
        if not state.hypotheses:
            return ""
        lines = []
        for h in sorted(state.hypotheses.values(), key=lambda x: -x.confidence):
            lines.append(
                f"- [{h.status.value.upper()}] {h.id}: {h.description} "
                f"(confidence: {h.confidence:.0%})"
            )
            for ev in h.supporting_evidence[-3:]:
                lines.append(f"    (+) {ev}")
            for ev in h.contradicting_evidence[-3:]:
                lines.append(f"    (-) {ev}")
        return "\n".join(lines)

    # ── Next steps for low-confidence reports ─────────────────────────

    @staticmethod
    def _build_next_steps(state: InvestigationState, incident: IncidentQuery) -> list[str]:
        """Build recommended next steps based on data gaps and unchecked signals."""
        steps: list[str] = []

        # From data gaps
        for gap in state.data_gaps:
            if gap.recommendation:
                steps.append(gap.recommendation)

        # From unchecked signals
        for signal, check in state.signal_checklist.items():
            if not check.checked:
                steps.append(f"Investigate signal '{signal}' which was not checked during this investigation.")
            elif check.checked and not check.data_found:
                steps.append(f"Signal '{signal}' returned no data — verify instrumentation for {incident.service}.")

        # Generic depth suggestions
        if state.hypotheses:
            top = max(state.hypotheses.values(), key=lambda h: h.confidence, default=None)
            if top and top.confidence > 0.2:
                steps.append(
                    f"Deep-dive into leading hypothesis: '{top.description}' — "
                    f"check runtime metrics (GC, heap, goroutines) for the affected component."
                )

        return steps[:8]  # Cap at 8 recommendations
