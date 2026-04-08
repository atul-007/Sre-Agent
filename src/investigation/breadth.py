"""Breadth phase — signal checklist execution loop."""

from __future__ import annotations

import logging
import time
from typing import Any, Awaitable, Callable, Optional

from config.settings import AgentConfig
from src.claude.prompts import INVESTIGATION_PLANNING_PROMPT
from src.claude.reasoning import ClaudeReasoning
from src.investigation.analysis import AnalysisPhase
from src.investigation.execution import ActionExecutor
from src.investigation.helpers import (
    format_current_hypotheses,
    format_data_summary,
    format_trace_summary,
    is_empty_result,
    merge_data,
    parse_json_response,
)
from src.investigation.rules import (
    calibrate_confidence,
    can_conclude,
    format_signal_coverage,
    get_forced_next_action,
    get_unchecked_signals,
    mark_signals_checked,
)
from src.models.incident import (
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    ObservabilityData,
)

logger = logging.getLogger(__name__)


class BreadthPhase:
    """Executes the breadth-first signal checklist investigation loop."""

    def __init__(
        self,
        executor: ActionExecutor,
        analysis: AnalysisPhase,
        reasoning: ClaudeReasoning,
        config: AgentConfig,
        on_step_complete: Optional[Callable[[InvestigationStep], Awaitable[None]]] = None,
    ) -> None:
        self.executor = executor
        self.analysis = analysis
        self.reasoning = reasoning
        self.config = config
        self.on_step_complete = on_step_complete

    async def run(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
        max_steps: int,
    ) -> bool:
        """Run the breadth-first investigation loop.

        Returns True if concluded (root cause found or max steps reached).
        """
        state.phase = "breadth"

        while not trace.concluded and trace.total_steps < max_steps:
            step_start = time.monotonic()
            step_number = trace.total_steps + 1

            # 1. Ask Claude what to investigate next
            action_spec = await self._plan_next_action(
                incident, trace, accumulated_data, state
            )

            action_str = action_spec.get("action", "conclude")
            try:
                action_type = InvestigationActionType(action_str)
            except ValueError:
                logger.warning("Unknown action %r, concluding", action_str)
                action_type = InvestigationActionType.CONCLUDE

            # Conclusion guard
            if action_type == InvestigationActionType.CONCLUDE:
                is_last_step = trace.total_steps >= max_steps - 1
                ok, reason = can_conclude(
                    state,
                    min_coverage=self.config.min_signal_coverage_to_conclude,
                )
                if ok or is_last_step:
                    trace.concluded = True
                    trace.conclusion_reason = "root_cause_found" if ok else "max_steps_reached"
                    logger.info("Conclusion allowed: %s", reason)
                    break
                else:
                    logger.warning("Premature conclude blocked: %s", reason)
                    unchecked = get_unchecked_signals(state.signal_checklist)
                    if unchecked:
                        action_spec = get_forced_next_action(unchecked[0], incident.service)
                        action_str = action_spec["action"]
                        action_type = InvestigationActionType(action_str)
                        logger.info("Forcing action: %s for signal '%s'", action_str, unchecked[0])
                    else:
                        trace.concluded = True
                        trace.conclusion_reason = "root_cause_found"
                        break

            step = InvestigationStep(
                step_number=step_number,
                action=action_type,
                reason=action_spec.get("reason", ""),
                data_source=action_spec.get("data_source", incident.service),
                query_params=action_spec.get("query_params", {}),
            )

            logger.info(
                "Step %d: %s — %s (source: %s)",
                step_number, action_type.value, step.reason, step.data_source,
            )

            # 2. Execute the action
            raw_data = None
            try:
                raw_data, data_summary = await self.executor.execute(
                    action_type, action_spec.get("query_params", {}), incident
                )
                step.data_summary = data_summary
            except Exception as e:
                logger.warning("Step %d data fetch failed: %s", step_number, e)
                step.data_summary = f"Fetch failed: {e}"

            # Track signal coverage and handle empty data
            state.total_fetches += 1
            empty = is_empty_result(raw_data)

            if empty:
                state.empty_fetches += 1
                state.data_gap_log.append(
                    f"Step {step_number}: {action_type.value} for {step.data_source} returned empty"
                )

                # Smart retry with fallbacks
                retry_data, retry_summary, gap = await self.executor.retry_with_fallbacks(
                    action_type, action_spec.get("query_params", {}), incident
                )
                if not is_empty_result(retry_data):
                    raw_data = retry_data
                    step.data_summary = f"{retry_summary} (after retry)"
                    empty = False
                    logger.info("Step %d: retry succeeded — %s", step_number, retry_summary)
                elif gap:
                    state.data_gaps.append(gap)

            # Mark signals checked with quality scoring
            data_quality = 0.0
            if not empty:
                data_quality = self._compute_data_quality(raw_data)

            mark_signals_checked(
                state.signal_checklist,
                action_type.value,
                step_number,
                data_found=not empty,
                notes=step.data_summary,
                query=action_spec.get("query_params", {}).get("query", ""),
            )
            # Update quality on checked signals
            for signal, check in state.signal_checklist.items():
                if check.step_number == step_number and check.checked:
                    check.data_quality = data_quality

            # 3. Merge into accumulated data
            if raw_data is not None:
                merge_data(accumulated_data, raw_data, action_type)

            # 4. Claude analysis
            findings, hypotheses_str, decision, raw_confidence = await self.analysis.analyze_findings(
                step, raw_data, incident, trace, state
            )
            step.findings = findings
            step.hypotheses = hypotheses_str
            step.decision = decision

            # Calibrate confidence
            calibrated = calibrate_confidence(
                raw_confidence,
                state,
                confidence_cap_sparse=self.config.confidence_cap_on_sparse_data,
                confidence_cap_no_evidence=self.config.confidence_cap_no_direct_evidence,
            )
            step.confidence = calibrated
            if abs(calibrated - raw_confidence) > 0.01:
                logger.info(
                    "Step %d confidence calibrated: %.0f%% → %.0f%%",
                    step_number, raw_confidence * 100, calibrated * 100,
                )

            step.duration_ms = int((time.monotonic() - step_start) * 1000)

            trace.steps.append(step)
            trace.total_steps += 1

            logger.info(
                "Step %d complete: confidence=%.0f%%, decision=%s",
                step_number, calibrated * 100, decision[:80],
            )

            # 5. Notify callback
            if self.on_step_complete:
                try:
                    await self.on_step_complete(step)
                except Exception as e:
                    logger.warning("Step callback failed: %s", e)

            # 6. Check high-confidence conclusion
            if calibrated >= self.config.investigation_confidence_threshold:
                ok, reason = can_conclude(
                    state,
                    min_coverage=self.config.min_signal_coverage_to_conclude,
                )
                if ok:
                    trace.concluded = True
                    trace.conclusion_reason = "root_cause_found"

        return trace.concluded

    # ── Planning ──────────────────────────────────────────────────────

    async def _plan_next_action(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        accumulated_data: ObservabilityData,
        state: InvestigationState,
    ) -> dict:
        """Ask Claude what to investigate next."""
        trace_summary = format_trace_summary(trace)
        data_summary = format_data_summary(accumulated_data)

        if state.hypotheses:
            hypotheses_summary = self.analysis.format_tracked_hypotheses(state)
        else:
            hypotheses_summary = format_current_hypotheses(trace)

        signal_coverage = format_signal_coverage(state.signal_checklist) if state.signal_checklist else ""

        # Include discovered context
        discovered_context = ""
        if state.discovered_context:
            ctx = state.discovered_context
            ctx_parts = []
            if ctx.resolved_namespace:
                ctx_parts.append(f"Resolved namespace: {ctx.resolved_namespace}")
            if ctx.resolved_tags:
                ctx_parts.append(f"Resolved tags: {ctx.resolved_tags}")
            if ctx.dashboard_metrics:
                ctx_parts.append(
                    f"Dashboard metrics (team monitors these): {', '.join(ctx.dashboard_metrics[:15])}"
                )
            if ctx.available_metrics:
                ctx_parts.append(
                    f"Available metrics ({len(ctx.available_metrics)} total): "
                    + ", ".join(ctx.available_metrics[:20])
                )
            if ctx_parts:
                discovered_context = "\n".join(ctx_parts)

        # Include change context
        changes_context = ""
        if state.changes_detected:
            changes_lines = []
            for change in state.changes_detected:
                changes_lines.append(
                    f"  - [{change['type']}] {change.get('description', 'unknown')} "
                    f"({change.get('time_to_incident_minutes', '?')} min before incident)"
                )
            changes_context = "\n**Recent Changes:**\n" + "\n".join(changes_lines)

        prompt = INVESTIGATION_PLANNING_PROMPT.format(
            service=incident.service,
            symptom_type=incident.symptom_type.value,
            start_time=incident.start_time,
            end_time=incident.end_time,
            environment=incident.environment,
            raw_query=incident.raw_query,
            additional_context=(
                (f"\nAdditional context: {incident.additional_context}" if incident.additional_context else "")
                + changes_context
            ),
            step_count=trace.total_steps,
            trace_summary=trace_summary or "No steps taken yet.",
            data_summary=data_summary or "No data collected yet.",
            current_hypotheses=hypotheses_summary or "No hypotheses formed yet.",
            signal_coverage=signal_coverage or "No checklist configured.",
            discovered_context=discovered_context or "No discovery performed yet.",
        )

        response = await self.reasoning.query_dynamic(prompt)
        return parse_json_response(response, fallback={"action": "conclude"})

    # ── Data quality scoring ──────────────────────────────────────────

    @staticmethod
    def _compute_data_quality(raw_data: Any) -> float:
        """Score data quality: 0.0=empty, 0.5=partial, 1.0=substantial."""
        if raw_data is None:
            return 0.0
        if isinstance(raw_data, list):
            if len(raw_data) == 0:
                return 0.0
            if len(raw_data) < 3:
                return 0.5
            return 1.0
        if isinstance(raw_data, dict):
            if not raw_data:
                return 0.0
            return 1.0
        if hasattr(raw_data, "model_dump"):
            return 1.0
        return 0.5
