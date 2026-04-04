"""Dynamic investigation engine v2 — hypothesis-driven debugging with signal checklists,
smart retry, and calibrated confidence.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Optional

from config.settings import AgentConfig
from src.claude.prompts import (
    INVESTIGATION_ANALYSIS_PROMPT,
    INVESTIGATION_CONCLUSION_PROMPT,
    INVESTIGATION_PLANNING_PROMPT,
)
from src.claude.reasoning import ClaudeReasoning
from src.correlation.engine import CorrelationEngine
from src.datadog.client import DatadogClient
from src.investigation.rules import (
    ACTION_TO_SIGNALS,
    TAG_FALLBACKS,
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
    Hypothesis,
    HypothesisStatus,
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    ObservabilityData,
    RCAReport,
    TrackedHypothesis,
)

logger = logging.getLogger(__name__)


class InvestigationEngine:
    """Dynamic, hypothesis-driven investigation engine v2.

    Improvements over v1:
    - Structured hypothesis tracking across steps
    - Mandatory signal checklists per symptom type
    - Smart retry with tag fallbacks on empty data
    - Programmatic confidence calibration
    - Conclusion guards — won't stop until signals are covered
    """

    def __init__(
        self,
        dd_client: DatadogClient,
        reasoning: ClaudeReasoning,
        correlation: CorrelationEngine,
        config: AgentConfig,
        on_step_complete: Optional[Callable[[InvestigationStep], Awaitable[None]]] = None,
        max_steps: int = 15,
        confidence_threshold: float = 0.85,
    ) -> None:
        self.dd_client = dd_client
        self.reasoning = reasoning
        self.correlation = correlation
        self.config = config
        self.on_step_complete = on_step_complete
        self.max_steps = max_steps
        self.confidence_threshold = confidence_threshold
        self.state: Optional[InvestigationState] = None

    async def investigate(self, incident: IncidentQuery) -> RCAReport:
        """Run a dynamic, step-by-step investigation with v2 enhancements."""
        self.reasoning.reset_dynamic_history()
        trace = InvestigationTrace()
        accumulated_data = ObservabilityData()
        start_time = time.monotonic()

        # v2: Initialize investigation state with signal checklist
        self.state = InvestigationState(
            signal_checklist=build_signal_checklist(incident.symptom_type.value),
        )

        logger.info("Starting dynamic investigation for %s", incident.service)
        logger.info(
            "Signal checklist: %s",
            ", ".join(self.state.signal_checklist.keys()),
        )

        async with self.dd_client:
            while not trace.concluded and trace.total_steps < self.max_steps:
                step_start = time.monotonic()
                step_number = trace.total_steps + 1

                # 1. Ask Claude what to investigate next
                action_spec = await self._plan_next_action(
                    incident, trace, accumulated_data
                )

                action_str = action_spec.get("action", "conclude")
                try:
                    action_type = InvestigationActionType(action_str)
                except ValueError:
                    logger.warning("Unknown action %r, concluding", action_str)
                    action_type = InvestigationActionType.CONCLUDE

                # v2: Conclude guard — check if we CAN conclude
                if action_type == InvestigationActionType.CONCLUDE:
                    is_last_step = trace.total_steps >= self.max_steps - 1
                    ok, reason = can_conclude(
                        self.state,
                        min_coverage=self.config.min_signal_coverage_to_conclude,
                    )
                    if ok or is_last_step:
                        trace.concluded = True
                        trace.conclusion_reason = "root_cause_found" if ok else "max_steps_reached"
                        logger.info("Conclusion allowed: %s", reason)
                        break
                    else:
                        # Override Claude's premature conclude
                        logger.warning("Premature conclude blocked: %s", reason)
                        unchecked = get_unchecked_signals(self.state.signal_checklist)
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

                # 2. Execute the action (fetch data from Datadog)
                raw_data = None
                try:
                    raw_data, data_summary = await self._execute_action(
                        action_type, action_spec.get("query_params", {}), incident
                    )
                    step.data_summary = data_summary
                except Exception as e:
                    logger.warning("Step %d data fetch failed: %s", step_number, e)
                    step.data_summary = f"Fetch failed: {e}"

                # v2: Track signal coverage and handle empty data
                self.state.total_fetches += 1
                is_empty = self._is_empty_result(raw_data)

                if is_empty:
                    self.state.empty_fetches += 1
                    self.state.data_gap_log.append(
                        f"Step {step_number}: {action_type.value} for {step.data_source} returned empty"
                    )

                    # v2: Smart retry with tag fallbacks
                    retry_data, retry_summary = await self._retry_with_fallbacks(
                        action_type, action_spec.get("query_params", {}), incident
                    )
                    if not self._is_empty_result(retry_data):
                        raw_data = retry_data
                        step.data_summary = f"{retry_summary} (after retry)"
                        is_empty = False
                        logger.info("Step %d: retry succeeded — %s", step_number, retry_summary)

                # v2: Mark signals checked
                mark_signals_checked(
                    self.state.signal_checklist,
                    action_type.value,
                    step_number,
                    data_found=not is_empty,
                    notes=step.data_summary,
                )

                # 3. Merge into accumulated data
                if raw_data is not None:
                    self._merge_data(accumulated_data, raw_data, action_type)

                # 4. Ask Claude to analyze the findings
                findings, hypotheses_str, decision, raw_confidence = await self._analyze_findings(
                    step, raw_data, incident, trace
                )
                step.findings = findings
                step.hypotheses = hypotheses_str
                step.decision = decision

                # v2: Calibrate confidence
                calibrated = calibrate_confidence(
                    raw_confidence,
                    self.state,
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

                # 5. Notify callback (for live Slack updates)
                if self.on_step_complete:
                    try:
                        await self.on_step_complete(step)
                    except Exception as e:
                        logger.warning("Step callback failed: %s", e)

                # 6. Check if calibrated confidence is high enough to conclude
                if calibrated >= self.confidence_threshold:
                    ok, reason = can_conclude(
                        self.state,
                        min_coverage=self.config.min_signal_coverage_to_conclude,
                    )
                    if ok:
                        trace.concluded = True
                        trace.conclusion_reason = "root_cause_found"

        if not trace.concluded:
            trace.concluded = True
            trace.conclusion_reason = "max_steps_reached"

        trace.total_duration_ms = int((time.monotonic() - start_time) * 1000)

        # v2: Store investigation state in trace for report rendering
        trace.investigation_state = self.state

        logger.info(
            "Investigation concluded: %d steps, %dms, reason=%s, "
            "empty_fetches=%d/%d, hypotheses=%d",
            trace.total_steps, trace.total_duration_ms, trace.conclusion_reason,
            self.state.empty_fetches, self.state.total_fetches,
            len(self.state.hypotheses),
        )

        return await self._generate_final_report(incident, trace, accumulated_data)

    # ── Planning ──────────────────────────────────────────────────────

    async def _plan_next_action(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        accumulated_data: ObservabilityData,
    ) -> dict:
        """Ask Claude what to investigate next."""
        trace_summary = self._format_trace_summary(trace)
        data_summary = self._format_data_summary(accumulated_data)

        # v2: Use tracked hypotheses instead of scraping from steps
        if self.state and self.state.hypotheses:
            hypotheses_summary = self._format_tracked_hypotheses()
        else:
            hypotheses_summary = self._format_current_hypotheses(trace)

        # v2: Signal coverage for the planning prompt
        signal_coverage = ""
        if self.state:
            signal_coverage = format_signal_coverage(self.state.signal_checklist)

        prompt = INVESTIGATION_PLANNING_PROMPT.format(
            service=incident.service,
            symptom_type=incident.symptom_type.value,
            start_time=incident.start_time,
            end_time=incident.end_time,
            environment=incident.environment,
            raw_query=incident.raw_query,
            additional_context=(
                f"\nAdditional context: {incident.additional_context}"
                if incident.additional_context else ""
            ),
            step_count=trace.total_steps,
            trace_summary=trace_summary or "No steps taken yet.",
            data_summary=data_summary or "No data collected yet.",
            current_hypotheses=hypotheses_summary or "No hypotheses formed yet.",
            signal_coverage=signal_coverage or "No checklist configured.",
        )

        response = await self.reasoning.query_dynamic(prompt)
        return self._parse_json_response(response, fallback={"action": "conclude"})

    # ── Execution ─────────────────────────────────────────────────────

    async def _execute_action(
        self,
        action_type: InvestigationActionType,
        params: dict,
        incident: IncidentQuery,
    ) -> tuple[Any, str]:
        """Execute a Datadog fetch based on action type. Returns (raw_data, summary)."""
        service = params.get("service", incident.service)
        start = incident.start_time
        end = incident.end_time

        if action_type == InvestigationActionType.FETCH_METRICS:
            data = await self.dd_client.fetch_service_metrics(service, start, end)
            summary = f"{len(data)} metric series for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_LOGS:
            data = await self.dd_client.fetch_service_logs(service, start, end)
            summary = f"{len(data)} log entries for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_TRACES:
            data = await self.dd_client.fetch_service_traces(service, start, end)
            summary = f"{len(data)} trace spans for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_SERVICE_MAP:
            data = await self.dd_client.get_service_dependencies(service, start, end)
            deps = len(data.dependencies) + len(data.dependents)
            summary = f"Service map: {deps} dependencies for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_EVENTS:
            tags = [f"service:{service}"]
            data = await self.dd_client.get_events(start, end, tags=tags)
            summary = f"{len(data)} events for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_DEPLOYMENTS:
            data = await self.dd_client.get_deployment_events(service, start, end)
            summary = f"{len(data)} deployment events for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_MONITORS:
            data = await self.dd_client.get_triggered_monitors(service)
            summary = f"{len(data)} triggered monitors for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_INFRA_METRICS:
            tags = params.get("tags", incident.source_tags)
            if not tags:
                tags = {"service": service}
            data = await self.dd_client.fetch_infra_metrics(tags, start, end)
            summary = f"{len(data)} infra metric series"
            return data, summary

        elif action_type == InvestigationActionType.QUERY_CUSTOM_METRIC:
            query = params.get("query", "")
            if not query:
                return [], "No query specified"
            data = await self.dd_client.query_metrics(query, start, end)
            summary = f"Custom metric query: {len(data)} series"
            return data, summary

        elif action_type == InvestigationActionType.SEARCH_LOGS_CUSTOM:
            query = params.get("query", f"service:{service}")
            data = await self.dd_client.search_logs(query, start, end)
            summary = f"Custom log search: {len(data)} entries"
            return data, summary

        elif action_type == InvestigationActionType.SEARCH_TRACES_CUSTOM:
            query = params.get("query", f"service:{service}")
            data = await self.dd_client.search_traces(query, start, end)
            summary = f"Custom trace search: {len(data)} spans"
            return data, summary

        elif action_type == InvestigationActionType.CORRELATE_SIGNALS:
            try:
                timeline = self.correlation.build_timeline(incident, accumulated_data)
            except TypeError:
                timeline = []
            service_corr = self.correlation.correlate_services(accumulated_data)
            anomaly_summary = self.correlation.compute_anomaly_summary(accumulated_data)
            data = {
                "timeline_events": len(timeline),
                "anomaly_summary": anomaly_summary,
                "service_correlation": service_corr,
            }
            summary = f"Correlation: {len(timeline)} timeline events"
            return data, summary

        elif action_type == InvestigationActionType.EXPAND_SCOPE:
            data = await self.dd_client.fetch_service_metrics(service, start, end)
            logs = await self.dd_client.fetch_service_logs(service, start, end)
            summary = f"Expanded to {service}: {len(data)} metrics, {len(logs)} logs"
            return {"metrics": data, "logs": logs}, summary

        return None, "Unknown action"

    # ── Smart Retry ──────────────────────────────────────────────────

    async def _retry_with_fallbacks(
        self,
        action_type: InvestigationActionType,
        params: dict,
        incident: IncidentQuery,
    ) -> tuple[Any, str]:
        """Retry a failed/empty fetch with alternative tags and expanded time window.

        Returns (data, summary). Data may still be empty if all retries fail.
        Retries don't count as investigation steps.
        """
        max_retries = self.config.max_retry_attempts

        # Only retry data-fetching actions (not correlate, analyze, conclude)
        retryable = {
            InvestigationActionType.FETCH_METRICS,
            InvestigationActionType.FETCH_LOGS,
            InvestigationActionType.FETCH_TRACES,
            InvestigationActionType.FETCH_INFRA_METRICS,
            InvestigationActionType.FETCH_EVENTS,
            InvestigationActionType.FETCH_DEPLOYMENTS,
            InvestigationActionType.FETCH_MONITORS,
            InvestigationActionType.QUERY_CUSTOM_METRIC,
            InvestigationActionType.SEARCH_LOGS_CUSTOM,
            InvestigationActionType.SEARCH_TRACES_CUSTOM,
        }
        if action_type not in retryable:
            return None, "Not retryable"

        # Strategy 1: Try alternative tag combinations
        original_tags = params.get("tags", incident.source_tags) or {"service": incident.service}
        fallback_tags_list = get_tag_fallbacks(original_tags)

        for i, alt_tags in enumerate(fallback_tags_list[:max_retries]):
            try:
                alt_params = dict(params)
                alt_params["tags"] = alt_tags
                data, summary = await self._execute_action(action_type, alt_params, incident)
                if not self._is_empty_result(data):
                    self.state.data_gap_log.append(
                        f"  Retry {i+1} succeeded with tags: {alt_tags}"
                    )
                    return data, summary
                self.state.data_gap_log.append(
                    f"  Retry {i+1} with tags {alt_tags}: still empty"
                )
            except Exception as e:
                self.state.data_gap_log.append(f"  Retry {i+1} failed: {e}")

        # Strategy 2: Expand time window
        expansion = self.config.time_window_expansion_factor
        expanded_start = incident.start_time - timedelta(
            seconds=(incident.end_time - incident.start_time).total_seconds() * (expansion - 1)
        )
        try:
            # Create a temporary modified incident for the expanded window
            expanded_params = dict(params)
            # We modify start/end via a temp incident — but _execute_action reads from incident
            # So we use a custom query approach for metrics
            if action_type in (
                InvestigationActionType.FETCH_INFRA_METRICS,
                InvestigationActionType.QUERY_CUSTOM_METRIC,
            ):
                query = params.get("query", "")
                if query:
                    data = await self.dd_client.query_metrics(query, expanded_start, incident.end_time)
                    if not self._is_empty_result(data):
                        self.state.data_gap_log.append(
                            f"  Expanded time window retry succeeded ({expansion}x)"
                        )
                        return data, f"Custom metric query (expanded window): {len(data)} series"
        except Exception as e:
            self.state.data_gap_log.append(f"  Expanded window retry failed: {e}")

        return None, "All retries exhausted"

    # ── Analysis ──────────────────────────────────────────────────────

    async def _analyze_findings(
        self,
        step: InvestigationStep,
        raw_data: Any,
        incident: IncidentQuery,
        trace: InvestigationTrace,
    ) -> tuple[str, list[str], str, float]:
        """Ask Claude to analyze the data from a step."""
        data_content = self._format_raw_data(raw_data, step.action)

        previous_findings = "\n".join(
            f"Step {s.step_number}: {s.findings}" for s in trace.steps
        ) or "No previous findings."

        # v2: Use tracked hypotheses for context
        if self.state and self.state.hypotheses:
            current_hypotheses = self._format_tracked_hypotheses()
        else:
            current_hypotheses = self._format_current_hypotheses(trace) or "No hypotheses yet."

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
        parsed = self._parse_json_response(response, fallback={
            "findings": response[:500],
            "hypothesis_updates": [],
            "hypotheses": [],
            "decision": "Continue investigation",
            "confidence": 0.0,
        })

        # v2: Merge structured hypothesis updates into state
        self._merge_hypotheses(parsed, step.step_number)

        # Build legacy hypotheses list for backward compat
        hypotheses_str = parsed.get("hypotheses", [])
        if not hypotheses_str and self.state:
            hypotheses_str = [
                f"[{h.status.value.upper()}] {h.description} ({h.confidence:.0%})"
                for h in self.state.hypotheses.values()
            ]

        return (
            parsed.get("findings", ""),
            hypotheses_str,
            parsed.get("decision", ""),
            min(max(float(parsed.get("confidence", 0.0)), 0.0), 1.0),
        )

    # ── Hypothesis Management ─────────────────────────────────────────

    def _merge_hypotheses(self, parsed: dict, step_number: int) -> None:
        """Merge Claude's hypothesis updates into the tracked state."""
        if not self.state:
            return

        # Try structured format first (v2 prompt)
        updates = parsed.get("hypothesis_updates", [])
        if updates and isinstance(updates, list):
            for update in updates:
                if not isinstance(update, dict):
                    continue
                h_id = update.get("id", "")
                if h_id == "new" or h_id not in self.state.hypotheses:
                    # Create new hypothesis
                    new_id = h_id if h_id != "new" else f"h{len(self.state.hypotheses) + 1}"
                    status_str = update.get("status", "pending")
                    try:
                        status = HypothesisStatus(status_str)
                    except ValueError:
                        status = HypothesisStatus.PENDING

                    self.state.hypotheses[new_id] = TrackedHypothesis(
                        id=new_id,
                        description=update.get("description", ""),
                        status=status,
                        confidence=min(max(float(update.get("confidence", 0.0)), 0.0), 1.0),
                        supporting_evidence=update.get("supporting_evidence", []),
                        contradicting_evidence=update.get("contradicting_evidence", []),
                        created_at_step=step_number,
                        last_updated_step=step_number,
                    )
                else:
                    # Update existing hypothesis
                    h = self.state.hypotheses[h_id]
                    status_str = update.get("status", h.status.value)
                    try:
                        h.status = HypothesisStatus(status_str)
                    except ValueError:
                        pass
                    if "confidence" in update:
                        h.confidence = min(max(float(update["confidence"]), 0.0), 1.0)
                    h.supporting_evidence.extend(update.get("supporting_evidence", []))
                    h.contradicting_evidence.extend(update.get("contradicting_evidence", []))
                    h.last_updated_step = step_number
            return

        # Fallback: parse old-style hypotheses list (list[str])
        old_hyps = parsed.get("hypotheses", [])
        if old_hyps and isinstance(old_hyps, list):
            for i, hyp_str in enumerate(old_hyps):
                if not isinstance(hyp_str, str):
                    continue
                h_id = f"h{i + 1}"
                # Try to detect status from text
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

                if h_id in self.state.hypotheses:
                    self.state.hypotheses[h_id].status = status
                    self.state.hypotheses[h_id].description = hyp_str[:200]
                    self.state.hypotheses[h_id].last_updated_step = step_number
                else:
                    self.state.hypotheses[h_id] = TrackedHypothesis(
                        id=h_id,
                        description=hyp_str[:200],
                        status=status,
                        created_at_step=step_number,
                        last_updated_step=step_number,
                    )

    # ── Report Generation ─────────────────────────────────────────────

    async def _generate_final_report(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        accumulated_data: ObservabilityData,
    ) -> RCAReport:
        """Generate the final RCA report from the investigation trace."""
        full_trace = self._format_full_trace(trace)
        data_summary = self._format_data_summary(accumulated_data)

        # v2: Include signal coverage and hypothesis state in conclusion prompt
        extra_context = ""
        if self.state:
            extra_context = (
                f"\n\n**Signal Coverage:**\n{format_signal_coverage(self.state.signal_checklist)}"
                f"\n\n**Tracked Hypotheses:**\n{self._format_tracked_hypotheses()}"
                f"\n\n**Data Gaps:** {len(self.state.data_gap_log)} empty fetches out of "
                f"{self.state.total_fetches} total"
            )

        prompt = INVESTIGATION_CONCLUSION_PROMPT.format(
            step_count=trace.total_steps,
            incident_summary=(
                f"Service: {incident.service}, Symptom: {incident.symptom_type.value}, "
                f"Time: {incident.start_time} to {incident.end_time}, "
                f"Query: {incident.raw_query}"
                + extra_context
            ),
            full_trace=full_trace,
            all_data_summary=data_summary,
        )

        response = await self.reasoning.query_dynamic(prompt)
        parsed = self._parse_json_response(response, fallback={})

        # Build the report — v2: enrich from tracked hypotheses
        root_cause_data = parsed.get("root_cause", {})

        # Prefer tracked hypothesis evidence if available
        rc_supporting = self._ensure_str_list(root_cause_data.get("supporting_evidence", []))
        rc_contradicting = self._ensure_str_list(root_cause_data.get("contradicting_evidence", []))
        if self.state and self.state.hypotheses:
            top_hyp = max(self.state.hypotheses.values(), key=lambda h: h.confidence, default=None)
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

        # v2: Calibrate final report confidence
        if self.state:
            root_cause.confidence = calibrate_confidence(
                root_cause.confidence,
                self.state,
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

        # Build timeline from correlation (handle tz-aware/naive mismatch)
        try:
            timeline = self.correlation.build_timeline(incident, accumulated_data)
        except TypeError:
            logger.warning("Timeline build failed (datetime tz mismatch), skipping")
            timeline = []

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
        )

    # ── Formatting Helpers ────────────────────────────────────────────

    def _format_tracked_hypotheses(self) -> str:
        """Format tracked hypotheses for prompts."""
        if not self.state or not self.state.hypotheses:
            return ""
        lines = []
        for h in sorted(self.state.hypotheses.values(), key=lambda x: -x.confidence):
            lines.append(
                f"- [{h.status.value.upper()}] {h.id}: {h.description} "
                f"(confidence: {h.confidence:.0%})"
            )
            for ev in h.supporting_evidence[-3:]:
                lines.append(f"    (+) {ev}")
            for ev in h.contradicting_evidence[-3:]:
                lines.append(f"    (-) {ev}")
        return "\n".join(lines)

    @staticmethod
    def _is_empty_result(raw_data: Any) -> bool:
        """Check if fetch result is effectively empty."""
        if raw_data is None:
            return True
        if isinstance(raw_data, list) and len(raw_data) == 0:
            return True
        if isinstance(raw_data, dict) and not raw_data:
            return True
        return False

    @staticmethod
    def _parse_json_response(response: str, fallback: dict) -> dict:
        """Extract JSON from Claude's response."""
        json_match = re.search(r"\{[\s\S]*\}", response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        logger.warning("Failed to parse JSON from response, using fallback")
        return fallback

    @staticmethod
    def _ensure_str_list(items: list) -> list[str]:
        """Ensure all items in a list are strings."""
        result = []
        for item in items:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                parts = [str(v) for v in item.values() if v]
                result.append(" — ".join(parts) if parts else str(item))
            else:
                result.append(str(item))
        return result

    @staticmethod
    def _format_trace_summary(trace: InvestigationTrace) -> str:
        """Format trace steps for the planning prompt."""
        if not trace.steps:
            return ""
        lines = []
        for s in trace.steps:
            lines.append(
                f"Step {s.step_number}: [{s.action.value}] {s.data_source} — "
                f"{s.findings[:150]}... (confidence: {s.confidence:.0%})"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_current_hypotheses(trace: InvestigationTrace) -> str:
        """Get the latest hypotheses from the trace (legacy fallback)."""
        for step in reversed(trace.steps):
            if step.hypotheses:
                return "\n".join(f"- {h}" for h in step.hypotheses)
        return ""

    @staticmethod
    def _format_data_summary(data: ObservabilityData) -> str:
        """Compact summary of all accumulated data."""
        parts = []
        if data.metrics:
            parts.append(f"{len(data.metrics)} metric series")
        if data.logs:
            errors = sum(1 for l in data.logs if l.status == "error")
            parts.append(f"{len(data.logs)} logs ({errors} errors)")
        if data.traces:
            err_traces = sum(1 for t in data.traces if t.status == "error")
            parts.append(f"{len(data.traces)} trace spans ({err_traces} errors)")
        if data.service_map:
            parts.append(f"{len(data.service_map)} service nodes")
        if data.events:
            parts.append(f"{len(data.events)} events")
        if data.monitors:
            parts.append(f"{len(data.monitors)} monitors")
        if data.deployment_events:
            parts.append(f"{len(data.deployment_events)} deployments")
        return ", ".join(parts) if parts else "No data collected"

    @staticmethod
    def _format_full_trace(trace: InvestigationTrace) -> str:
        """Format the complete trace for the conclusion prompt."""
        lines = []
        for s in trace.steps:
            lines.append(
                f"--- Step {s.step_number} ---\n"
                f"Action: {s.action.value}\n"
                f"Reason: {s.reason}\n"
                f"Source: {s.data_source}\n"
                f"Data: {s.data_summary}\n"
                f"Findings: {s.findings}\n"
                f"Hypotheses: {'; '.join(s.hypotheses)}\n"
                f"Decision: {s.decision}\n"
                f"Confidence: {s.confidence:.0%}\n"
            )
        return "\n".join(lines)

    def _format_raw_data(self, raw_data: Any, action: InvestigationActionType) -> str:
        """Format raw data into a readable string for Claude, with truncation."""
        if raw_data is None:
            return "No data returned (fetch failed)."

        max_chars = 15_000

        if isinstance(raw_data, list):
            items = []
            for item in raw_data[:100]:
                if hasattr(item, "model_dump"):
                    items.append(item.model_dump())
                elif isinstance(item, dict):
                    items.append(item)
                else:
                    items.append(str(item))
            text = json.dumps(items, indent=2, default=str)
        elif hasattr(raw_data, "model_dump"):
            text = json.dumps(raw_data.model_dump(), indent=2, default=str)
        elif isinstance(raw_data, dict):
            text = json.dumps(raw_data, indent=2, default=str)
        else:
            text = str(raw_data)

        if len(text) > max_chars:
            text = text[:max_chars] + "\n... [truncated]"
        return text

    @staticmethod
    def _merge_data(
        accumulated: ObservabilityData,
        raw_data: Any,
        action_type: InvestigationActionType,
    ) -> None:
        """Merge fetched data into the accumulated ObservabilityData."""
        if raw_data is None:
            return

        if action_type in (
            InvestigationActionType.FETCH_METRICS,
            InvestigationActionType.QUERY_CUSTOM_METRIC,
            InvestigationActionType.FETCH_INFRA_METRICS,
        ):
            if isinstance(raw_data, list):
                accumulated.metrics.extend(raw_data)

        elif action_type in (
            InvestigationActionType.FETCH_LOGS,
            InvestigationActionType.SEARCH_LOGS_CUSTOM,
        ):
            if isinstance(raw_data, list):
                accumulated.logs.extend(raw_data)

        elif action_type in (
            InvestigationActionType.FETCH_TRACES,
            InvestigationActionType.SEARCH_TRACES_CUSTOM,
        ):
            if isinstance(raw_data, list):
                accumulated.traces.extend(raw_data)

        elif action_type == InvestigationActionType.FETCH_SERVICE_MAP:
            if hasattr(raw_data, "name"):
                accumulated.service_map.append(raw_data)

        elif action_type in (
            InvestigationActionType.FETCH_EVENTS,
            InvestigationActionType.FETCH_DEPLOYMENTS,
        ):
            if isinstance(raw_data, list):
                accumulated.events.extend(raw_data)

        elif action_type == InvestigationActionType.FETCH_MONITORS:
            if isinstance(raw_data, list):
                accumulated.monitors.extend(raw_data)

        elif action_type == InvestigationActionType.EXPAND_SCOPE:
            if isinstance(raw_data, dict):
                if "metrics" in raw_data and isinstance(raw_data["metrics"], list):
                    accumulated.metrics.extend(raw_data["metrics"])
                if "logs" in raw_data and isinstance(raw_data["logs"], list):
                    accumulated.logs.extend(raw_data["logs"])
