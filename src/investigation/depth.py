"""Depth phase — targeted deep-dive into the leading hypothesis.

After the breadth phase identifies WHAT happened (e.g., "hot pod"),
the depth phase investigates WHY it happened by running targeted queries
specific to the hypothesis category.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Awaitable, Callable, Optional

from config.settings import AgentConfig
from src.claude.prompts import DEPTH_ANALYSIS_PROMPT
from src.claude.reasoning import ClaudeReasoning
from src.investigation.analysis import AnalysisPhase
from src.investigation.execution import ActionExecutor
from src.investigation.helpers import (
    format_raw_data,
    is_empty_result,
    merge_data,
    parse_json_response,
)
from src.investigation.rules import (
    build_depth_queries,
    classify_hypothesis,
)
from src.models.incident import (
    DataGap,
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    ObservabilityData,
    TrackedHypothesis,
)

logger = logging.getLogger(__name__)


class DepthPhase:
    """Runs targeted, depth-first queries for the leading hypothesis."""

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
    ) -> None:
        """Run depth investigation for the leading hypothesis."""
        leading = self._get_leading_hypothesis(state)
        if not leading:
            logger.info("Depth phase: no hypothesis to investigate deeply")
            return

        if leading.confidence < 0.10:
            logger.info(
                "Depth phase: leading hypothesis confidence too low (%.0f%%), skipping",
                leading.confidence * 100,
            )
            return

        # Classify the hypothesis
        category = classify_hypothesis(leading.description)
        if category == "unknown":
            logger.info(
                "Depth phase: could not classify hypothesis '%s', skipping",
                leading.description[:80],
            )
            return

        logger.info(
            "Depth phase: investigating '%s' (category=%s, confidence=%.0f%%)",
            leading.description[:80], category, leading.confidence * 100,
        )

        # Get the pod name from investigation context for pod-specific queries
        pod = self._extract_pod_from_context(incident, state)

        # Build concrete queries from templates
        tags = {}
        if state.discovered_context:
            tags = dict(state.discovered_context.resolved_tags)
        if not tags:
            tags = dict(incident.source_tags)
        if not tags:
            tags = {"service": incident.service}

        depth_queries = build_depth_queries(category, incident.service, tags, pod)

        if not depth_queries:
            logger.info("Depth phase: no queries generated for category '%s'", category)
            return

        max_depth = self.config.max_depth_steps
        for i, query_spec in enumerate(depth_queries[:max_depth]):
            step_start = time.monotonic()
            step_number = trace.total_steps + 1
            state.depth_steps_taken += 1

            logger.info(
                "Depth step %d/%d: %s — %s",
                i + 1, min(len(depth_queries), max_depth),
                query_spec["signal"], query_spec["description"],
            )

            # Execute the query
            raw_data = None
            data_summary = ""
            try:
                if query_spec["type"] == "metric":
                    raw_data = await self.executor.dd_client.query_metrics(
                        query_spec["query"],
                        incident.start_time,
                        incident.end_time,
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} metric series"
                elif query_spec["type"] == "log":
                    raw_data = await self.executor.dd_client.search_logs(
                        query_spec["query"],
                        incident.start_time,
                        incident.end_time,
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} log entries"
            except Exception as e:
                logger.warning("Depth query failed: %s", e)
                data_summary = f"Query failed: {e}"

            # Track as investigation step
            step = InvestigationStep(
                step_number=step_number,
                action=InvestigationActionType.QUERY_CUSTOM_METRIC
                if query_spec["type"] == "metric"
                else InvestigationActionType.SEARCH_LOGS_CUSTOM,
                reason=f"[DEPTH] {query_spec['description']}",
                data_source=incident.service,
                query_params={"query": query_spec["query"], "depth_signal": query_spec["signal"]},
                data_summary=data_summary,
            )

            empty = is_empty_result(raw_data)
            if empty:
                state.data_gaps.append(DataGap(
                    signal=query_spec["signal"],
                    queries_attempted=[query_spec["query"]],
                    failure_reason="Depth query returned no data",
                    recommendation=f"Check if {query_spec['signal']} metrics are emitted for {incident.service}",
                    impact=f"Cannot determine {query_spec['description'].lower()}",
                ))
                step.findings = f"No data for {query_spec['signal']}"
                step.confidence = leading.confidence
            else:
                # Merge data
                if query_spec["type"] == "metric":
                    merge_data(accumulated_data, raw_data, InvestigationActionType.QUERY_CUSTOM_METRIC)
                else:
                    merge_data(accumulated_data, raw_data, InvestigationActionType.SEARCH_LOGS_CUSTOM)

                # Analyze with depth-specific prompt
                analysis_result = await self._analyze_depth_data(
                    raw_data, leading, category, query_spec, state
                )

                step.findings = analysis_result.get("evidence_summary", "")
                mechanism = analysis_result.get("mechanism", "")
                if mechanism:
                    step.findings = f"MECHANISM: {mechanism}\n{step.findings}"

                # Update hypothesis based on analysis
                delta = float(analysis_result.get("confidence_delta", 0.0))
                supports = analysis_result.get("supports", True)

                if supports:
                    evidence_text = analysis_result.get("evidence_summary", query_spec["description"])
                    leading.supporting_evidence.append(f"[depth:{query_spec['signal']}] {evidence_text}")
                    leading.confidence = min(1.0, max(0.0, leading.confidence + delta))
                else:
                    evidence_text = analysis_result.get("evidence_summary", query_spec["description"])
                    leading.contradicting_evidence.append(f"[depth:{query_spec['signal']}] {evidence_text}")
                    leading.confidence = max(0.0, leading.confidence - abs(delta))

                step.confidence = leading.confidence

            step.hypotheses = [
                f"[{leading.status.value.upper()}] {leading.description} ({leading.confidence:.0%})"
            ]
            step.decision = "Continue depth investigation" if i < len(depth_queries) - 1 else "Depth complete"
            step.duration_ms = int((time.monotonic() - step_start) * 1000)

            trace.steps.append(step)
            trace.total_steps += 1

            # Callback
            if self.on_step_complete:
                try:
                    await self.on_step_complete(step)
                except Exception as e:
                    logger.warning("Depth step callback failed: %s", e)

            logger.info(
                "Depth step %d complete: confidence=%.0f%%, empty=%s",
                i + 1, leading.confidence * 100, empty,
            )

        logger.info(
            "Depth phase complete: %d steps, hypothesis confidence now %.0f%%",
            state.depth_steps_taken, leading.confidence * 100,
        )

    # ── Analysis ──────────────────────────────────────────────────────

    async def _analyze_depth_data(
        self,
        raw_data: Any,
        hypothesis: TrackedHypothesis,
        category: str,
        query_spec: dict,
        state: InvestigationState,
    ) -> dict:
        """Analyze depth query results with a focused prompt."""
        data_content = format_raw_data(raw_data, InvestigationActionType.QUERY_CUSTOM_METRIC)

        prompt = DEPTH_ANALYSIS_PROMPT.format(
            hypothesis_description=hypothesis.description,
            confidence=hypothesis.confidence,
            category=category,
            query_description=query_spec.get("description", query_spec["signal"]),
            data_content=data_content,
            supporting_evidence="\n".join(hypothesis.supporting_evidence[-5:]) or "None yet",
            contradicting_evidence="\n".join(hypothesis.contradicting_evidence[-5:]) or "None yet",
        )

        response = await self.reasoning.query_dynamic(prompt)
        return parse_json_response(response, fallback={
            "supports": True,
            "mechanism": "",
            "evidence_summary": "Analysis inconclusive",
            "confidence_delta": 0.0,
            "next_query_suggestion": "",
        })

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _get_leading_hypothesis(state: InvestigationState) -> Optional[TrackedHypothesis]:
        """Get the hypothesis with highest confidence."""
        if not state.hypotheses:
            return None
        return max(state.hypotheses.values(), key=lambda h: h.confidence)

    @staticmethod
    def _extract_pod_from_context(incident: IncidentQuery, state: InvestigationState) -> str:
        """Try to extract a specific pod name from the incident context."""
        # Check source tags
        for key in ("pod_name", "kube_pod_name", "pod"):
            if key in incident.source_tags:
                return incident.source_tags[key]

        # Check raw query for pod name patterns
        import re
        pod_match = re.search(r"pod_name:([a-zA-Z0-9_.-]+)", incident.raw_query)
        if pod_match:
            return pod_match.group(1)

        return ""
