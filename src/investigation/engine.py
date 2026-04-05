"""Dynamic investigation engine v3 — composable phase architecture.

Orchestrates: Discovery → Changes → Breadth → Depth → Report
Split from the v2 monolith into focused phase classes.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from config.settings import AgentConfig
from src.claude.reasoning import ClaudeReasoning
from src.correlation.engine import CorrelationEngine
from src.datadog.client import DatadogClient
from src.investigation.analysis import AnalysisPhase
from src.investigation.breadth import BreadthPhase
from src.investigation.discovery import DiscoveryPhase
from src.investigation.execution import ActionExecutor
from src.investigation.rules import build_signal_checklist
from src.models.incident import (
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    ObservabilityData,
    RCAReport,
)

logger = logging.getLogger(__name__)


class InvestigationEngine:
    """Dynamic, hypothesis-driven investigation engine v3.

    Improvements over v2:
    - Composable phases: Discovery, Breadth, Depth, Analysis
    - Depth-first sub-investigations for leading hypotheses
    - Signal quality tracking with data gaps
    - Per-pod breakdowns for saturation/latency
    - Change correlation (deployment, config, scaling events)
    - Time budget enforcement
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
        """Run a dynamic, step-by-step investigation with v3 architecture."""
        self.reasoning.reset_dynamic_history()
        trace = InvestigationTrace()
        accumulated_data = ObservabilityData()
        start_time = time.monotonic()

        # Initialize investigation state
        self.state = InvestigationState(
            signal_checklist=build_signal_checklist(incident.symptom_type.value),
            investigation_start_time=datetime.now(timezone.utc),
            phase="discovery",
        )

        logger.info("Starting v3 investigation for %s", incident.service)
        logger.info(
            "Signal checklist: %s",
            ", ".join(self.state.signal_checklist.keys()),
        )

        # Build phase instances with shared dependencies
        discovery = DiscoveryPhase(self.dd_client, self.config)
        executor = ActionExecutor(
            self.dd_client, self.correlation, self.config, self.state
        )
        executor.set_accumulated_data(accumulated_data)
        analysis = AnalysisPhase(self.reasoning, self.correlation, self.config)
        breadth = BreadthPhase(
            executor, analysis, self.reasoning, self.config, self.on_step_complete
        )

        async with self.dd_client:
            # ── Phase 1: Discovery (Step 0) ──────────────────────────
            try:
                discovered = await discovery.discover(incident)
                self.state.discovered_context = discovered

                # Update incident source_tags with resolved tags
                if discovered.resolved_tags:
                    for k, v in discovered.resolved_tags.items():
                        if k not in incident.source_tags:
                            incident.source_tags[k] = v

                # Log discovery as step 0
                discovery_summary_parts = []
                if discovered.available_metrics:
                    discovery_summary_parts.append(
                        f"{len(discovered.available_metrics)} metrics"
                    )
                if discovered.resolved_namespace:
                    discovery_summary_parts.append(
                        f"namespace={discovered.resolved_namespace}"
                    )
                if discovered.dashboard_metrics:
                    discovery_summary_parts.append(
                        f"{len(discovered.dashboard_metrics)} dashboard metrics"
                    )
                if discovered.resolved_tags:
                    discovery_summary_parts.append(
                        f"tags={discovered.resolved_tags}"
                    )

                discovery_step = InvestigationStep(
                    step_number=0,
                    action=InvestigationActionType.DISCOVER_CONTEXT,
                    reason="Discover available metrics, tags, and dashboards before investigating",
                    data_source=incident.service,
                    findings=f"Discovered: {', '.join(discovery_summary_parts) or 'no context found'}",
                    data_summary=f"Discovery: {len(discovered.available_metrics)} metrics, "
                                 f"namespace={discovered.resolved_namespace or 'unresolved'}, "
                                 f"{len(discovered.dashboard_metrics)} dashboard metrics",
                    confidence=0.0,
                )
                trace.steps.append(discovery_step)

                if self.on_step_complete:
                    try:
                        await self.on_step_complete(discovery_step)
                    except Exception as e:
                        logger.warning("Step 0 callback failed: %s", e)

            except Exception as e:
                logger.warning("Service discovery failed (non-fatal): %s", e)

            # ── Phase 1.5: Change discovery ──────────────────────────
            if not self._time_exceeded():
                try:
                    changes = await discovery.discover_changes(incident)
                    self.state.changes_detected = changes
                    if changes:
                        logger.info(
                            "Discovered %d changes in 2h lookback (closest: %s min before incident)",
                            len(changes),
                            changes[0].get("time_to_incident_minutes", "?") if changes else "N/A",
                        )
                except Exception as e:
                    logger.warning("Change discovery failed (non-fatal): %s", e)

            # ── Phase 2: Breadth ─────────────────────────────────────
            if not self._time_exceeded():
                await breadth.run(
                    incident, trace, self.state, accumulated_data, self.max_steps
                )

            # ── Phase 3: Depth (if hypothesis needs it) ──────────────
            # Depth should run when:
            # 1. A leading hypothesis exists with meaningful confidence
            # 2. Confidence is below the "solved" threshold (otherwise depth is redundant)
            # Note: breadth setting trace.concluded=True does NOT mean the case is solved;
            # it means breadth's signal checklist is sufficiently covered.
            # Time budget is enforced WITHIN the depth phase (per-step), not as a gate
            # to entering it — depth is the most valuable phase for dependency failures.
            if True:
                leading = max(
                    self.state.hypotheses.values(), key=lambda h: h.confidence
                ) if self.state.hypotheses else None

                if (
                    leading
                    and leading.confidence >= 0.10
                    and leading.confidence < self.confidence_threshold
                ):
                    self.state.phase = "depth"
                    logger.info(
                        "Entering depth phase: leading hypothesis at %.0f%% confidence",
                        leading.confidence * 100,
                    )
                    try:
                        from src.investigation.depth import DepthPhase
                        depth = DepthPhase(
                            executor, analysis, self.reasoning, self.config,
                            self.on_step_complete,
                        )
                        await depth.run(incident, trace, self.state, accumulated_data)
                    except ImportError:
                        logger.debug("Depth phase not available")
                    except Exception as e:
                        logger.warning("Depth phase failed (non-fatal): %s", e)

        # Finalize trace
        if not trace.concluded:
            trace.concluded = True
            trace.conclusion_reason = "max_steps_reached"

        trace.total_duration_ms = int((time.monotonic() - start_time) * 1000)
        trace.investigation_state = self.state

        logger.info(
            "Investigation concluded: %d steps, %dms, reason=%s, "
            "empty_fetches=%d/%d, hypotheses=%d, data_gaps=%d",
            trace.total_steps, trace.total_duration_ms, trace.conclusion_reason,
            self.state.empty_fetches, self.state.total_fetches,
            len(self.state.hypotheses), len(self.state.data_gaps),
        )

        # ── Phase 4: Report generation ───────────────────────────────
        self.state.phase = "concluding"
        return await analysis.generate_final_report(
            incident, trace, accumulated_data, self.state
        )

    # ── Time budget ───────────────────────────────────────────────────

    def _time_exceeded(self) -> bool:
        """Check if the investigation has exceeded the time budget."""
        if not self.state or not self.state.investigation_start_time:
            return False
        elapsed = (datetime.now(timezone.utc) - self.state.investigation_start_time).total_seconds()
        if elapsed > self.config.max_investigation_seconds:
            logger.warning(
                "Investigation time budget exceeded: %.0fs > %ds",
                elapsed, self.config.max_investigation_seconds,
            )
            return True
        return False
