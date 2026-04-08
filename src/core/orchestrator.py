"""Main orchestrator — ties all components together for end-to-end investigation."""

from __future__ import annotations

import logging
from typing import Awaitable, Callable, Optional

from config.settings import AgentConfig
from src.claude.reasoning import ClaudeReasoning
from src.core.parser import parse_incident_query
from src.correlation.engine import CorrelationEngine
from src.datadog.client import DatadogClient
from src.datadog.fetcher import DatadogFetcher
from src.formatters.report import ReportFormatter
from src.investigation.engine import InvestigationEngine
from src.models.incident import IncidentQuery, InvestigationStep, RCAReport
from src.rca.engine import RCAEngine

logger = logging.getLogger(__name__)


class SREAgent:
    """Top-level SRE investigation agent.

    Usage:
        config = AgentConfig()
        agent = SREAgent(config)
        report = await agent.investigate("Why did checkout-service latency spike at 2pm?")
        print(report.to_markdown())
    """

    def __init__(self, config: "AgentConfig | None" = None) -> None:
        self.config = config or AgentConfig()
        self.dd_client = DatadogClient(self.config.datadog)
        self.fetcher = DatadogFetcher(self.dd_client, self.config)
        self.correlation = CorrelationEngine(self.config.correlation_window_seconds)
        self.reasoning = ClaudeReasoning(self.config.claude)
        self.rca = RCAEngine(self.reasoning, self.correlation)
        self.formatter = ReportFormatter()

    async def investigate(self, query: str) -> RCAReport:
        """Run a full investigation from natural language query to RCA report.

        Args:
            query: Natural language incident question, e.g.
                   "Why did service X latency spike at time T?"

        Returns:
            RCAReport with root cause, evidence chain, and remediation steps.
        """
        logger.info("Starting investigation: %s", query)

        logger.info("Parsing incident query...")
        incident = await parse_incident_query(query, self.config.claude)
        logger.info(
            "Parsed: service=%s, symptom=%s, window=%s→%s",
            incident.service,
            incident.symptom_type.value,
            incident.start_time,
            incident.end_time,
        )

        # Enrich with monitor definition if monitor_id was extracted from the alert
        if incident.monitor_id and not incident.additional_context:
            incident = await self._enrich_with_monitor(incident)

        return await self.investigate_from_incident(incident)

    async def investigate_from_incident(
        self,
        incident: IncidentQuery,
        *,
        mode: str = "dynamic",
        on_step_complete: Optional[Callable[[InvestigationStep], Awaitable[None]]] = None,
    ) -> RCAReport:
        """Run investigation from a pre-built IncidentQuery.

        Args:
            incident: Structured incident query.
            mode: "dynamic" for step-by-step investigation, "legacy" for fixed 4-phase pipeline.
            on_step_complete: Async callback invoked after each investigation step (dynamic mode only).
        """
        logger.info(
            "Investigating (%s mode): service=%s, symptom=%s, window=%s→%s",
            mode,
            incident.service,
            incident.symptom_type.value,
            incident.start_time,
            incident.end_time,
        )

        if mode == "dynamic":
            try:
                engine = InvestigationEngine(
                    dd_client=self.dd_client,
                    reasoning=self.reasoning,
                    correlation=self.correlation,
                    config=self.config,
                    on_step_complete=on_step_complete,
                    max_steps=self.config.max_investigation_steps,
                    confidence_threshold=self.config.investigation_confidence_threshold,
                )
                report = await engine.investigate(incident)
                logger.info(
                    "Dynamic investigation complete. Confidence: %.0f%%",
                    report.confidence_score * 100,
                )
                return report
            except Exception as e:
                logger.warning(
                    "Dynamic investigation failed, falling back to legacy: %s", e
                )

        # Legacy mode (fixed 4-phase pipeline)
        logger.info("Running legacy 4-phase investigation...")
        async with self.dd_client:
            data = await self.fetcher.fetch_all(incident)

        logger.info(
            "Collected: %d metric series, %d logs, %d trace spans, "
            "%d service nodes, %d events, %d monitors",
            len(data.metrics),
            len(data.logs),
            len(data.traces),
            len(data.service_map),
            len(data.events),
            len(data.monitors),
        )

        report = await self.rca.investigate(incident, data)
        logger.info("Investigation complete. Confidence: %.0f%%", report.confidence_score * 100)
        return report

    async def investigate_and_format(
        self,
        query: str,
        output_format: str = "markdown",
    ) -> str:
        """Investigate and return formatted output.

        Args:
            query: Natural language incident question.
            output_format: One of "markdown", "slack", "compact".
        """
        report = await self.investigate(query)

        if output_format == "slack":
            import json
            return json.dumps(self.formatter.to_slack_blocks(report), indent=2)
        elif output_format == "compact":
            return self.formatter.to_compact(report)
        else:
            return self.formatter.to_markdown(report)

    async def _enrich_with_monitor(self, incident: IncidentQuery) -> IncidentQuery:
        """Fetch monitor definition from Datadog and enrich the incident query.

        Adds monitor name, exact query, thresholds, and tags to additional_context
        so the investigation has full visibility into what triggered the alert.
        """
        try:
            monitor_def = await self.dd_client.get_monitor(incident.monitor_id)
        except Exception as e:
            logger.warning("Failed to fetch monitor %d: %s", incident.monitor_id, e)
            return incident

        monitor_name = monitor_def.get("name", "")
        monitor_query = monitor_def.get("query", "")
        monitor_tags = monitor_def.get("tags", [])
        thresholds = monitor_def.get("options", {}).get("thresholds", {})
        monitor_message = monitor_def.get("message", "")

        logger.info("Fetched monitor %d: %s", incident.monitor_id, monitor_name)
        logger.info("Monitor query: %s", monitor_query)

        context_parts = []
        if monitor_name:
            context_parts.append(f"Monitor name: {monitor_name}")
        if monitor_query:
            context_parts.append(f"Monitor query: {monitor_query}")
        if thresholds:
            context_parts.append(f"Thresholds: {thresholds}")
        if monitor_tags:
            context_parts.append(f"Monitor tags: {', '.join(monitor_tags)}")
        if monitor_message:
            # Truncate long messages (often contain Slack formatting/runbook links)
            context_parts.append(f"Monitor message: {monitor_message[:500]}")

        updated = incident.model_copy(
            update={
                "additional_context": "\n".join(context_parts),
                "monitor_query": monitor_query or incident.monitor_query,
            }
        )

        return updated

    async def close(self) -> None:
        await self.dd_client.close()
