"""Action execution and smart retry for investigation steps."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any, Optional

from config.settings import AgentConfig
from src.correlation.engine import CorrelationEngine
from src.datadog.client import DatadogClient
from src.investigation.discovery import DiscoveryPhase
from src.investigation.helpers import is_empty_result
from src.investigation.rules import get_tag_fallbacks
from src.models.incident import (
    DataGap,
    DiscoveredContext,
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    ObservabilityData,
    SymptomType,
)

logger = logging.getLogger(__name__)


class ActionExecutor:
    """Executes Datadog fetches and retries with tag fallbacks."""

    def __init__(
        self,
        dd_client: DatadogClient,
        correlation: CorrelationEngine,
        config: AgentConfig,
        state: Optional[InvestigationState] = None,
    ) -> None:
        self.dd_client = dd_client
        self.correlation = correlation
        self.config = config
        self.state = state
        # Accumulated data reference (set by engine before running)
        self._accumulated_data: Optional[ObservabilityData] = None

    def set_accumulated_data(self, data: ObservabilityData) -> None:
        self._accumulated_data = data

    # ── Main execution ────────────────────────────────────────────────

    async def execute(
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

            # If standard APM metrics returned empty, try discovered metrics
            if not data and self.state and self.state.discovered_context:
                ctx = self.state.discovered_context
                discovered_queries = DiscoveryPhase.build_queries_from_discovered(ctx, service)
                if discovered_queries:
                    logger.info("APM metrics empty, trying %d discovered metrics", len(discovered_queries))
                    tasks = [self.dd_client.query_metrics(q, start, end) for q in discovered_queries[:10]]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in results:
                        if isinstance(r, list):
                            data.extend(r)

            # v3: Auto per-pod breakdown for saturation/latency
            if data and self.config.auto_per_pod_breakdown and incident.symptom_type in (
                SymptomType.SATURATION, SymptomType.LATENCY,
            ):
                data = await self._add_per_pod_breakdown(data, service, start, end)

            summary = f"{len(data)} metric series for {service}"
            return data, summary

        elif action_type == InvestigationActionType.FETCH_LOGS:
            namespace = ""
            container_name = ""
            if self.state and self.state.discovered_context:
                ctx = self.state.discovered_context
                namespace = ctx.resolved_namespace
                container_name = ctx.resolved_tags.get("kube_container_name", "")
            data = await self.dd_client.fetch_service_logs(
                service, start, end,
                namespace=namespace,
                container_name=container_name,
            )
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

            # Use resolved tags from discovery if available
            if self.state and self.state.discovered_context:
                ctx = self.state.discovered_context
                if ctx.resolved_tags:
                    merged_tags = dict(ctx.resolved_tags)
                    merged_tags.update(tags)
                    tags = merged_tags

            data = await self.dd_client.fetch_infra_metrics(tags, start, end)

            # If still empty, try discovered infra metrics directly
            if not data and self.state and self.state.discovered_context:
                ctx = self.state.discovered_context
                infra_to_try = ctx.infra_metrics + ctx.container_metrics
                if infra_to_try:
                    tag_filter = ",".join(f"{k}:{v}" for k, v in tags.items())
                    logger.info("Infra metrics empty, trying %d discovered infra metrics", len(infra_to_try))
                    queries = [f"avg:{m}{{{tag_filter}}}" for m in infra_to_try[:8]]
                    tasks = [self.dd_client.query_metrics(q, start, end) for q in queries]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in results:
                        if isinstance(r, list):
                            data.extend(r)

            # v3: Auto per-pod breakdown for saturation/latency
            if data and self.config.auto_per_pod_breakdown and incident.symptom_type in (
                SymptomType.SATURATION, SymptomType.LATENCY,
            ):
                data = await self._add_per_pod_breakdown(data, service, start, end, tags)

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
            accumulated = self._accumulated_data or ObservabilityData()
            timeline = self.correlation.build_timeline(incident, accumulated)
            service_corr = self.correlation.correlate_services(accumulated)
            anomaly_summary = self.correlation.compute_anomaly_summary(accumulated)
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

        elif action_type == InvestigationActionType.DISCOVER_CONTEXT:
            return None, "Discovery handled separately"

        return None, "Unknown action"

    # ── Smart Retry ───────────────────────────────────────────────────

    async def retry_with_fallbacks(
        self,
        action_type: InvestigationActionType,
        params: dict,
        incident: IncidentQuery,
    ) -> tuple[Any, str, Optional[DataGap]]:
        """Retry a failed/empty fetch with alternative tags and expanded time window.

        Returns (data, summary, data_gap). data_gap is populated if all retries fail.
        Retries don't count as investigation steps.
        """
        max_retries = self.config.max_retry_attempts
        queries_attempted: list[str] = []

        # Only retry data-fetching actions
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
            return None, "Not retryable", None

        # Strategy 1: Alternative tag combinations
        original_tags = params.get("tags", incident.source_tags) or {"service": incident.service}
        fallback_tags_list = get_tag_fallbacks(original_tags)

        for i, alt_tags in enumerate(fallback_tags_list[:max_retries]):
            try:
                alt_params = dict(params)
                alt_params["tags"] = alt_tags
                queries_attempted.append(f"tags={alt_tags}")
                data, summary = await self.execute(action_type, alt_params, incident)
                if not is_empty_result(data):
                    if self.state:
                        self.state.data_gap_log.append(
                            f"  Retry {i+1} succeeded with tags: {alt_tags}"
                        )
                    return data, summary, None
                if self.state:
                    self.state.data_gap_log.append(
                        f"  Retry {i+1} with tags {alt_tags}: still empty"
                    )
            except Exception as e:
                if self.state:
                    self.state.data_gap_log.append(f"  Retry {i+1} failed: {e}")

        # Strategy 2: Discovered tags
        if self.state and self.state.discovered_context:
            ctx = self.state.discovered_context
            if ctx.resolved_tags and action_type in (
                InvestigationActionType.FETCH_INFRA_METRICS,
                InvestigationActionType.FETCH_METRICS,
            ):
                alt_params = dict(params)
                alt_params["tags"] = ctx.resolved_tags
                queries_attempted.append(f"discovered_tags={ctx.resolved_tags}")
                try:
                    data, summary = await self.execute(action_type, alt_params, incident)
                    if not is_empty_result(data):
                        if self.state:
                            self.state.data_gap_log.append(
                                f"  Retry with discovered tags {ctx.resolved_tags}: succeeded"
                            )
                        return data, summary, None
                    if self.state:
                        self.state.data_gap_log.append("  Retry with discovered tags: still empty")
                except Exception as e:
                    if self.state:
                        self.state.data_gap_log.append(f"  Retry with discovered tags failed: {e}")

        # Strategy 3: Expand time window
        expansion = self.config.time_window_expansion_factor
        expanded_start = incident.start_time - timedelta(
            seconds=(incident.end_time - incident.start_time).total_seconds() * (expansion - 1)
        )
        try:
            if action_type in (
                InvestigationActionType.FETCH_INFRA_METRICS,
                InvestigationActionType.QUERY_CUSTOM_METRIC,
            ):
                query = params.get("query", "")
                if query:
                    queries_attempted.append(f"expanded_window={expansion}x")
                    data = await self.dd_client.query_metrics(query, expanded_start, incident.end_time)
                    if not is_empty_result(data):
                        if self.state:
                            self.state.data_gap_log.append(
                                f"  Expanded time window retry succeeded ({expansion}x)"
                            )
                        return data, f"Custom metric query (expanded window): {len(data)} series", None
        except Exception as e:
            if self.state:
                self.state.data_gap_log.append(f"  Expanded window retry failed: {e}")

        # All retries failed — build DataGap
        gap = DataGap(
            signal=action_type.value,
            queries_attempted=queries_attempted,
            failure_reason=f"All {len(queries_attempted)} retry strategies returned empty data",
            recommendation=self._recommend_for_gap(action_type),
            impact=self._impact_for_gap(action_type),
        )

        return None, "All retries exhausted", gap

    # ── Per-pod breakdown ─────────────────────────────────────────────

    async def _add_per_pod_breakdown(
        self,
        existing_data: list,
        service: str,
        start,
        end,
        tags: dict | None = None,
    ) -> list:
        """Append per-pod breakdown queries for saturation/latency diagnosis."""
        if tags:
            tag_filter = ",".join(f"{k}:{v}" for k, v in tags.items())
        else:
            tag_filter = f"service:{service}"

        breakdown_metrics = [
            f"avg:kubernetes.cpu.usage.total{{{tag_filter}}} by {{pod_name}}",
            f"avg:kubernetes.memory.usage{{{tag_filter}}} by {{pod_name}}",
        ]

        try:
            tasks = [self.dd_client.query_metrics(q, start, end) for q in breakdown_metrics]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    existing_data.extend(r)
        except Exception as e:
            logger.debug("Per-pod breakdown failed: %s", e)

        return existing_data

    # ── Gap recommendations ───────────────────────────────────────────

    @staticmethod
    def _recommend_for_gap(action_type: InvestigationActionType) -> str:
        recommendations = {
            InvestigationActionType.FETCH_METRICS: "Verify service is instrumented with Datadog APM or has custom metrics emitting.",
            InvestigationActionType.FETCH_LOGS: "Check that the service sends logs to Datadog. Verify log pipeline configuration.",
            InvestigationActionType.FETCH_TRACES: "Enable APM tracing for this service. Check DD_TRACE_ENABLED env var.",
            InvestigationActionType.FETCH_INFRA_METRICS: "Verify Kubernetes integration is active and DaemonSet is deployed.",
            InvestigationActionType.FETCH_DEPLOYMENTS: "Ensure deployment tools emit events to Datadog (CI/CD integration).",
            InvestigationActionType.FETCH_SERVICE_MAP: "Enable APM service catalog for dependency mapping.",
        }
        return recommendations.get(action_type, "Check Datadog integration for this data source.")

    @staticmethod
    def _impact_for_gap(action_type: InvestigationActionType) -> str:
        impacts = {
            InvestigationActionType.FETCH_METRICS: "Cannot analyze application-level performance patterns.",
            InvestigationActionType.FETCH_LOGS: "Cannot analyze error messages or application behavior.",
            InvestigationActionType.FETCH_TRACES: "Cannot trace individual request paths or identify slow operations.",
            InvestigationActionType.FETCH_INFRA_METRICS: "Cannot analyze infrastructure-level resource usage.",
            InvestigationActionType.FETCH_DEPLOYMENTS: "Cannot correlate issue with recent deployments.",
            InvestigationActionType.FETCH_SERVICE_MAP: "Cannot identify upstream/downstream impact.",
        }
        return impacts.get(action_type, "Limited investigation scope for this data source.")
