"""Orchestrates parallel data fetching from Datadog across all signal types."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from config.settings import AgentConfig
from src.datadog.client import DatadogClient
from src.models.incident import IncidentQuery, ObservabilityData, ServiceNode

logger = logging.getLogger(__name__)


class DatadogFetcher:
    """Fetches all observability signals for an incident in parallel."""

    def __init__(self, client: DatadogClient, config: AgentConfig) -> None:
        self.client = client
        self.config = config

    async def fetch_all(self, incident: IncidentQuery) -> ObservabilityData:
        """Fetch all data signals in parallel for the incident time window."""
        # Expand time window slightly to capture pre-incident signals
        expanded_start = incident.start_time - timedelta(
            seconds=self.config.correlation_window_seconds
        )
        expanded_end = incident.end_time + timedelta(
            seconds=self.config.correlation_window_seconds // 2
        )
        service = incident.service

        logger.info(
            "Fetching all observability data for %s [%s → %s]",
            service,
            expanded_start,
            expanded_end,
        )

        # Phase 1: Fetch primary service data in parallel
        (
            metrics_result,
            logs_result,
            traces_result,
            service_map_result,
            events_result,
            deploy_result,
            monitors_result,
        ) = await asyncio.gather(
            self._safe(self.client.fetch_service_metrics(service, expanded_start, expanded_end)),
            self._safe(self.client.fetch_service_logs(service, expanded_start, expanded_end)),
            self._safe(self.client.fetch_service_traces(service, expanded_start, expanded_end)),
            self._safe(self.client.get_service_dependencies(service, expanded_start, expanded_end)),
            self._safe(
                self.client.get_events(
                    expanded_start, expanded_end, tags=[f"service:{service}"]
                )
            ),
            self._safe(self.client.get_deployment_events(service, expanded_start, expanded_end)),
            self._safe(self.client.get_triggered_monitors(service)),
        )

        # Phase 2: Fetch upstream/downstream dependency data
        service_map: list[ServiceNode] = []
        if isinstance(service_map_result, ServiceNode):
            service_map = [service_map_result]
            dep_data = await self._fetch_dependency_data(
                service_map_result, expanded_start, expanded_end
            )
            metrics_result = (metrics_result or []) + dep_data["metrics"]
            logs_result = (logs_result or []) + dep_data["logs"]
            traces_result = (traces_result or []) + dep_data["traces"]
            service_map.extend(dep_data["service_nodes"])

        return ObservabilityData(
            metrics=metrics_result or [],
            logs=logs_result or [],
            traces=traces_result or [],
            service_map=service_map,
            events=events_result or [],
            monitors=monitors_result or [],
            deployment_events=deploy_result or [],
        )

    async def _fetch_dependency_data(
        self,
        service_node: ServiceNode,
        start,
        end,
    ) -> dict:
        """Fetch metrics/logs/traces for upstream and downstream services."""
        dep_services = set()

        for dep in service_node.dependencies:
            dep_services.add(dep.target_service)
        for dep in service_node.dependents:
            dep_services.add(dep.source_service)

        all_metrics = []
        all_logs = []
        all_traces = []
        all_nodes = []

        tasks = []
        for svc in dep_services:
            tasks.append(self._fetch_single_dependency(svc, start, end))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                all_metrics.extend(r.get("metrics", []))
                all_logs.extend(r.get("logs", []))
                all_traces.extend(r.get("traces", []))
                if r.get("node"):
                    all_nodes.append(r["node"])
            elif isinstance(r, Exception):
                logger.warning("Dependency fetch failed: %s", r)

        return {
            "metrics": all_metrics,
            "logs": all_logs,
            "traces": all_traces,
            "service_nodes": all_nodes,
        }

    async def _fetch_single_dependency(self, service: str, start, end) -> dict:
        """Fetch data for a single dependency service."""
        metrics, logs, traces, node = await asyncio.gather(
            self._safe(self.client.fetch_service_metrics(service, start, end)),
            self._safe(self.client.fetch_service_logs(service, start, end)),
            self._safe(self.client.fetch_service_traces(service, start, end)),
            self._safe(self.client.get_service_dependencies(service, start, end)),
        )
        return {
            "metrics": metrics or [],
            "logs": logs or [],
            "traces": traces or [],
            "node": node,
        }

    @staticmethod
    async def _safe(coro):
        """Execute a coroutine, returning None on failure instead of raising."""
        try:
            return await coro
        except Exception as e:
            logger.warning("Data fetch failed (non-fatal): %s", e)
            return None
