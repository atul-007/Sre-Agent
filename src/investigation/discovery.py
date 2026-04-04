"""Discovery phase — resolves metrics, tags, namespaces, dashboards, and monitors
before the investigation loop begins (Step 0).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from config.settings import AgentConfig
from src.datadog.client import DatadogClient
from src.models.incident import (
    DiscoveredContext,
    IncidentQuery,
)

logger = logging.getLogger(__name__)


class DiscoveryPhase:
    """Discovers what metrics, tags, dashboards, and monitors exist for a service."""

    def __init__(self, dd_client: DatadogClient, config: AgentConfig) -> None:
        self.dd_client = dd_client
        self.config = config

    # ── Main discovery ────────────────────────────────────────────────

    async def discover(self, incident: IncidentQuery) -> DiscoveredContext:
        """Discover what metrics, tags, and dashboards exist for the service.

        Runs as step 0 before any investigation, replacing blind guessing
        with actual API lookups.
        """
        ctx = DiscoveredContext()
        service = incident.service

        logger.info("Step 0: Discovering service context for %s", service)

        # 1. Search for metrics matching the service name
        search_terms = [service]
        parts = service.split("-")
        if len(parts) > 2:
            search_terms.append("-".join(parts[-3:]))
            search_terms.append("-".join(parts[-2:]))
        if len(parts) > 1:
            search_terms.append("-".join(parts[1:]))

        all_found_metrics: set[str] = set()
        for term in search_terms:
            try:
                metrics = await self.dd_client.search_metrics(term)
                all_found_metrics.update(metrics)
                if metrics:
                    logger.info("  Metric search '%s': found %d metrics", term, len(metrics))
            except Exception as e:
                logger.warning("  Metric search '%s' failed: %s", term, e)

        # 2. Categorize discovered metrics
        for m in all_found_metrics:
            m_lower = m.lower()
            if any(k in m_lower for k in ("container.", "docker.")):
                ctx.container_metrics.append(m)
            elif any(k in m_lower for k in ("kubernetes.", "kube_")):
                ctx.infra_metrics.append(m)
            elif any(k in m_lower for k in ("trace.", "apm.")):
                ctx.apm_metrics.append(m)
            else:
                ctx.custom_metrics.append(m)

        ctx.available_metrics = sorted(all_found_metrics)
        logger.info(
            "  Discovered %d metrics: %d container, %d k8s, %d APM, %d custom",
            len(ctx.available_metrics),
            len(ctx.container_metrics),
            len(ctx.infra_metrics),
            len(ctx.apm_metrics),
            len(ctx.custom_metrics),
        )

        # 3. Resolve namespace
        namespace_candidates = self.generate_namespace_candidates(
            incident.environment, service, incident.source_tags
        )
        for ns_candidate in namespace_candidates:
            try:
                test_query = f"avg:kubernetes.cpu.usage.total{{kube_namespace:{ns_candidate}}}"
                test_results = await self.dd_client.query_metrics(
                    test_query, incident.start_time, incident.end_time
                )
                if test_results and any(s.points for s in test_results):
                    ctx.resolved_namespace = ns_candidate
                    ctx.resolved_tags["kube_namespace"] = ns_candidate
                    logger.info("  Resolved namespace: %s", ns_candidate)
                    break
            except Exception as e:
                logger.debug("  Namespace probe '%s' failed: %s", ns_candidate, e)

        # 4. Discover container/service tags
        if ctx.resolved_namespace:
            try:
                tag_values = await self.dd_client.get_metric_tag_values(
                    "kubernetes.cpu.usage.total", "kube_namespace"
                )
                if ctx.resolved_namespace in tag_values:
                    logger.info("  Confirmed namespace exists in tag values")
            except Exception as e:
                logger.debug("  Tag value lookup failed: %s", e)

            try:
                container_values = await self.dd_client.get_metric_tag_values(
                    "kubernetes.cpu.usage.total", "kube_container_name"
                )
                for cv in container_values:
                    if any(part in cv for part in parts if len(part) > 3):
                        ctx.resolved_tags["kube_container_name"] = cv
                        logger.info("  Resolved container name: %s", cv)
                        break
            except Exception as e:
                logger.debug("  Container name lookup failed: %s", e)

        # 5. Dashboard mining
        try:
            dashboards = await self.dd_client.find_dashboards_for_service(service)
            for dash in dashboards:
                dash_id = dash.get("id", "")
                if dash_id:
                    ctx.dashboard_ids.append(dash_id)
                dash_metrics = DatadogClient.extract_metrics_from_dashboard(dash)
                ctx.dashboard_metrics.extend(dash_metrics)
                logger.info(
                    "  Dashboard '%s': found %d metrics",
                    dash.get("title", "unknown"),
                    len(dash_metrics),
                )
        except Exception as e:
            logger.warning("  Dashboard mining failed: %s", e)

        ctx.dashboard_metrics = sorted(set(ctx.dashboard_metrics))

        # 6. Monitor mining
        try:
            monitors = await self.dd_client.search_monitors(
                tags=[f"service:{service}"]
            )
            if not monitors and ctx.resolved_namespace:
                monitors = await self.dd_client.search_monitors(
                    query=ctx.resolved_namespace
                )
                monitors = monitors[:100]

            if monitors:
                monitor_metrics = DatadogClient.extract_metrics_from_monitors(monitors)
                for m in monitor_metrics:
                    if m not in ctx.dashboard_metrics:
                        ctx.dashboard_metrics.append(m)
                    if m not in all_found_metrics:
                        all_found_metrics.add(m)
                        ctx.available_metrics = sorted(all_found_metrics)
                logger.info(
                    "  Monitor mining: %d monitors, %d metrics extracted",
                    len(monitors), len(monitor_metrics),
                )
        except Exception as e:
            logger.warning("  Monitor mining failed: %s", e)

        # 7. Host-based tag discovery fallback
        if not ctx.resolved_tags:
            try:
                hosts = await self.dd_client.search_hosts_by_tag(f"service:{service}")
                if hosts:
                    host = hosts[0]
                    host_tags = host.get("tags_by_source", {})
                    for source_tags in host_tags.values():
                        for tag in source_tags:
                            if ":" in tag:
                                k, v = tag.split(":", 1)
                                if k in ("kube_namespace", "kube_cluster_name", "env"):
                                    ctx.resolved_tags[k] = v
                    if ctx.resolved_tags:
                        ctx.resolved_namespace = ctx.resolved_tags.get(
                            "kube_namespace", ctx.resolved_namespace
                        )
                        logger.info("  Resolved tags from host: %s", ctx.resolved_tags)
            except Exception as e:
                logger.debug("  Host tag lookup failed: %s", e)

        logger.info(
            "Step 0 complete: %d metrics, namespace=%s, %d dashboard metrics, tags=%s",
            len(ctx.available_metrics),
            ctx.resolved_namespace or "(unresolved)",
            len(ctx.dashboard_metrics),
            ctx.resolved_tags,
        )

        return ctx

    # ── Change discovery (Step 0.5) ───────────────────────────────────

    async def discover_changes(self, incident: IncidentQuery) -> list[dict[str, Any]]:
        """Query deployment, scaling, and config changes in a 2-hour lookback window.

        Returns changes sorted by timestamp, with time-to-incident calculated.
        """
        lookback_start = incident.start_time - timedelta(hours=2)
        changes: list[dict[str, Any]] = []

        # Deployment events
        try:
            deploys = await self.dd_client.get_deployment_events(
                incident.service, lookback_start, incident.end_time
            )
            for deploy in deploys:
                delta = (incident.start_time - deploy.timestamp).total_seconds() / 60
                changes.append({
                    "type": "deployment",
                    "timestamp": deploy.timestamp.isoformat(),
                    "description": deploy.title,
                    "time_to_incident_minutes": round(delta, 1),
                })
        except Exception as e:
            logger.warning("  Deployment event discovery failed: %s", e)

        # Kubernetes / infrastructure events
        try:
            events = await self.dd_client.get_events(
                lookback_start, incident.end_time,
                tags=[f"service:{incident.service}"],
                sources=["kubernetes", "chef", "puppet", "ansible", "terraform"],
            )
            for event in events:
                title_lower = event.title.lower()
                if any(kw in title_lower for kw in (
                    "scale", "deploy", "config", "restart", "oom", "evict", "rollout",
                )):
                    delta = (incident.start_time - event.timestamp).total_seconds() / 60
                    changes.append({
                        "type": "infrastructure",
                        "timestamp": event.timestamp.isoformat(),
                        "description": event.title,
                        "source": event.source,
                        "time_to_incident_minutes": round(delta, 1),
                    })
        except Exception as e:
            logger.warning("  Infrastructure event discovery failed: %s", e)

        changes.sort(key=lambda c: c["timestamp"])
        if changes:
            logger.info("  Discovered %d changes in 2h lookback", len(changes))
        return changes

    # ── Query building from discovered context ────────────────────────

    @staticmethod
    def build_queries_from_discovered(
        ctx: DiscoveredContext, service: str
    ) -> list[str]:
        """Build Datadog metric queries from discovered metrics.

        Prioritizes dashboard metrics (team already monitors these),
        then container/infra metrics, then custom metrics.
        """
        queries: list[str] = []

        if ctx.resolved_tags:
            tag_filter = ",".join(f"{k}:{v}" for k, v in ctx.resolved_tags.items())
        else:
            tag_filter = f"service:{service}"

        for m in ctx.dashboard_metrics[:5]:
            queries.append(f"avg:{m}{{{tag_filter}}}")

        container_priorities = ["container.cpu", "container.memory", "container.io"]
        for m in ctx.container_metrics:
            if any(p in m.lower() for p in container_priorities):
                queries.append(f"avg:{m}{{{tag_filter}}}")

        infra_priorities = ["kubernetes.cpu", "kubernetes.memory", "cpu.throttled"]
        for m in ctx.infra_metrics:
            if any(p in m.lower() for p in infra_priorities):
                queries.append(f"avg:{m}{{{tag_filter}}}")

        for m in ctx.custom_metrics[:5]:
            queries.append(f"avg:{m}{{{tag_filter}}}")

        return queries

    # ── Namespace candidates ──────────────────────────────────────────

    @staticmethod
    def generate_namespace_candidates(
        environment: str, service: str, source_tags: dict[str, str]
    ) -> list[str]:
        """Generate namespace candidates to probe, ordered by likelihood."""
        candidates: list[str] = []

        if "kube_namespace" in source_tags:
            candidates.append(source_tags["kube_namespace"])

        parts = service.split("-")
        candidates.append(service)

        env_suffixes = ["-prod", "-production", "-prd", ""]
        env_lower = environment.lower()
        if "prod" in env_lower:
            env_suffixes = ["-prod", "-production", "-prd", ""]
        elif "stag" in env_lower:
            env_suffixes = ["-staging", "-stg", ""]

        if "namespace" in source_tags:
            ns_base = source_tags["namespace"]
            for suffix in env_suffixes:
                candidates.append(f"{ns_base}{suffix}")

        if len(parts) >= 2:
            for prefix_len in range(2, min(len(parts), 5)):
                base = "-".join(parts[:prefix_len])
                for suffix in env_suffixes:
                    candidates.append(f"{base}{suffix}")

        seen: set[str] = set()
        unique: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        return unique
