"""Datadog API client for fetching observability data."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import DatadogConfig
from src.utils.time import ensure_utc, safe_fromisoformat, safe_timestamp
from src.models.incident import (
    DatadogEvent,
    LogEntry,
    MetricDataPoint,
    MetricSeries,
    MonitorStatus,
    ServiceDependency,
    ServiceNode,
    TraceSpan,
)

logger = logging.getLogger(__name__)


class DatadogClient:
    """Async client for Datadog APIs with retry and circuit-breaking."""

    def __init__(self, config: DatadogConfig) -> None:
        self.config = config
        self.base_url = f"https://api.{config.site}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "DD-API-KEY": config.api_key,
                "DD-APPLICATION-KEY": config.app_key,
                "Content-Type": "application/json",
            },
            timeout=config.timeout_seconds,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # ── Discovery ────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_metrics(self, query: str) -> list[str]:
        """Search for available metric names matching a query string.

        Uses GET /api/v1/search?q=metrics:<query> to discover what metrics
        actually exist for a service or tag pattern.
        """
        resp = await self._client.get(
            "/api/v1/search",
            params={"q": f"metrics:{query}"},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", {}).get("metrics", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def list_active_metrics(self, host: str = "") -> list[str]:
        """List actively reporting metrics (past 24h).

        Uses GET /api/v1/metrics with optional host filter.
        """
        import time as _time

        params: dict[str, Any] = {"from": int(_time.time()) - 86400}
        if host:
            params["host"] = host
        resp = await self._client.get("/api/v1/metrics", params=params)
        resp.raise_for_status()
        data = resp.json()
        return data.get("metrics", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_metric_tags(self, metric_name: str) -> list[str]:
        """Get all tag keys for a specific metric.

        Uses GET /api/v2/metrics/{metric_name}/all-tags
        """
        safe_name = metric_name.replace("/", "%2F")
        resp = await self._client.get(f"/api/v2/metrics/{safe_name}/all-tags")
        resp.raise_for_status()
        data = resp.json()
        tags_data = data.get("data", {}).get("attributes", {}).get("tags", [])
        return tags_data

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_metric_tag_values(
        self, metric_name: str, tag_key: str
    ) -> list[str]:
        """Get distinct values for a specific tag on a metric.

        Uses tag filtering via metric search to find values.
        Falls back to querying with a wildcard and reading tag values from results.
        """
        # Query the metric with a wildcard for the tag to discover values
        import time as _time

        now = int(_time.time())
        query = f"avg:{metric_name}{{{tag_key}:*}}"
        resp = await self._client.get(
            "/api/v1/query",
            params={"query": query, "from": now - 3600, "to": now},
        )
        resp.raise_for_status()
        data = resp.json()

        values: set[str] = set()
        for series in data.get("series", []):
            scope = series.get("scope", "")
            for part in scope.split(","):
                part = part.strip()
                if part.startswith(f"{tag_key}:"):
                    values.add(part.split(":", 1)[1])
        return sorted(values)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_hosts_by_tag(self, tag_filter: str) -> list[dict]:
        """Search for hosts matching a tag filter.

        Uses GET /api/v1/hosts?filter=<tag> to find hosts and their tags.
        """
        resp = await self._client.get(
            "/api/v1/hosts",
            params={"filter": tag_filter, "count": 10},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("host_list", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_tag_values(self, source: str = "") -> dict[str, list[str]]:
        """Get all host tags and their values.

        Uses GET /api/v1/tags/hosts to enumerate tag keys and values.
        """
        params: dict[str, Any] = {}
        if source:
            params["source"] = source
        resp = await self._client.get("/api/v1/tags/hosts", params=params)
        resp.raise_for_status()
        data = resp.json()
        return data.get("tags", {})

    # ── Dashboard Mining ─────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def list_dashboards(self) -> list[dict]:
        """List all dashboards (summary info only).

        Uses GET /api/v1/dashboard to get dashboard list.
        """
        resp = await self._client.get("/api/v1/dashboard")
        resp.raise_for_status()
        data = resp.json()
        return data.get("dashboards", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_dashboard(self, dashboard_id: str) -> dict:
        """Get full dashboard definition including widgets and queries.

        Uses GET /api/v1/dashboard/{dashboard_id}
        """
        resp = await self._client.get(f"/api/v1/dashboard/{dashboard_id}")
        resp.raise_for_status()
        return resp.json()

    async def find_dashboards_for_service(self, service: str) -> list[dict]:
        """Find dashboards that reference a specific service.

        Searches dashboard titles and descriptions for the service name,
        then fetches full definitions to extract metric queries.
        """
        all_dashboards = await self.list_dashboards()

        # Filter dashboards whose title mentions the service or related terms
        service_lower = service.lower()
        # Also try shortened forms (e.g., mk-sp-event-log-router -> event-log-router)
        service_parts = service_lower.split("-")
        search_terms = [service_lower]
        if len(service_parts) > 2:
            search_terms.append("-".join(service_parts[-3:]))
            search_terms.append("-".join(service_parts[-2:]))

        matching: list[dict] = []
        for dash in all_dashboards:
            title = (dash.get("title") or "").lower()
            desc = (dash.get("description") or "").lower()
            if any(term in title or term in desc for term in search_terms):
                matching.append(dash)

        # Fetch full details for matching dashboards (max 5 to avoid rate limits)
        results: list[dict] = []
        for dash in matching[:5]:
            try:
                full = await self.get_dashboard(dash["id"])
                results.append(full)
            except Exception as e:
                logger.warning("Failed to fetch dashboard %s: %s", dash.get("id"), e)

        return results

    @staticmethod
    def extract_metrics_from_dashboard(dashboard: dict) -> list[str]:
        """Extract all metric names referenced in a dashboard's widgets."""
        import re as _re

        metrics: set[str] = set()
        widgets = dashboard.get("widgets", [])

        def _extract_from_widget(widget: dict) -> None:
            definition = widget.get("definition", {})

            # Check requests in timeseries, query_value, toplist, etc.
            for request in definition.get("requests", []):
                # Standard query format
                for q_field in ("q", "query"):
                    query_str = request.get(q_field, "")
                    if isinstance(query_str, str) and query_str:
                        # Extract metric name: avg:metric.name{...}
                        for match in _re.finditer(
                            r"(?:avg|sum|max|min|count):([a-zA-Z0-9_.]+)\{",
                            query_str,
                        ):
                            metrics.add(match.group(1))

                # Nested queries (formulas, etc.)
                for query_obj in request.get("queries", []):
                    if isinstance(query_obj, dict):
                        q = query_obj.get("query", "")
                        if isinstance(q, str):
                            for match in _re.finditer(
                                r"(?:avg|sum|max|min|count):([a-zA-Z0-9_.]+)\{",
                                q,
                            ):
                                metrics.add(match.group(1))

            # Recurse into nested widgets (groups, etc.)
            for nested in definition.get("widgets", []):
                _extract_from_widget(nested)

        for widget in widgets:
            _extract_from_widget(widget)

        return sorted(metrics)

    async def __aenter__(self) -> DatadogClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ── Metrics ──────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def query_metrics(
        self,
        query: str,
        start: datetime,
        end: datetime,
    ) -> list[MetricSeries]:
        """Query Datadog metrics API (timeseries)."""
        resp = await self._client.get(
            "/api/v1/query",
            params={
                "query": query,
                "from": int(start.timestamp()),
                "to": int(end.timestamp()),
            },
        )
        resp.raise_for_status()
        data = resp.json()

        results: list[MetricSeries] = []
        for series in data.get("series", []):
            points = [
                MetricDataPoint(
                    timestamp=safe_timestamp(pt[0] / 1000),
                    value=pt[1] if pt[1] is not None else 0.0,
                )
                for pt in series.get("pointlist", [])
            ]
            results.append(
                MetricSeries(
                    metric_name=series.get("metric", query),
                    display_name=series.get("display_name", series.get("expression", query)),
                    points=points,
                    unit=series.get("unit", [{}])[0].get("name", "") if series.get("unit") else "",
                )
            )
        return results

    async def fetch_service_metrics(
        self,
        service: str,
        start: datetime,
        end: datetime,
    ) -> list[MetricSeries]:
        """Fetch standard service-level metrics (latency, errors, throughput).

        Tries APM trace metrics first (works for HTTP-instrumented services),
        then falls back to system-level metrics.
        """
        queries = [
            # APM metrics (may not exist for non-HTTP services like Flink)
            f"avg:trace.http.request.duration{{service:{service}}}",
            f"sum:trace.http.request.errors{{service:{service}}}.as_count()",
            f"sum:trace.http.request.hits{{service:{service}}}.as_count()",
            # System metrics
            f"max:system.cpu.user{{service:{service}}}",
            f"avg:system.mem.used{{service:{service}}}",
            # Container metrics (broader compatibility)
            f"avg:container.cpu.usage{{service:{service}}}",
            f"avg:container.memory.usage{{service:{service}}}",
        ]
        tasks = [self.query_metrics(q, start, end) for q in queries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_series: list[MetricSeries] = []
        for r in results:
            if isinstance(r, list):
                all_series.extend(r)
            elif isinstance(r, Exception):
                logger.warning("Metric query failed: %s", r)
        return all_series

    # ── Logs ─────────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_logs(
        self,
        query: str,
        start: datetime,
        end: datetime,
        limit: Optional[int] = None,
    ) -> list[LogEntry]:
        """Search logs using Datadog Log Search API v2."""
        limit = limit or self.config.max_log_lines
        # Ensure timestamps are UTC and format correctly for Datadog API
        start_utc = ensure_utc(start)
        end_utc = ensure_utc(end)
        body = {
            "filter": {
                "query": query,
                "from": start_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "to": end_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "sort": "timestamp",
            "page": {"limit": min(limit, 1000)},
        }
        resp = await self._client.post("/api/v2/logs/events/search", json=body)
        resp.raise_for_status()
        data = resp.json()

        entries: list[LogEntry] = []
        for log in data.get("data", []):
            attrs = log.get("attributes", {})
            entries.append(
                LogEntry(
                    timestamp=safe_fromisoformat(attrs.get("timestamp", "")),
                    message=attrs.get("message", ""),
                    service=attrs.get("service", ""),
                    status=attrs.get("status", "info"),
                    host=attrs.get("host", ""),
                    attributes=attrs.get("attributes", {}),
                    trace_id=attrs.get("attributes", {}).get("trace_id", ""),
                )
            )
        return entries

    async def fetch_service_logs(
        self,
        service: str,
        start: datetime,
        end: datetime,
        namespace: str = "",
        container_name: str = "",
    ) -> list[LogEntry]:
        """Fetch error and warning logs for a service.

        Searches using multiple tag combinations to maximize coverage:
        - service:<name>
        - kube_namespace:<namespace> (if provided)
        - container_name:<name> (if provided)
        - source:<service-related>
        """
        queries = [
            f"service:{service} status:error",
            f"service:{service} status:warn",
        ]

        # Broaden search with namespace tag
        if namespace:
            queries.append(f"kube_namespace:{namespace} status:error")

        # Try container name
        if container_name:
            queries.append(f"kube_container_name:{container_name} status:error")

        # Try partial service name (e.g., last 2-3 segments)
        parts = service.split("-")
        if len(parts) > 2:
            short_name = "-".join(parts[-2:])
            queries.append(f"*{short_name}* status:error")

        tasks = [self.search_logs(q, start, end, limit=500) for q in queries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_logs: list[LogEntry] = []
        seen_msgs: set[str] = set()
        for r in results:
            if isinstance(r, list):
                for log in r:
                    # Deduplicate by timestamp + message prefix
                    key = f"{log.timestamp}:{log.message[:50]}"
                    if key not in seen_msgs:
                        seen_msgs.add(key)
                        all_logs.append(log)
            elif isinstance(r, Exception):
                logger.warning("Log search failed: %s", r)

        all_logs.sort(key=lambda l: l.timestamp)
        return all_logs

    # ── Traces ───────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_traces(
        self,
        query: str,
        start: datetime,
        end: datetime,
        limit: Optional[int] = None,
    ) -> list[TraceSpan]:
        """Search APM traces using Datadog Trace Search API v2."""
        limit = limit or self.config.max_trace_spans
        start_utc = ensure_utc(start)
        end_utc = ensure_utc(end)
        body = {
            "filter": {
                "query": query,
                "from": start_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "to": end_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "sort": "timestamp",
            "page": {"limit": min(limit, 500)},
        }
        resp = await self._client.post("/api/v2/spans/events/search", json=body)
        resp.raise_for_status()
        data = resp.json()

        spans: list[TraceSpan] = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            spans.append(
                TraceSpan(
                    trace_id=attrs.get("trace_id", ""),
                    span_id=attrs.get("span_id", ""),
                    parent_id=attrs.get("parent_id", ""),
                    service=attrs.get("service", ""),
                    operation=attrs.get("operation_name", ""),
                    resource=attrs.get("resource_name", ""),
                    duration_ns=attrs.get("duration", 0),
                    start_time=safe_timestamp(attrs.get("start", 0) / 1e9),
                    status="error" if attrs.get("is_error") else "ok",
                    error_message=attrs.get("meta", {}).get("error.message", ""),
                    error_type=attrs.get("meta", {}).get("error.type", ""),
                    meta=attrs.get("meta", {}),
                )
            )
        return spans

    async def fetch_service_traces(
        self,
        service: str,
        start: datetime,
        end: datetime,
    ) -> list[TraceSpan]:
        """Fetch error traces and slow traces for a service."""
        queries = [
            f"service:{service} status:error",
            f"service:{service} @duration:>1s",
        ]
        tasks = [self.search_traces(q, start, end, limit=250) for q in queries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_spans: list[TraceSpan] = []
        seen_ids: set[str] = set()
        for r in results:
            if isinstance(r, list):
                for span in r:
                    key = f"{span.trace_id}:{span.span_id}"
                    if key not in seen_ids:
                        seen_ids.add(key)
                        all_spans.append(span)
            elif isinstance(r, Exception):
                logger.warning("Trace search failed: %s", r)
        return all_spans

    # ── Service Map / Dependencies ────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_service_dependencies(
        self,
        service: str,
        start: datetime,
        end: datetime,
    ) -> ServiceNode:
        """Get service map/dependencies from Datadog APM."""
        resp = await self._client.get(
            "/api/v1/service_dependencies",
            params={
                "service": service,
                "start": int(start.timestamp()),
                "end": int(end.timestamp()),
                "env": "production",
            },
        )
        resp.raise_for_status()
        data = resp.json()

        deps = [
            ServiceDependency(
                source_service=service,
                target_service=dep.get("name", ""),
                call_type=dep.get("type", "http"),
                avg_latency_ms=dep.get("avg_duration_ms", 0.0),
                error_rate=dep.get("error_rate", 0.0),
                calls_per_minute=dep.get("hits_per_minute", 0.0),
            )
            for dep in data.get("dependencies", [])
        ]
        dependents = [
            ServiceDependency(
                source_service=dep.get("name", ""),
                target_service=service,
                call_type=dep.get("type", "http"),
                avg_latency_ms=dep.get("avg_duration_ms", 0.0),
                error_rate=dep.get("error_rate", 0.0),
                calls_per_minute=dep.get("hits_per_minute", 0.0),
            )
            for dep in data.get("dependents", [])
        ]
        return ServiceNode(
            name=service,
            service_type=data.get("type", ""),
            dependencies=deps,
            dependents=dependents,
        )

    # ── Events ───────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_events(
        self,
        start: datetime,
        end: datetime,
        tags: Optional[list[str]] = None,
        sources: Optional[list[str]] = None,
    ) -> list[DatadogEvent]:
        """Fetch events from the Datadog Event Stream."""
        params: dict[str, Any] = {
            "start": int(start.timestamp()),
            "end": int(end.timestamp()),
        }
        if tags:
            params["tags"] = ",".join(tags)
        if sources:
            params["sources"] = ",".join(sources)

        resp = await self._client.get("/api/v1/events", params=params)
        resp.raise_for_status()
        data = resp.json()

        return [
            DatadogEvent(
                timestamp=safe_timestamp(evt.get("date_happened", 0)),
                title=evt.get("title", ""),
                text=evt.get("text", ""),
                source=evt.get("source", ""),
                tags=evt.get("tags", []),
                alert_type=evt.get("alert_type", ""),
            )
            for evt in data.get("events", [])
        ]

    async def get_deployment_events(
        self,
        service: str,
        start: datetime,
        end: datetime,
    ) -> list[DatadogEvent]:
        """Fetch deployment-specific events."""
        return await self.get_events(
            start=start,
            end=end,
            tags=[f"service:{service}"],
            sources=["deploy", "jenkins", "github", "argocd", "spinnaker"],
        )

    # ── Monitors ─────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_monitor(self, monitor_id: int) -> dict:
        """Fetch a single monitor definition by ID."""
        resp = await self._client.get(f"/api/v1/monitor/{monitor_id}")
        resp.raise_for_status()
        return resp.json()

    async def fetch_infra_metrics(
        self,
        tags: dict[str, str],
        start: datetime,
        end: datetime,
    ) -> list[MetricSeries]:
        """Fetch K8s infrastructure metrics for given tags.

        Includes: CPU usage/limits/throttling, memory usage/limits,
        pod restarts, OOMKills, pod status, network, and disk.
        """
        tag_filter = ",".join(f"{k}:{v}" for k, v in tags.items())
        queries = [
            # CPU
            f"avg:kubernetes.cpu.usage.total{{{tag_filter}}}",
            f"avg:kubernetes.cpu.limits{{{tag_filter}}}",
            f"avg:kubernetes.cpu.requests{{{tag_filter}}}",
            f"avg:container.cpu.throttled{{{tag_filter}}}",
            f"avg:container.cpu.usage{{{tag_filter}}}",
            # Memory
            f"avg:kubernetes.memory.usage{{{tag_filter}}}",
            f"avg:kubernetes.memory.limits{{{tag_filter}}}",
            f"avg:container.memory.usage{{{tag_filter}}}",
            # Pod health
            f"sum:kubernetes.containers.restarts{{{tag_filter}}}.as_count()",
            f"sum:kubernetes_state.container.status_report.count.waiting{{{tag_filter}}}",
            f"max:kubernetes_state.container.oom_killed{{{tag_filter}}}",
            f"avg:kubernetes.pods.running{{{tag_filter}}}",
            # Network
            f"avg:kubernetes.network.rx_bytes{{{tag_filter}}}",
            f"avg:kubernetes.network.tx_bytes{{{tag_filter}}}",
        ]
        tasks = [self.query_metrics(q, start, end) for q in queries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_series: list[MetricSeries] = []
        for r in results:
            if isinstance(r, list):
                all_series.extend(r)
            elif isinstance(r, Exception):
                logger.warning("Infra metric query failed: %s", r)
        return all_series

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_monitors(
        self,
        query: str = "",
        tags: Optional[list[str]] = None,
    ) -> list[dict]:
        """Search for all monitors matching a query or tag filter.

        Returns full monitor definitions including their metric queries.
        """
        params: dict[str, Any] = {}
        if query:
            params["query"] = query
        if tags:
            params["monitor_tags"] = ",".join(tags)
        resp = await self._client.get("/api/v1/monitor", params=params)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []

    @staticmethod
    def extract_metrics_from_monitors(monitors: list[dict]) -> list[str]:
        """Extract metric names from monitor query definitions."""
        import re as _re

        metrics: set[str] = set()
        for mon in monitors:
            query = mon.get("query", "")
            if isinstance(query, str) and query:
                for match in _re.finditer(
                    r"(?:avg|sum|max|min|count|percentile)\(?:?([a-zA-Z0-9_.]+)\{",
                    query,
                ):
                    metrics.add(match.group(1))
                # Also try simpler pattern without aggregation prefix
                for match in _re.finditer(
                    r"([a-zA-Z][a-zA-Z0-9_.]+\.[a-zA-Z][a-zA-Z0-9_.]+)\{",
                    query,
                ):
                    metrics.add(match.group(1))
        return sorted(metrics)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def get_triggered_monitors(
        self,
        service: str,
    ) -> list[MonitorStatus]:
        """Get monitors currently in alert/warn state for a service."""
        resp = await self._client.get(
            "/api/v1/monitor",
            params={
                "monitor_tags": f"service:{service}",
                "group_states": "alert,warn",
            },
        )
        resp.raise_for_status()
        data = resp.json()

        return [
            MonitorStatus(
                monitor_id=mon.get("id", 0),
                name=mon.get("name", ""),
                status=mon.get("overall_state", ""),
                message=mon.get("message", ""),
                tags=mon.get("tags", []),
            )
            for mon in data
            if isinstance(data, list)
        ]
