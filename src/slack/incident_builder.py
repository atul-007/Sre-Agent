"""Build an IncidentQuery from Slack alert context and Datadog monitor definition."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from src.datadog.client import DatadogClient
from src.models.incident import IncidentQuery, SymptomType
from src.slack.parser import SlackAlertContext

logger = logging.getLogger(__name__)

# Keyword patterns for symptom type classification
_SYMPTOM_PATTERNS: list[tuple[re.Pattern, SymptomType]] = [
    (re.compile(r"latency|duration|p99|p95|p50|response.time", re.I), SymptomType.LATENCY),
    (re.compile(r"error|5xx|4xx|fault|exception", re.I), SymptomType.ERROR_RATE),
    (re.compile(r"cpu|memory|mem|disk|saturat|throttl", re.I), SymptomType.SATURATION),
    (re.compile(r"hits|throughput|request.*count|rps|qps|traffic", re.I), SymptomType.THROUGHPUT),
    (re.compile(r"availab|uptime|health|down", re.I), SymptomType.AVAILABILITY),
]


def _classify_symptom(query: str, name: str = "") -> SymptomType:
    """Determine symptom type from monitor query and name."""
    combined = f"{query} {name}"
    for pattern, symptom in _SYMPTOM_PATTERNS:
        if pattern.search(combined):
            return symptom
    return SymptomType.UNKNOWN


def _extract_service_from_query(query: str) -> str | None:
    """Try to extract a service name from a Datadog metric query."""
    match = re.search(r"service:([^\s,}]+)", query)
    return match.group(1) if match else None


async def build_incident_from_alert(
    alert_context: SlackAlertContext,
    dd_client: DatadogClient,
) -> IncidentQuery:
    """Build an IncidentQuery from a Slack alert context.

    Fetches the monitor definition from Datadog to extract the full query,
    service name, and threshold information. Falls back to tag-based
    extraction if the monitor fetch fails.
    """
    monitor_name = ""
    monitor_query = ""
    monitor_tags: list[str] = []
    thresholds: dict = {}

    # Fetch monitor definition
    try:
        monitor_def = await dd_client.get_monitor(alert_context.monitor_id)
        monitor_name = monitor_def.get("name", "")
        monitor_query = monitor_def.get("query", "")
        monitor_tags = monitor_def.get("tags", [])
        thresholds = monitor_def.get("options", {}).get("thresholds", {})
        logger.info(
            "Fetched monitor %d: %s", alert_context.monitor_id, monitor_name
        )
    except Exception as e:
        logger.warning(
            "Failed to fetch monitor %d: %s. Using alert context only.",
            alert_context.monitor_id, e,
        )

    # Determine service name (priority order)
    service = (
        alert_context.group_tags.get("service")
        or _extract_service_from_tags(monitor_tags)
        or _extract_service_from_query(monitor_query)
        or _extract_service_from_query(alert_context.metric_query or "")
        or alert_context.group_tags.get("kube_deployment")
        or "unknown"
    )

    # Determine symptom type
    symptom = _classify_symptom(
        monitor_query or alert_context.metric_query or "",
        monitor_name or alert_context.alert_title,
    )

    # Determine time window
    now = datetime.now(timezone.utc)
    if alert_context.from_ts and alert_context.to_ts:
        start_time = alert_context.from_ts
        end_time = alert_context.to_ts
    elif alert_context.to_ts:
        start_time = alert_context.to_ts - timedelta(hours=1)
        end_time = alert_context.to_ts
    else:
        start_time = now - timedelta(hours=1)
        end_time = now

    # Determine environment
    environment = (
        alert_context.group_tags.get("env")
        or alert_context.group_tags.get("environment")
        or _extract_env_from_tags(monitor_tags)
        or "production"
    )

    # Build additional context for the RCA pipeline
    context_parts = []
    if monitor_name:
        context_parts.append(f"Monitor: {monitor_name}")
    if monitor_query:
        context_parts.append(f"Query: {monitor_query}")
    if thresholds:
        context_parts.append(f"Thresholds: {thresholds}")
    if alert_context.threshold:
        context_parts.append(f"Current value: {alert_context.threshold}")
    if alert_context.group_tags:
        tags_str = ", ".join(f"{k}={v}" for k, v in alert_context.group_tags.items())
        context_parts.append(f"Tags: {tags_str}")
    if alert_context.alert_title:
        context_parts.append(f"Alert: {alert_context.alert_title}")

    return IncidentQuery(
        raw_query=f"Datadog alert: {monitor_name or alert_context.alert_title} "
                  f"for {service} [{environment}]",
        service=service,
        symptom_type=symptom,
        start_time=start_time,
        end_time=end_time,
        environment=environment,
        additional_context="\n".join(context_parts),
        monitor_id=alert_context.monitor_id,
        monitor_query=monitor_query,
        source_tags=alert_context.group_tags,
    )


def _extract_service_from_tags(tags: list[str]) -> str | None:
    """Extract service name from a list of Datadog tags."""
    for tag in tags:
        if tag.startswith("service:"):
            return tag.split(":", 1)[1]
    return None


def _extract_env_from_tags(tags: list[str]) -> str | None:
    """Extract environment from a list of Datadog tags."""
    for tag in tags:
        if tag.startswith("env:"):
            return tag.split(":", 1)[1]
    return None
