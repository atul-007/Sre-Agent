"""Stateless utility functions for the investigation engine."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from src.models.incident import (
    InvestigationActionType,
    InvestigationTrace,
    ObservabilityData,
)

logger = logging.getLogger(__name__)


def is_empty_result(raw_data: Any) -> bool:
    """Check if fetch result is effectively empty."""
    if raw_data is None:
        return True
    if isinstance(raw_data, list) and len(raw_data) == 0:
        return True
    if isinstance(raw_data, dict) and not raw_data:
        return True
    return False


def parse_json_response(response: str, fallback: dict) -> dict:
    """Extract JSON from Claude's response."""
    json_match = re.search(r"\{[\s\S]*\}", response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    logger.warning("Failed to parse JSON from response, using fallback")
    return fallback


def ensure_str_list(items: list) -> list[str]:
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


def format_trace_summary(trace: InvestigationTrace) -> str:
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


def format_current_hypotheses(trace: InvestigationTrace) -> str:
    """Get the latest hypotheses from the trace (legacy fallback)."""
    for step in reversed(trace.steps):
        if step.hypotheses:
            return "\n".join(f"- {h}" for h in step.hypotheses)
    return ""


def format_data_summary(data: ObservabilityData) -> str:
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


def format_full_trace(trace: InvestigationTrace) -> str:
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


def format_raw_data(raw_data: Any, action: InvestigationActionType) -> str:
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


def merge_data(
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
