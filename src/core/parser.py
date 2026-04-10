"""Parses natural language incident queries into structured IncidentQuery objects using Claude."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import anthropic

from config.settings import ClaudeConfig
from src.models.incident import IncidentQuery, SymptomType

PARSE_PROMPT = """Parse this incident investigation query into structured fields.

Query: "{query}"
Current time: {now}

Extract:
- service: the primary service name
- symptom_type: one of [latency, error_rate, availability, throughput, saturation, unknown]
- start_time: ISO 8601 timestamp (if relative like "1 hour ago", compute from current time)
- end_time: ISO 8601 timestamp (defaults to current time if not specified)
- environment: production/staging/etc (default: production)

Return ONLY a JSON object with these fields. No explanation."""


async def parse_incident_query(
    query: str,
    config: ClaudeConfig,
    now: "datetime | None" = None,
) -> IncidentQuery:
    """Parse a natural language query into a structured IncidentQuery."""
    now = now or datetime.now(timezone.utc)

    client_kwargs: dict = {"api_key": config.api_key}
    if config.base_url:
        client_kwargs["base_url"] = config.base_url
    client = anthropic.AsyncAnthropic(**client_kwargs)
    response = await client.messages.create(
        model=config.model,
        max_tokens=500,
        temperature=0.0,
        messages=[
            {
                "role": "user",
                "content": PARSE_PROMPT.format(query=query, now=now.isoformat()),
            }
        ],
    )

    # Handle different response formats (standard Anthropic vs LiteLLM proxy)
    if hasattr(response, 'content') and response.content:
        text = response.content[0].text
    elif isinstance(response, str):
        text = response
    else:
        # Try to extract text from various possible formats
        text = str(response)

    json_match = re.search(r"\{[\s\S]*\}", text)
    if not json_match:
        raise ValueError(f"Failed to parse query: {text}")

    data = json.loads(json_match.group())

    symptom_map = {v.value: v for v in SymptomType}
    symptom = symptom_map.get(data.get("symptom_type", ""), SymptomType.UNKNOWN)

    # Default end_time to now, start_time to 1 hour before
    end_time = now
    start_time = now - timedelta(hours=1)

    if data.get("end_time"):
        try:
            end_time = datetime.fromisoformat(data["end_time"].replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

    if data.get("start_time"):
        try:
            start_time = datetime.fromisoformat(data["start_time"].replace("Z", "+00:00"))
        except (ValueError, TypeError):
            start_time = end_time - timedelta(hours=1)

    # If start and end are identical (zero-width window), expand to 1 hour
    if start_time == end_time:
        start_time = end_time - timedelta(hours=1)

    # Extract structured tags from the alert text (Datadog alerts include them)
    source_tags = _extract_tags_from_alert(query)

    # Extract timestamps from Datadog monitor URL if present
    url_start, url_end = _extract_timestamps_from_url(query)
    if url_start and url_end:
        start_time = url_start
        end_time = url_end

    # Extract monitor ID from URL if present
    monitor_id = _extract_monitor_id(query)

    # Extract monitor query if present
    monitor_query = ""
    monitor_match = re.search(
        r"(?:avg|sum|max|min|count)\(last_\d+[mhd]\):.*?(?:>|<|>=|<=)\s*\d+",
        query,
    )
    if monitor_match:
        monitor_query = monitor_match.group(0)

    return IncidentQuery(
        raw_query=query,
        service=data.get("service", "unknown"),
        symptom_type=symptom,
        start_time=start_time,
        end_time=end_time,
        environment=data.get("environment", "production"),
        source_tags=source_tags,
        monitor_id=monitor_id,
        monitor_query=monitor_query,
    )


def _extract_tags_from_alert(text: str) -> dict[str, str]:
    """Extract Datadog tags from alert text.

    Looks for patterns like:
    - container_name:query-server
    - kube_namespace:my-service-prod
    - cluster-name:cluster-prod-us-east-01
    - Tags section: container_name:query-server, kube_deployment:query-server
    """
    tags: dict[str, str] = {}

    # Known tag keys to extract
    tag_keys = [
        "kube_namespace", "kube_deployment", "kube_service",
        "container_name", "kube_container_name",
        "pod_name", "kube_pod_name",
        "cluster-name", "kube_cluster_name",
        "env", "environment", "service", "app",
    ]

    for key in tag_keys:
        # Match tag:value patterns (value is alphanumeric with hyphens, dots, underscores)
        pattern = rf"{re.escape(key)}:([a-zA-Z0-9._-]+)"
        match = re.search(pattern, text)
        if match:
            tags[key] = match.group(1)

    return tags


def _extract_monitor_id(text: str) -> int | None:
    """Extract monitor ID from a Datadog monitor URL or alert text.

    Handles:
      - monitors/12345 (URL path)
      - monitors#12345 (URL fragment)
      - Monitor #12345 or Monitor ID: 12345 (alert text)
    """
    for pattern in [
        r"monitors[/#](\d+)",
        r"[Mm]onitor\s*#?\s*(?:ID:?\s*)?(\d{4,})",
    ]:
        match = re.search(pattern, text)
        if match:
            return int(match.group(1))
    return None


def _extract_timestamps_from_url(text: str) -> tuple[datetime | None, datetime | None]:
    """Extract from_ts and to_ts from a Datadog monitor URL in the text."""
    from_match = re.search(r"from_ts=(\d+)", text)
    to_match = re.search(r"to_ts=(\d+)", text)

    start = None
    end = None

    if from_match:
        try:
            start = datetime.fromtimestamp(
                int(from_match.group(1)) / 1000, tz=timezone.utc
            )
        except (ValueError, OSError):
            pass

    if to_match:
        try:
            end = datetime.fromtimestamp(
                int(to_match.group(1)) / 1000, tz=timezone.utc
            )
        except (ValueError, OSError):
            pass

    return start, end
