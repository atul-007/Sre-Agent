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

    return IncidentQuery(
        raw_query=query,
        service=data.get("service", "unknown"),
        symptom_type=symptom,
        start_time=start_time,
        end_time=end_time,
        environment=data.get("environment", "production"),
    )
