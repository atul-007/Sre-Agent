"""Parse Datadog alert messages from Slack to extract structured incident context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qs, urlparse

# Known Datadog infrastructure tag keys
KNOWN_TAG_KEYS = {
    "container_name", "pod_name", "kube_deployment", "kube_namespace",
    "kube_cluster_name", "cluster-name", "cluster_name", "host", "service",
    "env", "environment", "kube_stateful_set", "kube_daemon_set",
    "kube_replica_set", "image_name", "short_image", "kube_container_name",
}

MONITOR_URL_PATTERN = re.compile(
    r"https?://app\.datadoghq\.com/monitors/(\d+)([^\s>)\]]*)"
)

TAG_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in KNOWN_TAG_KEYS) + r"):([^\s,>)\]]+)"
)


@dataclass
class SlackAlertContext:
    """Structured data extracted from a Datadog alert message in Slack."""

    monitor_id: int
    monitor_url: str
    group_tags: dict[str, str] = field(default_factory=dict)
    from_ts: Optional[datetime] = None
    to_ts: Optional[datetime] = None
    event_id: Optional[str] = None
    metric_query: Optional[str] = None
    threshold: Optional[str] = None
    alert_title: str = ""
    raw_text: str = ""


def parse_monitor_url(url: str) -> dict:
    """Extract monitor_id, group tags, time range, and event_id from a Datadog monitor URL.

    Example URL:
        https://app.datadoghq.com/monitors/12345?group=container_name:foo,pod_name:bar&from_ts=1700000000000&to_ts=1700003600000&event_id=abc123
    """
    parsed = urlparse(url)

    # Extract monitor_id from path: /monitors/{id} or /monitors#12345
    monitor_id = 0
    path_match = re.search(r"/monitors/(\d+)", parsed.path)
    if path_match:
        monitor_id = int(path_match.group(1))
    elif parsed.fragment and parsed.fragment.isdigit():
        monitor_id = int(parsed.fragment)

    params = parse_qs(parsed.query)

    # Parse group tags (e.g., "container_name:foo,pod_name:bar")
    group_tags: dict[str, str] = {}
    for group_value in params.get("group", []):
        for pair in group_value.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                group_tags[k.strip()] = v.strip()

    # Parse timestamps (Datadog uses millisecond epoch)
    from_ts = None
    to_ts = None
    if "from_ts" in params:
        try:
            from_ts = datetime.fromtimestamp(
                int(params["from_ts"][0]) / 1000, tz=timezone.utc
            )
        except (ValueError, IndexError):
            pass
    if "to_ts" in params:
        try:
            to_ts = datetime.fromtimestamp(
                int(params["to_ts"][0]) / 1000, tz=timezone.utc
            )
        except (ValueError, IndexError):
            pass

    event_id = params.get("event_id", [None])[0]

    return {
        "monitor_id": monitor_id,
        "group_tags": group_tags,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "event_id": event_id,
    }


def extract_tags_from_text(text: str) -> dict[str, str]:
    """Extract known Datadog infrastructure tags from free text."""
    tags: dict[str, str] = {}
    for match in TAG_PATTERN.finditer(text):
        tags[match.group(1)] = match.group(2)
    return tags


def _extract_monitor_urls(text: str) -> list[str]:
    """Find all Datadog monitor URLs in text."""
    return [
        f"https://app.datadoghq.com/monitors/{m.group(1)}{m.group(2)}"
        for m in MONITOR_URL_PATTERN.finditer(text)
    ]


def _collect_text_from_blocks(blocks: list[dict]) -> str:
    """Recursively extract text content from Slack Block Kit blocks."""
    parts: list[str] = []
    for block in blocks:
        if "text" in block:
            text_obj = block["text"]
            if isinstance(text_obj, dict):
                parts.append(text_obj.get("text", ""))
            elif isinstance(text_obj, str):
                parts.append(text_obj)
        for child_key in ("elements", "fields"):
            if child_key in block:
                parts.append(_collect_text_from_blocks(block[child_key]))
    return "\n".join(parts)


def parse_datadog_alert_message(
    text: str,
    attachments: list[dict] | None = None,
    blocks: list[dict] | None = None,
) -> SlackAlertContext:
    """Parse a Datadog alert Slack message into structured context.

    Searches for monitor URLs in the message text, attachments, and blocks.
    Extracts tags, metric query, and threshold information from the body.

    Raises:
        ValueError: If no Datadog monitor URL is found in the message.
    """
    attachments = attachments or []
    blocks = blocks or []

    # Collect all text sources
    all_text_parts = [text]
    for att in attachments:
        all_text_parts.append(att.get("text", ""))
        all_text_parts.append(att.get("fallback", ""))
        all_text_parts.append(att.get("pretext", ""))
        if "title_link" in att:
            all_text_parts.append(att["title_link"])
    if blocks:
        all_text_parts.append(_collect_text_from_blocks(blocks))

    combined_text = "\n".join(all_text_parts)

    # Find monitor URLs
    urls = _extract_monitor_urls(combined_text)
    if not urls:
        raise ValueError(
            "No Datadog monitor URL found in message. "
            "Please use this command in a thread containing a Datadog alert."
        )

    # Parse the first URL found
    url_data = parse_monitor_url(urls[0])

    # Extract tags from message body (merge with URL group tags)
    body_tags = extract_tags_from_text(combined_text)
    all_tags = {**body_tags, **url_data["group_tags"]}  # URL tags take precedence

    # Extract alert title (first line of text, stripped of Slack formatting)
    title_match = re.match(r"[*_~]*([^*_~\n]+)", text.strip())
    alert_title = title_match.group(1).strip() if title_match else text[:200].strip()

    # Extract metric query (common patterns in Datadog alerts)
    metric_query = None
    query_match = re.search(
        r"(?:avg|sum|max|min|count)\s*\([^)]*\)\s*:\s*(.+?)(?:\n|$)", combined_text
    )
    if query_match:
        metric_query = query_match.group(0).strip()
    else:
        # Try alternate format: "Query: ..."
        alt_match = re.search(r"(?:Query|query):\s*(.+?)(?:\n|$)", combined_text)
        if alt_match:
            metric_query = alt_match.group(1).strip()

    # Extract threshold
    threshold = None
    threshold_match = re.search(
        r"(?:Metric value|Value|threshold)[:\s]*([0-9.]+%?)", combined_text, re.IGNORECASE
    )
    if threshold_match:
        threshold = threshold_match.group(1)

    return SlackAlertContext(
        monitor_id=url_data["monitor_id"],
        monitor_url=urls[0],
        group_tags=all_tags,
        from_ts=url_data["from_ts"],
        to_ts=url_data["to_ts"],
        event_id=url_data["event_id"],
        metric_query=metric_query,
        threshold=threshold,
        alert_title=alert_title,
        raw_text=combined_text,
    )
