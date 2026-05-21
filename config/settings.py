"""Configuration settings for the SRE Agent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class DatadogConfig:
    api_key: str = field(default_factory=lambda: os.environ.get("DD_API_KEY", ""))
    app_key: str = field(default_factory=lambda: os.environ.get("DD_APP_KEY", ""))
    site: str = field(default_factory=lambda: os.environ.get("DD_SITE", "datadoghq.com"))
    timeout_seconds: int = 30
    max_retries: int = 3
    max_log_lines: int = 1000
    max_trace_spans: int = 500
    metric_query_batch_size: int = 10


@dataclass(frozen=True)
class ClaudeConfig:
    api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    base_url: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_BASE_URL", ""))
    model: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"))
    max_tokens: int = 8192
    # Some newer models (e.g. claude-opus-4-7-lb behind LiteLLM) reject the
    # temperature parameter as deprecated. Set to None (default) to omit it
    # from the API call entirely. Set a float to send it for older models.
    temperature: Optional[float] = None
    max_context_chars: int = 150_000  # Budget for data payload in prompts


@dataclass(frozen=True)
class SlackConfig:
    bot_token: str = field(default_factory=lambda: os.environ.get("SLACK_BOT_TOKEN", ""))
    app_token: str = field(default_factory=lambda: os.environ.get("SLACK_APP_TOKEN", ""))
    signing_secret: str = field(default_factory=lambda: os.environ.get("SLACK_SIGNING_SECRET", ""))
    socket_mode: bool = field(
        default_factory=lambda: bool(os.environ.get("SLACK_APP_TOKEN", ""))
    )
    # Cloud Run injects PORT; SLACK_BOT_PORT is the legacy local-dev override.
    port: int = field(
        default_factory=lambda: int(
            os.environ.get("PORT") or os.environ.get("SLACK_BOT_PORT") or "3000"
        )
    )


def _load_team_knowledge() -> str:
    """Load team_knowledge.md from project root if present.

    Optional file that lets users encode org-specific facts (service
    ownership, known issues, false-positive monitors, escalation paths)
    that get injected into the conclusion prompt.
    """
    path_env = os.environ.get("TEAM_KNOWLEDGE_PATH", "")
    if path_env and os.path.isfile(path_env):
        path = path_env
    else:
        # Default: project root (3 levels up from config/settings.py)
        here = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(os.path.dirname(here), "team_knowledge.md")
        if not os.path.isfile(candidate):
            return ""
        path = candidate
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        # Cap at ~10K chars to keep prompt size sane
        if len(content) > 10_000:
            content = content[:10_000] + "\n\n[truncated — team_knowledge.md exceeded 10K chars]"
        return content
    except OSError:
        return ""


@dataclass(frozen=True)
class AgentConfig:
    datadog: DatadogConfig = field(default_factory=DatadogConfig)
    claude: ClaudeConfig = field(default_factory=ClaudeConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)
    correlation_window_seconds: int = 300  # 5 min window for temporal correlation
    max_upstream_depth: int = 3
    max_downstream_depth: int = 3
    parallel_fetch_limit: int = 20
    max_investigation_steps: int = 15
    investigation_confidence_threshold: float = 0.85
    # v2 investigation settings
    max_retry_attempts: int = 3
    time_window_expansion_factor: float = 2.0
    min_signal_coverage_to_conclude: float = 0.7
    confidence_cap_on_sparse_data: float = 0.4
    confidence_cap_no_direct_evidence: float = 0.6
    # v3 investigation settings
    max_investigation_seconds: int = 600
    max_depth_steps: int = 10
    max_downstream_steps: int = 15
    auto_per_pod_breakdown: bool = True
    # v4: Team knowledge loaded from team_knowledge.md (empty if not present)
    team_knowledge: str = field(default_factory=_load_team_knowledge)
    # v4: Time-range expansion when initial window has no anomalies
    enable_time_range_expansion: bool = True
    time_range_expansion_hours: int = 24
