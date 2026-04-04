"""Claude reasoning layer — multi-pass analysis using Claude API."""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from config.settings import ClaudeConfig
from src.claude.prompts import (
    CAUSAL_REASONING_PROMPT,
    HYPOTHESIS_GENERATION_PROMPT,
    INITIAL_ANALYSIS_PROMPT,
    INVESTIGATION_SYSTEM_PROMPT,
    REMEDIATION_PROMPT,
    SYSTEM_PROMPT,
)

logger = logging.getLogger(__name__)


class ClaudeReasoning:
    """Multi-pass reasoning engine using Claude for incident analysis."""

    def __init__(self, config: ClaudeConfig) -> None:
        self.config = config
        client_kwargs: dict = {"api_key": config.api_key}
        if config.base_url:
            client_kwargs["base_url"] = config.base_url
        self.client = anthropic.AsyncAnthropic(**client_kwargs)
        self.conversation_history: list[dict] = []
        self.dynamic_history: list[dict] = []

    async def _query(self, user_message: str, *, expect_json: bool = False) -> str:
        """Send a message to Claude and get a response, maintaining conversation context."""
        self.conversation_history.append({"role": "user", "content": user_message})

        response = await self.client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=SYSTEM_PROMPT,
            messages=self.conversation_history,
        )

        # Handle different response formats (standard Anthropic vs LiteLLM proxy)
        if hasattr(response, 'content') and response.content:
            assistant_text = response.content[0].text
        elif isinstance(response, str):
            assistant_text = response
        else:
            # Try to extract text from various possible formats
            assistant_text = str(response)

        self.conversation_history.append({"role": "assistant", "content": assistant_text})

        logger.info(
            "Claude response: %d tokens in, %d tokens out",
            response.usage.input_tokens,
            response.usage.output_tokens,
        )

        return assistant_text

    async def initial_analysis(
        self,
        incident_context: dict,
        anomaly_summary: dict,
        timeline: list[dict],
        service_correlation: dict,
        monitors: list[dict],
        deployments: list[dict],
    ) -> str:
        """Phase 1: Initial symptom identification and event sequencing."""
        self.conversation_history = []  # Fresh conversation for each investigation

        prompt = INITIAL_ANALYSIS_PROMPT.format(
            service=incident_context["service"],
            symptom_type=incident_context["symptom_type"],
            start_time=incident_context["start_time"],
            end_time=incident_context["end_time"],
            raw_query=incident_context["raw_query"],
            anomaly_summary=_format_json(anomaly_summary),
            timeline=_format_timeline(timeline),
            service_correlation=_format_json(service_correlation),
            monitors=_format_json(monitors),
            deployments=_format_json(deployments),
        )

        return await self._query(prompt)

    async def generate_hypotheses(
        self,
        initial_analysis: str,
        top_errors: list[dict],
        cross_service_traces: list[dict],
        metric_anomalies: list[dict],
        service_map: list[dict],
    ) -> str:
        """Phase 2: Generate ranked root cause hypotheses."""
        prompt = HYPOTHESIS_GENERATION_PROMPT.format(
            initial_analysis=initial_analysis,
            top_errors=_format_json(top_errors),
            cross_service_traces=_format_json(cross_service_traces),
            metric_anomalies=_format_json(metric_anomalies),
            service_map=_format_json(service_map),
        )

        return await self._query(prompt, expect_json=True)

    async def causal_reasoning(
        self,
        hypotheses: str,
        timeline: list[dict],
        metric_anomalies: list[dict],
        error_patterns: list[dict],
        error_propagation: list[dict],
        service_dependencies: list[dict],
        deployments: list[dict],
    ) -> str:
        """Phase 3: Deep causal analysis to determine root cause."""
        prompt = CAUSAL_REASONING_PROMPT.format(
            hypotheses=hypotheses,
            timeline=_format_timeline(timeline),
            metric_anomalies=_format_json(metric_anomalies),
            error_patterns=_format_json(error_patterns),
            error_propagation=_format_json(error_propagation),
            service_dependencies=_format_json(service_dependencies),
            deployments=_format_json(deployments),
        )

        return await self._query(prompt)

    async def generate_remediation(
        self,
        root_cause: str,
        contributing_factors: str,
        affected_services: list[str],
        causal_chain: str,
    ) -> str:
        """Phase 4: Generate remediation recommendations."""
        prompt = REMEDIATION_PROMPT.format(
            root_cause=root_cause,
            contributing_factors=contributing_factors,
            affected_services=", ".join(affected_services),
            causal_chain=causal_chain,
        )

        return await self._query(prompt)

    # ── Dynamic investigation mode ────────────────────────────────────

    async def query_dynamic(
        self,
        user_message: str,
        *,
        system_prompt: str = "",
    ) -> str:
        """Send a message in the dynamic investigation conversation.

        Uses a separate conversation history from the legacy 4-phase flow.
        """
        system = system_prompt or INVESTIGATION_SYSTEM_PROMPT
        self.dynamic_history.append({"role": "user", "content": user_message})

        response = await self.client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            system=system,
            messages=self.dynamic_history,
        )

        if hasattr(response, "content") and response.content:
            assistant_text = response.content[0].text
        elif isinstance(response, str):
            assistant_text = response
        else:
            assistant_text = str(response)

        self.dynamic_history.append({"role": "assistant", "content": assistant_text})

        if hasattr(response, "usage"):
            logger.info(
                "Claude dynamic response: %d tokens in, %d tokens out",
                response.usage.input_tokens,
                response.usage.output_tokens,
            )

        return assistant_text

    def reset_dynamic_history(self) -> None:
        """Reset the dynamic investigation conversation."""
        self.dynamic_history = []


def _format_json(data: Any, max_chars: int = 20_000) -> str:
    """Format data as readable JSON, truncating if necessary."""
    text = json.dumps(data, indent=2, default=str)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated]"
    return text


def _format_timeline(events: list[dict], max_events: int = 100) -> str:
    """Format timeline events as a readable list."""
    if not events:
        return "No events in timeline."

    lines = []
    for evt in events[:max_events]:
        ts = evt.get("timestamp", "?")
        etype = evt.get("event_type", "?")
        source = evt.get("source", "?")
        desc = evt.get("description", "?")
        severity = evt.get("severity", "?")
        lines.append(f"[{ts}] [{severity}] [{etype}] {source}: {desc}")

    result = "\n".join(lines)
    if len(events) > max_events:
        result += f"\n... and {len(events) - max_events} more events"
    return result
