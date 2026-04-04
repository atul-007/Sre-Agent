"""Slack bot handler for the SRE Investigation Agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_sdk.web.async_client import AsyncWebClient

from config.settings import AgentConfig
from src.core.orchestrator import SREAgent
from src.formatters.report import ReportFormatter, _action_emoji
from src.models.incident import InvestigationStep
from src.slack.incident_builder import build_incident_from_alert
from src.slack.parser import parse_datadog_alert_message
from src.slack.utils import format_error_blocks, sanitize_error, truncate_blocks

logger = logging.getLogger(__name__)


class SlackBot:
    """Slack bot that triggers SRE investigations from Datadog alert threads."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.formatter = ReportFormatter()

        # Initialize Slack Bolt app
        self.app = AsyncApp(
            token=config.slack.bot_token,
            signing_secret=config.slack.signing_secret or None,
        )

        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register Slack event handlers."""

        @self.app.event("app_mention")
        async def handle_mention(event: dict, say: Any, client: AsyncWebClient) -> None:
            await self._handle_mention(event, say, client)

    async def _handle_mention(
        self, event: dict, say: Any, client: AsyncWebClient
    ) -> None:
        """Handle @bot mention events."""
        text = event.get("text", "").lower()
        channel = event["channel"]
        thread_ts = event.get("thread_ts") or event.get("ts")

        # Check for "investigate" command
        if "investigate" not in text:
            await say(
                text=(
                    "Hi! I can investigate Datadog alerts. "
                    "Reply to a Datadog alert message with `@atul-bot investigate` "
                    "to start an investigation."
                ),
                thread_ts=thread_ts,
            )
            return

        # Must be in a thread (replying to an alert message)
        if not event.get("thread_ts"):
            await say(
                text=(
                    "Please use this command as a *reply* to a Datadog alert message. "
                    "Find the alert in this channel, then reply with `@atul-bot investigate`."
                ),
                thread_ts=event.get("ts"),
            )
            return

        # Post immediate acknowledgment
        ack_response = await say(
            text=":mag: *Investigation in progress...*\nThis typically takes 2-5 minutes. "
                 "I'll post the results in this thread when done.",
            thread_ts=thread_ts,
        )

        # Spawn investigation as background task
        asyncio.create_task(
            self._run_investigation(channel, thread_ts, client)
        )

    async def _run_investigation(
        self,
        channel: str,
        thread_ts: str,
        client: AsyncWebClient,
    ) -> None:
        """Run the full investigation pipeline and post results to Slack."""
        try:
            # Fetch the parent message (root of the thread = the Datadog alert)
            history = await client.conversations_replies(
                channel=channel,
                ts=thread_ts,
                inclusive=True,
                limit=1,
            )
            messages = history.get("messages", [])
            if not messages:
                await client.chat_postMessage(
                    channel=channel,
                    thread_ts=thread_ts,
                    text=":warning: Could not fetch the parent message. "
                         "Make sure the bot has access to this channel.",
                )
                return

            parent_message = messages[0]

            # Parse the Datadog alert message
            try:
                alert_context = parse_datadog_alert_message(
                    text=parent_message.get("text", ""),
                    attachments=parent_message.get("attachments", []),
                    blocks=parent_message.get("blocks", []),
                )
            except ValueError as e:
                await client.chat_postMessage(
                    channel=channel,
                    thread_ts=thread_ts,
                    text=f":warning: {e}",
                )
                return

            logger.info(
                "Parsed alert: monitor_id=%d, service tags=%s",
                alert_context.monitor_id,
                alert_context.group_tags,
            )

            # Build IncidentQuery from alert context
            agent = SREAgent(self.config)
            try:
                incident = await build_incident_from_alert(
                    alert_context, agent.dd_client
                )
                logger.info(
                    "Built incident: service=%s, symptom=%s, window=%s→%s",
                    incident.service,
                    incident.symptom_type.value,
                    incident.start_time,
                    incident.end_time,
                )

                # Build live step callback for real-time Slack updates
                async def on_step_complete(step: InvestigationStep) -> None:
                    emoji = _action_emoji(step.action.value)
                    findings_preview = step.findings[:200]
                    if len(step.findings) > 200:
                        findings_preview += "..."
                    hyp_text = ""
                    if step.hypotheses:
                        hyp_text = "\n    _Hypotheses: " + "; ".join(
                            h[:60] for h in step.hypotheses[:3]
                        ) + "_"
                    step_text = (
                        f"{emoji} *Step {step.step_number}:* {step.reason}\n"
                        f"    _Source: {step.data_source} | "
                        f"Data: {step.data_summary}_\n"
                        f"    {findings_preview}"
                        f"{hyp_text}\n"
                        f"    Confidence: {step.confidence:.0%}"
                    )
                    await client.chat_postMessage(
                        channel=channel,
                        thread_ts=thread_ts,
                        text=step_text,
                    )

                # Run the investigation with live updates
                report = await agent.investigate_from_incident(
                    incident,
                    mode="dynamic",
                    on_step_complete=on_step_complete,
                )

                # Format and post results
                blocks = self.formatter.to_slack_blocks(report)
                blocks = truncate_blocks(blocks)

                await client.chat_postMessage(
                    channel=channel,
                    thread_ts=thread_ts,
                    blocks=blocks,
                    text=report.summary,  # Fallback text for notifications
                )

                logger.info(
                    "Investigation posted: service=%s, confidence=%.0f%%",
                    incident.service,
                    report.confidence_score * 100,
                )
            finally:
                await agent.close()

        except Exception as e:
            logger.exception("Investigation failed: %s", e)
            error_msg = sanitize_error(e)
            try:
                await client.chat_postMessage(
                    channel=channel,
                    thread_ts=thread_ts,
                    blocks=format_error_blocks(error_msg),
                    text=f"Investigation failed: {error_msg}",
                )
            except Exception:
                logger.exception("Failed to post error message to Slack")

    def start(self) -> None:
        """Start the Slack bot (blocking)."""
        if self.config.slack.socket_mode:
            logger.info("Starting Slack bot in Socket Mode...")
            handler = AsyncSocketModeHandler(self.app, self.config.slack.app_token)
            asyncio.get_event_loop().run_until_complete(handler.start_async())
        else:
            logger.info("Starting Slack bot in HTTP mode on port %d...", self.config.slack.port)
            self.app.start(port=self.config.slack.port)
