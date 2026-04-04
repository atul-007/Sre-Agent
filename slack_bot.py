"""Slack bot entrypoint for the SRE Investigation Agent."""

from __future__ import annotations

import logging
import sys

from config.settings import AgentConfig
from src.slack.handler import SlackBot

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def main() -> None:
    config = AgentConfig()

    if not config.slack.bot_token:
        print("Error: SLACK_BOT_TOKEN environment variable is required.")
        print("See env.example for the full list of required variables.")
        sys.exit(1)

    if config.slack.socket_mode and not config.slack.app_token:
        print("Error: SLACK_APP_TOKEN is required for Socket Mode.")
        print("Either set SLACK_APP_TOKEN or set SLACK_SIGNING_SECRET for HTTP mode.")
        sys.exit(1)

    bot = SlackBot(config)
    bot.start()


if __name__ == "__main__":
    main()
