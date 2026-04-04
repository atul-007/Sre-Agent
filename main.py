"""CLI entrypoint for the SRE Investigation Agent."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# Load .env file if present (before importing settings that read env vars)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

from config.settings import AgentConfig
from src.core.orchestrator import SREAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python main.py '<incident query>'")
        print('Example: python main.py "Why did checkout-service latency spike at 2pm today?"')
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    config = AgentConfig()
    agent = SREAgent(config)

    try:
        report_md = await agent.investigate_and_format(query, output_format="markdown")
        print(report_md)
    finally:
        await agent.close()


if __name__ == "__main__":
    asyncio.run(main())
