# SRE Investigation Agent

An AI-powered Site Reliability Engineering agent that automatically investigates production incidents by correlating observability signals from Datadog and performing root cause analysis using Claude's reasoning capabilities.

Given a natural language query like *"Why did checkout-service latency spike at 2pm today?"*, the agent fetches all relevant traces, logs, metrics, service dependencies, deployments, and monitor alerts -- then applies multi-pass causal reasoning to produce an evidence-backed Root Cause Analysis report.

---

## Architecture

```
User Query (natural language)
    |
    v
 [Query Parser] ---- Claude NLP ---> Structured IncidentQuery
    |
    v
 [Datadog Fetcher] -- Parallel API calls -->
    |  Metrics (latency, errors, CPU, memory, disk, network, throughput)
    |  Logs (error + warning)
    |  Traces (error spans + slow spans >1s)
    |  Service Map (upstream/downstream dependencies)
    |  Deployment Events
    |  Monitor Alerts
    v
 [Correlation Engine]
    |  Build unified timeline (z-score anomaly detection)
    |  Correlate cross-service errors via trace propagation
    |  Compute anomaly summary
    v
 [RCA Engine] ---- 4-pass Claude reasoning --->
    |  Phase 1: Initial Analysis (symptom identification + sequencing)
    |  Phase 2: Hypothesis Generation (>=3 ranked candidates)
    |  Phase 3: Causal Reasoning (temporal, counterfactual, mechanism, elimination)
    |  Phase 4: Remediation (immediate, short-term, long-term actions)
    v
 [Report Formatter] --> Markdown | Slack Blocks | Compact
```

### Key Components

| Component | Path | Purpose |
|-----------|------|---------|
| **Orchestrator** | `src/core/orchestrator.py` | Main `SREAgent` class -- ties the full pipeline together |
| **Query Parser** | `src/core/parser.py` | Uses Claude to parse free-form text into structured `IncidentQuery` |
| **Datadog Client** | `src/datadog/client.py` | Async HTTP client with retry/backoff for all Datadog APIs |
| **Datadog Fetcher** | `src/datadog/fetcher.py` | Parallel data fetching across services with recursive dependency traversal |
| **Correlation Engine** | `src/correlation/engine.py` | Timeline building, z-score anomaly detection, cross-service error correlation |
| **Claude Reasoning** | `src/claude/reasoning.py` | Multi-pass reasoning engine (4 phases) |
| **Prompt Templates** | `src/claude/prompts.py` | Structured prompts for each reasoning phase |
| **RCA Engine** | `src/rca/engine.py` | Orchestrates reasoning phases, selects root cause, builds final report |
| **Report Formatter** | `src/formatters/report.py` | Markdown, Slack Block Kit, and compact output formatters |
| **Data Models** | `src/models/incident.py` | Pydantic models for all domain types |
| **Configuration** | `config/settings.py` | Environment-based configuration for Datadog and Claude |

---

## Requirements

- Python >= 3.11
- Datadog API key and Application key
- Anthropic API key (Claude)

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd sre-agent

# Install dependencies
pip install -e .

# For development
pip install -e ".[dev]"
```

## Configuration

Set the following environment variables:

```bash
export DD_API_KEY="your-datadog-api-key"
export DD_APP_KEY="your-datadog-app-key"
export DD_SITE="datadoghq.com"          # optional, defaults to datadoghq.com
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

## Usage

### CLI

```bash
python main.py "Why did checkout-service latency spike at 2pm today?"
```

### Programmatic

```python
import asyncio
from config.settings import AgentConfig
from src.core.orchestrator import SREAgent

async def investigate():
    config = AgentConfig()
    agent = SREAgent(config)
    try:
        # Get formatted markdown report
        report = await agent.investigate_and_format(
            "Why did checkout-service latency spike at 2pm today?",
            output_format="markdown"  # or "slack" or "compact"
        )
        print(report)
    finally:
        await agent.close()

asyncio.run(investigate())
```

### Slack Bot

The agent can run as a Slack bot that investigates Datadog alerts directly from Slack threads.

**Setup:**
1. Create a Slack App at [api.slack.com](https://api.slack.com/apps)
2. Enable Socket Mode (generates `SLACK_APP_TOKEN` with `connections:write` scope)
3. Add Bot Token Scopes: `app_mentions:read`, `chat:write`, `channels:history`, `groups:history`
4. Subscribe to Events: `app_mention`
5. Install to workspace (generates `SLACK_BOT_TOKEN`)

**Install Slack dependencies:**
```bash
pip install slack-bolt slack-sdk aiohttp
```

**Set environment variables and start:**
```bash
export SLACK_BOT_TOKEN="xoxb-..."
export SLACK_APP_TOKEN="xapp-..."
python slack_bot.py
```

**Usage in Slack:**
1. Find a Datadog alert message in any channel the bot is in
2. Reply to it in a thread with: `@atul-bot investigate`
3. The bot posts "Investigation in progress..." immediately
4. Full RCA report appears in the thread within 2-5 minutes, including:
   - Root cause with confidence score
   - Key evidence and timeline
   - Service impact analysis
   - Remediation steps
   - Direct links to Datadog monitors, APM, and logs

The bot extracts the **Datadog monitor URL** from the alert message as its primary entry point, fetches the monitor definition, and constructs a structured investigation query without needing NLP parsing.

### Demo with Mock Data

Run a full investigation pipeline without live Datadog access (requires only `ANTHROPIC_API_KEY`):

```bash
python examples/demo_investigation.py
```

## Output Formats

| Format | Use Case |
|--------|----------|
| **markdown** | Full investigation report with sections for root cause, timeline, blast radius, remediation, and collapsible detailed analysis |
| **slack** | Slack Block Kit JSON ready for `chat.postMessage` |
| **compact** | Single-paragraph summary for alerts or notifications |

## How It Works

### Data Collection

The agent fetches **8 metric types** per service (latency, error rate, throughput, CPU, memory, disk I/O, network), along with error/warning logs, APM traces (errors + slow spans), the service dependency map, recent deployments, and triggered monitors. Data is fetched in parallel with a configurable concurrency limit (default: 20). Dependency services are fetched recursively up to 3 hops deep.

### Signal Correlation

- **Anomaly detection**: Statistical z-score analysis (threshold > 3.0) on metric timeseries
- **Timeline unification**: All signals (metrics, logs, traces, deploys, alerts) merged into a chronological timeline with severity classification
- **Cross-service correlation**: Traces spanning multiple services are used to build error propagation graphs

### Multi-Pass Reasoning

The RCA engine makes 4 separate Claude API calls, each building on the previous:

1. **Initial Analysis** -- Identify symptoms (not causes), temporal sequence, and change correlation
2. **Hypothesis Generation** -- Produce 3+ ranked hypotheses with confidence scores and evidence
3. **Causal Reasoning** -- Apply temporal precedence, counterfactual analysis, mechanism tracing, and hypothesis elimination to select the root cause
4. **Remediation** -- Generate immediate mitigation, short-term fixes, long-term improvements, and monitoring recommendations

### Design Decisions

- **Fully async**: End-to-end async/await for maximum parallelism
- **Graceful degradation**: If a dependency service fetch fails, the investigation continues with available data
- **Temporal context expansion**: Fetches data +/- 5 minutes beyond the incident window to capture pre-incident signals
- **Structured + unstructured**: Pydantic models enforce type safety while allowing rich free-text reasoning from Claude
- **JSON fallback parsing**: Claude output is extracted via regex for robustness against formatting variations

## Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test module
pytest tests/test_correlation.py
```

Tests cover the correlation engine, RCA hypothesis parsing/selection, and all output formatters using mocked data and fixtures.

## Project Structure

```
sre-agent/
├── config/
│   └── settings.py            # DatadogConfig, ClaudeConfig, SlackConfig, AgentConfig
├── src/
│   ├── core/
│   │   ├── orchestrator.py    # SREAgent (main entry point)
│   │   └── parser.py          # NL query -> IncidentQuery
│   ├── models/
│   │   └── incident.py        # All Pydantic data models
│   ├── datadog/
│   │   ├── client.py          # Async Datadog API client
│   │   └── fetcher.py         # Parallel multi-service data fetcher
│   ├── claude/
│   │   ├── reasoning.py       # Multi-pass Claude reasoning engine
│   │   └── prompts.py         # Prompt templates per reasoning phase
│   ├── correlation/
│   │   └── engine.py          # Timeline + signal correlation
│   ├── rca/
│   │   └── engine.py          # RCA orchestration + report building
│   ├── formatters/
│   │   └── report.py          # Markdown / Slack / Compact formatters
│   ├── slack/
│   │   ├── handler.py         # Slack bot event handler (app_mention)
│   │   ├── parser.py          # Datadog alert message parser
│   │   ├── incident_builder.py # Slack context -> IncidentQuery
│   │   └── utils.py           # Block truncation, error formatting
│   └── utils/                 # Utilities (placeholder)
├── tests/
│   ├── conftest.py
│   ├── test_rca_engine.py
│   ├── test_correlation.py
│   ├── test_formatter.py
│   ├── test_slack_parser.py
│   └── test_incident_builder.py
├── examples/
│   └── demo_investigation.py  # Full demo with mock Datadog data
├── main.py                    # CLI entrypoint
├── slack_bot.py               # Slack bot entrypoint
└── pyproject.toml             # Dependencies and project metadata
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `anthropic` | Claude API client |
| `datadog-api-client` | Datadog API SDK |
| `httpx` | Async HTTP client |
| `pydantic` | Data validation and models |
| `rich` | Console output formatting |
| `tenacity` | Retry with exponential backoff |
| `structlog` | Structured logging |
| `slack-bolt` | Slack bot framework (optional) |
| `slack-sdk` | Slack API client (optional) |

## License

This project is private and not licensed for redistribution.
