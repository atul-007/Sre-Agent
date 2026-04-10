# SRE Investigation Agent

An AI-powered Site Reliability Engineering agent that automatically investigates production incidents by correlating observability signals from Datadog and performing root cause analysis using Claude's reasoning capabilities.

Given a natural language query like *"Why did checkout-service latency spike at 2pm today?"*, or a Datadog alert forwarded via Slack, the agent fetches all relevant traces, logs, metrics, service dependencies, deployments, and monitor alerts -- then applies multi-phase causal reasoning to produce an evidence-backed Root Cause Analysis report with full dependency chain tracking.

---

## Architecture

```
User Query / Slack Alert
    |
    v
 [Query Parser / Alert Parser] ---> Structured IncidentQuery
    |
    v
 [Dynamic Investigation Engine]
    |
    |  Phase 0: Discovery — resolve service namespace, find available
    |           metrics, dashboards, and monitors via Datadog APIs
    |
    |  Phase 1: Breadth — fetch metrics, logs, traces, service map,
    |           deployments, monitors; build signal coverage
    |
    |  Phase 2: Depth — deep-dive into leading hypothesis with targeted
    |           queries; cross-service investigation follows dependency
    |           chain hop-by-hop (with confidence floor)
    |
    |  Phase 3: Conclusion — synthesize all evidence into final report
    |           with full dependency path (A → B → C)
    |
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
| **Investigation Engine** | `src/investigation/engine.py` | Dynamic investigation loop — plans, executes, analyzes, repeats |
| **Discovery Phase** | `src/investigation/discovery.py` | Pre-investigation: resolves namespace, finds metrics/dashboards/monitors |
| **Breadth Phase** | `src/investigation/breadth.py` | Signal coverage: fetches all data types, tracks what's been checked |
| **Depth Phase** | `src/investigation/depth.py` | Hypothesis-driven deep-dive and cross-service dependency investigation |
| **Analysis Phase** | `src/investigation/analysis.py` | Hypothesis tracking, conclusion generation, final report assembly |
| **Execution** | `src/investigation/execution.py` | Dispatches investigation actions to data sources |
| **Investigation Rules** | `src/investigation/rules.py` | Signal checklists, conclusion guards, phase transition rules |
| **Investigation Helpers** | `src/investigation/helpers.py` | Data summarization and formatting utilities |
| **Correlation Engine** | `src/correlation/engine.py` | Timeline building, z-score anomaly detection, cross-service error correlation |
| **Claude Reasoning** | `src/claude/reasoning.py` | Multi-pass reasoning engine |
| **Prompt Templates** | `src/claude/prompts.py` | Structured prompts for each reasoning phase |
| **RCA Engine** | `src/rca/engine.py` | Static 4-pass reasoning mode (legacy) |
| **Report Formatter** | `src/formatters/report.py` | Markdown, Slack Block Kit, and compact output formatters |
| **Data Models** | `src/models/incident.py` | Pydantic models for all domain types |
| **Slack Bot** | `src/slack/handler.py` | Slack event handler — triggers investigations from alert threads |
| **Alert Parser** | `src/slack/parser.py` | Extracts monitor URL, tags, and context from Datadog alert messages |
| **Incident Builder** | `src/slack/incident_builder.py` | Converts Slack alert context into structured `IncidentQuery` |
| **Time Utilities** | `src/utils/time.py` | UTC normalization, safe timestamp parsing |
| **Configuration** | `config/settings.py` | Environment-based configuration for Datadog, Claude, and Slack |

---

## Requirements

- Python >= 3.11
- Datadog API key and Application key
- Anthropic API key (Claude)

## Installation

```bash
# Clone the repository
git clone https://github.com/atul-007/Sre-Agent.git
cd Sre-Agent

# Install dependencies
pip install -e .

# For development
pip install -e ".[dev]"

# For Slack bot
pip install -e ".[slack]"
```

## Configuration

Create a `.env` file in the project root (auto-loaded by the CLI and Slack bot):

```bash
DD_API_KEY="your-datadog-api-key"
DD_APP_KEY="your-datadog-app-key"
DD_SITE="datadoghq.com"          # optional, defaults to datadoghq.com
ANTHROPIC_API_KEY="your-anthropic-api-key"

# Slack bot (optional)
SLACK_BOT_TOKEN="xoxb-..."
SLACK_APP_TOKEN="xapp-..."
```

Or export them directly:

```bash
export DD_API_KEY="your-datadog-api-key"
export DD_APP_KEY="your-datadog-app-key"
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

The agent runs as a Slack bot that investigates Datadog alerts directly from Slack threads.

**Setup:**
1. Create a Slack App at [api.slack.com](https://api.slack.com/apps)
2. Enable Socket Mode (generates `SLACK_APP_TOKEN` with `connections:write` scope)
3. Add Bot Token Scopes: `app_mentions:read`, `chat:write`, `channels:history`, `groups:history`
4. Subscribe to Events: `app_mention`
5. Install to workspace (generates `SLACK_BOT_TOKEN`)

**Install Slack dependencies and start:**
```bash
pip install -e ".[slack]"
python slack_bot.py
```

**Usage in Slack:**
1. Find a Datadog alert message in any channel the bot is in
2. Reply to it in a thread with: `@bot-name investigate`
3. The bot posts an acknowledgment immediately
4. The full RCA report appears in the thread within 2-5 minutes, including:
   - Root cause with confidence score
   - Dependency path showing how the failure cascades across services
   - Affected services with roles (root cause / propagator / victim)
   - Key evidence and timeline
   - Service-specific remediation steps
   - Direct links to Datadog monitors, APM, and logs

### Demo with Mock Data

Run a full investigation pipeline without live Datadog access (requires only `ANTHROPIC_API_KEY`):

```bash
python examples/demo_investigation.py
```

## Output Formats

| Format | Use Case |
|--------|----------|
| **markdown** | Full investigation report with dependency path, root cause, timeline, blast radius, remediation, hypothesis tracking, data quality, and collapsible detailed analysis |
| **slack** | Slack Block Kit JSON with dependency path, structured service impact, and Datadog deep links |
| **compact** | Single-paragraph summary for alerts or notifications |

## How It Works

### Dynamic Investigation Engine

The primary investigation mode is a dynamic, multi-phase engine that adapts its queries based on what it discovers:

1. **Discovery** (Phase 0) -- Before fetching any data, the engine resolves the service's Kubernetes namespace, discovers available metrics (APM, infra, container, custom), finds relevant dashboards and monitors, and builds a context object so subsequent queries use real metric names instead of guesses.

2. **Breadth** (Phase 1) -- The engine fetches metrics, logs, traces, service maps, deployments, and monitors. A signal checklist tracks which data types have been checked. Claude analyzes each result, updates hypotheses, and decides the next action. The phase continues until signal coverage is sufficient.

3. **Depth** (Phase 2) -- Once a leading hypothesis emerges, the engine deep-dives with targeted queries (e.g., per-pod metrics, specific trace filters). If the hypothesis points to a downstream dependency, the engine follows the chain hop-by-hop, investigating each service in turn. A confidence floor prevents spurious drops when ruling out intermediate services.

4. **Conclusion** (Phase 3) -- The engine synthesizes all evidence into a final report. The conclusion prompt receives the full dependency path discovered during depth, and Claude is required to explain the exact cascade (e.g., "Spanner timeouts in service-A caused auth failures in service-B, which cascaded into service-C").

### Data Collection

The agent fetches metrics (latency, error rate, throughput, CPU, memory, disk I/O, network), error/warning logs, APM traces (errors + slow spans), the service dependency map, recent deployments, and triggered monitors. Data is fetched in parallel with retry and backoff. Dependency services are investigated recursively.

### Signal Correlation

- **Anomaly detection**: Statistical z-score analysis (threshold > 3.0) on metric timeseries
- **Timeline unification**: All signals (metrics, logs, traces, deploys, alerts) merged into a chronological timeline with severity classification
- **Cross-service correlation**: Traces spanning multiple services build error propagation graphs

### Dependency Chain Tracking

When the depth phase investigates downstream services, it records the hop-by-hop path (e.g., `search-platform → mercari-authority → mercari-authority-spanner`). This chain is:
- Passed to Claude's conclusion prompt so the root cause description includes the full path
- Stored in the report as `dependency_chain`
- Rendered in both Markdown and Slack reports with service roles (root cause / propagator / victim)

### Static RCA Mode (Legacy)

The original 4-pass reasoning mode is still available:

1. **Initial Analysis** -- Identify symptoms, temporal sequence, and change correlation
2. **Hypothesis Generation** -- Produce 3+ ranked hypotheses with confidence scores
3. **Causal Reasoning** -- Temporal precedence, counterfactual analysis, mechanism tracing
4. **Remediation** -- Immediate mitigation, short-term fixes, long-term improvements

### Design Decisions

- **Fully async**: End-to-end async/await for maximum parallelism
- **Graceful degradation**: If a data fetch fails, the investigation continues with available data
- **Discovery before investigation**: Real metric names from Datadog APIs replace hardcoded guesses
- **Confidence floor in depth phase**: Prevents cascading confidence drops when eliminating intermediate services
- **Structured + unstructured**: Pydantic models enforce type safety while allowing rich free-text reasoning from Claude
- **JSON fallback parsing**: Claude output is extracted via regex for robustness against formatting variations

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test module
python3 -m pytest tests/test_depth.py -v

# Run single test
python3 -m pytest tests/test_analysis.py::TestIsNearDuplicate::test_exact_duplicate -v
```

Tests use mocks -- no Datadog or Claude API keys needed. Uses `pytest-asyncio` for async tests and `unittest.mock.AsyncMock` for async mocks.

## Project Structure

```
sre-agent/
├── config/
│   └── settings.py              # DatadogConfig, ClaudeConfig, SlackConfig, AgentConfig
├── src/
│   ├── core/
│   │   ├── orchestrator.py      # SREAgent (main entry point)
│   │   └── parser.py            # NL query -> IncidentQuery
│   ├── models/
│   │   └── incident.py          # All Pydantic data models
│   ├── datadog/
│   │   ├── client.py            # Async Datadog API client
│   │   └── fetcher.py           # Parallel multi-service data fetcher
│   ├── claude/
│   │   ├── reasoning.py         # Multi-pass Claude reasoning engine
│   │   └── prompts.py           # Prompt templates per reasoning phase
│   ├── investigation/
│   │   ├── engine.py            # Dynamic investigation loop
│   │   ├── discovery.py         # Phase 0: service context discovery
│   │   ├── breadth.py           # Phase 1: broad signal collection
│   │   ├── depth.py             # Phase 2: hypothesis deep-dive + cross-service
│   │   ├── analysis.py          # Hypothesis tracking + conclusion generation
│   │   ├── execution.py         # Action dispatch to data sources
│   │   ├── rules.py             # Signal checklists and conclusion guards
│   │   └── helpers.py           # Data summarization utilities
│   ├── correlation/
│   │   └── engine.py            # Timeline + signal correlation
│   ├── rca/
│   │   └── engine.py            # Static 4-pass RCA (legacy mode)
│   ├── formatters/
│   │   └── report.py            # Markdown / Slack / Compact formatters
│   ├── slack/
│   │   ├── handler.py           # Slack bot event handler (app_mention)
│   │   ├── parser.py            # Datadog alert message parser
│   │   ├── incident_builder.py  # Slack context -> IncidentQuery
│   │   └── utils.py             # Block truncation, error formatting
│   └── utils/
│       └── time.py              # UTC normalization, safe timestamp parsing
├── tests/
│   ├── conftest.py
│   ├── test_analysis.py
│   ├── test_correlation.py
│   ├── test_depth.py
│   ├── test_discovery.py
│   ├── test_formatter.py
│   ├── test_helpers.py
│   ├── test_incident_builder.py
│   ├── test_investigation_rules.py
│   ├── test_rca_engine.py
│   ├── test_report_improvements.py
│   ├── test_signal_quality.py
│   ├── test_slack_parser.py
│   └── test_time_utils.py
├── examples/
│   └── demo_investigation.py    # Full demo with mock Datadog data
├── main.py                      # CLI entrypoint
├── slack_bot.py                 # Slack bot entrypoint
├── CONTRIBUTING.md              # Contributor guide
└── pyproject.toml               # Dependencies and project metadata
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
| `python-dotenv` | `.env` file loading |
| `slack-bolt` | Slack bot framework (optional) |
| `slack-sdk` | Slack API client (optional) |
| `aiohttp` | Async HTTP for Socket Mode (optional) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, code style, testing guidelines, and how to add new investigation capabilities.

## License

This project is licensed under the [MIT License](LICENSE).
