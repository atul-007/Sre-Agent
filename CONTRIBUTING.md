# Contributing to SRE Agent

## Getting Started

1. **Fork and clone**

   ```bash
   git clone https://github.com/atul-007/Sre-Agent.git
   cd Sre-Agent
   ```

2. **Create a virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install with dev dependencies**

   ```bash
   pip install -e ".[dev]"
   # For Slack bot work:
   pip install -e ".[dev,slack]"
   ```

4. **Set up environment**

   ```bash
   cp env.example .env
   # Fill in DD_API_KEY, DD_APP_KEY, and ANTHROPIC_API_KEY
   ```

## Project Structure

```
src/
  core/           # Orchestrator, query parser
  models/         # Pydantic data models (incident, traces, metrics, investigation state)
  datadog/        # Datadog API client and data fetcher
  claude/         # LLM reasoning engine and prompt templates
  investigation/  # Dynamic investigation engine
    engine.py     #   Main investigation loop
    discovery.py  #   Phase 0: service context discovery (metrics, namespace, dashboards)
    breadth.py    #   Phase 1: broad signal collection
    depth.py      #   Phase 2: hypothesis deep-dive + cross-service dependency tracking
    analysis.py   #   Hypothesis management + conclusion generation
    execution.py  #   Action dispatch to data sources
    rules.py      #   Signal checklists, conclusion guards, phase transitions
    helpers.py    #   Data summarization utilities
  correlation/    # Timeline building and signal correlation
  rca/            # Static 4-pass root cause analysis (legacy mode)
  formatters/     # Report output (markdown, slack blocks, compact)
  slack/          # Slack bot handler, alert parser, incident builder
  utils/          # Time utilities (UTC normalization, safe parsing)
config/           # Settings (dataclasses loaded from env vars)
tests/            # Unit tests (pytest + pytest-asyncio)
examples/         # Demo with mock data
```

Key entry points:
- `main.py` — CLI
- `slack_bot.py` — Slack bot
- `examples/demo_investigation.py` — Demo with mock data (no API keys needed)

## Code Style

**Formatting and linting** — enforced by [Ruff](https://docs.astral.sh/ruff/):

```bash
ruff check .          # Lint
ruff format .         # Format
ruff check --fix .    # Auto-fix lint issues
```

Configuration in `pyproject.toml`: line length 100, target Python 3.11.

**Type checking:**

```bash
mypy src/
```

**Conventions:**
- Use `from __future__ import annotations` in all modules
- Type hints on all function signatures
- Pydantic `BaseModel` for data structures
- `async`/`await` throughout — no blocking I/O
- Docstrings on classes and public methods (skip for obvious helpers)
- Imports: stdlib, then third-party, then local — Ruff handles ordering

## Running Tests

```bash
# All tests
python3 -m pytest tests/ -v

# Specific module
python3 -m pytest tests/test_depth.py -v

# Single test
python3 -m pytest tests/test_analysis.py::TestIsNearDuplicate::test_exact_duplicate -v
```

Tests use mocks — no Datadog or Claude API keys needed. Use `pytest-asyncio` for async tests and `unittest.mock.AsyncMock` for async mocks.

When adding tests:
- Place in `tests/test_<module>.py`
- Use `@pytest.mark.asyncio` for async test methods
- Mock external API calls (Datadog client, Claude reasoning)
- Test edge cases: empty data, null responses, malformed input

## Making Changes

1. **Branch from `main`:**

   ```bash
   git checkout -b feature/your-change
   ```

2. **Make your changes** — keep PRs focused on one thing.

3. **Run checks before committing:**

   ```bash
   ruff check . && ruff format --check . && python3 -m pytest tests/ -v
   ```

4. **Commit with a descriptive message:**

   ```
   Fix confidence drop when ruling out victim services in depth phase

   Depth phase negative deltas were accumulating across unrelated
   downstream services, dropping confidence from 85% to 61%. Added
   a confidence floor at 80% of the entry value.
   ```

## Pull Request Guidelines

- Keep PRs small and reviewable — one logical change per PR
- Include context on *why*, not just *what*
- Add or update tests for any behavior change
- Ensure all tests pass and linting is clean
- If adding a new data source or signal type, update the signal checklist in `src/investigation/rules.py`

## Adding New Investigation Capabilities

**New Datadog data source:**
1. Add the API method in `src/datadog/client.py`
2. Add the action type in `src/models/incident.py` (`InvestigationActionType`)
3. Wire it into `src/investigation/execution.py` for data fetching
4. Add depth query templates in `src/investigation/depth.py` (`build_depth_queries`)
5. Add the signal to the checklist in `src/investigation/rules.py` if it should be tracked

**New signal type:**
1. Add to the signal checklist in `src/investigation/rules.py`
2. Update signal inference in the breadth/depth phases
3. Add formatter support in `src/formatters/report.py`

**New report format:**
1. Add a formatter in `src/formatters/`
2. Register it in the orchestrator (`src/core/orchestrator.py`)

**New investigation phase or behavior:**
1. Phase transitions are controlled in `src/investigation/engine.py`
2. Conclusion guards live in `src/investigation/rules.py`
3. Prompt templates for Claude reasoning in `src/claude/prompts.py`
4. Hypothesis tracking and merge logic in `src/investigation/analysis.py`

## Questions?

Open an issue at [github.com/atul-007/Sre-Agent/issues](https://github.com/atul-007/Sre-Agent/issues).
