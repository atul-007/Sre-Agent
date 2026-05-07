# Regression Benchmark

A small framework for measuring whether prompt and logic changes
regress investigation quality. Each case in `cases/` is a stored
alert + expected RCA fields. The runner invokes the agent on each
case and scores the resulting report.

This is **not** a unit test. It calls real Datadog APIs and Claude.
It's intended to be run before merging non-trivial changes (new
prompts, depth phase tweaks, signal-checklist edits) and after
investigations to backfill cases the agent got wrong.

## Running

```bash
# Run all cases
python scripts/run_benchmark.py

# Run one case
python scripts/run_benchmark.py --case 001_db_timeout_cascade

# Save scored output to a file for diffing across runs
python scripts/run_benchmark.py --output benchmark_2026-05-07.json
```

Required env vars (same as the main agent): `DD_API_KEY`, `DD_APP_KEY`,
`ANTHROPIC_API_KEY`.

## Case schema

Each `cases/<id>.json` file:

```json
{
  "id": "001_db_timeout_cascade",
  "description": "Short human description",
  "alert": "<full alert text — title, tags, monitor URL>",
  "expected": {
    "root_cause_keywords_any": ["timeout", "database"],
    "root_cause_keywords_all": [],
    "dependency_chain_includes": ["auth-db", "auth-service"],
    "min_confidence": 0.30,
    "expected_report_type": "rca",
    "must_mention_services": ["auth-db"]
  },
  "skip": false,
  "notes": "Optional notes on origin / why this case matters"
}
```

Field semantics:

| field | meaning |
|---|---|
| `root_cause_keywords_any` | At least one keyword (case-insensitive) must appear in `report.root_cause.description` or `report.summary`. Empty list = skip check. |
| `root_cause_keywords_all` | All keywords must appear. Use sparingly — exact wording is brittle. |
| `dependency_chain_includes` | All listed services must appear in `report.dependency_chain`, in order. |
| `min_confidence` | `report.confidence_score` must be at least this value. |
| `expected_report_type` | `"rca"` or `"investigation_summary"`. |
| `must_mention_services` | Services that must appear somewhere in `affected_services`. |

## Adding a new case

1. After an incident the agent investigated well (or poorly), copy
   the alert text to `cases/<NNN>_<short_slug>.json`.
2. Set `expected.*` based on what a reasonable RCA should contain.
3. If the agent is wrong on this case today, set `skip: true` with a
   note — that turns it into a known-failing case. Remove `skip`
   when fixed.
4. Commit the case alongside the fix.

## Scoring

Each case yields a per-check pass/fail and an overall pass/fail.
The runner prints a summary table and exits non-zero if any case
fails (excluding skipped). The JSON output captures every check
for diffing.
