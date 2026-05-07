"""Regression benchmark runner for the SRE Investigation Agent.

Loads test cases from benchmarks/cases/*.json, invokes the agent on
each one, and scores the resulting report against the expected fields.

Run:
    python scripts/run_benchmark.py
    python scripts/run_benchmark.py --case 001_example_db_cascade
    python scripts/run_benchmark.py --output run_2026-05-07.json

Exits non-zero if any non-skipped case fails. Designed to be run
before merging prompt or logic changes — diff the JSON output across
runs to see whether quality improved or regressed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# Load .env if present so DD_API_KEY etc. are available
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

# Make project root importable when running as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import AgentConfig  # noqa: E402
from src.core.orchestrator import SREAgent  # noqa: E402
from src.models.incident import RCAReport  # noqa: E402

logging.basicConfig(
    level=logging.WARNING,  # quiet during benchmark; agent logs are verbose
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

CASES_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "cases"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class CaseResult:
    case_id: str
    description: str
    skipped: bool = False
    error: str = ""
    duration_seconds: float = 0.0
    overall_passed: bool = False
    checks: list[CheckResult] = field(default_factory=list)
    report_summary: str = ""
    report_root_cause: str = ""
    report_confidence: float = 0.0
    report_dependency_chain: list[str] = field(default_factory=list)
    report_affected_services: list[str] = field(default_factory=list)
    report_type: str = ""


def load_cases(case_filter: Optional[str] = None) -> list[dict[str, Any]]:
    """Load all benchmark cases from disk, optionally filtering by id."""
    if not CASES_DIR.exists():
        return []
    cases = []
    for path in sorted(CASES_DIR.glob("*.json")):
        with open(path, "r", encoding="utf-8") as f:
            case = json.load(f)
        if case_filter and case.get("id") != case_filter:
            continue
        cases.append(case)
    return cases


def score_report(report: RCAReport, expected: dict[str, Any]) -> list[CheckResult]:
    """Score a single report against expected fields. Returns one CheckResult per check."""
    checks: list[CheckResult] = []

    haystack = " ".join([
        report.summary or "",
        report.root_cause.description if report.root_cause else "",
    ]).lower()

    # root_cause_keywords_any — at least one must match
    any_keywords = expected.get("root_cause_keywords_any", [])
    if any_keywords:
        matched = [kw for kw in any_keywords if kw.lower() in haystack]
        checks.append(CheckResult(
            name="root_cause_keywords_any",
            passed=bool(matched),
            detail=f"matched: {matched}" if matched else f"none of {any_keywords} in summary/root_cause",
        ))

    # root_cause_keywords_all — all must match
    all_keywords = expected.get("root_cause_keywords_all", [])
    if all_keywords:
        missing = [kw for kw in all_keywords if kw.lower() not in haystack]
        checks.append(CheckResult(
            name="root_cause_keywords_all",
            passed=not missing,
            detail=f"missing: {missing}" if missing else "all matched",
        ))

    # dependency_chain_includes — services must appear in order
    expected_chain = expected.get("dependency_chain_includes", [])
    if expected_chain:
        actual_chain = [s.lower() for s in (report.dependency_chain or [])]
        # Walk: each expected service must appear after the previous one
        idx = 0
        all_found = True
        missing_at = ""
        for svc in expected_chain:
            target = svc.lower()
            found = False
            while idx < len(actual_chain):
                if target in actual_chain[idx]:
                    idx += 1
                    found = True
                    break
                idx += 1
            if not found:
                all_found = False
                missing_at = svc
                break
        checks.append(CheckResult(
            name="dependency_chain_includes",
            passed=all_found,
            detail=(
                f"actual chain: {report.dependency_chain}"
                if all_found
                else f"could not find '{missing_at}' in remainder of {report.dependency_chain}"
            ),
        ))

    # min_confidence
    min_conf = expected.get("min_confidence")
    if min_conf is not None:
        passed = report.confidence_score >= min_conf
        checks.append(CheckResult(
            name="min_confidence",
            passed=passed,
            detail=f"got {report.confidence_score:.2f}, expected >= {min_conf:.2f}",
        ))

    # expected_report_type
    expected_type = expected.get("expected_report_type")
    if expected_type:
        passed = report.report_type == expected_type
        checks.append(CheckResult(
            name="expected_report_type",
            passed=passed,
            detail=f"got '{report.report_type}', expected '{expected_type}'",
        ))

    # must_mention_services
    must_mention = expected.get("must_mention_services", [])
    if must_mention:
        affected_lower = " ".join(report.affected_services or []).lower()
        missing = [s for s in must_mention if s.lower() not in affected_lower]
        checks.append(CheckResult(
            name="must_mention_services",
            passed=not missing,
            detail=f"missing: {missing}" if missing else f"all in {report.affected_services}",
        ))

    return checks


async def run_case(case: dict[str, Any], agent: SREAgent) -> CaseResult:
    """Run one case through the agent and score the result."""
    result = CaseResult(
        case_id=case.get("id", "<unknown>"),
        description=case.get("description", ""),
    )

    if case.get("skip"):
        result.skipped = True
        return result

    start = time.monotonic()
    try:
        report: RCAReport = await agent.investigate(case["alert"])
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        result.duration_seconds = time.monotonic() - start
        return result

    result.duration_seconds = time.monotonic() - start
    result.report_summary = report.summary
    result.report_root_cause = (
        report.root_cause.description if report.root_cause else ""
    )
    result.report_confidence = report.confidence_score
    result.report_dependency_chain = list(report.dependency_chain or [])
    result.report_affected_services = list(report.affected_services or [])
    result.report_type = report.report_type

    result.checks = score_report(report, case.get("expected", {}))
    result.overall_passed = bool(result.checks) and all(c.passed for c in result.checks)
    return result


def print_summary(results: list[CaseResult]) -> None:
    """Print a one-line summary per case + overall counts."""
    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS")
    print("=" * 80)
    passed = failed = skipped = errored = 0
    for r in results:
        if r.skipped:
            print(f"  [SKIP]  {r.case_id}")
            skipped += 1
            continue
        if r.error:
            print(f"  [ERROR] {r.case_id}: {r.error}")
            errored += 1
            continue
        status = "[PASS]" if r.overall_passed else "[FAIL]"
        print(
            f"  {status}  {r.case_id}  "
            f"({r.duration_seconds:.0f}s, conf={r.report_confidence:.2f})"
        )
        for c in r.checks:
            tick = "+" if c.passed else "-"
            print(f"           {tick} {c.name}: {c.detail}")
        if r.overall_passed:
            passed += 1
        else:
            failed += 1

    print("-" * 80)
    print(
        f"  Total: {len(results)}  "
        f"Pass: {passed}  Fail: {failed}  Error: {errored}  Skip: {skipped}"
    )
    print("=" * 80)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SRE agent regression benchmark.")
    parser.add_argument("--case", help="Run only the case with this id")
    parser.add_argument("--output", help="Write JSON-formatted results to this path")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show agent INFO logs during runs"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    cases = load_cases(args.case)
    if not cases:
        print(f"No cases found in {CASES_DIR}")
        return 0

    # Sanity-check required env vars before paying for any API calls
    missing_env = [
        v for v in ("DD_API_KEY", "DD_APP_KEY", "ANTHROPIC_API_KEY")
        if not os.environ.get(v)
    ]
    if missing_env:
        print(f"Missing required env vars: {', '.join(missing_env)}", file=sys.stderr)
        return 2

    config = AgentConfig()
    agent = SREAgent(config)

    async def runner() -> list[CaseResult]:
        try:
            results = []
            for case in cases:
                print(f"\n--- Running {case.get('id')} ---")
                result = await run_case(case, agent)
                results.append(result)
            return results
        finally:
            await agent.close()

    results = asyncio.run(runner())
    print_summary(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(r) for r in results],
                f,
                indent=2,
                default=str,
            )
        print(f"Wrote results to {args.output}")

    # Exit non-zero if any non-skipped case failed or errored
    failures = [r for r in results if not r.skipped and (r.error or not r.overall_passed)]
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
