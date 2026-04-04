"""Deterministic rule engine for investigation — signal checklists, confidence calibration, conclusion guards.

No LLM calls. Pure logic.
"""

from __future__ import annotations

import logging
from typing import Optional

from src.models.incident import (
    HypothesisStatus,
    InvestigationActionType,
    InvestigationState,
    SignalCheckResult,
    SymptomType,
    TrackedHypothesis,
)

logger = logging.getLogger(__name__)

# ── Required signals per symptom type ─────────────────────────────────

REQUIRED_SIGNALS: dict[str, list[str]] = {
    SymptomType.SATURATION.value: [
        "cpu_usage",
        "cpu_limits",
        "cpu_throttling",
        "request_rate",
        "latency",
        "error_rate",
        "memory",
        "deployments",
    ],
    SymptomType.LATENCY.value: [
        "latency",
        "error_rate",
        "request_rate",
        "cpu_usage",
        "memory",
        "traces",
        "dependencies",
        "deployments",
    ],
    SymptomType.ERROR_RATE.value: [
        "error_rate",
        "error_logs",
        "traces",
        "latency",
        "deployments",
        "dependencies",
        "cpu_usage",
    ],
    SymptomType.AVAILABILITY.value: [
        "error_rate",
        "error_logs",
        "monitors",
        "deployments",
        "cpu_usage",
        "memory",
        "dependencies",
    ],
    SymptomType.THROUGHPUT.value: [
        "request_rate",
        "latency",
        "error_rate",
        "cpu_usage",
        "memory",
        "deployments",
        "dependencies",
    ],
    SymptomType.UNKNOWN.value: [
        "metrics",
        "error_logs",
        "traces",
        "deployments",
        "monitors",
        "dependencies",
    ],
}

# ── Signal → Action mapping ───────────────────────────────────────────

SIGNAL_TO_ACTION: dict[str, dict] = {
    "cpu_usage": {
        "action": InvestigationActionType.FETCH_METRICS.value,
        "reason": "Check CPU usage metrics for the service",
    },
    "cpu_limits": {
        "action": InvestigationActionType.FETCH_INFRA_METRICS.value,
        "reason": "Check Kubernetes CPU limits and requests",
    },
    "cpu_throttling": {
        "action": InvestigationActionType.FETCH_INFRA_METRICS.value,
        "reason": "Check CPU throttling metrics (container.cpu.throttled)",
    },
    "memory": {
        "action": InvestigationActionType.FETCH_INFRA_METRICS.value,
        "reason": "Check memory usage and limits",
    },
    "request_rate": {
        "action": InvestigationActionType.FETCH_METRICS.value,
        "reason": "Check request rate / throughput metrics",
    },
    "latency": {
        "action": InvestigationActionType.FETCH_METRICS.value,
        "reason": "Check latency metrics (p50/p95/p99)",
    },
    "error_rate": {
        "action": InvestigationActionType.FETCH_METRICS.value,
        "reason": "Check error rate metrics",
    },
    "error_logs": {
        "action": InvestigationActionType.FETCH_LOGS.value,
        "reason": "Fetch error and warning logs",
    },
    "traces": {
        "action": InvestigationActionType.FETCH_TRACES.value,
        "reason": "Fetch error and slow trace spans",
    },
    "deployments": {
        "action": InvestigationActionType.FETCH_DEPLOYMENTS.value,
        "reason": "Check for recent deployment events",
    },
    "monitors": {
        "action": InvestigationActionType.FETCH_MONITORS.value,
        "reason": "Check triggered monitors and alerts",
    },
    "dependencies": {
        "action": InvestigationActionType.FETCH_SERVICE_MAP.value,
        "reason": "Check service dependency map for error propagation",
    },
    "metrics": {
        "action": InvestigationActionType.FETCH_METRICS.value,
        "reason": "Fetch standard service metrics",
    },
    "latency_p50_p99": {
        "action": InvestigationActionType.FETCH_METRICS.value,
        "reason": "Check latency percentiles (p50/p95/p99)",
    },
}

# ── Action → Signals reverse map ─────────────────────────────────────

ACTION_TO_SIGNALS: dict[str, list[str]] = {
    InvestigationActionType.FETCH_METRICS.value: [
        "cpu_usage", "latency", "error_rate", "request_rate", "memory",
        "latency_p50_p99", "metrics",
    ],
    InvestigationActionType.FETCH_INFRA_METRICS.value: [
        "cpu_usage", "cpu_limits", "cpu_throttling", "memory",
    ],
    InvestigationActionType.FETCH_LOGS.value: ["error_logs"],
    InvestigationActionType.SEARCH_LOGS_CUSTOM.value: ["error_logs"],
    InvestigationActionType.FETCH_TRACES.value: ["traces"],
    InvestigationActionType.SEARCH_TRACES_CUSTOM.value: ["traces"],
    InvestigationActionType.FETCH_DEPLOYMENTS.value: ["deployments"],
    InvestigationActionType.FETCH_EVENTS.value: ["deployments"],
    InvestigationActionType.FETCH_MONITORS.value: ["monitors"],
    InvestigationActionType.FETCH_SERVICE_MAP.value: ["dependencies"],
    InvestigationActionType.QUERY_CUSTOM_METRIC.value: [],  # depends on query
    InvestigationActionType.CORRELATE_SIGNALS.value: [],
    InvestigationActionType.EXPAND_SCOPE.value: ["dependencies"],
    InvestigationActionType.ANALYZE_HYPOTHESIS.value: [],
    InvestigationActionType.CONCLUDE.value: [],
}

# ── Tag fallback patterns ─────────────────────────────────────────────

TAG_FALLBACKS: dict[str, list[str]] = {
    "service": ["service", "kube_service", "app", "kube_deployment"],
    "container_name": [
        "container_name", "kube_container_name", "container_id",
        "short_image",
    ],
    "namespace": ["kube_namespace", "namespace", "env", "kube_cluster_name"],
    "pod_name": ["pod_name", "kube_pod_name", "pod"],
}


# ── Public functions ──────────────────────────────────────────────────


def build_signal_checklist(symptom_type: str) -> dict[str, SignalCheckResult]:
    """Initialize the required signal checklist for a given symptom type."""
    signals = REQUIRED_SIGNALS.get(symptom_type, REQUIRED_SIGNALS[SymptomType.UNKNOWN.value])
    return {
        sig: SignalCheckResult(signal_type=sig)
        for sig in signals
    }


def mark_signals_checked(
    checklist: dict[str, SignalCheckResult],
    action_type: str,
    step_number: int,
    data_found: bool,
    notes: str = "",
) -> None:
    """Mark all signals satisfied by this action as checked."""
    satisfied = ACTION_TO_SIGNALS.get(action_type, [])
    for sig in satisfied:
        if sig in checklist:
            checklist[sig].checked = True
            checklist[sig].step_number = step_number
            checklist[sig].data_found = checklist[sig].data_found or data_found
            if notes:
                checklist[sig].notes = notes


def get_unchecked_signals(checklist: dict[str, SignalCheckResult]) -> list[str]:
    """Return signal keys that haven't been checked yet."""
    return [sig for sig, result in checklist.items() if not result.checked]


def get_forced_next_action(unchecked_signal: str, service: str) -> dict:
    """Generate an action spec for a missing signal, same format as Claude returns."""
    action_spec = SIGNAL_TO_ACTION.get(unchecked_signal)
    if not action_spec:
        return {"action": "fetch_metrics", "reason": f"Check {unchecked_signal}", "data_source": service}
    return {
        "action": action_spec["action"],
        "reason": f"[FORCED] {action_spec['reason']} — signal '{unchecked_signal}' not yet checked",
        "data_source": service,
        "query_params": {},
    }


def get_tag_fallbacks(original_tags: dict[str, str]) -> list[dict[str, str]]:
    """Generate alternative tag combinations for retrying empty fetches."""
    fallbacks = []
    for key, value in original_tags.items():
        alt_keys = TAG_FALLBACKS.get(key, [])
        for alt_key in alt_keys:
            if alt_key != key:
                alt_tags = dict(original_tags)
                alt_tags.pop(key)
                alt_tags[alt_key] = value
                fallbacks.append(alt_tags)
    return fallbacks[:3]  # max 3 fallback attempts


def calibrate_confidence(
    raw_confidence: float,
    state: InvestigationState,
    *,
    confidence_cap_sparse: float = 0.40,
    confidence_cap_no_evidence: float = 0.60,
) -> float:
    """Apply programmatic confidence calibration rules.

    Rules:
    - >50% empty fetches → cap at confidence_cap_sparse
    - No direct supporting evidence for any hypothesis → cap at confidence_cap_no_evidence
    - >80% only if 2+ supporting evidence and 0 contradicting for top hypothesis
    """
    calibrated = min(max(raw_confidence, 0.0), 1.0)

    # Rule 1: Sparse data cap
    if state.total_fetches > 0:
        empty_ratio = state.empty_fetches / state.total_fetches
        if empty_ratio > 0.5:
            calibrated = min(calibrated, confidence_cap_sparse)
            logger.debug(
                "Confidence capped at %.0f%% (%.0f%% empty fetches)",
                confidence_cap_sparse * 100, empty_ratio * 100,
            )

    # Rule 2: No direct evidence cap
    has_direct_evidence = any(
        len(h.supporting_evidence) > 0
        for h in state.hypotheses.values()
        if h.status in (HypothesisStatus.INVESTIGATING, HypothesisStatus.CONFIRMED)
    )
    if not has_direct_evidence:
        calibrated = min(calibrated, confidence_cap_no_evidence)

    # Rule 3: High confidence gate
    if calibrated > 0.80:
        top_hyp = _get_leading_hypothesis(state.hypotheses)
        if top_hyp is None:
            calibrated = min(calibrated, 0.80)
        elif len(top_hyp.supporting_evidence) < 2 or len(top_hyp.contradicting_evidence) > 0:
            calibrated = min(calibrated, 0.80)

    return calibrated


def can_conclude(
    state: InvestigationState,
    min_coverage: float = 0.7,
) -> tuple[bool, str]:
    """Check if the investigation has enough coverage to conclude.

    Returns (can_conclude, reason).
    """
    checklist = state.signal_checklist
    if not checklist:
        return True, "No signal checklist configured"

    total = len(checklist)
    checked = sum(1 for r in checklist.values() if r.checked)
    coverage = checked / max(total, 1)

    if coverage < min_coverage:
        unchecked = get_unchecked_signals(checklist)
        return False, f"Signal coverage {coverage:.0%} < {min_coverage:.0%}. Missing: {', '.join(unchecked[:5])}"

    # At least one hypothesis must have evidence
    has_evidence = any(
        len(h.supporting_evidence) > 0 or len(h.contradicting_evidence) > 0
        for h in state.hypotheses.values()
    )
    if not has_evidence and state.hypotheses:
        return False, "No hypothesis has any evidence yet"

    return True, "Signal coverage sufficient"


def format_signal_coverage(checklist: dict[str, SignalCheckResult]) -> str:
    """Format signal checklist for inclusion in prompts."""
    if not checklist:
        return "No signal checklist."
    lines = []
    for sig, result in checklist.items():
        if result.checked:
            data_note = "data found" if result.data_found else "NO DATA"
            lines.append(f"  [x] {sig} (step {result.step_number}, {data_note})")
        else:
            lines.append(f"  [ ] {sig} — NOT YET CHECKED")
    return "\n".join(lines)


# ── Private helpers ───────────────────────────────────────────────────


def _get_leading_hypothesis(
    hypotheses: dict[str, TrackedHypothesis],
) -> Optional[TrackedHypothesis]:
    """Get the hypothesis with highest confidence."""
    if not hypotheses:
        return None
    return max(hypotheses.values(), key=lambda h: h.confidence)
