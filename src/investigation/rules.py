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
        "error_logs",
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
    InvestigationActionType.DISCOVER_CONTEXT.value: [],
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
    query: str = "",
) -> None:
    """Mark all signals satisfied by this action as checked.

    For query_custom_metric actions, infers which signals the query covers
    based on the metric name in the query string.
    """
    satisfied = ACTION_TO_SIGNALS.get(action_type, [])

    # Infer signals from custom metric queries based on metric name
    if action_type == InvestigationActionType.QUERY_CUSTOM_METRIC.value and query:
        satisfied = list(satisfied) + _infer_signals_from_query(query)

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
    - Average data quality < 0.3 → cap at 0.45
    """
    calibrated = min(max(raw_confidence, 0.0), 1.0)

    # Rule 1: Sparse data cap — only penalize when we have NO data at all.
    # Empty fetches mean "not checked", not "contradicts hypothesis".
    if state.total_fetches > 0:
        non_empty = state.total_fetches - state.empty_fetches
        if non_empty == 0:
            # Zero evidence — cap very low
            calibrated = min(calibrated, 0.20)
            logger.debug(
                "Confidence capped at 20%% (all %d fetches empty)",
                state.total_fetches,
            )
        elif non_empty == 1:
            # Only 1 data source — cap moderately
            calibrated = min(calibrated, confidence_cap_sparse)
            logger.debug(
                "Confidence capped at %.0f%% (only 1 non-empty fetch)",
                confidence_cap_sparse * 100,
            )

    # Rule 1b: Low data quality cap
    checked_signals = [r for r in state.signal_checklist.values() if r.checked]
    if checked_signals:
        avg_quality = sum(r.data_quality for r in checked_signals) / len(checked_signals)
        if avg_quality < 0.3:
            calibrated = min(calibrated, 0.45)
            logger.debug(
                "Confidence capped at 45%% (avg data quality %.2f < 0.3)",
                avg_quality,
            )

    # Rule 2: No direct evidence cap
    has_direct_evidence = any(
        len(h.supporting_evidence) > 0
        for h in state.hypotheses.values()
        if h.status in (HypothesisStatus.INVESTIGATING, HypothesisStatus.CONFIRMED)
    )
    if not has_direct_evidence:
        calibrated = min(calibrated, confidence_cap_no_evidence)

    # Rule 3: High confidence gate — allow >0.80 if supporting evidence
    # significantly outweighs contradicting evidence.
    if calibrated > 0.80:
        top_hyp = _get_leading_hypothesis(state.hypotheses)
        if top_hyp is None:
            calibrated = min(calibrated, 0.80)
        elif len(top_hyp.supporting_evidence) < 2:
            calibrated = min(calibrated, 0.80)
        elif len(top_hyp.contradicting_evidence) > len(top_hyp.supporting_evidence) // 2:
            calibrated = min(calibrated, 0.80)

    return calibrated


def can_conclude(
    state: InvestigationState,
    min_coverage: float = 0.7,
) -> tuple[bool, str]:
    """Check if the investigation has enough coverage to conclude.

    Returns (can_conclude, reason).
    v3: Also requires data_found=True for >=50% of checked signals.
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

    # v3: Require data_found for at least 50% of checked signals
    if checked > 0:
        with_data = sum(1 for r in checklist.values() if r.checked and r.data_found)
        data_ratio = with_data / checked
        if data_ratio < 0.5:
            empty_signals = [
                sig for sig, r in checklist.items() if r.checked and not r.data_found
            ]
            return False, (
                f"Only {data_ratio:.0%} of checked signals returned data. "
                f"Empty: {', '.join(empty_signals[:5])}"
            )

    # At least one hypothesis must have evidence
    has_evidence = any(
        len(h.supporting_evidence) > 0 or len(h.contradicting_evidence) > 0
        for h in state.hypotheses.values()
    )
    if not has_evidence and state.hypotheses:
        return False, "No hypothesis has any evidence yet"

    # v3: For error_rate and latency investigations, ALWAYS require traces and
    # dependencies to be checked before concluding. These signals are critical
    # for following the request flow through downstream services. Without them,
    # the agent can falsely conclude "no issue" or miss cascading failures.
    symptom = state.symptom_type if hasattr(state, "symptom_type") else ""
    symptom_str = symptom.value if hasattr(symptom, "value") else str(symptom)
    trace_required_symptoms = {
        SymptomType.ERROR_RATE.value,
        SymptomType.LATENCY.value,
        SymptomType.AVAILABILITY.value,
    }
    if symptom_str in trace_required_symptoms:
        traces_signal = checklist.get("traces")
        deps_signal = checklist.get("dependencies")
        missing = []
        if traces_signal and not traces_signal.checked:
            missing.append("traces")
        if deps_signal and not deps_signal.checked:
            missing.append("dependencies")
        if missing:
            return False, (
                f"Cannot conclude {symptom_str} investigation without checking "
                f"{', '.join(missing)}. These signals are critical for identifying "
                f"cascading failures and downstream service issues."
            )

    # Also block conclusion if leading hypothesis involves dependency keywords,
    # even for symptom types not in the list above.
    leading = _get_leading_hypothesis(state.hypotheses) if state.hypotheses else None
    if leading:
        dep_keywords = {
            "dependency", "downstream", "upstream", "component", "service failure",
            "cascade", "timeout", "connection", "circuit breaker", "unavailable",
            "failed to get", "internal", "rpc error",
        }
        desc_lower = leading.description.lower()
        is_dependency_hypothesis = any(kw in desc_lower for kw in dep_keywords)
        if is_dependency_hypothesis:
            traces_signal = checklist.get("traces")
            if traces_signal and not traces_signal.checked:
                return False, (
                    f"Leading hypothesis involves dependency failure "
                    f"('{leading.description[:80]}...') but traces have not been checked. "
                    f"Traces are critical for following the request flow through downstream services."
                )

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


# ── Custom metric → signal inference ──────────────────────────────────

# Patterns in metric names that map to signals
_METRIC_SIGNAL_PATTERNS: list[tuple[list[str], list[str]]] = [
    # Latency / duration metrics
    (["latency", "duration", "response_time", "p50", "p75", "p95", "p99"], ["latency"]),
    # Error metrics
    (["error", "errors", "fault", "5xx", "4xx"], ["error_rate"]),
    # Request rate / throughput
    (["hits", "requests", "throughput", "count", "rate", "qps", "rps"], ["request_rate"]),
    # CPU metrics
    (["cpu.usage", "cpu.total", "cpu.system", "cpu.user"], ["cpu_usage"]),
    # CPU throttling
    (["throttl"], ["cpu_throttling"]),
    # Memory
    (["memory", "mem.usage", "heap", "rss"], ["memory"]),
    # Trace-derived metrics (trace.* are aggregate metrics from APM, NOT actual trace spans).
    # They provide latency/error/request data but do NOT satisfy the "traces" signal,
    # which requires actual span-level data to follow request flows and identify downstream services.
    (["trace."], ["latency", "error_rate", "request_rate"]),
]


def _infer_signals_from_query(query: str) -> list[str]:
    """Infer which signals a custom metric query covers based on metric name patterns."""
    query_lower = query.lower()
    signals: list[str] = []
    for patterns, signal_names in _METRIC_SIGNAL_PATTERNS:
        for pattern in patterns:
            if pattern in query_lower:
                signals.extend(signal_names)
                break
    return list(set(signals))


def _get_leading_hypothesis(
    hypotheses: dict[str, TrackedHypothesis],
) -> Optional[TrackedHypothesis]:
    """Get the hypothesis with highest confidence."""
    if not hypotheses:
        return None
    return max(hypotheses.values(), key=lambda h: h.confidence)


# ── Signal alternatives for pivot logic ──────────────────────────────

SIGNAL_ALTERNATIVES: dict[str, list[str]] = {
    "traces": ["error_logs"],
    "request_rate": ["error_logs"],
    "latency": ["traces", "error_logs"],
    "dependencies": ["traces"],
    "metrics": ["error_logs", "traces"],
}


def get_alternative_signal(failed_signal: str) -> Optional[str]:
    """After 2 failures for a signal, suggest an alternative."""
    alternatives = SIGNAL_ALTERNATIVES.get(failed_signal, [])
    return alternatives[0] if alternatives else None


# ── Depth query templates per hypothesis category ────────────────────

DEPTH_QUERIES: dict[str, dict] = {
    "hot_pod": {
        "description": "Single pod showing anomalous behavior vs fleet",
        "keywords": [
            "hot pod", "single pod", "one pod", "uneven", "imbalance",
            "specific pod", "individual pod", "pod.*saturat", "disproportionate",
            "outlier pod", "pod_name",
        ],
        "queries": [
            {
                "type": "metric",
                "query_template": "avg:kubernetes.cpu.usage.total{{{tags}}} by {{pod_name}}",
                "signal": "per_pod_cpu",
                "description": "CPU usage breakdown by pod",
            },
            {
                "type": "metric",
                "query_template": "avg:kubernetes.memory.usage{{{tags}}} by {{pod_name}}",
                "signal": "per_pod_memory",
                "description": "Memory usage breakdown by pod",
            },
            {
                "type": "metric",
                "query_template": "avg:container.cpu.throttled{{{tags}}}",
                "signal": "cpu_throttling",
                "description": "CPU throttling (indicates resource exhaustion)",
            },
            {
                "type": "metric",
                "query_template": "avg:kubernetes.containers.restarts{{{tags}}} by {{pod_name}}",
                "signal": "restart_history",
                "description": "Pod restart history (OOM kills, crash loops)",
            },
            {
                "type": "log",
                "query_template": "pod_name:{pod} status:error",
                "signal": "pod_error_logs",
                "description": "Error logs specific to the hot pod",
            },
        ],
    },
    "deployment_regression": {
        "description": "Metrics degraded after a deployment",
        "keywords": [
            "deploy", "release", "rollout", "new version", "regression",
            "after deploy", "since deploy", "code change", "build",
        ],
        "queries": [
            {
                "type": "metric",
                "query_template": "avg:kubernetes.cpu.usage.total{{{tags}}}",
                "signal": "cpu_trend",
                "description": "CPU usage trend (look for step change at deploy time)",
                "time_shift": True,
            },
            {
                "type": "metric",
                "query_template": "avg:kubernetes.containers.restarts{{{tags}}} by {{pod_name}}",
                "signal": "post_deploy_restarts",
                "description": "Pod restarts after deployment",
            },
            {
                "type": "log",
                "query_template": "service:{service} status:error",
                "signal": "post_deploy_errors",
                "description": "Error logs after deployment",
            },
        ],
    },
    "dependency_failure": {
        "description": "Upstream or downstream service causing issues",
        "keywords": [
            "upstream", "downstream", "dependency", "external", "timeout",
            "connection", "circuit breaker", "retry storm", "cascad",
            "context cancel", "failing internally", "service failure",
            "unavailable", "failed to get", "rpc error", "internal error",
            "internal", "grpc", "getcomponents", "failed to call",
            "resource constraint", "backend", "propagat", "deadline",
            "latency.*depend", "depend.*latency", "error.*service",
            "service.*error", "call.*fail", "fail.*call",
        ],
        "queries": [
            {
                "type": "log",
                "query_template": "service:{service} status:error (timeout OR connection OR circuit OR refused)",
                "signal": "dependency_errors",
                "description": "Error logs related to dependency failures",
            },
            {
                "type": "metric",
                "query_template": "avg:trace.http.request.duration{{{tags}}} by {{peer_service}}",
                "signal": "dependency_latency",
                "description": "Latency breakdown by downstream service",
            },
        ],
    },
    "resource_exhaustion": {
        "description": "OOM, disk, or resource limit reached",
        "keywords": [
            "oom", "memory", "disk", "exhaustion", "limit", "quota",
            "out of memory", "killed", "evict", "resource",
            "saturat", "thread pool", "heap", "gc storm", "capacity",
        ],
        "queries": [
            {
                "type": "metric",
                "query_template": "avg:kubernetes.memory.usage{{{tags}}} by {{pod_name}}",
                "signal": "memory_by_pod",
                "description": "Memory usage per pod",
            },
            {
                "type": "metric",
                "query_template": "avg:kubernetes.memory.limits{{{tags}}}",
                "signal": "memory_limits",
                "description": "Memory limits vs actual usage",
            },
            {
                "type": "metric",
                "query_template": "avg:kubernetes.cpu.limits{{{tags}}}",
                "signal": "cpu_limits_check",
                "description": "CPU limits vs actual usage",
            },
            {
                "type": "metric",
                "query_template": "sum:kubernetes.containers.last_state.terminated{{{tags}}} by {{reason}}",
                "signal": "termination_reasons",
                "description": "Pod termination reasons (OOMKilled, etc.)",
            },
        ],
    },
    "traffic_spike": {
        "description": "Sudden increase in request volume",
        "keywords": [
            "traffic", "spike", "surge", "request rate", "throughput",
            "load", "burst", "flood", "volume",
        ],
        "queries": [
            {
                "type": "metric",
                "query_template": "sum:trace.servlet.request.hits{{{tags}}} by {{resource_name}}.as_count()",
                "signal": "requests_by_endpoint",
                "description": "Request rate broken down by endpoint",
            },
            {
                "type": "metric",
                "query_template": "avg:kubernetes.cpu.usage.total{{{tags}}} by {{pod_name}}",
                "signal": "cpu_under_load",
                "description": "CPU per pod under load spike",
            },
        ],
    },
}


def classify_hypothesis(description: str) -> str:
    """Match hypothesis description to a depth query category.

    Returns the best-matching category key, or 'dependency_failure' as fallback
    when the description mentions any service/infrastructure issue but doesn't
    match a specific category. This prevents the depth phase from being skipped
    entirely on vague hypothesis descriptions.
    """
    import re as _re

    desc_lower = description.lower()
    best_category = "unknown"
    best_score = 0

    for category, spec in DEPTH_QUERIES.items():
        score = 0
        for keyword in spec["keywords"]:
            if _re.search(keyword, desc_lower):
                score += 1
        if score > best_score:
            best_score = score
            best_category = category

    if best_score > 0:
        return best_category

    # Fallback: if the hypothesis mentions anything infrastructure-related,
    # default to dependency_failure so depth phase still runs and traces
    # can be followed to downstream services.
    infra_hints = [
        "service", "latency", "error", "failure", "issue", "spike",
        "degrad", "slow", "impact", "incident", "constraint", "bottleneck",
        "overload", "pressure", "contention", "starv",
    ]
    if any(hint in desc_lower for hint in infra_hints):
        logger.info(
            "classify_hypothesis: no keyword match for '%s', "
            "falling back to 'dependency_failure' (infra hint detected)",
            description[:80],
        )
        return "dependency_failure"

    return "unknown"


def build_depth_queries(
    category: str,
    service: str,
    tags: dict[str, str],
    pod: str = "",
) -> list[dict]:
    """Generate concrete Datadog queries from depth templates.

    Substitutes {tags}, {service}, and {pod} into query templates.
    Returns list of query specs ready for execution.
    """
    spec = DEPTH_QUERIES.get(category)
    if not spec:
        return []

    tag_filter = ",".join(f"{k}:{v}" for k, v in tags.items()) if tags else f"service:{service}"
    queries = []

    for q in spec["queries"]:
        template = q["query_template"]
        query = template.replace("{tags}", tag_filter)
        query = query.replace("{service}", service)
        if pod:
            query = query.replace("{pod}", pod)

        queries.append({
            "type": q["type"],
            "query": query,
            "signal": q["signal"],
            "description": q.get("description", ""),
            "time_shift": q.get("time_shift", False),
        })

    return queries
