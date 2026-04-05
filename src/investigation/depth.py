"""Depth phase — targeted deep-dive into the leading hypothesis.

After the breadth phase identifies WHAT happened (e.g., "hot pod"),
the depth phase investigates WHY it happened by running targeted queries
specific to the hypothesis category.

For dependency_failure hypotheses, the depth phase follows the dependency
chain — identifying downstream services from evidence and investigating
them directly (logs, metrics, pod health, events).
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Awaitable, Callable, Optional

from config.settings import AgentConfig
from src.claude.prompts import (
    DEPTH_ANALYSIS_PROMPT,
    DOWNSTREAM_DEPTH_PROMPT,
    DOWNSTREAM_EXTRACTION_PROMPT,
)
from src.claude.reasoning import ClaudeReasoning
from src.investigation.analysis import AnalysisPhase
from src.investigation.execution import ActionExecutor
from src.investigation.helpers import (
    format_raw_data,
    is_empty_result,
    merge_data,
    parse_json_response,
)
from src.investigation.rules import (
    build_depth_queries,
    classify_hypothesis,
)
from src.models.incident import (
    DataGap,
    IncidentQuery,
    InvestigationActionType,
    InvestigationState,
    InvestigationStep,
    InvestigationTrace,
    ObservabilityData,
    TrackedHypothesis,
)

logger = logging.getLogger(__name__)

# Maximum number of downstream services to follow in a single depth run
MAX_DOWNSTREAM_HOPS = 3


class DepthPhase:
    """Runs targeted, depth-first queries for the leading hypothesis.

    For dependency_failure hypotheses, follows the dependency chain by:
    1. Extracting downstream service names from breadth evidence
    2. Investigating each downstream service (logs, metrics, pod health)
    3. Following the chain further if the downstream points to another service
    """

    def __init__(
        self,
        executor: ActionExecutor,
        analysis: AnalysisPhase,
        reasoning: ClaudeReasoning,
        config: AgentConfig,
        on_step_complete: Optional[Callable[[InvestigationStep], Awaitable[None]]] = None,
    ) -> None:
        self.executor = executor
        self.analysis = analysis
        self.reasoning = reasoning
        self.config = config
        self.on_step_complete = on_step_complete

    async def run(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
    ) -> None:
        """Run depth investigation for the leading hypothesis."""
        leading = self._get_leading_hypothesis(state)
        if not leading:
            logger.info("Depth phase: no hypothesis to investigate deeply")
            return

        if leading.confidence < 0.10:
            logger.info(
                "Depth phase: leading hypothesis confidence too low (%.0f%%), skipping",
                leading.confidence * 100,
            )
            return

        # Classify the hypothesis
        category = classify_hypothesis(leading.description)
        if category == "unknown":
            logger.info(
                "Depth phase: could not classify hypothesis '%s', skipping",
                leading.description[:80],
            )
            return

        logger.info(
            "Depth phase: investigating '%s' (category=%s, confidence=%.0f%%)",
            leading.description[:80], category, leading.confidence * 100,
        )

        # For dependency failures, use cross-service investigation
        if category == "dependency_failure":
            await self._run_cross_service_investigation(
                incident, trace, state, accumulated_data, leading, category,
            )
        else:
            await self._run_standard_depth(
                incident, trace, state, accumulated_data, leading, category,
            )

        logger.info(
            "Depth phase complete: %d steps, hypothesis confidence now %.0f%%",
            state.depth_steps_taken, leading.confidence * 100,
        )

    # ── Standard depth (hot_pod, resource_exhaustion, etc.) ──────────

    async def _run_standard_depth(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
        leading: TrackedHypothesis,
        category: str,
    ) -> None:
        """Run standard depth queries from templates."""
        pod = self._extract_pod_from_context(incident, state)

        tags = {}
        if state.discovered_context:
            tags = dict(state.discovered_context.resolved_tags)
        if not tags:
            tags = dict(incident.source_tags)
        if not tags:
            tags = {"service": incident.service}

        depth_queries = build_depth_queries(category, incident.service, tags, pod)
        if not depth_queries:
            logger.info("Depth phase: no queries generated for category '%s'", category)
            return

        max_depth = self.config.max_depth_steps
        for i, query_spec in enumerate(depth_queries[:max_depth]):
            await self._execute_depth_query(
                i, query_spec, incident, trace, state, accumulated_data, leading,
            )

    # ── Cross-service investigation (dependency_failure) ─────────────

    async def _run_cross_service_investigation(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
        leading: TrackedHypothesis,
        category: str,
    ) -> None:
        """Follow the dependency chain to downstream services.

        1. Extract downstream services from evidence
        2. Investigate each downstream service
        3. Follow further downstream if needed
        """
        # First run the standard dependency_failure queries
        await self._run_standard_depth(
            incident, trace, state, accumulated_data, leading, category,
        )

        # Extract downstream services from evidence
        downstream_services = await self._identify_downstream_services(
            incident, state, leading, accumulated_data,
        )

        if not downstream_services:
            logger.info("Depth phase: no downstream services identified from evidence")
            return

        # Investigate each downstream service
        investigated: set[str] = set()
        services_to_investigate = list(downstream_services)
        hop = 0

        while services_to_investigate and hop < MAX_DOWNSTREAM_HOPS:
            svc_info = services_to_investigate.pop(0)
            svc_name = svc_info["service_name"]

            if svc_name in investigated or svc_name == incident.service:
                continue
            investigated.add(svc_name)

            if state.depth_steps_taken >= self.config.max_depth_steps:
                logger.info("Depth phase: max depth steps reached, stopping")
                break

            logger.info(
                "Depth phase: investigating downstream service '%s' (hop %d, source: %s)",
                svc_name, hop + 1, svc_info.get("source", "unknown"),
            )

            # Run downstream investigation queries
            further = await self._investigate_downstream_service(
                svc_name,
                svc_info.get("likely_k8s_namespace", ""),
                incident, trace, state, accumulated_data, leading, category,
            )

            # If the downstream points to another service, queue it
            if further and further not in investigated:
                services_to_investigate.append({
                    "service_name": further,
                    "source": f"further downstream from {svc_name}",
                    "likely_k8s_namespace": "",
                    "investigation_priority": "high",
                })
                hop += 1

    async def _identify_downstream_services(
        self,
        incident: IncidentQuery,
        state: InvestigationState,
        leading: TrackedHypothesis,
        accumulated_data: ObservabilityData,
    ) -> list[dict]:
        """Extract downstream service names from evidence collected so far.

        Uses both pattern matching (fast) and Claude analysis (thorough).
        """
        # Fast path: extract service names from evidence strings using patterns
        services_from_patterns = self._extract_services_from_evidence(
            leading, state, incident,
        )

        if services_from_patterns:
            logger.info(
                "Depth phase: found %d downstream services from pattern matching: %s",
                len(services_from_patterns),
                [s["service_name"] for s in services_from_patterns],
            )
            # Combine pattern results with Claude analysis for completeness
            # but don't block on Claude if we already have good candidates

        # Claude analysis: ask Claude to identify downstream services
        # Always run this — Claude can find services patterns miss
        evidence_lines = []
        for e in leading.supporting_evidence[-10:]:
            evidence_lines.append(f"  (+) {e}")
        for e in leading.contradicting_evidence[-5:]:
            evidence_lines.append(f"  (-) {e}")

        raw_data_samples = self._collect_raw_data_samples(accumulated_data, state)

        prompt = DOWNSTREAM_EXTRACTION_PROMPT.format(
            service=incident.service,
            hypothesis=leading.description,
            evidence="\n".join(evidence_lines) or "No evidence collected",
            raw_data_samples=raw_data_samples[:3000],
        )

        response = await self.reasoning.query_dynamic(prompt)
        result = parse_json_response(response, fallback={"downstream_services": []})

        claude_services = result.get("downstream_services", [])
        # Filter out the primary service and validate
        claude_services = [
            s for s in claude_services
            if s.get("service_name")
            and s["service_name"] != incident.service
            and DepthPhase._is_valid_service_name(s["service_name"], incident.service)
        ]

        if claude_services:
            logger.info(
                "Depth phase: Claude identified %d downstream services: %s",
                len(claude_services),
                [s["service_name"] for s in claude_services],
            )

        # Merge: pattern matches first (higher confidence), then Claude results
        merged: dict[str, dict] = {}
        for svc in services_from_patterns:
            merged[svc["service_name"]] = svc
        for svc in claude_services:
            if svc["service_name"] not in merged:
                merged[svc["service_name"]] = svc

        all_services = list(merged.values())
        # Sort by priority: high first
        priority_order = {"high": 0, "medium": 1, "low": 2}
        all_services.sort(key=lambda s: priority_order.get(s.get("investigation_priority", "low"), 2))

        return all_services[:5]

    # Common English words that regex might accidentally extract as service names
    _NOT_SERVICE_NAMES = frozenset({
        "pairs", "issue", "issues", "failure", "failures", "service", "services",
        "search", "still", "that", "this", "with", "from", "into", "about",
        "after", "before", "during", "between", "through", "under", "over",
        "above", "below", "open", "close", "closed", "status", "error", "errors",
        "count", "total", "data", "empty", "found", "check", "checking",
        "tags", "metrics", "logs", "traces", "query", "unknown", "confirmed",
        "investigating", "pending", "rejected", "true", "false", "none",
        "downstream", "upstream", "dependency", "dependencies", "timeout",
        "connection", "circuit", "breaker", "production", "staging",
    })

    @staticmethod
    def _is_valid_service_name(name: str, incident_service: str) -> bool:
        """Check if a string looks like a real service name, not an English word."""
        if not name or len(name) < 4:
            return False
        if name == incident_service:
            return False
        if name.lower() in DepthPhase._NOT_SERVICE_NAMES:
            return False
        if name.startswith("http"):
            return False
        # Real service names almost always contain a hyphen or underscore
        # or have a domain-like structure (e.g., mercari-searchx-jp)
        has_separator = "-" in name or "_" in name or "." in name
        # Single words without separators are likely English words, not services
        if not has_separator and name.isalpha():
            return False
        return True

    @staticmethod
    def _extract_services_from_evidence(
        leading: TrackedHypothesis,
        state: InvestigationState,
        incident: IncidentQuery,
    ) -> list[dict]:
        """Extract service names from evidence using regex patterns."""
        services: dict[str, dict] = {}
        all_evidence = (
            leading.supporting_evidence
            + leading.contradicting_evidence
            + state.data_gap_log
        )
        all_text = " ".join(all_evidence)

        # Pattern 1: Tag-style values with colon separator (most reliable)
        # Matches: from-service:mercari-searchx-jp, search-service:triton-text-embeddings
        for match in re.finditer(
            r"(?:from[_-]service|search[_-]service|peer_service|target_service|"
            r"downstream_service|upstream_service):([a-zA-Z0-9][-a-zA-Z0-9_.]+)",
            all_text,
        ):
            svc = match.group(1)
            if DepthPhase._is_valid_service_name(svc, incident.service):
                services[svc] = {
                    "service_name": svc,
                    "source": "circuit breaker / dependency tag",
                    "likely_k8s_namespace": "",
                    "investigation_priority": "high",
                }

        # Pattern 2: Kubernetes service endpoints in logs (very reliable)
        # e.g., triton-text-embeddings-ruri-small-v2.mercari-embeddings-jp-prod.svc.cluster.local:8001
        for match in re.finditer(
            r"([a-zA-Z0-9][-a-zA-Z0-9]*)\.([-a-zA-Z0-9]+)\.svc\.cluster\.local",
            all_text,
        ):
            svc = match.group(1)
            ns = match.group(2)
            if svc != incident.service:
                services[svc] = {
                    "service_name": svc,
                    "source": "Kubernetes service endpoint in logs",
                    "likely_k8s_namespace": ns,
                    "investigation_priority": "high",
                }

        # Pattern 3: gRPC service names with colon separator
        for match in re.finditer(
            r"grpc_service:([a-zA-Z0-9][-a-zA-Z0-9_.]+)",
            all_text,
        ):
            svc = match.group(1)
            if DepthPhase._is_valid_service_name(svc, incident.service):
                services.setdefault(svc, {
                    "service_name": svc,
                    "source": "gRPC service tag",
                    "likely_k8s_namespace": "",
                    "investigation_priority": "medium",
                })

        # Pattern 4: connection/timeout errors with specific service name patterns
        # Only match names that look like real service names (contain hyphens/underscores)
        for match in re.finditer(
            r"(?:connection to|timeout calling|error from)\s+([a-zA-Z0-9][-a-zA-Z0-9_.]+)",
            all_text, re.IGNORECASE,
        ):
            svc = match.group(1)
            if DepthPhase._is_valid_service_name(svc, incident.service):
                services.setdefault(svc, {
                    "service_name": svc,
                    "source": "error message",
                    "likely_k8s_namespace": "",
                    "investigation_priority": "medium",
                })

        return list(services.values())

    async def _investigate_downstream_service(
        self,
        downstream_service: str,
        namespace: str,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
        leading: TrackedHypothesis,
        category: str,
    ) -> Optional[str]:
        """Investigate a specific downstream service.

        Queries: error logs, metrics, pod restarts, events.
        Returns the name of a further-downstream service if identified.
        """
        further_downstream = None
        context_lines = []
        for e in leading.supporting_evidence[-5:]:
            context_lines.append(f"  (+) {e}")
        context = "\n".join(context_lines)

        # Build investigation queries for the downstream service
        downstream_queries = self._build_downstream_queries(
            downstream_service, namespace, incident,
        )

        for query_spec in downstream_queries:
            if state.depth_steps_taken >= self.config.max_depth_steps:
                break

            step_start = time.monotonic()
            step_number = trace.total_steps + 1
            state.depth_steps_taken += 1

            logger.info(
                "Depth step (downstream %s): %s — %s",
                downstream_service, query_spec["signal"], query_spec["description"],
            )

            # Execute
            raw_data = None
            data_summary = ""
            try:
                if query_spec["type"] == "metric":
                    raw_data = await self.executor.dd_client.query_metrics(
                        query_spec["query"], incident.start_time, incident.end_time,
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} metric series"
                elif query_spec["type"] == "log":
                    raw_data = await self.executor.dd_client.search_logs(
                        query_spec["query"], incident.start_time, incident.end_time,
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} log entries"
                elif query_spec["type"] == "event":
                    raw_data = await self.executor.dd_client.get_events(
                        incident.start_time, incident.end_time,
                        tags=[f"service:{downstream_service}"],
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} events"
                elif query_spec["type"] == "monitors":
                    raw_data = await self.executor.dd_client.get_triggered_monitors(
                        downstream_service,
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} monitors"
            except Exception as e:
                logger.warning("Downstream query for %s failed: %s", downstream_service, e)
                data_summary = f"Query failed: {e}"

            step = InvestigationStep(
                step_number=step_number,
                action=InvestigationActionType.QUERY_CUSTOM_METRIC
                if query_spec["type"] == "metric"
                else InvestigationActionType.SEARCH_LOGS_CUSTOM,
                reason=f"[DEPTH:downstream:{downstream_service}] {query_spec['description']}",
                data_source=downstream_service,
                query_params={"query": query_spec["query"], "depth_signal": query_spec["signal"]},
                data_summary=data_summary,
            )

            empty = is_empty_result(raw_data)
            if empty:
                step.findings = f"No data for {query_spec['signal']} on {downstream_service}"
                step.confidence = leading.confidence
            else:
                # Merge data using correct action type based on query type
                merge_action = (
                    InvestigationActionType.QUERY_CUSTOM_METRIC
                    if query_spec["type"] == "metric"
                    else InvestigationActionType.SEARCH_LOGS_CUSTOM
                )
                merge_data(accumulated_data, raw_data, merge_action)

                # Analyze with downstream-specific prompt
                data_content = format_raw_data(raw_data, merge_action)
                prompt = DOWNSTREAM_DEPTH_PROMPT.format(
                    upstream_service=incident.service,
                    downstream_service=downstream_service,
                    hypothesis=leading.description,
                    category=category,
                    query_description=query_spec["description"],
                    data_content=data_content,
                    context=context,
                )
                response = await self.reasoning.query_dynamic(prompt)
                result = parse_json_response(response, fallback={
                    "is_source": False,
                    "root_cause": "",
                    "mechanism": "",
                    "evidence_summary": "Analysis inconclusive",
                    "confidence_delta": 0.0,
                    "further_downstream": "",
                    "further_downstream_reason": "",
                })

                step.findings = result.get("evidence_summary", "")
                mechanism = result.get("root_cause", "") or result.get("mechanism", "")
                if mechanism:
                    step.findings = f"MECHANISM: {mechanism}\n{step.findings}"

                # Update hypothesis
                delta = float(result.get("confidence_delta", 0.0))
                is_source = result.get("is_source", False)

                evidence_text = result.get("evidence_summary", query_spec["description"])
                if is_source or delta > 0:
                    leading.supporting_evidence.append(
                        f"[depth:downstream:{downstream_service}:{query_spec['signal']}] {evidence_text}"
                    )
                    leading.confidence = min(1.0, max(0.0, leading.confidence + delta))
                elif delta < 0:
                    leading.contradicting_evidence.append(
                        f"[depth:downstream:{downstream_service}:{query_spec['signal']}] {evidence_text}"
                    )
                    leading.confidence = max(0.0, leading.confidence + delta)

                step.confidence = leading.confidence

                # Check if there's a further downstream service
                fd = result.get("further_downstream", "")
                if fd and fd != downstream_service and fd != incident.service:
                    further_downstream = fd
                    logger.info(
                        "Depth phase: downstream %s points further to %s (%s)",
                        downstream_service, fd,
                        result.get("further_downstream_reason", ""),
                    )

                # Update context for next query
                if step.findings:
                    context += f"\n  (+) {step.findings[:200]}"

            step.hypotheses = [
                f"[{leading.status.value.upper()}] {leading.description} ({leading.confidence:.0%})"
            ]
            step.decision = f"Investigating downstream: {downstream_service}"
            step.duration_ms = int((time.monotonic() - step_start) * 1000)

            trace.steps.append(step)
            trace.total_steps += 1

            if self.on_step_complete:
                try:
                    await self.on_step_complete(step)
                except Exception as e:
                    logger.warning("Depth step callback failed: %s", e)

            logger.info(
                "Depth step (downstream %s) complete: confidence=%.0f%%, empty=%s",
                downstream_service, leading.confidence * 100, empty,
            )

        return further_downstream

    @staticmethod
    def _build_downstream_queries(
        service: str,
        namespace: str,
        incident: IncidentQuery,
    ) -> list[dict]:
        """Build investigation queries for a downstream service.

        These queries investigate the downstream service's health directly:
        error logs, pod restarts, latency, resource usage, and events.
        """
        queries = []

        # 1. Error logs from the downstream service
        log_query = f"service:{service} status:error"
        if namespace:
            log_query = f"(service:{service} OR kube_namespace:{namespace}) status:error"
        queries.append({
            "type": "log",
            "query": log_query,
            "signal": f"{service}_error_logs",
            "description": f"Error logs from downstream service {service}",
        })

        # 2. Error logs mentioning the downstream service from any source
        queries.append({
            "type": "log",
            "query": f"*{service}* (error OR timeout OR unavailable OR SIGTERM OR OOMKilled OR restart)",
            "signal": f"{service}_mentions",
            "description": f"Log mentions of {service} with error/timeout/restart keywords",
        })

        # 3. Pod restarts / termination for the downstream service
        ns_filter = f"kube_namespace:{namespace}" if namespace else f"service:{service}"
        queries.append({
            "type": "metric",
            "query": f"sum:kubernetes.containers.restarts{{{ns_filter}}} by {{pod_name}}.as_count()",
            "signal": f"{service}_restarts",
            "description": f"Pod restarts for {service}",
        })

        # 4. CPU/memory for the downstream service
        queries.append({
            "type": "metric",
            "query": f"avg:kubernetes.cpu.usage.total{{{ns_filter}}} by {{pod_name}}",
            "signal": f"{service}_cpu",
            "description": f"CPU usage by pod for {service}",
        })

        # 5. Readiness/liveness probe failures (via logs in the namespace)
        if namespace:
            queries.append({
                "type": "log",
                "query": f"kube_namespace:{namespace} (readiness OR liveness OR probe OR SIGTERM OR terminated OR OOMKilled)",
                "signal": f"{service}_probe_failures",
                "description": f"Readiness/liveness probe failures and terminations for {service}",
            })

        return queries

    # ── Standard depth query execution ───────────────────────────────

    async def _execute_depth_query(
        self,
        index: int,
        query_spec: dict,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
        leading: TrackedHypothesis,
    ) -> None:
        """Execute a single depth query and update state."""
        step_start = time.monotonic()
        step_number = trace.total_steps + 1
        state.depth_steps_taken += 1

        logger.info(
            "Depth step %d: %s — %s",
            index + 1, query_spec["signal"], query_spec["description"],
        )

        raw_data = None
        data_summary = ""
        try:
            if query_spec["type"] == "metric":
                raw_data = await self.executor.dd_client.query_metrics(
                    query_spec["query"], incident.start_time, incident.end_time,
                )
                data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} metric series"
            elif query_spec["type"] == "log":
                raw_data = await self.executor.dd_client.search_logs(
                    query_spec["query"], incident.start_time, incident.end_time,
                )
                data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} log entries"
        except Exception as e:
            logger.warning("Depth query failed: %s", e)
            data_summary = f"Query failed: {e}"

        step = InvestigationStep(
            step_number=step_number,
            action=InvestigationActionType.QUERY_CUSTOM_METRIC
            if query_spec["type"] == "metric"
            else InvestigationActionType.SEARCH_LOGS_CUSTOM,
            reason=f"[DEPTH] {query_spec['description']}",
            data_source=incident.service,
            query_params={"query": query_spec["query"], "depth_signal": query_spec["signal"]},
            data_summary=data_summary,
        )

        empty = is_empty_result(raw_data)
        if empty:
            state.data_gaps.append(DataGap(
                signal=query_spec["signal"],
                queries_attempted=[query_spec["query"]],
                failure_reason="Depth query returned no data",
                recommendation=f"Check if {query_spec['signal']} metrics are emitted for {incident.service}",
                impact=f"Cannot determine {query_spec['description'].lower()}",
            ))
            step.findings = f"No data for {query_spec['signal']}"
            step.confidence = leading.confidence
        else:
            if query_spec["type"] == "metric":
                merge_data(accumulated_data, raw_data, InvestigationActionType.QUERY_CUSTOM_METRIC)
            else:
                merge_data(accumulated_data, raw_data, InvestigationActionType.SEARCH_LOGS_CUSTOM)

            analysis_result = await self._analyze_depth_data(
                raw_data, leading, classify_hypothesis(leading.description), query_spec, state,
            )

            step.findings = analysis_result.get("evidence_summary", "")
            mechanism = analysis_result.get("mechanism", "")
            if mechanism:
                step.findings = f"MECHANISM: {mechanism}\n{step.findings}"

            delta = float(analysis_result.get("confidence_delta", 0.0))
            supports = analysis_result.get("supports", True)

            if supports:
                evidence_text = analysis_result.get("evidence_summary", query_spec["description"])
                leading.supporting_evidence.append(f"[depth:{query_spec['signal']}] {evidence_text}")
                leading.confidence = min(1.0, max(0.0, leading.confidence + delta))
            else:
                evidence_text = analysis_result.get("evidence_summary", query_spec["description"])
                leading.contradicting_evidence.append(f"[depth:{query_spec['signal']}] {evidence_text}")
                leading.confidence = max(0.0, leading.confidence - abs(delta))

            step.confidence = leading.confidence

        step.hypotheses = [
            f"[{leading.status.value.upper()}] {leading.description} ({leading.confidence:.0%})"
        ]
        step.decision = "Continue depth investigation"
        step.duration_ms = int((time.monotonic() - step_start) * 1000)

        trace.steps.append(step)
        trace.total_steps += 1

        if self.on_step_complete:
            try:
                await self.on_step_complete(step)
            except Exception as e:
                logger.warning("Depth step callback failed: %s", e)

        logger.info(
            "Depth step %d complete: confidence=%.0f%%, empty=%s",
            index + 1, leading.confidence * 100, empty,
        )

    # ── Analysis ──────────────────────────────────────────────────────

    async def _analyze_depth_data(
        self,
        raw_data: Any,
        hypothesis: TrackedHypothesis,
        category: str,
        query_spec: dict,
        state: InvestigationState,
    ) -> dict:
        """Analyze depth query results with a focused prompt."""
        data_content = format_raw_data(raw_data, InvestigationActionType.QUERY_CUSTOM_METRIC)

        prompt = DEPTH_ANALYSIS_PROMPT.format(
            hypothesis_description=hypothesis.description,
            confidence=hypothesis.confidence,
            category=category,
            query_description=query_spec.get("description", query_spec["signal"]),
            data_content=data_content,
            supporting_evidence="\n".join(hypothesis.supporting_evidence[-5:]) or "None yet",
            contradicting_evidence="\n".join(hypothesis.contradicting_evidence[-5:]) or "None yet",
        )

        response = await self.reasoning.query_dynamic(prompt)
        return parse_json_response(response, fallback={
            "supports": True,
            "mechanism": "",
            "evidence_summary": "Analysis inconclusive",
            "confidence_delta": 0.0,
            "next_query_suggestion": "",
        })

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _collect_raw_data_samples(
        accumulated_data: ObservabilityData,
        state: InvestigationState,
    ) -> str:
        """Collect raw data samples for downstream extraction prompt."""
        samples = []

        # Metric names and tags
        for m in accumulated_data.metrics[:10]:
            tags_str = ""
            if hasattr(m, "tags") and m.tags:
                tags_str = f" tags={m.tags}"
            samples.append(f"metric: {m.metric_name}{tags_str}")

        # Log samples
        for log in accumulated_data.logs[:10]:
            msg = log.message[:200] if log.message else ""
            samples.append(f"log [{log.service}]: {msg}")

        # Data gap log entries
        for entry in state.data_gap_log[:5]:
            samples.append(f"gap: {entry}")

        return "\n".join(samples) if samples else "No raw data samples available"

    @staticmethod
    def _get_leading_hypothesis(state: InvestigationState) -> Optional[TrackedHypothesis]:
        """Get the hypothesis with highest confidence."""
        if not state.hypotheses:
            return None
        return max(state.hypotheses.values(), key=lambda h: h.confidence)

    @staticmethod
    def _extract_pod_from_context(incident: IncidentQuery, state: InvestigationState) -> str:
        """Try to extract a specific pod name from the incident context."""
        for key in ("pod_name", "kube_pod_name", "pod"):
            if key in incident.source_tags:
                return incident.source_tags[key]

        pod_match = re.search(r"pod_name:([a-zA-Z0-9_.-]+)", incident.raw_query)
        if pod_match:
            return pod_match.group(1)

        return ""
