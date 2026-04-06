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
    DOWNSTREAM_RANKING_PROMPT,
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

        1. Follow trace IDs to discover actual downstream service names
        2. Extract additional services from evidence
        3. Investigate each downstream service
        4. Follow further downstream if needed
        """
        # Step 1: Follow trace IDs to discover downstream services
        # Client-side spans (service=mercari-home-jp) don't reveal downstream
        # service names. We need to look up ALL spans in the same traces to
        # find server-side spans from the actual downstream services.
        trace_discovered = await self._follow_trace_ids(
            incident, trace, state, accumulated_data, leading,
        )

        # Step 2: Run standard dependency_failure queries
        await self._run_standard_depth(
            incident, trace, state, accumulated_data, leading, category,
        )

        # Step 3: Extract downstream services from trace-following + evidence
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

            if state.downstream_steps_taken >= self.config.max_downstream_steps:
                logger.info("Depth phase: max downstream steps reached, stopping")
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

    async def _follow_trace_ids(
        self,
        incident: IncidentQuery,
        trace: InvestigationTrace,
        state: InvestigationState,
        accumulated_data: ObservabilityData,
        leading: TrackedHypothesis,
    ) -> list[str]:
        """Follow trace IDs from error spans to discover downstream services.

        Client-side spans all have service=<primary_service>. To find the actual
        downstream services, we search for ALL spans sharing the same trace_id.
        The server-side spans will have different service names — those are the
        real downstream services.

        Returns list of discovered service names.
        """
        # Collect unique trace IDs from error spans
        error_trace_ids: list[str] = []
        seen_ids: set[str] = set()
        for span in accumulated_data.traces:
            if span.status == "error" and span.trace_id and span.trace_id not in seen_ids:
                seen_ids.add(span.trace_id)
                error_trace_ids.append(span.trace_id)

        if not error_trace_ids:
            logger.info("Depth phase: no error trace IDs to follow")
            return []

        # Search for all spans in these traces (up to 5 trace IDs to limit API calls)
        trace_ids_to_follow = error_trace_ids[:5]
        logger.info(
            "Depth phase: following %d error trace IDs to discover downstream services",
            len(trace_ids_to_follow),
        )

        step_start = time.monotonic()
        step_number = trace.total_steps + 1
        state.depth_steps_taken += 1

        # Build query: trace_id:X OR trace_id:Y (search for all spans in these traces)
        trace_id_query = " OR ".join(f"trace_id:{tid}" for tid in trace_ids_to_follow)
        query = f"({trace_id_query}) -service:{incident.service}"

        all_spans = []
        try:
            all_spans = await self.executor.dd_client.search_traces(
                query, incident.start_time, incident.end_time, limit=500,
            )
        except Exception as e:
            logger.warning("Trace ID follow-up failed: %s", e)

        # Merge discovered spans into accumulated data
        if all_spans:
            merge_data(accumulated_data, all_spans, InvestigationActionType.FETCH_TRACES)

        # Extract unique downstream service names
        discovered_services: dict[str, str] = {}
        for span in all_spans:
            if span.service and span.service != incident.service:
                if span.service not in discovered_services:
                    status = "error" if span.status == "error" else "ok"
                    discovered_services[span.service] = status

        data_summary = (
            f"{len(all_spans)} spans from {len(discovered_services)} downstream services"
        )
        svc_list = [
            f"{svc} ({'ERROR' if status == 'error' else 'ok'})"
            for svc, status in discovered_services.items()
        ]

        step = InvestigationStep(
            step_number=step_number,
            action=InvestigationActionType.FETCH_TRACES,
            reason=f"[DEPTH:trace-follow] Following {len(trace_ids_to_follow)} error trace IDs to discover downstream services in the call chain",
            data_source=incident.service,
            query_params={"query": query, "depth_signal": "trace_id_follow"},
            data_summary=data_summary,
            findings=f"Discovered {len(discovered_services)} downstream services: {', '.join(svc_list)}" if discovered_services else "No downstream spans found in traced requests",
            confidence=leading.confidence,
        )
        step.hypotheses = [
            f"[{leading.status.value.upper()}] {leading.description} ({leading.confidence:.0%})"
        ]
        step.decision = "Follow distributed traces to find downstream service names"
        step.duration_ms = int((time.monotonic() - step_start) * 1000)

        trace.steps.append(step)
        trace.total_steps += 1

        if self.on_step_complete:
            try:
                await self.on_step_complete(step)
            except Exception as e:
                logger.warning("Depth step callback failed: %s", e)

        if discovered_services:
            logger.info(
                "Depth phase: trace-follow discovered %d downstream services: %s",
                len(discovered_services), list(discovered_services.keys()),
            )
            # Add as supporting evidence
            leading.supporting_evidence.append(
                f"[depth:trace-follow] Distributed trace analysis revealed {len(discovered_services)} "
                f"downstream services in the call chain: {', '.join(svc_list)}"
            )
        else:
            logger.info("Depth phase: trace-follow found no downstream spans")

        return list(discovered_services.keys())

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
        # Fast path: extract service names from evidence strings and trace spans
        services_from_patterns = self._extract_services_from_evidence(
            leading, state, incident, accumulated_data,
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
        # Sort by priority: high first (fallback ordering)
        priority_order = {"high": 0, "medium": 1, "low": 2}
        all_services.sort(key=lambda s: priority_order.get(s.get("investigation_priority", "low"), 2))

        # Use LLM ranking when we have enough candidates to benefit
        if len(all_services) > 3:
            ranked = await self._rank_downstream_services(
                all_services, incident, leading, accumulated_data,
            )
            if ranked:
                return ranked

        return all_services[:5]

    async def _rank_downstream_services(
        self,
        candidates: list[dict],
        incident: IncidentQuery,
        leading: TrackedHypothesis,
        accumulated_data: ObservabilityData,
    ) -> Optional[list[dict]]:
        """Ask Claude to rank downstream services by root-cause likelihood.

        Returns ranked list of service dicts, or None on failure (caller falls back).
        """
        trace_tree = self._build_trace_tree_summary(accumulated_data, incident.service)
        candidates_text = self._build_candidates_summary(candidates, accumulated_data)

        # Collect error messages from hypothesis evidence
        error_messages = "\n".join(
            e[:300] for e in leading.supporting_evidence[:5]
        ) or "No error patterns identified yet"

        prompt = DOWNSTREAM_RANKING_PROMPT.format(
            service=incident.service,
            hypothesis=leading.description,
            error_messages=error_messages,
            candidates=candidates_text,
            trace_tree=trace_tree,
        )

        try:
            response = await self.reasoning.query_dynamic(prompt)
            result = parse_json_response(response, fallback={"ranked_services": []})
            ranked_names = [
                s["service_name"] for s in result.get("ranked_services", [])
                if s.get("service_name")
            ]
        except Exception as e:
            logger.warning("LLM ranking failed: %s", e)
            return None

        if not ranked_names:
            return None

        # Map ranked names back to original candidate dicts
        candidates_by_name = {c["service_name"]: c for c in candidates}
        ranked = []
        for name in ranked_names[:5]:
            if name in candidates_by_name:
                ranked.append(candidates_by_name[name])
            else:
                # Claude may have returned a name not in our list — skip it
                logger.debug("LLM ranked unknown service '%s', skipping", name)

        if ranked:
            logger.info(
                "Depth phase: LLM ranked services: %s",
                [s["service_name"] for s in ranked],
            )

        return ranked if ranked else None

    @staticmethod
    def _build_trace_tree_summary(
        accumulated_data: ObservabilityData,
        incident_service: str,
    ) -> str:
        """Build a compact tree showing request flow from distributed traces.

        Groups spans by trace_id, builds parent-child trees, returns text.
        Focuses on error traces to show the failure path.
        """
        if not accumulated_data.traces:
            return "No trace data available"

        # Group spans by trace_id, prioritize error traces
        traces_by_id: dict[str, list] = {}
        for span in accumulated_data.traces:
            if span.trace_id:
                traces_by_id.setdefault(span.trace_id, []).append(span)

        # Pick up to 3 traces that contain errors
        error_trace_ids = [
            tid for tid, spans in traces_by_id.items()
            if any(s.status == "error" for s in spans)
        ][:3]

        if not error_trace_ids:
            error_trace_ids = list(traces_by_id.keys())[:2]

        lines = []
        for tid in error_trace_ids:
            spans = traces_by_id[tid]
            # Build parent-child map
            by_span_id: dict[str, Any] = {}
            roots: list = []
            for span in spans:
                by_span_id[span.span_id] = span
            for span in spans:
                if not span.parent_id or span.parent_id not in by_span_id:
                    roots.append(span)

            lines.append(f"Trace {tid[:12]}...:")

            def _render_span(sp, depth=1):
                prefix = "  " * depth
                error_str = f", {sp.status}" if sp.status == "error" else ""
                handling = ""
                if sp.meta.get("error.handling") == "handled":
                    handling = " [handled]"
                dur = f"{sp.duration_ns / 1e6:.0f}ms" if sp.duration_ns else "?"
                lines.append(
                    f"{prefix}{sp.service}: {sp.operation} {sp.resource[:60]} "
                    f"({dur}{error_str}{handling})"
                )
                # Find children
                children = [
                    s for s in spans
                    if s.parent_id == sp.span_id and s.span_id != sp.span_id
                ]
                for child in children[:5]:  # limit children per node
                    _render_span(child, depth + 1)

            for root in roots[:3]:  # limit roots per trace
                _render_span(root)

        result = "\n".join(lines)
        return result[:2000] if len(result) > 2000 else result

    @staticmethod
    def _build_candidates_summary(
        candidates: list[dict],
        accumulated_data: ObservabilityData,
    ) -> str:
        """Format candidate services with trace status and operation info."""
        # Build a map of service -> trace info from spans
        svc_info: dict[str, dict] = {}
        for span in accumulated_data.traces:
            if span.service and span.service not in svc_info:
                handling = span.meta.get("error.handling", "")
                svc_info[span.service] = {
                    "operation": span.operation,
                    "resource": span.resource[:60] if span.resource else "",
                    "status": span.status,
                    "error_msg": span.error_message[:80] if span.error_message else "",
                    "handling": handling,
                }
            elif span.service and span.status == "error":
                # Prefer error spans for the summary
                handling = span.meta.get("error.handling", "")
                svc_info[span.service] = {
                    "operation": span.operation,
                    "resource": span.resource[:60] if span.resource else "",
                    "status": "error",
                    "error_msg": span.error_message[:80] if span.error_message else "",
                    "handling": handling,
                }

        lines = []
        for c in candidates:
            name = c["service_name"]
            info = svc_info.get(name, {})
            status = info.get("status", "unknown").upper()
            op = info.get("operation", "")
            err = info.get("error_msg", "")
            handling = info.get("handling", "")
            source = c.get("source", "unknown")

            parts = [f"- {name} [{status}]"]
            if op:
                parts.append(f"(operation: {op}")
                if err:
                    parts.append(f", error: {err}")
                if handling:
                    parts.append(f", {handling}")
                parts.append(f", source: {source})")
            else:
                parts.append(f"(source: {source})")
            lines.append("".join(parts))

        return "\n".join(lines)

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
        # Reject Go package paths (e.g., google.golang.org/grpc, net/http)
        if "/" in name:
            return False
        # Reject domain-like names that are clearly not K8s services
        if name.endswith(".org") or name.endswith(".com") or name.endswith(".io"):
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
        accumulated_data: Optional[ObservabilityData] = None,
    ) -> list[dict]:
        """Extract service names from evidence using regex patterns and trace spans."""
        services: dict[str, dict] = {}

        # Extract from trace spans first — most reliable for finding downstream services
        if accumulated_data and accumulated_data.traces:
            for span in accumulated_data.traces:
                # Each span's service field tells us which service processed it
                if span.service and span.service != incident.service:
                    if DepthPhase._is_valid_service_name(span.service, incident.service):
                        priority = "high" if span.status == "error" else "medium"
                        if span.service not in services or priority == "high":
                            services[span.service] = {
                                "service_name": span.service,
                                "source": f"trace span (operation={span.operation}, status={span.status})",
                                "likely_k8s_namespace": "",
                                "investigation_priority": priority,
                            }
                # Check meta for peer_service, target_service, etc.
                # NOTE: "component" is excluded — it contains Go library names
                # (e.g., google.golang.org/grpc, net/http), not service names
                for meta_key in ("peer.service", "peer_service", "target.service"):
                    meta_val = span.meta.get(meta_key, "")
                    if meta_val and meta_val != incident.service:
                        if DepthPhase._is_valid_service_name(meta_val, incident.service):
                            services.setdefault(meta_val, {
                                "service_name": meta_val,
                                "source": f"trace meta {meta_key}",
                                "likely_k8s_namespace": "",
                                "investigation_priority": "high",
                            })

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

        # Pattern 5: gRPC protobuf service names (e.g., mercari.platform.home.ddui.v1.ComponentService)
        # These need to be mapped to K8s service names by Claude, but we capture the
        # package prefix which often maps to a team/service namespace
        for match in re.finditer(
            r"(?:service|method|rpc)\s+(?:call\s+)?(?:to\s+)?([a-z][a-z0-9]+(?:\.[a-z][a-z0-9]+){2,}\.[A-Z][a-zA-Z]+)",
            all_text,
        ):
            proto_svc = match.group(1)
            # Extract a likely K8s-friendly name from the protobuf path
            # e.g., mercari.platform.home.ddui.v1.ComponentService -> ComponentService
            parts = proto_svc.split(".")
            svc_name = parts[-1]  # e.g., ComponentService
            # Use the full protobuf name as hint for Claude
            services.setdefault(proto_svc, {
                "service_name": proto_svc,
                "source": "gRPC protobuf service name",
                "likely_k8s_namespace": "",
                "investigation_priority": "high",
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

        skip_remaining = False
        for idx, query_spec in enumerate(downstream_queries):
            if skip_remaining:
                break
            if state.downstream_steps_taken >= self.config.max_downstream_steps:
                break

            step_start = time.monotonic()
            step_number = trace.total_steps + 1
            state.downstream_steps_taken += 1
            state.depth_steps_taken += 1  # keep total accurate for logging

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
                elif query_spec["type"] == "trace":
                    raw_data = await self.executor.dd_client.search_traces(
                        query_spec["query"], incident.start_time, incident.end_time,
                    )
                    data_summary = f"{len(raw_data) if isinstance(raw_data, list) else 0} trace spans"
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

            action_type_map = {
                "metric": InvestigationActionType.QUERY_CUSTOM_METRIC,
                "log": InvestigationActionType.SEARCH_LOGS_CUSTOM,
                "trace": InvestigationActionType.FETCH_TRACES,
                "event": InvestigationActionType.FETCH_DEPLOYMENTS,
                "monitors": InvestigationActionType.QUERY_CUSTOM_METRIC,
            }
            step_action = action_type_map.get(
                query_spec["type"], InvestigationActionType.QUERY_CUSTOM_METRIC
            )

            step = InvestigationStep(
                step_number=step_number,
                action=step_action,
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
                merge_data(accumulated_data, raw_data, step_action)

                # Analyze with downstream-specific prompt
                data_content = format_raw_data(raw_data, step_action)
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

                # Early exit: after first query, if service is a victim, skip remaining
                if idx == 0:
                    is_victim_source = result.get("is_source", False)
                    if not is_victim_source:
                        victim_mechanism = (result.get("mechanism", "") or "").lower()
                        victim_indicators = [
                            "context canceled", "context cancelled",
                            "deadline exceeded", "circuit breaker",
                            "graceful", "handled", "propagated from upstream",
                            "victim", "not the source",
                        ]
                        if any(ind in victim_mechanism for ind in victim_indicators):
                            logger.info(
                                "Depth phase: %s is a victim (%s), skipping remaining queries",
                                downstream_service, victim_mechanism[:80],
                            )
                            leading.contradicting_evidence.append(
                                f"[depth:downstream:{downstream_service}:early-exit] "
                                f"Service is a victim, not a source: {victim_mechanism[:150]}"
                            )
                            skip_remaining = True

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
        traces (critical for following dependency chains), error logs, pod restarts,
        latency, resource usage, and events.
        """
        queries = []

        # 1. Traces from/to the downstream service — MOST IMPORTANT
        # This is how we follow the dependency chain further downstream
        queries.append({
            "type": "trace",
            "query": f"service:{service} status:error",
            "signal": f"{service}_error_traces",
            "description": f"Error traces from downstream service {service} (reveals further downstream dependencies)",
        })

        # 2. Error logs from the downstream service
        log_query = f"service:{service} status:error"
        if namespace:
            log_query = f"(service:{service} OR kube_namespace:{namespace}) status:error"
        queries.append({
            "type": "log",
            "query": log_query,
            "signal": f"{service}_error_logs",
            "description": f"Error logs from downstream service {service}",
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

        # Trace spans — most valuable for identifying downstream services
        for span in accumulated_data.traces[:20]:
            meta_str = ""
            if span.meta:
                # Include key meta fields that may contain service names
                relevant_keys = [
                    k for k in span.meta
                    if any(t in k.lower() for t in ["service", "peer", "target", "component", "error"])
                ]
                if relevant_keys:
                    meta_str = " meta={" + ", ".join(f"{k}:{span.meta[k]}" for k in relevant_keys[:5]) + "}"
            error_str = ""
            if span.error_message:
                error_str = f" error='{span.error_message[:150]}'"
            samples.append(
                f"trace: service={span.service} operation={span.operation} "
                f"resource={span.resource} status={span.status} "
                f"duration={span.duration_ns/1e6:.0f}ms{error_str}{meta_str}"
            )

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
