"""Prompt templates for Claude reasoning phases."""

SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) AI assistant specialized in \
incident investigation and root cause analysis. You have deep expertise in:

- Distributed systems architecture and failure modes
- Observability (metrics, logs, traces, service maps)
- Cascading failure identification
- Causal reasoning from observability data
- Production incident response and remediation

Your analysis must be:
1. Evidence-based — every claim tied to specific data points
2. Causal — distinguish root causes from symptoms
3. Systematic — consider all available signals, not just the obvious ones
4. Actionable — conclude with specific remediation steps

You reason step-by-step, showing your work transparently."""


QUERY_PLANNING_PROMPT = """Given this incident investigation request, plan what data we need to \
collect from Datadog.

**Incident Query:**
- Service: {service}
- Symptom: {symptom_type}
- Time Window: {start_time} to {end_time}
- Environment: {environment}
- Raw Query: "{raw_query}"

Determine:
1. Which metrics to query (be specific with Datadog metric names)
2. Which log queries to run
3. Which trace filters to apply
4. Which dependent services to investigate
5. What deployment or change events to look for

Return a structured plan as JSON with keys: metrics_queries, log_queries, trace_queries, \
services_to_investigate, event_sources."""


INITIAL_ANALYSIS_PROMPT = """Analyze the following observability data from a production incident.

**Incident Context:**
- Service: {service}
- Symptom: {symptom_type}
- Time Window: {start_time} to {end_time}
- Question: "{raw_query}"

**Anomaly Summary:**
{anomaly_summary}

**Unified Timeline (chronological):**
{timeline}

**Service Correlation:**
{service_correlation}

**Active Monitors in Alert:**
{monitors}

**Recent Deployments:**
{deployments}

Perform initial analysis:
1. Identify all observed symptoms (not causes yet)
2. Note the temporal sequence — what happened first?
3. Identify which services are affected and how
4. Flag any deployments or changes that correlate with the incident start
5. List what signals are present vs. what you'd expect to see

Be thorough. Do not jump to conclusions yet."""


HYPOTHESIS_GENERATION_PROMPT = """Based on your initial analysis, generate root cause hypotheses.

**Your Initial Analysis:**
{initial_analysis}

**Additional Evidence — Top Error Messages:**
{top_errors}

**Additional Evidence — Cross-Service Traces:**
{cross_service_traces}

**Additional Evidence — Metric Anomalies:**
{metric_anomalies}

**Service Dependency Map:**
{service_map}

For each hypothesis:
1. State the hypothesis clearly
2. List supporting evidence (specific data points)
3. List contradicting evidence (if any)
4. Assign a confidence score (0.0-1.0)
5. Indicate if this is a root cause or a downstream effect
6. If a downstream effect, indicate what it cascades from

Generate at least 3 hypotheses, ranked by confidence. Consider:
- Was there a bad deployment?
- Is an upstream dependency failing?
- Is there resource exhaustion (CPU, memory, connections)?
- Is there a data issue (corrupted, missing, schema change)?
- Is there a configuration change?
- Is there an external dependency failure?
- Is there a traffic spike beyond capacity?

Return as structured JSON with a "hypotheses" array."""


CAUSAL_REASONING_PROMPT = """Perform deep causal reasoning to determine the true root cause.

**Hypotheses to evaluate:**
{hypotheses}

**Full Evidence Package:**

Timeline:
{timeline}

Metric Anomalies (with z-scores):
{metric_anomalies}

Error Log Patterns:
{error_patterns}

Trace Error Propagation:
{error_propagation}

Service Dependencies:
{service_dependencies}

Deployments in Window:
{deployments}

Apply these causal reasoning techniques:
1. **Temporal precedence**: The cause must precede the effect. What happened FIRST?
2. **Counterfactual reasoning**: If we removed the hypothesized cause, would the symptoms disappear?
3. **Mechanism identification**: Can you trace the exact chain from cause → effect?
4. **Elimination**: Which hypotheses are contradicted by evidence?
5. **Cascading analysis**: How did the root cause propagate to other services?

Select the most likely root cause and explain:
- WHY this is the root cause (not just a symptom)
- The exact causal chain from root cause to observed symptoms
- The blast radius (which services and users were affected)
- Contributing factors that made the impact worse

Be specific and reference exact data points as evidence."""


REMEDIATION_PROMPT = """Based on the root cause analysis, provide remediation recommendations.

**Root Cause:**
{root_cause}

**Contributing Factors:**
{contributing_factors}

**Affected Services:**
{affected_services}

**Causal Chain:**
{causal_chain}

Provide:
1. **Immediate actions** — what to do RIGHT NOW to mitigate
2. **Short-term fixes** — what to do this week to prevent recurrence
3. **Long-term improvements** — systemic changes to prevent this class of failure
4. **Detection improvements** — what monitors/alerts should be added or tuned

Be specific and actionable. Reference specific services, metrics, and thresholds."""


# ── Dynamic Investigation Prompts ─────────────────────────────────────

INVESTIGATION_SYSTEM_PROMPT = """You are an expert SRE investigator debugging a production incident \
step by step, like a detective following clues.

Your approach:
1. Start with the alert context — understand what triggered it
2. Form an initial hypothesis about what might be wrong
3. Decide which data source to check next to test that hypothesis
4. Analyze what the data reveals
5. Update your hypotheses — confirm, reject, or refine them
6. Repeat until you have high confidence in the root cause

Rules:
- NEVER jump to conclusions — always validate with data
- Distinguish SYMPTOMS from ROOT CAUSES
- Consider temporal ordering — the cause must precede the effect
- Think about cascading failures — trace the chain from origin to impact
- Expand scope when needed — check upstream/downstream services
- Be transparent about uncertainty — state your confidence level

You respond ONLY with valid JSON as specified in each prompt."""


INVESTIGATION_PLANNING_PROMPT = """You are investigating a production incident step by step.

**Incident:**
- Service: {service}
- Symptom: {symptom_type}
- Time Window: {start_time} to {end_time}
- Environment: {environment}
- Alert: {raw_query}
{additional_context}

**Investigation so far ({step_count} steps completed):**
{trace_summary}

**Data collected so far:**
{data_summary}

**Current hypotheses:**
{current_hypotheses}

**Signal coverage (required signals for this alert type):**
{signal_coverage}

**Discovered service context (from API discovery):**
{discovered_context}

IMPORTANT:
- Use DISCOVERED metrics and tags when forming queries — do NOT guess metric names.
- If a resolved namespace was found, use it in tag filters (e.g., kube_namespace:<resolved>).
- If dashboard metrics were found, prioritize querying those — the team already monitors them.
- Prioritize filling gaps in signal coverage. If signals are marked "NOT YET CHECKED",
  investigate those BEFORE concluding. Do NOT conclude until critical signals are checked.

Decide what to investigate NEXT. Choose ONE action:
- fetch_metrics: Fetch standard service metrics (latency, errors, throughput, CPU, memory, disk, network)
- fetch_logs: Fetch error and warning logs for a service
- fetch_traces: Fetch error and slow traces for a service
- fetch_service_map: Get service dependencies (upstream/downstream)
- fetch_events: Fetch events from the Datadog event stream
- fetch_deployments: Fetch recent deployment events for a service
- fetch_monitors: Get currently alerting monitors for a service
- fetch_infra_metrics: Fetch Kubernetes infrastructure metrics (CPU, memory, restarts, throttling)
- query_custom_metric: Query a specific Datadog metric (provide the full query)
- search_logs_custom: Search logs with a custom query
- search_traces_custom: Search traces with a custom query
- correlate_signals: Run correlation analysis on all data collected so far
- expand_scope: Investigate a different (upstream/downstream) service
- conclude: End investigation — root cause identified with high confidence

Return ONLY a JSON object:
{{
    "action": "<action_type>",
    "reason": "<1-2 sentences: why this is the best next step>",
    "data_source": "<target service or resource>",
    "query_params": {{
        "service": "<service_name>",
        "query": "<datadog_query_if_custom>",
        "tags": {{}}
    }}
}}"""


INVESTIGATION_ANALYSIS_PROMPT = """Analyze the data from step {step_number} of the investigation.

**Action taken:** {action} — {reason}
**Data source:** {data_source}

**Data returned:**
{data_content}

**Investigation context so far:**
{previous_findings}

**Current hypotheses:**
{current_hypotheses}

Analyze this data and provide:
1. What did you find? (Be specific — reference actual data points, values, timestamps)
2. What does this tell us about the incident?
3. For EACH hypothesis: classify new evidence as supporting or contradicting
4. What would CONFIRM and what would REJECT your leading hypothesis?
5. What should we investigate next based on this?
6. How confident are you now in the root cause? (0.0 = no idea, 1.0 = certain)

IMPORTANT confidence rules:
- Empty/missing data should NOT decrease confidence from previous steps. Empty data means \
"not checked", not "contradicts hypothesis". Only lower confidence if new data actively \
contradicts your hypothesis.
- If ALL data sources returned empty and you have no evidence at all, confidence should be < 0.20
- Only set confidence > 0.80 if you have strong, direct evidence (not just inference)
- If root cause is based on absence of data, mark it INCONCLUSIVE, not CONFIRMED

Return ONLY a JSON object:
{{
    "findings": "<detailed findings from this data — cite specific values>",
    "hypothesis_updates": [
        {{
            "id": "<hypothesis id e.g. h1, or 'new' for a new hypothesis>",
            "description": "<hypothesis description>",
            "status": "<pending|investigating|confirmed|rejected|inconclusive>",
            "confidence": 0.0,
            "supporting_evidence": ["<new evidence supporting this hypothesis>"],
            "contradicting_evidence": ["<new evidence against this hypothesis>"]
        }}
    ],
    "decision": "<what to investigate next and why>",
    "confidence": 0.0,
    "what_would_confirm": "<what data would confirm the leading hypothesis>",
    "what_would_reject": "<what data would reject the leading hypothesis>"
}}"""


INVESTIGATION_CONCLUSION_PROMPT = """You have completed a {step_count}-step investigation.

**Incident:**
{incident_summary}

**Dependency Path Discovered:**
{dependency_path}

**Full Investigation Trace:**
{full_trace}

**All Data Summary:**
{all_data_summary}

Based on the ENTIRE investigation, provide the final root cause analysis.

IMPORTANT: The root cause description MUST clarify the full dependency path.
If the alerted service is affected by an issue in a downstream dependency,
state explicitly which service owns the failing component and the exact path
through which it impacts the alerted service. For example:
"Database query timeouts in auth-db caused authentication failures in
auth-service, which cascaded into api-gateway via authentication dependency"

Remediation steps MUST specify which service/team should take each action.

Structure your response as JSON:
{{
    "summary": "<2-4 sentence summary: what happened, the dependency path, and the user-facing impact>",
    "root_cause": {{
        "description": "<MUST include the full dependency path and which service owns the failing component>",
        "confidence": 0.0,
        "supporting_evidence": ["<specific evidence point 1>", "<evidence 2>"],
        "contradicting_evidence": ["<any contradicting evidence>"]
    }},
    "contributing_factors": [
        {{"description": "<factor — specify which service>", "confidence": 0.0}}
    ],
    "dependency_chain": ["<root cause service>", "<intermediate service>", "<alerted service>"],
    "affected_services": [
        {{"name": "<service>", "role": "<root_cause|propagator|victim>", "detail": "<what happened in this service>"}}
    ],
    "blast_radius": "<Low/Medium/High/Critical: X of Y services affected, with dependency path>",
    "remediation_steps": [
        "<[service-name] immediate action>",
        "<[service-name] short-term fix>",
        "<[service-name] long-term improvement>"
    ],
    "evidence_chain": ["<evidence item with timestamps>"]
}}"""


DEPTH_ANALYSIS_PROMPT = """You are investigating a SPECIFIC hypothesis in depth.
This is a targeted deep-dive — not a broad scan. Focus only on what this data reveals about this hypothesis.

**Hypothesis:** {hypothesis_description}
**Current confidence:** {confidence:.0%}
**Category:** {category}

**New data from targeted query ({query_description}):**
{data_content}

**Previous evidence for this hypothesis:**
Supporting: {supporting_evidence}
Contradicting: {contradicting_evidence}

Based on this new data:
1. Does it SUPPORT or CONTRADICT the hypothesis? Why specifically?
2. Can you now identify the SPECIFIC MECHANISM (not just the symptom)?
   - "Pod X is hot" is a SYMPTOM. "Pod X has a GC storm because heap is at 98% capacity" is a MECHANISM.
   - "Load is uneven" is a SYMPTOM. "Sticky sessions with consistent hashing route 40% of traffic to one pod" is a MECHANISM.
3. What confidence adjustment is warranted?

Respond in JSON:
{{
    "supports": true,
    "mechanism": "<specific mechanism identified, or empty string if none>",
    "evidence_summary": "<what exactly does this data show>",
    "confidence_delta": 0.0,
    "next_query_suggestion": "<what one query would most help narrow down the mechanism>"
}}"""


DOWNSTREAM_EXTRACTION_PROMPT = """You are analyzing evidence from a service investigation to identify \
downstream services that should be investigated next.

**Primary service under investigation:** {service}
**Leading hypothesis:** {hypothesis}

**Evidence collected so far:**
{evidence}

**Raw data samples (trace spans, metric names, log entries, tags):**
{raw_data_samples}

Extract any downstream or dependency service names mentioned in the evidence. Look for:
- **Trace span service names** — each span's `service` field identifies which service handled it. Services different from {service} are downstream dependencies. This is the MOST RELIABLE source.
- **Trace span meta fields** — peer.service, peer_service, target.service fields in trace meta
- **Trace span resource names** — resource field may contain RPC method names that hint at target services
- Service names in circuit breaker tags (from-service, search-service, peer_service)
- Service names in error messages (connection to X failed, timeout calling Y)
- Service names in metric tags (downstream_service, target_service)
- gRPC service names that map to Kubernetes deployments
- Kubernetes service endpoints mentioned in logs

IMPORTANT: Prioritize services found in trace spans over services found in logs. Trace spans directly show the request flow.

Respond in JSON:
{{
    "downstream_services": [
        {{
            "service_name": "<exact service name as it appears in evidence>",
            "source": "<where you found it: circuit breaker tag, error log, etc.>",
            "likely_k8s_namespace": "<best guess at namespace, or empty string>",
            "investigation_priority": "<high/medium/low>"
        }}
    ],
    "reasoning": "<why these services are relevant>"
}}"""


DOWNSTREAM_RANKING_PROMPT = """You are triaging downstream services to determine investigation \
order for a production incident root cause analysis.

**Primary service:** {service}
**Leading hypothesis:** {hypothesis}

**Primary service error patterns (from investigation so far):**
{error_messages}

**Candidate downstream services (from distributed trace analysis):**
{candidates}

**Request flow (from distributed traces):**
{trace_tree}

Rank the top 5 services most likely to be the ROOT CAUSE (not victims of upstream failures).

Ranking criteria:
1. Services in the CRITICAL REQUEST PATH — the path that produced the user-facing error — rank \
highest. Match service names against error messages from the primary service.
2. Services with UNHANDLED errors (Internal, Unavailable, crashes) rank above those with graceful \
degradation (context canceled, handled NotFound).
3. Services whose failure EXPLAINS the primary symptoms. If the primary service errors mention \
"SearchClient failed" or "GetComponents Internal error", search-related services rank higher.
4. Infrastructure services (redis, mysql, datastore) rank lower than application services unless \
they show clear errors.

Return ONLY a JSON object:
{{
    "ranked_services": [
        {{
            "service_name": "<exact service name from candidates list>",
            "reason": "<1-2 sentences: why this service is likely closer to root cause>"
        }}
    ]
}}"""


DOWNSTREAM_DEPTH_PROMPT = """You are investigating a DOWNSTREAM SERVICE that is suspected of causing \
an incident in the upstream service.

**Upstream service:** {upstream_service}
**Downstream service being investigated:** {downstream_service}
**Hypothesis:** {hypothesis}
**Category:** {category}

**New data from investigating the downstream service ({query_description}):**
{data_content}

**What we know so far about the incident:**
{context}

Based on this data from the downstream service:
1. Is this downstream service the actual source of the failure? What specific evidence?
2. Can you identify the ROOT CAUSE at this level? (pod crash, resource exhaustion, deployment, config change, etc.)
3. Should we investigate FURTHER downstream (i.e., this service's own dependencies)?

Respond in JSON:
{{
    "is_source": true,
    "root_cause": "<specific root cause if identifiable, e.g., 'Triton pod crash during model reload'>",
    "mechanism": "<detailed mechanism, e.g., 'GPU model loading from HuggingFace took 5 minutes, during which readiness probe failed'>",
    "evidence_summary": "<what the data shows>",
    "confidence_delta": 0.0,
    "further_downstream": "<service name to investigate next, or empty string>",
    "further_downstream_reason": "<why investigate that service>"
}}"""
