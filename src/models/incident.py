"""Data models for incident investigation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SymptomType(str, Enum):
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    AVAILABILITY = "availability"
    THROUGHPUT = "throughput"
    SATURATION = "saturation"
    UNKNOWN = "unknown"


class IncidentQuery(BaseModel):
    """Parsed incident investigation request."""

    raw_query: str
    service: str
    symptom_type: SymptomType = SymptomType.UNKNOWN
    start_time: datetime
    end_time: datetime
    environment: str = "production"
    additional_context: str = ""
    monitor_id: Optional[int] = None
    monitor_query: str = ""
    source_tags: dict[str, str] = Field(default_factory=dict)


class MetricDataPoint(BaseModel):
    timestamp: datetime
    value: float
    tags: dict[str, str] = Field(default_factory=dict)


class MetricSeries(BaseModel):
    metric_name: str
    display_name: str
    points: list[MetricDataPoint]
    unit: str = ""
    aggregation: str = "avg"


class LogEntry(BaseModel):
    timestamp: datetime
    message: str
    service: str
    status: str  # error, warn, info, debug
    host: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    trace_id: str = ""


class TraceSpan(BaseModel):
    trace_id: str
    span_id: str
    parent_id: str = ""
    service: str
    operation: str
    resource: str
    duration_ns: int
    start_time: datetime
    status: str  # ok, error
    error_message: str = ""
    error_type: str = ""
    meta: dict[str, str] = Field(default_factory=dict)


class ServiceDependency(BaseModel):
    source_service: str
    target_service: str
    call_type: str  # http, grpc, kafka, db, cache
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    calls_per_minute: float = 0.0


class ServiceNode(BaseModel):
    name: str
    service_type: str = ""  # web, db, cache, queue, external
    dependencies: list[ServiceDependency] = Field(default_factory=list)
    dependents: list[ServiceDependency] = Field(default_factory=list)


class DatadogEvent(BaseModel):
    timestamp: datetime
    title: str
    text: str
    source: str
    tags: list[str] = Field(default_factory=list)
    alert_type: str = ""  # info, warning, error


class MonitorStatus(BaseModel):
    monitor_id: int
    name: str
    status: str  # OK, Alert, Warn, No Data
    message: str = ""
    tags: list[str] = Field(default_factory=list)
    last_triggered: Optional[datetime] = None


class ObservabilityData(BaseModel):
    """All collected observability data for an incident."""

    metrics: list[MetricSeries] = Field(default_factory=list)
    logs: list[LogEntry] = Field(default_factory=list)
    traces: list[TraceSpan] = Field(default_factory=list)
    service_map: list[ServiceNode] = Field(default_factory=list)
    events: list[DatadogEvent] = Field(default_factory=list)
    monitors: list[MonitorStatus] = Field(default_factory=list)
    deployment_events: list[DatadogEvent] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """A single event on the investigation timeline."""

    timestamp: datetime
    event_type: str  # metric_anomaly, error_log, deployment, monitor_alert, trace_error
    source: str
    description: str
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    evidence: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    """A potential root cause hypothesis."""

    id: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    is_root_cause: bool = False
    cascading_from: Optional[str] = None


class HypothesisStatus(str, Enum):
    """Status of a tracked hypothesis during investigation."""

    PENDING = "pending"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class TrackedHypothesis(BaseModel):
    """A hypothesis tracked across multiple investigation steps."""

    id: str
    description: str
    status: HypothesisStatus = HypothesisStatus.PENDING
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    last_updated_step: int = 0
    created_at_step: int = 0
    parent_hypothesis_id: Optional[str] = None


class SignalCheckResult(BaseModel):
    """Result of checking a required signal during investigation."""

    signal_type: str
    checked: bool = False
    step_number: int = 0
    data_found: bool = False
    notes: str = ""


class DiscoveredContext(BaseModel):
    """Service context discovered before investigation starts (step 0).

    Contains actual metrics, tags, and namespace values found via Datadog APIs,
    replacing hardcoded assumptions about what metrics exist.
    """

    available_metrics: list[str] = Field(default_factory=list)
    metric_tags: dict[str, list[str]] = Field(default_factory=dict)
    resolved_namespace: str = ""
    resolved_tags: dict[str, str] = Field(default_factory=dict)
    dashboard_metrics: list[str] = Field(default_factory=list)
    dashboard_ids: list[str] = Field(default_factory=list)
    infra_metrics: list[str] = Field(default_factory=list)
    container_metrics: list[str] = Field(default_factory=list)
    apm_metrics: list[str] = Field(default_factory=list)
    custom_metrics: list[str] = Field(default_factory=list)


class InvestigationState(BaseModel):
    """Cross-step investigation state — hypothesis tree + signal coverage."""

    hypotheses: dict[str, TrackedHypothesis] = Field(default_factory=dict)
    signal_checklist: dict[str, SignalCheckResult] = Field(default_factory=dict)
    empty_fetches: int = 0
    total_fetches: int = 0
    data_gap_log: list[str] = Field(default_factory=list)
    discovered_context: Optional[DiscoveredContext] = None


class InvestigationActionType(str, Enum):
    """Types of actions the investigation engine can take."""

    FETCH_METRICS = "fetch_metrics"
    FETCH_LOGS = "fetch_logs"
    FETCH_TRACES = "fetch_traces"
    FETCH_SERVICE_MAP = "fetch_service_map"
    FETCH_EVENTS = "fetch_events"
    FETCH_DEPLOYMENTS = "fetch_deployments"
    FETCH_MONITORS = "fetch_monitors"
    FETCH_INFRA_METRICS = "fetch_infra_metrics"
    QUERY_CUSTOM_METRIC = "query_custom_metric"
    SEARCH_LOGS_CUSTOM = "search_logs_custom"
    SEARCH_TRACES_CUSTOM = "search_traces_custom"
    CORRELATE_SIGNALS = "correlate_signals"
    ANALYZE_HYPOTHESIS = "analyze_hypothesis"
    EXPAND_SCOPE = "expand_scope"
    DISCOVER_CONTEXT = "discover_context"
    CONCLUDE = "conclude"


class InvestigationStep(BaseModel):
    """A single step in the investigation trace."""

    step_number: int
    action: InvestigationActionType
    reason: str
    data_source: str = ""
    query_params: dict[str, Any] = Field(default_factory=dict)
    findings: str = ""
    data_summary: str = ""
    hypotheses: list[str] = Field(default_factory=list)
    decision: str = ""
    confidence: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = 0


class InvestigationTrace(BaseModel):
    """Full trace of an investigation."""

    steps: list[InvestigationStep] = Field(default_factory=list)
    total_duration_ms: int = 0
    total_steps: int = 0
    concluded: bool = False
    conclusion_reason: str = ""
    investigation_state: Optional[InvestigationState] = None


class RCAReport(BaseModel):
    """Final Root Cause Analysis report."""

    incident: IncidentQuery
    summary: str
    root_cause: Hypothesis
    contributing_factors: list[Hypothesis] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)
    blast_radius: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    confidence_score: float = Field(ge=0.0, le=1.0)
    evidence_chain: list[str] = Field(default_factory=list)
    raw_reasoning: str = ""
    investigation_trace: Optional[InvestigationTrace] = None
