"""Formats RCA reports into human-readable output."""

from __future__ import annotations

from src.models.incident import RCAReport


class ReportFormatter:
    """Formats an RCAReport into various output formats."""

    @staticmethod
    def to_markdown(report: RCAReport) -> str:
        """Render the RCA report as a detailed Markdown document."""
        lines: list[str] = []

        # v3: Report type header
        is_summary = getattr(report, "report_type", "rca") == "investigation_summary"
        if is_summary:
            lines.append("# Investigation Summary")
            lines.append(
                "> *This investigation did not reach sufficient confidence for a Root Cause Analysis. "
                "The findings below describe what was observed and what data was unavailable.*"
            )
        else:
            lines.append("# Incident Investigation Report")
        lines.append(f"**Service:** {report.incident.service}")
        lines.append(f"**Time Window:** {report.incident.start_time} → {report.incident.end_time}")
        lines.append(f"**Query:** {report.incident.raw_query}")
        lines.append(f"**Confidence:** {report.confidence_score:.0%}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append(report.summary)
        lines.append("")

        # Root Cause
        lines.append("## Root Cause")
        lines.append(f"**{report.root_cause.description}**")
        lines.append(f"- Confidence: {report.root_cause.confidence:.0%}")
        lines.append("")
        if report.root_cause.supporting_evidence:
            lines.append("### Supporting Evidence")
            for ev in report.root_cause.supporting_evidence:
                lines.append(f"- {ev}")
            lines.append("")
        if report.root_cause.contradicting_evidence:
            lines.append("### Contradicting Evidence")
            for ev in report.root_cause.contradicting_evidence:
                lines.append(f"- {ev}")
            lines.append("")

        # Dependency Path
        dep_chain = getattr(report, "dependency_chain", [])
        if dep_chain and len(dep_chain) > 1:
            lines.append("## Dependency Path")
            role_map: dict[str, str] = {}
            for detail in getattr(report, "affected_service_details", []):
                if isinstance(detail, dict):
                    role_map[detail.get("name", "")] = detail.get("role", "")
            chain_parts = []
            for svc in dep_chain:
                role = role_map.get(svc, "")
                if role:
                    chain_parts.append(f"{svc} ({role})")
                else:
                    chain_parts.append(svc)
            lines.append(" → ".join(chain_parts))
            lines.append("")

        # Contributing Factors
        if report.contributing_factors:
            lines.append("## Contributing Factors")
            for factor in report.contributing_factors:
                lines.append(
                    f"- **{factor.description}** (confidence: {factor.confidence:.0%})"
                )
                if factor.cascading_from:
                    lines.append(f"  - Cascading from: {factor.cascading_from}")
            lines.append("")

        # Timeline
        if report.timeline:
            lines.append("## Investigation Timeline")
            lines.append("| Time | Severity | Type | Source | Description |")
            lines.append("|------|----------|------|--------|-------------|")
            for evt in report.timeline[:50]:
                lines.append(
                    f"| {evt.timestamp.strftime('%H:%M:%S')} "
                    f"| {evt.severity.value} "
                    f"| {evt.event_type} "
                    f"| {evt.source} "
                    f"| {evt.description[:100]} |"
                )
            if len(report.timeline) > 50:
                lines.append(f"| ... | ... | ... | ... | +{len(report.timeline)-50} more events |")
            lines.append("")

        # Blast Radius
        lines.append("## Blast Radius")
        lines.append(report.blast_radius)
        if report.affected_services:
            lines.append("")
            lines.append("**Affected Services:**")
            detail_map: dict[str, dict[str, str]] = {}
            for detail in getattr(report, "affected_service_details", []):
                if isinstance(detail, dict):
                    detail_map[detail.get("name", "")] = detail
            for svc in report.affected_services:
                d = detail_map.get(svc, {})
                role = d.get("role", "")
                desc = d.get("detail", "")
                if role and desc:
                    lines.append(f"- **{svc}** — *{role}* ({desc})")
                elif role:
                    lines.append(f"- **{svc}** — *{role}*")
                else:
                    lines.append(f"- {svc}")
        lines.append("")

        # Remediation
        if report.remediation_steps:
            lines.append("## Remediation Steps")
            for i, step in enumerate(report.remediation_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Evidence Chain
        if report.evidence_chain:
            lines.append("## Evidence Chain")
            for i, ev in enumerate(report.evidence_chain, 1):
                lines.append(f"{i}. {ev}")
            lines.append("")

        # Investigation Trace
        if report.investigation_trace and report.investigation_trace.steps:
            trace = report.investigation_trace
            lines.append("## Investigation Trace")
            lines.append(
                f"*{trace.total_steps} steps, "
                f"{trace.total_duration_ms / 1000:.1f}s total, "
                f"concluded: {trace.conclusion_reason}*"
            )
            lines.append("")
            lines.append("| Step | Action | Source | Duration | Confidence |")
            lines.append("|------|--------|--------|----------|------------|")
            for step in trace.steps:
                lines.append(
                    f"| {step.step_number} "
                    f"| {step.action.value} "
                    f"| {step.data_source} "
                    f"| {step.duration_ms}ms "
                    f"| {step.confidence:.0%} |"
                )
            lines.append("")

            # v2: Hypothesis Tracking
            if trace.investigation_state and trace.investigation_state.hypotheses:
                lines.append("### Hypothesis Tracking")
                for h in sorted(
                    trace.investigation_state.hypotheses.values(),
                    key=lambda x: -x.confidence,
                ):
                    lines.append(
                        f"- **[{h.status.value.upper()}]** {h.description} "
                        f"(confidence: {h.confidence:.0%})"
                    )
                    for ev in h.supporting_evidence:
                        lines.append(f"  - (+) {ev}")
                    for ev in h.contradicting_evidence:
                        lines.append(f"  - (-) {ev}")
                lines.append("")

            # v3: Data Quality table (replaces v2 signal coverage)
            if trace.investigation_state and trace.investigation_state.signal_checklist:
                lines.append("### Data Quality")
                lines.append("| Signal | Status | Quality | Data Found | Notes |")
                lines.append("|--------|--------|---------|------------|-------|")
                for sig_key, result in trace.investigation_state.signal_checklist.items():
                    if result.checked:
                        status = "[x]"
                        quality_labels = {0.0: "Empty", 0.5: "Partial", 1.0: "Complete"}
                        quality_label = quality_labels.get(result.data_quality, f"{result.data_quality:.1f}")
                        data_found = "Yes" if result.data_found else "No"
                        notes = result.notes[:60] if result.notes else ""
                    else:
                        status = "[ ]"
                        quality_label = "—"
                        data_found = "—"
                        notes = "Not checked"
                    lines.append(
                        f"| {sig_key} | {status} | {quality_label} | {data_found} | {notes} |"
                    )
                lines.append("")

            # v3: What We Don't Know (data gaps)
            data_gaps = getattr(report, "data_gaps", [])
            if data_gaps:
                lines.append("### What We Don't Know")
                for gap in data_gaps:
                    lines.append(f"- **{gap.signal}**: {gap.failure_reason}")
                    if gap.impact:
                        lines.append(f"  - *Impact:* {gap.impact}")
                    if gap.recommendation:
                        lines.append(f"  - *Recommendation:* {gap.recommendation}")
                lines.append("")

            # v3: Recommended Next Steps
            next_steps = getattr(report, "recommended_next_steps", [])
            if next_steps:
                lines.append("### Recommended Next Steps")
                for i, step in enumerate(next_steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

            lines.append("<details>")
            lines.append("<summary>Click to expand full investigation steps</summary>")
            lines.append("")
            for step in trace.steps:
                lines.append(f"### Step {step.step_number}: {step.action.value}")
                lines.append(f"**Why:** {step.reason}")
                lines.append(f"**Source:** {step.data_source}")
                lines.append(f"**Data:** {step.data_summary}")
                lines.append(f"**Findings:** {step.findings}")
                lines.append(f"**Decision:** {step.decision}")
                if step.hypotheses:
                    lines.append(f"**Hypotheses:** {'; '.join(step.hypotheses)}")
                lines.append(f"**Confidence:** {step.confidence:.0%}")
                lines.append("")
            lines.append("</details>")
            lines.append("")

        # Raw Reasoning
        if report.raw_reasoning:
            lines.append("## Detailed Analysis")
            lines.append("<details>")
            lines.append("<summary>Click to expand full reasoning</summary>")
            lines.append("")
            lines.append(report.raw_reasoning)
            lines.append("")
            lines.append("</details>")

        return "\n".join(lines)

    @staticmethod
    def to_slack_blocks(report: RCAReport) -> list[dict]:
        """Render the RCA report as Slack Block Kit blocks for posting to Slack."""
        is_summary = getattr(report, "report_type", "rca") == "investigation_summary"
        header_text = (
            f"Investigation Summary: {report.incident.service}"
            if is_summary
            else f"RCA: {report.incident.service}"
        )
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": header_text,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Confidence:* {report.confidence_score:.0%}\n"
                        f"*Time Window:* {report.incident.start_time} → "
                        f"{report.incident.end_time}\n"
                        f"*Blast Radius:* {report.blast_radius}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Root Cause:*\n{report.root_cause.description}",
                },
            },
        ]

        # Dependency path
        dep_chain = getattr(report, "dependency_chain", [])
        if dep_chain and len(dep_chain) > 1:
            chain_str = " → ".join(dep_chain)
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":rotating_light: *Dependency Path:*\n{chain_str}",
                    },
                }
            )

        if report.remediation_steps:
            steps_text = "\n".join(
                f"• {step}" for step in report.remediation_steps[:5]
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Remediation:*\n{steps_text}",
                    },
                }
            )

        # Evidence chain (top 5)
        if report.evidence_chain:
            evidence_text = "\n".join(
                f"{i}. {ev}" for i, ev in enumerate(report.evidence_chain[:5], 1)
            )
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Key Evidence:*\n{evidence_text}",
                    },
                }
            )

        # Affected services (with roles if available)
        if report.affected_services:
            detail_map: dict[str, dict[str, str]] = {}
            for detail in getattr(report, "affected_service_details", []):
                if isinstance(detail, dict):
                    detail_map[detail.get("name", "")] = detail
            svc_lines = []
            for svc in report.affected_services:
                d = detail_map.get(svc, {})
                role = d.get("role", "")
                desc = d.get("detail", "")
                if role and desc:
                    svc_lines.append(f"• *{svc}* — _{role}_ ({desc})")
                elif role:
                    svc_lines.append(f"• *{svc}* — _{role}_")
                else:
                    svc_lines.append(f"• {svc}")
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Service Impact:*\n" + "\n".join(svc_lines),
                    },
                }
            )

        # Timeline (top 10 events)
        if report.timeline:
            timeline_lines = []
            for evt in report.timeline[:10]:
                ts = evt.timestamp.strftime("%H:%M:%S")
                timeline_lines.append(f"`{ts}` [{evt.severity.value}] {evt.description[:80]}")
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Timeline:*\n" + "\n".join(timeline_lines),
                    },
                }
            )

        # Investigation trace (dynamic mode)
        if report.investigation_trace and report.investigation_trace.steps:
            trace = report.investigation_trace
            trace_lines = []
            for step in trace.steps:
                emoji = _action_emoji(step.action.value)
                trace_lines.append(
                    f"{emoji} `Step {step.step_number}` *{step.action.value}* "
                    f"({step.data_source}) — {step.decision[:60]}"
                )
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Investigation Trace* ({trace.total_steps} steps, "
                            f"{trace.total_duration_ms / 1000:.0f}s, "
                            f"{trace.conclusion_reason}):\n"
                            + "\n".join(trace_lines[:10])
                        ),
                    },
                }
            )

        # v2: Hypothesis tracking (Slack)
        if (
            report.investigation_trace
            and report.investigation_trace.investigation_state
            and report.investigation_trace.investigation_state.hypotheses
        ):
            hyp_state = report.investigation_trace.investigation_state
            status_icons = {
                "confirmed": ":white_check_mark:",
                "rejected": ":x:",
                "investigating": ":mag:",
                "pending": ":grey_question:",
                "inconclusive": ":warning:",
            }
            hyp_lines = []
            for h in sorted(hyp_state.hypotheses.values(), key=lambda x: -x.confidence):
                icon = status_icons.get(h.status.value, ":grey_question:")
                hyp_lines.append(f"{icon} *{h.description}* ({h.confidence:.0%})")
            if hyp_lines:
                blocks.append({"type": "divider"})
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Hypotheses:*\n" + "\n".join(hyp_lines[:5]),
                        },
                    }
                )

        # v3: Data gaps (Slack)
        data_gaps = getattr(report, "data_gaps", [])
        if data_gaps:
            gap_lines = []
            for gap in data_gaps[:5]:
                gap_lines.append(f":warning: *{gap.signal}*: {gap.failure_reason}")
                if gap.recommendation:
                    gap_lines.append(f"    _Recommendation: {gap.recommendation}_")
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Data Gaps:*\n" + "\n".join(gap_lines),
                    },
                }
            )

        # v3: Next steps for low-confidence (Slack)
        next_steps = getattr(report, "recommended_next_steps", [])
        if next_steps:
            steps_text = "\n".join(f"• {step}" for step in next_steps[:5])
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Recommended Next Steps:*\n{steps_text}",
                    },
                }
            )

        # Datadog deep links (when triggered from a monitor alert)
        if report.incident.monitor_id:
            site = "datadoghq.com"
            start_ms = int(report.incident.start_time.timestamp() * 1000)
            end_ms = int(report.incident.end_time.timestamp() * 1000)
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Datadog Links:*\n"
                            f"• <https://app.{site}/monitors/{report.incident.monitor_id}|Monitor>\n"
                            f"• <https://app.{site}/apm/services/{report.incident.service}|APM Service>\n"
                            f"• <https://app.{site}/logs?query=service%3A{report.incident.service}"
                            f"&from_ts={start_ms}&to_ts={end_ms}|Logs>"
                        ),
                    },
                }
            )

        return blocks

    @staticmethod
    def to_compact(report: RCAReport) -> str:
        """Render a compact one-paragraph summary for alerts/notifications."""
        return (
            f"[{report.confidence_score:.0%} confidence] "
            f"Root cause for {report.incident.service}: {report.root_cause.description}. "
            f"{report.blast_radius}. "
            f"Top remediation: {report.remediation_steps[0] if report.remediation_steps else 'N/A'}"
        )


def _action_emoji(action: str) -> str:
    """Map investigation action types to emojis for Slack display."""
    mapping = {
        "fetch_metrics": ":chart_with_upwards_trend:",
        "fetch_logs": ":page_facing_up:",
        "fetch_traces": ":footprints:",
        "fetch_service_map": ":spider_web:",
        "fetch_events": ":calendar:",
        "fetch_deployments": ":rocket:",
        "fetch_monitors": ":bell:",
        "fetch_infra_metrics": ":gear:",
        "query_custom_metric": ":bar_chart:",
        "search_logs_custom": ":mag_right:",
        "search_traces_custom": ":microscope:",
        "correlate_signals": ":link:",
        "expand_scope": ":telescope:",
        "analyze_hypothesis": ":brain:",
        "conclude": ":white_check_mark:",
        "discover_context": ":compass:",
    }
    return mapping.get(action, ":mag:")
