"""Tests for Slack Datadog alert message parser."""

from datetime import datetime, timezone

import pytest

from src.slack.parser import (
    SlackAlertContext,
    extract_tags_from_text,
    parse_datadog_alert_message,
    parse_monitor_url,
)


class TestParseMonitorUrl:
    def test_full_url(self):
        url = (
            "https://app.datadoghq.com/monitors/12345"
            "?group=container_name:flink-main,pod_name:my-pod"
            "&from_ts=1700000000000&to_ts=1700003600000"
            "&event_id=abc123"
        )
        result = parse_monitor_url(url)
        assert result["monitor_id"] == 12345
        assert result["group_tags"] == {
            "container_name": "flink-main",
            "pod_name": "my-pod",
        }
        assert result["from_ts"] == datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
        assert result["to_ts"] is not None
        assert result["event_id"] == "abc123"

    def test_minimal_url(self):
        url = "https://app.datadoghq.com/monitors/99999"
        result = parse_monitor_url(url)
        assert result["monitor_id"] == 99999
        assert result["group_tags"] == {}
        assert result["from_ts"] is None
        assert result["to_ts"] is None
        assert result["event_id"] is None

    def test_url_with_complex_group_tags(self):
        url = (
            "https://app.datadoghq.com/monitors/42"
            "?group=container_name:flink-main-container,"
            "kube_deployment:mk-sp-event-log-router,"
            "pod_name:mk-sp-event-log-router-58f87f4fb6-xmq8f"
        )
        result = parse_monitor_url(url)
        assert result["monitor_id"] == 42
        assert result["group_tags"]["container_name"] == "flink-main-container"
        assert result["group_tags"]["kube_deployment"] == "mk-sp-event-log-router"
        assert result["group_tags"]["pod_name"] == "mk-sp-event-log-router-58f87f4fb6-xmq8f"


class TestExtractTags:
    def test_extract_known_tags(self):
        text = (
            "container_name:flink-main-container, "
            "kube_deployment:mk-sp-event-log-router, "
            "pod_name:mk-sp-event-log-router-58f87f4fb6-xmq8f"
        )
        tags = extract_tags_from_text(text)
        assert tags["container_name"] == "flink-main-container"
        assert tags["kube_deployment"] == "mk-sp-event-log-router"
        assert tags["pod_name"] == "mk-sp-event-log-router-58f87f4fb6-xmq8f"

    def test_no_tags(self):
        tags = extract_tags_from_text("No tags here, just plain text.")
        assert tags == {}


class TestParseDatadogAlertMessage:
    def test_parse_from_text(self):
        text = (
            "Triggered: [search-platform][production] "
            "K8s pod CPU usage on container_name:flink-main-container,"
            "kube_deployment:mk-sp-event-log-router\n"
            "CPU Usage is 92.51%\n"
            "Metric value: 92.51\n"
            "https://app.datadoghq.com/monitors/12345"
            "?group=container_name:flink-main-container"
            "&from_ts=1700000000000&to_ts=1700003600000"
        )
        ctx = parse_datadog_alert_message(text)
        assert ctx.monitor_id == 12345
        assert ctx.group_tags["container_name"] == "flink-main-container"
        assert ctx.group_tags["kube_deployment"] == "mk-sp-event-log-router"
        assert ctx.from_ts is not None
        assert ctx.to_ts is not None
        assert ctx.threshold == "92.51"

    def test_parse_from_attachments(self):
        text = "Alert notification"
        attachments = [
            {
                "text": "CPU usage alert for pod",
                "title_link": (
                    "https://app.datadoghq.com/monitors/555"
                    "?group=pod_name:my-pod"
                ),
            }
        ]
        ctx = parse_datadog_alert_message(text, attachments=attachments)
        assert ctx.monitor_id == 555
        assert ctx.group_tags["pod_name"] == "my-pod"

    def test_parse_from_blocks(self):
        text = "Alert"
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Check https://app.datadoghq.com/monitors/777",
                },
            }
        ]
        ctx = parse_datadog_alert_message(text, blocks=blocks)
        assert ctx.monitor_id == 777

    def test_no_monitor_url_raises(self):
        with pytest.raises(ValueError, match="No Datadog monitor URL"):
            parse_datadog_alert_message("Just a regular message, no links")

    def test_real_world_datadog_alert(self):
        """Test with a realistic Datadog Slack alert format."""
        text = (
            "Triggered: [search-platform][production]K8s pod CPU usage "
            "on container_name:flink-main-container,"
            "kube_deployment:mk-sp-event-log-router,"
            "pod_name:mk-sp-event-log-router-58f87f4fb6-xmq8f"
            "One (or more) pod(s) CPU usage percentage of deployment "
            "mk-sp-event-log-router container flink-main-container "
            "is above the thresholds.\nCPU Usage is 92.51%\n"
            "@slack-alert-search-team\n"
            "avg(last_10m):   (     "
            "sum:kubernetes.cpu.usage.total{"
            "kube_namespace:search-platform-prod,"
            "cluster-name:cluster-prod-01} by "
            "{container_name,pod_name,kube_deployment} / (1000 * 1000 * 1000) /     "
            "sum:kubernetes.cpu.limits{"
            "kube_namespace:search-platform-prod,"
            "cluster-name:cluster-prod-01} by "
            "{container_name,pod_name,kube_deployment}   )   * 100 > 80\n"
            "Metric value: 92.51\n"
            "https://app.datadoghq.com/monitors/98765"
            "?group=container_name:flink-main-container,"
            "kube_deployment:mk-sp-event-log-router,"
            "pod_name:mk-sp-event-log-router-58f87f4fb6-xmq8f"
        )

        ctx = parse_datadog_alert_message(text)
        assert ctx.monitor_id == 98765
        assert ctx.group_tags["container_name"] == "flink-main-container"
        assert ctx.group_tags["kube_deployment"] == "mk-sp-event-log-router"
        assert ctx.threshold == "92.51"
