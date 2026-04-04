"""Tests for investigation helper utilities."""

import pytest

from src.investigation.helpers import (
    is_empty_result,
    parse_json_response,
    ensure_str_list,
    format_trace_summary,
    format_data_summary,
    merge_data,
)
from src.models.incident import (
    InvestigationActionType,
    InvestigationStep,
    InvestigationTrace,
    MetricSeries,
    MetricDataPoint,
    LogEntry,
    ObservabilityData,
)
from datetime import datetime, timezone


class TestIsEmptyResult:
    def test_none(self):
        assert is_empty_result(None) is True

    def test_empty_list(self):
        assert is_empty_result([]) is True

    def test_empty_dict(self):
        assert is_empty_result({}) is True

    def test_nonempty_list(self):
        assert is_empty_result([1, 2, 3]) is False

    def test_nonempty_dict(self):
        assert is_empty_result({"key": "value"}) is False

    def test_string(self):
        assert is_empty_result("data") is False

    def test_zero(self):
        assert is_empty_result(0) is False


class TestParseJsonResponse:
    def test_valid_json(self):
        result = parse_json_response('{"action": "fetch_metrics"}', {})
        assert result == {"action": "fetch_metrics"}

    def test_json_with_text(self):
        result = parse_json_response('Here is the plan:\n{"action": "conclude"}\nDone.', {})
        assert result["action"] == "conclude"

    def test_invalid_json_returns_fallback(self):
        result = parse_json_response("no json here", {"fallback": True})
        assert result == {"fallback": True}

    def test_empty_response(self):
        result = parse_json_response("", {"default": "val"})
        assert result == {"default": "val"}


class TestEnsureStrList:
    def test_strings(self):
        assert ensure_str_list(["a", "b"]) == ["a", "b"]

    def test_dicts(self):
        result = ensure_str_list([{"key": "value", "key2": "value2"}])
        assert len(result) == 1
        assert "value" in result[0]

    def test_mixed(self):
        result = ensure_str_list(["text", 42, {"k": "v"}])
        assert result[0] == "text"
        assert result[1] == "42"


class TestFormatDataSummary:
    def test_empty_data(self):
        data = ObservabilityData()
        assert format_data_summary(data) == "No data collected"

    def test_with_metrics(self):
        now = datetime.now(timezone.utc)
        data = ObservabilityData(
            metrics=[
                MetricSeries(
                    metric_name="test",
                    display_name="test",
                    points=[MetricDataPoint(timestamp=now, value=1.0)],
                )
            ]
        )
        result = format_data_summary(data)
        assert "1 metric series" in result

    def test_with_logs(self):
        now = datetime.now(timezone.utc)
        data = ObservabilityData(
            logs=[
                LogEntry(timestamp=now, message="err", service="svc", status="error"),
                LogEntry(timestamp=now, message="info", service="svc", status="info"),
            ]
        )
        result = format_data_summary(data)
        assert "2 logs (1 errors)" in result


class TestMergeData:
    def test_merge_metrics(self):
        now = datetime.now(timezone.utc)
        data = ObservabilityData()
        metrics = [MetricSeries(metric_name="cpu", display_name="cpu", points=[MetricDataPoint(timestamp=now, value=0.5)])]
        merge_data(data, metrics, InvestigationActionType.FETCH_METRICS)
        assert len(data.metrics) == 1

    def test_merge_logs(self):
        now = datetime.now(timezone.utc)
        data = ObservabilityData()
        logs = [LogEntry(timestamp=now, message="test", service="svc", status="error")]
        merge_data(data, logs, InvestigationActionType.FETCH_LOGS)
        assert len(data.logs) == 1

    def test_merge_none_is_noop(self):
        data = ObservabilityData()
        merge_data(data, None, InvestigationActionType.FETCH_METRICS)
        assert len(data.metrics) == 0

    def test_merge_expand_scope(self):
        now = datetime.now(timezone.utc)
        data = ObservabilityData()
        raw = {
            "metrics": [MetricSeries(metric_name="cpu", display_name="cpu", points=[MetricDataPoint(timestamp=now, value=0.5)])],
            "logs": [LogEntry(timestamp=now, message="test", service="svc", status="error")],
        }
        merge_data(data, raw, InvestigationActionType.EXPAND_SCOPE)
        assert len(data.metrics) == 1
        assert len(data.logs) == 1
