"""Tests for timezone utility functions."""

from datetime import datetime, timezone, timedelta

from src.utils.time import ensure_utc, safe_fromisoformat, safe_timestamp


class TestEnsureUtc:
    def test_naive_becomes_utc(self):
        naive = datetime(2024, 1, 15, 10, 30)
        result = ensure_utc(naive)
        assert result.tzinfo == timezone.utc
        assert result.hour == 10

    def test_utc_stays_utc(self):
        utc = datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)
        result = ensure_utc(utc)
        assert result.tzinfo == timezone.utc
        assert result == utc

    def test_other_tz_converts_to_utc(self):
        jst = timezone(timedelta(hours=9))
        jst_time = datetime(2024, 1, 15, 19, 30, tzinfo=jst)
        result = ensure_utc(jst_time)
        assert result.tzinfo == timezone.utc
        assert result.hour == 10  # 19:30 JST = 10:30 UTC


class TestSafeTimestamp:
    def test_basic(self):
        result = safe_timestamp(0)
        assert result.tzinfo == timezone.utc
        assert result.year == 1970

    def test_recent(self):
        result = safe_timestamp(1700000000)
        assert result.tzinfo == timezone.utc
        assert result.year == 2023


class TestSafeFromIsoformat:
    def test_with_z(self):
        result = safe_fromisoformat("2024-01-15T10:30:00Z")
        assert result.tzinfo == timezone.utc

    def test_with_offset(self):
        result = safe_fromisoformat("2024-01-15T10:30:00+00:00")
        assert result.tzinfo == timezone.utc

    def test_without_tz(self):
        result = safe_fromisoformat("2024-01-15T10:30:00")
        assert result.tzinfo == timezone.utc
