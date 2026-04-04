"""Timezone utilities to prevent naive/aware datetime mismatches."""

from __future__ import annotations

from datetime import datetime, timezone


def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (UTC).

    - If naive: assume UTC and attach tzinfo
    - If aware but not UTC: convert to UTC
    - If already UTC: return as-is
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def safe_timestamp(epoch_seconds: float) -> datetime:
    """Create a UTC-aware datetime from an epoch timestamp."""
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)


def safe_fromisoformat(iso_str: str) -> datetime:
    """Parse an ISO format string into a UTC-aware datetime.

    Handles trailing 'Z', missing timezone, etc.
    """
    cleaned = iso_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    return ensure_utc(dt)
