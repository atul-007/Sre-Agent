"""Tests for analysis phase helpers (evidence deduplication, etc.)
and Datadog client edge cases."""

from src.investigation.analysis import _is_near_duplicate


class TestIsNearDuplicate:
    def test_detects_rephrased_duplicate(self):
        """Rephrased evidence with high word overlap should be detected as duplicate."""
        existing = ["Error logs show 'upstream request timeout' errors starting at 21:00:53"]
        assert _is_near_duplicate(
            "Error logs show upstream request timeout errors starting at 21:00:53.321",
            existing,
        ) is True

    def test_detects_subset_duplicate(self):
        """Evidence that is a subset of existing should be detected."""
        existing = [
            "Client traces show DeadlineExceeded errors at exactly 500ms timeout starting 21:00:53.105"
        ]
        assert _is_near_duplicate(
            "Client traces show DeadlineExceeded errors at exactly 500ms timeout",
            existing,
        ) is True

    def test_allows_distinct_evidence(self):
        """Genuinely different evidence should pass through."""
        existing = ["CPU usage was declining during high latency period"]
        assert _is_near_duplicate(
            "Error logs show upstream request timeout errors from TagSuggestService",
            existing,
        ) is False

    def test_empty_existing_list(self):
        """Empty existing list should always return False."""
        assert _is_near_duplicate("some evidence", []) is False

    def test_empty_new_entry(self):
        """Empty new entry should return False."""
        assert _is_near_duplicate("", ["some evidence"]) is False

    def test_exact_duplicate(self):
        """Exact string match should be detected."""
        existing = ["No deployments found around incident time"]
        assert _is_near_duplicate(
            "No deployments found around incident time",
            existing,
        ) is True

    def test_custom_threshold(self):
        """Higher threshold should be stricter."""
        existing = ["Error logs show timeout errors from downstream services"]
        # With low overlap, should pass at 0.6 but might fail at 0.9
        new = "Timeout errors found in error logs for downstream"
        assert _is_near_duplicate(new, existing, threshold=0.9) is False
