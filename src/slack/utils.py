"""Slack-specific utilities for message formatting and error handling."""

from __future__ import annotations

import traceback


def truncate_blocks(blocks: list[dict], max_blocks: int = 50) -> list[dict]:
    """Truncate Slack blocks to stay within the 50-block message limit.

    Preserves the header, root cause, and remediation sections.
    Trims from the middle (timeline/evidence) if needed.
    """
    if len(blocks) <= max_blocks:
        return blocks

    # Keep first 5 blocks (header, summary, divider, root cause, remediation)
    # and last 2 blocks (links, etc.)
    head = blocks[:5]
    tail = blocks[-2:]
    remaining = max_blocks - len(head) - len(tail) - 1  # -1 for truncation notice

    middle = blocks[5:-2][:remaining] if remaining > 0 else []

    truncation_notice = {
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"_Showing {len(head) + len(middle) + len(tail)} of "
                        f"{len(blocks)} blocks. Full report available in thread._",
            }
        ],
    }

    return head + middle + [truncation_notice] + tail


def sanitize_error(exception: Exception) -> str:
    """Return a user-friendly error description without stack traces."""
    error_type = type(exception).__name__
    message = str(exception)

    # Truncate long messages
    if len(message) > 300:
        message = message[:300] + "..."

    # Remove file paths and line numbers
    message = _strip_paths(message)

    return f"{error_type}: {message}" if message else error_type


def _strip_paths(text: str) -> str:
    """Remove file system paths from error messages."""
    import re
    return re.sub(r"(/[\w/.-]+\.py):?\d*", "<source>", text)


def format_error_blocks(error_msg: str) -> list[dict]:
    """Create Slack blocks for an error message."""
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":warning: *Investigation failed*\n{error_msg}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Check the bot logs for full details. "
                            "You can also try running the investigation again.",
                }
            ],
        },
    ]
