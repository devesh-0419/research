"""
utils/logger.py
===============
Shared structured logging utility.
All agents call log_event() to produce consistent log entries.
These are appended to state["logs"] for the LoggerAgent to audit.
"""

from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4


def log_event(
    agent_id:   str,
    event:      str,
    details:    dict | None = None,
    message_id: str | None  = None,
    level:      str         = "INFO",
) -> dict:
    """
    Create a structured log entry.
    
    Returns a dict that gets appended to state["logs"].
    The LoggerAgent then processes these for audit + anomaly detection.
    """
    return {
        "log_id":     str(uuid4())[:8],
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "agent_id":   agent_id,
        "event":      event,
        "level":      level,
        "message_id": message_id,
        "details":    details or {},
    }
