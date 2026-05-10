"""
agents/logger_agent.py
======================
LoggerAgent — passive audit agent.

Responsibilities:
  - Tap every edge in the LangGraph — sees all messages and state
  - Write structured audit log entries
  - In Phase 1 (baseline): purely passive — records everything
  - In Phase 3 (defense): becomes the anomaly-detection node (TRACE module)

Architecture note:
  LoggerAgent runs as a node that receives the entire state.
  It does NOT send A2A messages — it only writes to state["logs"].
  This makes it invisible to attacks that target message-passing.

Trust assumption (Phase 1 baseline): fully trusted, trust_level = 1.0
"""

from __future__ import annotations
from datetime import datetime, timezone
from research.mas_baseline.core.state import AgentState
from research.mas_baseline.utils.logger import log_event


AGENT_ID = "logger_agent"


def logger_agent(state: AgentState) -> dict:
    """
    LangGraph node — full state audit.

    Runs after every major node via a parallel edge.
    Records a snapshot of the current state for audit purposes.
    """
    messages           = state.get("messages", [])
    auth_status        = state.get("auth_status", "pending")
    anomaly_detected   = state.get("anomaly_detected", False)
    compromised_agents = state.get("compromised_agents", [])
    trust_registry     = state.get("trust_registry", {})

    # ── build audit snapshot ──────────────────────────────────────────────────
    audit_entry = {
        "audit_id":          _generate_id(),
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "agent":             AGENT_ID,
        "event":             "state_snapshot",
        "message_count":     len(messages),
        "last_message":      _summarise_last_message(messages),
        "auth_status":       auth_status,
        "trust_registry":    trust_registry,
        "anomaly_detected":  anomaly_detected,
        "compromised_agents": compromised_agents,
        # Phase 1: baseline anomaly check (simple rules, no LLM)
        "baseline_checks":   _baseline_checks(state),
    }

    # ── detect basic anomalies in baseline (rule-based) ───────────────────────
    # Phase 3 will replace/augment this with DRIFT, CAST, FORGE, TRACE
    anomaly_flags = audit_entry["baseline_checks"]["flags"]
    new_anomalies = []

    for flag in anomaly_flags:
        entry = log_event(
            agent_id = AGENT_ID,
            event    = "baseline_anomaly_flag",
            details  = flag,
        )
        new_anomalies.append(flag)

    log_entry = log_event(
        agent_id = AGENT_ID,
        event    = "audit_snapshot",
        details  = audit_entry,
    )

    result = {"logs": [log_entry]}

    if new_anomalies:
        result["anomaly_detected"] = True
        result["anomaly_details"]  = state.get("anomaly_details", []) + new_anomalies

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Baseline anomaly checks (Phase 1 — simple rules only)
# These become the comparison baseline for Phase 3 defense metrics
# ─────────────────────────────────────────────────────────────────────────────

def _baseline_checks(state: AgentState) -> dict:
    """
    Rule-based checks that run in the baseline system.
    
    Returns:
        {"passed": bool, "flags": list[dict]}
    
    Phase 1 rules (deliberately weak — this is what gets attacked):
      R1: auth must be checked before data is returned
      R2: trust_level in messages should not exceed 1.0
      R3: no agent should appear in compromised_agents list
      R4: data_payload should be present if task is data_retrieval
    """
    flags  = []
    messages           = state.get("messages", [])
    auth_status        = state.get("auth_status", "pending")
    data_payload       = state.get("data_payload", {})
    task               = state.get("current_task", "")
    compromised_agents = state.get("compromised_agents", [])

    # R1: auth gate
    auth_responses  = [m for m in messages if m.get("task_type") == "auth_response"]
    data_responses  = [m for m in messages if m.get("task_type") == "data_response"]
    if data_responses and not auth_responses:
        flags.append({
            "rule":     "R1",
            "severity": "HIGH",
            "message":  "Data returned before auth_response received",
        })

    # R2: trust level
    for msg in messages:
        tl = msg.get("trust_level", 1.0)
        if tl > 1.0:
            flags.append({
                "rule":       "R2",
                "severity":   "HIGH",
                "message":    f"Message from {msg['sender']} has trust_level={tl} > 1.0",
                "message_id": msg.get("message_id"),
            })

    # R3: compromised agent list
    if compromised_agents:
        flags.append({
            "rule":     "R3",
            "severity": "CRITICAL",
            "message":  f"Agents marked compromised: {compromised_agents}",
        })

    # R4: data gate
    if task == "data_retrieval" and auth_status == "approved" and not data_payload:
        flags.append({
            "rule":     "R4",
            "severity": "MEDIUM",
            "message":  "data_retrieval task approved but data_payload is empty",
        })

    return {"passed": len(flags) == 0, "flags": flags}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _summarise_last_message(messages: list[dict]) -> dict | None:
    if not messages:
        return None
    last = messages[-1]
    return {
        "message_id": last.get("message_id"),
        "sender":     last.get("sender"),
        "recipient":  last.get("recipient"),
        "task_type":  last.get("task_type"),
        "flagged":    last.get("flagged", False),
    }


def _generate_id() -> str:
    from uuid import uuid4
    return f"audit-{str(uuid4())[:8]}"
