"""
core/state.py
=============
Shared state schema for the 5-agent MAS.
All inter-agent communication flows through AgentState.
Messages are structured as A2A envelopes for realistic protocol modelling.
"""

from __future__ import annotations
from typing import TypedDict, Annotated, Literal, Any
from uuid import uuid4
from datetime import datetime, timezone
import operator


# ─────────────────────────────────────────────────────────────────────────────
# A2A Message Envelope
# ─────────────────────────────────────────────────────────────────────────────

def make_a2a_message(
    sender: str,
    recipient: str,
    task_type: str,
    payload: dict,
    trust_level: float = 1.0,
    signature: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """
    Creates an A2A-format message envelope.
    
    In a real A2A deployment this would be an HTTP/JSON-RPC call.
    Here we simulate it as a structured dict in LangGraph state, which
    is sufficient to model the message-layer attack surface.
    """
    return {
        "message_id":  str(uuid4()),
        "sender":      sender,
        "recipient":   recipient,
        "task_type":   task_type,
        "payload":     payload,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "trust_level": trust_level,        # ← mutated by attack/defense phases
        "signature":   signature,          # ← populated by defense layer
        "metadata":    metadata or {},
        "flagged":     False,              # ← set True by defense detection
        "flag_reason": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Shared Agent State
# ─────────────────────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    # ── core conversation ─────────────────────────────────────────────────────
    user_query:        str
    current_task:      str
    final_response:    str

    # ── A2A message bus ───────────────────────────────────────────────────────
    # Annotated with operator.add so each node appends rather than overwrites
    messages: Annotated[list[dict], operator.add]

    # ── data plane ────────────────────────────────────────────────────────────
    data_payload:      dict           # result from DataManagerAgent
    auth_status:       Literal["pending", "approved", "denied"]

    # ── trust & security ──────────────────────────────────────────────────────
    trust_registry: dict              # {agent_id: trust_score}  0.0–1.0
    anomaly_detected:  bool
    anomaly_details:   list[dict]     # list of flagged events (for defense)

    # ── audit trail ───────────────────────────────────────────────────────────
    # Annotated with operator.add so logger appends without clobbering
    logs: Annotated[list[dict], operator.add]

    # ── attack injection points (populated only in attack phase) ──────────────
    injected_payload:  str | None     # raw injected string
    attack_type:       str | None     # "a2a_injection" | "propagation" | "orchestrator_compromise"
    compromised_agents: list[str]     # which agents are currently compromised


# ─────────────────────────────────────────────────────────────────────────────
# Default / initial state factory
# ─────────────────────────────────────────────────────────────────────────────

def initial_state(user_query: str) -> AgentState:
    return AgentState(
        user_query         = user_query,
        current_task       = "",
        final_response     = "",
        messages           = [],
        data_payload       = {},
        auth_status        = "pending",
        trust_registry     = {          # Phase 1: full mutual trust
            "user_facing_agent":   1.0,
            "orchestrator_agent":  1.0,
            "data_manager_agent":  1.0,
            "authorizer_agent":    1.0,
            "logger_agent":        1.0,
        },
        anomaly_detected   = False,
        anomaly_details    = [],
        logs               = [],
        injected_payload   = None,
        attack_type        = None,
        compromised_agents = [],
    )
