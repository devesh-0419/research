"""
agents/user_facing.py
=====================
UserFacingAgent — entry point of the MAS.

Responsibilities:
  - Receive raw user input
  - Wrap it in an A2A envelope addressed to the Orchestrator
  - Return the final response to the user after the pipeline completes

Trust assumption (Phase 1 baseline): fully trusted, trust_level = 1.0
"""

from __future__ import annotations
from research.mas_baseline.core.state import AgentState, make_a2a_message
from research.mas_baseline.utils.logger import log_event


AGENT_ID = "user_facing_agent"


def user_facing_agent(state: AgentState) -> dict:
    """
    LangGraph node function for UserFacingAgent.
    
    Input  : state["user_query"]  (raw user string)
    Output : appends A2A message to state["messages"]
             sets state["current_task"]
    """
    user_query = state["user_query"]

    # ── parse intent (lightweight, no LLM call needed at entry) ──────────────
    intent = _parse_intent(user_query)

    # ── build A2A envelope ────────────────────────────────────────────────────
    msg = make_a2a_message(
        sender     = AGENT_ID,
        recipient  = "orchestrator_agent",
        task_type  = "user_request",
        payload    = {
            "raw_query": user_query,
            "intent":    intent,
            "user_id":   "user_001",           # hardcoded for baseline
            "user_role": "editor",             # hardcoded for baseline
        },
        trust_level = state["trust_registry"].get(AGENT_ID, 1.0),
    )

    log_entry = log_event(
        agent_id  = AGENT_ID,
        event     = "received_user_query",
        details   = {"query": user_query, "intent": intent},
        message_id = msg["message_id"],
    )

    return {
        "messages":    [msg],
        "current_task": intent.get("task", "general_query"),
        "logs":        [log_entry],
    }


def user_facing_respond(state: AgentState) -> dict:
    """
    Terminal node: formats and returns final response to the user.
    Called after Orchestrator assembles the response.
    """
    final = state.get("final_response", "No response generated.")

    log_entry = log_event(
        agent_id = AGENT_ID,
        event    = "returning_response_to_user",
        details  = {"response_preview": final[:120]},
    )

    # Print to stdout so it's visible during testing
    print(f"\n{'='*60}")
    print(f"[UserFacingAgent] Response to user:")
    print(f"{final}")
    print(f"{'='*60}\n")

    return {"logs": [log_entry]}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_intent(query: str) -> dict:
    """
    Lightweight rule-based intent parser.
    In a full system this would call an LLM; here we keep it
    deterministic so tests are reproducible.
    """
    q = query.lower()

    if any(w in q for w in ["get", "fetch", "retrieve", "show", "list", "query"]):
        task      = "data_retrieval"
        operation = "read"
    elif any(w in q for w in ["write", "save", "create", "insert", "add"]):
        task      = "data_write"
        operation = "write"
    elif any(w in q for w in ["delete", "remove", "drop"]):
        task      = "data_delete"
        operation = "delete"
    elif any(w in q for w in ["admin", "configure", "config"]):
        task      = "admin_action"
        operation = "admin_action"
    else:
        task      = "general_query"
        operation = "read"

    return {
        "task":      task,
        "operation": operation,
        "raw":       query,
    }
