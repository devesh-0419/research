"""
agents/orchestrator.py
======================
OrchestratorAgent — central coordinator of the MAS.

Responsibilities:
  - Parse the incoming A2A message from UserFacingAgent
  - Decide routing: which agents to invoke and in what order
  - Delegate to DataManagerAgent and AuthorizerAgent via A2A messages
  - Assemble the final response from sub-agent results
  - This agent is the highest-value target for compromise (Phase 2)

Trust assumption (Phase 1 baseline): fully trusted, trust_level = 1.0
"""

from __future__ import annotations
from research.mas_baseline.core.state import AgentState, make_a2a_message
from research.mas_baseline.utils.logger import log_event


AGENT_ID = "orchestrator_agent"


def orchestrator_agent(state: AgentState) -> dict:
    """
    LangGraph node — main orchestration logic.

    Reads the latest message from UserFacingAgent, decides a plan,
    and enqueues A2A messages for DataManager and Authorizer.
    """
    # ── find the most recent user_request message ────────────────────────────
    incoming = _get_latest_message(state, task_type="user_request")
    if not incoming:
        return _error_response(state, "orchestrator received no user_request message")

    payload    = incoming["payload"]
    intent     = payload.get("intent", {})
    user_role  = payload.get("user_role", "viewer")
    operation  = intent.get("operation", "read")
    task       = intent.get("task", "general_query")
    raw_query  = payload.get("raw_query", "")

    # ── build execution plan ─────────────────────────────────────────────────
    plan = _build_plan(task, operation, user_role)

    log_entry = log_event(
        agent_id   = AGENT_ID,
        event      = "built_execution_plan",
        details    = {"plan": plan, "task": task, "operation": operation},
        message_id = incoming["message_id"],
    )

    outbound_messages = []

    # Step 1: always request auth check first
    auth_msg = make_a2a_message(
        sender     = AGENT_ID,
        recipient  = "authorizer_agent",
        task_type  = "auth_check",
        payload    = {
            "user_role": user_role,
            "operation": operation,
            "task":      task,
            "context":   raw_query,
        },
        trust_level = state["trust_registry"].get(AGENT_ID, 1.0),
    )
    outbound_messages.append(auth_msg)

    # Step 2: if data is involved, enqueue data request
    if plan.get("needs_data"):
        data_msg = make_a2a_message(
            sender     = AGENT_ID,
            recipient  = "data_manager_agent",
            task_type  = "data_request",
            payload    = {
                "operation": operation,
                "table":     plan.get("table", "users"),
                "filters":   plan.get("filters", {}),
                "raw_query": raw_query,
            },
            trust_level = state["trust_registry"].get(AGENT_ID, 1.0),
        )
        outbound_messages.append(data_msg)

    return {
        "messages":    outbound_messages,
        "current_task": task,
        "logs":        [log_entry],
    }


def orchestrator_assemble(state: AgentState) -> dict:
    """
    LangGraph node — called after DataManager and Authorizer have run.
    Assembles the final response from sub-agent outputs.
    """
    auth_status  = state.get("auth_status", "pending")
    data_payload = state.get("data_payload", {})
    task         = state.get("current_task", "general_query")

    if auth_status == "denied":
        response = (
            f"[Orchestrator] Request DENIED by AuthorizerAgent. "
            f"You do not have permission to perform: {task}."
        )
    elif auth_status == "approved":
        if data_payload:
            rows  = data_payload.get("rows", data_payload.get("record", data_payload))
            count = data_payload.get("count", "")
            count_str = f" ({count} records)" if count else ""
            response = (
                f"[Orchestrator] Request approved. "
                f"Task '{task}' completed{count_str}.\n"
                f"Data: {rows}"
            )
        else:
            response = (
                f"[Orchestrator] Request approved. "
                f"Task '{task}' completed. No data payload."
            )
    else:
        response = "[Orchestrator] Auth status still pending — pipeline may be incomplete."

    log_entry = log_event(
        agent_id = AGENT_ID,
        event    = "assembled_final_response",
        details  = {
            "auth_status":     auth_status,
            "has_data":        bool(data_payload),
            "response_preview": response[:100],
        },
    )

    return {
        "final_response": response,
        "logs":           [log_entry],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_plan(task: str, operation: str, user_role: str) -> dict:
    """Decide what the orchestrator needs to do."""
    table_map = {
        "data_retrieval": "users",
        "data_write":     "records",
        "data_delete":    "records",
        "admin_action":   "config",
        "general_query":  "users",
    }
    return {
        "needs_data": task in ("data_retrieval", "data_write", "data_delete", "general_query", "admin_action"),
        "table":      table_map.get(task, "users"),
        "filters":    {},
        "steps":      ["auth_check", "data_operation"] if task != "general_query" else ["auth_check"],
    }


def _get_latest_message(state: AgentState, task_type: str) -> dict | None:
    for msg in reversed(state.get("messages", [])):
        if msg.get("task_type") == task_type:
            return msg
    return None


def _error_response(state: AgentState, reason: str) -> dict:
    log_entry = log_event(
        agent_id = AGENT_ID,
        event    = "orchestration_error",
        details  = {"reason": reason},
    )
    return {
        "final_response": f"[Orchestrator ERROR] {reason}",
        "logs":           [log_entry],
    }
