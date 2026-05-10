"""
agents/authorizer.py
====================
AuthorizerAgent — permission enforcement layer.

Responsibilities:
  - Receive auth_check A2A messages from OrchestratorAgent
  - Call MockPolicyMCPClient to evaluate role + operation
  - Set state["auth_status"] to "approved" or "denied"
  - In Phase 2: can be bypassed or its response forged

Trust assumption (Phase 1 baseline): fully trusted, trust_level = 1.0
"""

from __future__ import annotations
from research.mas_baseline.core.state import AgentState, make_a2a_message
from research.mas_baseline.mcp_mock.clients import MockPolicyMCPClient
from research.mas_baseline.utils.logger import log_event


AGENT_ID = "authorizer_agent"
_policy_client = MockPolicyMCPClient()


def authorizer_agent(state: AgentState) -> dict:
    """
    LangGraph node — policy enforcement.

    1. Finds the most recent auth_check request
    2. Calls MockPolicyMCPClient.call_tool("policy_check", ...)
    3. Sets state["auth_status"] = "approved" | "denied"
    """
    incoming = _get_latest_message(state, task_type="auth_check")
    if not incoming:
        return _no_op(state, reason="no auth_check found in state")

    payload   = incoming["payload"]
    user_role = payload.get("user_role", "viewer")
    operation = payload.get("operation", "read")
    task      = payload.get("task", "general_query")
    context   = payload.get("context", "")

    # ── call mock policy MCP server ───────────────────────────────────────────
    mcp_response = _policy_client.call_tool(
        "policy_check",
        {"role": user_role, "operation": operation},
    )

    if mcp_response["error"]:
        # Fail-closed: deny on error
        auth_status = "denied"
        decision_reason = f"Policy MCP error: {mcp_response['error']}"
    else:
        policy_result   = mcp_response["tool_response"]
        auth_status     = policy_result["decision"]    # "approved" | "denied"
        decision_reason = policy_result["reason"]

    # ── build response A2A message ────────────────────────────────────────────
    response_msg = make_a2a_message(
        sender     = AGENT_ID,
        recipient  = "orchestrator_agent",
        task_type  = "auth_response",
        payload    = {
            "auth_status":      auth_status,
            "user_role":        user_role,
            "operation":        operation,
            "decision_reason":  decision_reason,
            "mcp_server":       mcp_response["server"],
        },
        trust_level = state["trust_registry"].get(AGENT_ID, 1.0),
    )

    log_entry = log_event(
        agent_id   = AGENT_ID,
        event      = "auth_decision",
        details    = {
            "user_role":  user_role,
            "operation":  operation,
            "task":       task,
            "decision":   auth_status,
            "reason":     decision_reason,
        },
        message_id = incoming["message_id"],
    )

    return {
        "messages":   [response_msg],
        "auth_status": auth_status,
        "logs":        [log_entry],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_latest_message(state: AgentState, task_type: str) -> dict | None:
    for msg in reversed(state.get("messages", [])):
        if msg.get("task_type") == task_type:
            return msg
    return None


def _no_op(state: AgentState, reason: str) -> dict:
    log_entry = log_event(
        agent_id = AGENT_ID,
        event    = "skipped_no_request",
        details  = {"reason": reason},
    )
    return {"logs": [log_entry], "auth_status": "pending"}
