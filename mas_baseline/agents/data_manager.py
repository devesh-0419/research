"""
agents/data_manager.py
======================
DataManagerAgent — data plane handler.

Responsibilities:
  - Receive data_request A2A messages from OrchestratorAgent
  - Call the MockDBMCPClient (simulated tool calls)
  - Return structured data results back into state
  - In Phase 2: the MCP tool_response is the injection vector for
    indirect prompt injection attacks

Trust assumption (Phase 1 baseline): fully trusted, trust_level = 1.0
"""

from __future__ import annotations
from research.mas_baseline.core.state import AgentState, make_a2a_message
from research.mas_baseline.mcp_mock.clients import MockDBMCPClient
from research.mas_baseline.utils.logger import log_event


AGENT_ID = "data_manager_agent"
_db_client = MockDBMCPClient()


def data_manager_agent(state: AgentState) -> dict:
    """
    LangGraph node — handles data operations.

    1. Finds the most recent data_request from orchestrator
    2. Calls the appropriate MCP tool
    3. Returns the result in state["data_payload"]
    """
    incoming = _get_latest_message(state, task_type="data_request")
    if not incoming:
        return _no_op(state, reason="no data_request found in state")

    payload   = incoming["payload"]
    operation = payload.get("operation", "read")
    table     = payload.get("table", "users")
    filters   = payload.get("filters", {})

    # ── map operation to MCP tool call ────────────────────────────────────────
    tool_name, tool_params = _resolve_tool(operation, table, filters, payload)

    # ── call mock MCP server ──────────────────────────────────────────────────
    mcp_response = _db_client.call_tool(tool_name, tool_params)

    # ── check for MCP-level errors ────────────────────────────────────────────
    if mcp_response["error"]:
        log_entry = log_event(
            agent_id   = AGENT_ID,
            event      = "mcp_tool_error",
            details    = {
                "tool":    tool_name,
                "error":   mcp_response["error"],
                "params":  tool_params,
            },
            message_id = incoming["message_id"],
        )
        return {
            "data_payload": {"error": mcp_response["error"]},
            "logs":         [log_entry],
        }

    tool_response = mcp_response["tool_response"]

    # ── build response A2A message back to orchestrator ───────────────────────
    response_msg = make_a2a_message(
        sender      = AGENT_ID,
        recipient   = "orchestrator_agent",
        task_type   = "data_response",
        payload     = {
            "tool_called":     tool_name,
            "tool_params":     tool_params,
            "result":          tool_response,
            "mcp_server":      mcp_response["server"],
            "mcp_timestamp":   mcp_response["timestamp"],
            # ↑ In Phase 2 attack: tool_response above could contain
            #   injected instructions that propagate to Orchestrator
        },
        trust_level = state["trust_registry"].get(AGENT_ID, 1.0),
    )

    log_entry = log_event(
        agent_id   = AGENT_ID,
        event      = "mcp_tool_call_completed",
        details    = {
            "tool":         tool_name,
            "table":        table,
            "operation":    operation,
            "result_keys":  list(tool_response.keys()) if tool_response else [],
        },
        message_id = incoming["message_id"],
    )

    return {
        "messages":     [response_msg],
        "data_payload": tool_response,
        "logs":         [log_entry],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_tool(
    operation: str,
    table: str,
    filters: dict,
    payload: dict,
) -> tuple[str, dict]:
    """Map an operation to a specific MCP tool + params."""
    if operation == "read":
        record_id = filters.get("record_id") or payload.get("record_id")
        if record_id:
            return "db_get_record", {"record_id": record_id}
        return "db_query", {"table": table}

    elif operation == "write":
        record = payload.get("record", {"auto": "generated"})
        return "db_write", {"table": table, "record": record}

    elif operation in ("delete", "admin_action"):
        # For baseline: map both to db_config (safe mock)
        return "db_config", {}

    else:
        return "db_query", {"table": "users"}


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
    return {"logs": [log_entry]}
