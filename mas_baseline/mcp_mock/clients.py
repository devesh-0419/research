"""
mcp_mock/clients.py
===================
Lightweight mock MCP (Model Context Protocol) clients.

In production these would be JSON-RPC calls to real MCP servers.
Here we simulate the call/response surface — this is where
indirect prompt injection via tool responses enters the system
in Phase 2 (attack phase).
"""

from __future__ import annotations
import json
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# Mock MCP Server: Database
# ─────────────────────────────────────────────────────────────────────────────

_MOCK_DB = {
    "users": [
        {"id": 1, "name": "Alice",   "role": "admin",  "email": "alice@corp.com"},
        {"id": 2, "name": "Bob",     "role": "viewer", "email": "bob@corp.com"},
        {"id": 3, "name": "Charlie", "role": "editor", "email": "charlie@corp.com"},
    ],
    "records": [
        {"record_id": "R001", "owner": "Alice", "data": "financial_q1"},
        {"record_id": "R002", "owner": "Bob",   "data": "report_march"},
    ],
    "config": {
        "max_records_per_query": 100,
        "allowed_operations":    ["read", "write", "delete"],
    }
}

_MOCK_POLICIES = {
    "admin":  {"allowed": ["read", "write", "delete", "admin_action"],
               "denied":  []},
    "editor": {"allowed": ["read", "write"],
               "denied":  ["delete", "admin_action"]},
    "viewer": {"allowed": ["read"],
               "denied":  ["write", "delete", "admin_action"]},
}


class MockDBMCPClient:
    """
    Simulates MCP server: database operations.
    
    Attack surface: the `tool_response` field of the returned dict
    is what an indirect injection attack would poison.
    """

    SERVER_NAME = "mock-db-mcp"

    def call_tool(self, tool_name: str, params: dict) -> dict:
        """
        Simulate JSON-RPC: tools/call  →  { content: [{type:text, text:...}] }
        """
        try:
            result = self._dispatch(tool_name, params)
            return {
                "tool_name":     tool_name,
                "params":        params,
                "tool_response": result,
                "error":         None,
                "server":        self.SERVER_NAME,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "tool_name":     tool_name,
                "params":        params,
                "tool_response": None,
                "error":         str(exc),
                "server":        self.SERVER_NAME,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
            }

    def _dispatch(self, tool_name: str, params: dict) -> dict:
        if tool_name == "db_query":
            table = params.get("table", "users")
            return {"rows": _MOCK_DB.get(table, []), "count": len(_MOCK_DB.get(table, []))}

        elif tool_name == "db_get_record":
            record_id = params.get("record_id")
            records = _MOCK_DB["records"]
            match = next((r for r in records if r["record_id"] == record_id), None)
            if match:
                return {"record": match}
            raise ValueError(f"Record {record_id!r} not found")

        elif tool_name == "db_write":
            table  = params.get("table", "records")
            record = params.get("record", {})
            # In mock: just echo back confirming write
            return {"status": "written", "table": table, "record": record}

        elif tool_name == "db_config":
            return _MOCK_DB["config"]

        else:
            raise ValueError(f"Unknown tool: {tool_name!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Mock MCP Server: Policy / Auth
# ─────────────────────────────────────────────────────────────────────────────

class MockPolicyMCPClient:
    """
    Simulates MCP server: policy enforcement.
    AuthorizerAgent calls this to check whether a role may perform an action.
    """

    SERVER_NAME = "mock-policy-mcp"

    def call_tool(self, tool_name: str, params: dict) -> dict:
        try:
            result = self._dispatch(tool_name, params)
            return {
                "tool_name":     tool_name,
                "params":        params,
                "tool_response": result,
                "error":         None,
                "server":        self.SERVER_NAME,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "tool_name":     tool_name,
                "params":        params,
                "tool_response": None,
                "error":         str(exc),
                "server":        self.SERVER_NAME,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
            }

    def _dispatch(self, tool_name: str, params: dict) -> dict:
        if tool_name == "policy_check":
            role      = params.get("role",      "viewer")
            operation = params.get("operation", "read")
            policy    = _MOCK_POLICIES.get(role, _MOCK_POLICIES["viewer"])
            allowed   = operation in policy["allowed"]
            return {
                "role":      role,
                "operation": operation,
                "decision":  "approved" if allowed else "denied",
                "reason":    f"Role '{role}' {'may' if allowed else 'may not'} perform '{operation}'",
            }

        elif tool_name == "policy_list_roles":
            return {"roles": list(_MOCK_POLICIES.keys())}

        elif tool_name == "policy_get_role":
            role = params.get("role", "viewer")
            if role not in _MOCK_POLICIES:
                raise ValueError(f"Unknown role: {role!r}")
            return {"role": role, "policy": _MOCK_POLICIES[role]}

        else:
            raise ValueError(f"Unknown tool: {tool_name!r}")
