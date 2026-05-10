"""
server.py
=========
Flask backend that runs the actual LangGraph MAS pipeline
and streams real agent events to the frontend via SSE
(Server-Sent Events).

Endpoints:
  POST /api/run          — run a query, returns full result as JSON
  GET  /api/stream?q=... — run a query, stream events as SSE
  GET  /api/health       — health check

Usage:
  python server.py
  # Then open frontend/index.html in a browser
  # (or serve it: python -m http.server 5500 --directory frontend)
"""

from __future__ import annotations
import json
import sys
import os
import time
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS

# ── make project root importable ──────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from research.mas_baseline.core.state   import initial_state
from research.mas_baseline.core.llm_config import print_llm_config
from research.mas_baseline.graph        import get_graph

app  = Flask(__name__, static_folder="frontend", static_url_path="")
CORS(app)   # allow browser requests from file:// or localhost:5500


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/run  — full pipeline, returns complete result
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/run", methods=["POST"])
def run_pipeline():
    data  = request.get_json(force=True)
    query = (data.get("query") or "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    try:
        graph  = get_graph()
        state  = initial_state(query)
        result = graph.invoke(state)
        return jsonify(_serialise_result(result))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/stream?q=...  — streams real pipeline events as SSE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/stream")
def stream_pipeline():
    query = (request.args.get("q") or "").strip()
    if not query:
        return jsonify({"error": "q param required"}), 400

    def generate():
        try:
            graph = get_graph()
            state = initial_state(query)

            # ── stream via LangGraph's stream() ──────────────────────────────
            # stream_mode="updates" yields {node_name: state_update} after
            # each node completes — gives us real per-agent events.
            for chunk in graph.stream(state, stream_mode="updates"):
                for node_name, node_update in chunk.items():
                    event = _build_sse_event(node_name, node_update)
                    yield f"data: {json.dumps(event)}\n\n"
                    time.sleep(0.05)   # tiny pause so browser renders smoothly

            # ── final complete event ──────────────────────────────────────────
            final_result = graph.invoke(initial_state(query))
            done_event = {
                "type":       "done",
                "node":       "pipeline",
                "result":     _serialise_result(final_result),
            }
            yield f"data: {json.dumps(done_event)}\n\n"

        except Exception as exc:
            err_event = {"type": "error", "message": str(exc)}
            yield f"data: {json.dumps(err_event)}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/health
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    from research.mas_baseline.core.llm_config import LLM_PROVIDER, LLM_MODEL, LLM_ENABLED
    return jsonify({
        "status":       "ok",
        "llm_provider": LLM_PROVIDER,
        "llm_model":    LLM_MODEL or "default",
        "llm_enabled":  LLM_ENABLED,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Serve frontend directly from Flask (convenience)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("frontend", path)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

# Node name → agent_id mapping (LangGraph node names)
_NODE_TO_AGENT = {
    "user_facing":           "user_facing_agent",
    "orchestrator":          "orchestrator_agent",
    "authorizer":            "authorizer_agent",
    "data_manager":          "data_manager_agent",
    "logger":                "logger_agent",
    "orchestrator_assemble": "orchestrator_agent",
    "user_facing_respond":   "user_facing_agent",
}


def _build_sse_event(node_name: str, node_update: dict) -> dict:
    """
    Convert a LangGraph state update from a single node into an SSE event
    that the frontend can consume directly.
    """
    agent_id = _NODE_TO_AGENT.get(node_name, node_name)

    # Extract new messages added by this node
    new_messages = node_update.get("messages", [])

    # Extract new log entries added by this node
    new_logs = node_update.get("logs", [])

    return {
        "type":        "node_complete",
        "node":        node_name,
        "agent_id":    agent_id,
        "messages":    new_messages,          # A2A envelopes from this node
        "logs":        new_logs,              # log entries from this node
        "auth_status": node_update.get("auth_status"),
        "data_payload": node_update.get("data_payload"),
        "anomaly_detected": node_update.get("anomaly_detected"),
        "anomaly_details":  node_update.get("anomaly_details", []),
        "final_response":   node_update.get("final_response"),
        "trust_registry":   node_update.get("trust_registry"),
        "current_task":     node_update.get("current_task"),
    }


def _serialise_result(result: dict) -> dict:
    """Make the AgentState JSON-safe for the API response."""
    return {
        "final_response":    result.get("final_response", ""),
        "auth_status":       result.get("auth_status", "pending"),
        "current_task":      result.get("current_task", ""),
        "messages":          result.get("messages", []),
        "logs":              result.get("logs", []),
        "trust_registry":    result.get("trust_registry", {}),
        "anomaly_detected":  result.get("anomaly_detected", False),
        "anomaly_details":   result.get("anomaly_details", []),
        "data_payload":      result.get("data_payload", {}),
        "attack_type":       result.get("attack_type"),
        "compromised_agents": result.get("compromised_agents", []),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  AEGIS-MAS  —  Backend Server")
    print("="*55)
    print_llm_config()
    print("\n  Frontend:  http://localhost:5000")
    print("  API:       http://localhost:5000/api/run")
    print("  Health:    http://localhost:5000/api/health")
    print("  Stream:    http://localhost:5000/api/stream?q=<query>")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
