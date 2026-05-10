"""
aiges/graph_builder.py
=======================
AIGES-Protected Graph Builder

PURPOSE:
    Produces a LangGraph StateGraph identical to the baseline but with
    every agent node wrapped by the AIGES middleware.
    
    ZERO REWIRING:
        This builder imports the baseline graph builder and agent functions
        without modifying them. It only wraps the execution.
    
    Usage:
        from aiges.graph_builder import build_aiges_graph
        
        graph = build_aiges_graph(
            cast=True, drift=True, forge=True, trace=True
        )
        result = graph.invoke(initial_state)
        
        # Defense report is embedded in the result state:
        aiges_report = result["aiges_active_alerts"]
        threat_level = result["aiges_threat_level"]
"""

from __future__ import annotations
import sys
import os
import operator
from pathlib import Path
from typing import Any, TypedDict, Annotated

from .middleware.aiges_middleware import AIGESMiddleware
from .core.defense_state import make_initial_defense_state


# ─────────────────────────────────────────────────────────────────────────────
# Demo graph state schema (module-level so get_type_hints can resolve Annotated)
# ─────────────────────────────────────────────────────────────────────────────

class DemoState(TypedDict, total=False):
    """
    State schema for the standalone AIGES demo graph.
    
    Reducer notes:
      - operator.add on `list` fields means new agent returns are *appended*
        rather than replacing the prior list. Used for fields where every
        node may contribute new entries.
      - Fields without Annotated default to LastValue semantics: the most
        recent writer wins. Used for fields where each AIGES module returns
        its complete current list/dict (e.g., causal_edges from CAST).
    """
    user_query: str
    messages: Annotated[list, operator.add]      # delta append
    logs: Annotated[list, operator.add]          # delta append
    current_task: str
    orchestrator_plan: str
    auth_status: str
    data_payload: dict
    final_response: str

    aiges_step: int
    aiges_threat_level: str
    aiges_response_taken: str
    aiges_active_alerts: Annotated[list, operator.add]
    causal_edges: list                           # full list from CAST module
    causal_chain: dict
    cast_step_count: int
    cast_risk_per_message: dict
    infection_vectors: dict
    drift_quarantine_list: list
    drift_isolation_list: list
    forge_plans: list                            # full list from FORGE module
    forge_divergence_count: int
    forge_last_distance: float
    merkle_chain: Annotated[list, operator.add]  # delta append
    merkle_chain_valid: bool
    trace_secondary_digest: str
    anomaly_detected: bool
    trust_flags: dict
    cast_enabled: bool
    drift_enabled: bool
    forge_enabled: bool
    trace_enabled: bool
    centroids_initialized: bool
    role_centroids: dict


# ─────────────────────────────────────────────────────────────────────────────
# Baseline import helpers
# ─────────────────────────────────────────────────────────────────────────────

def _find_baseline():
    """
    Locate the baseline MAS. Tries multiple paths relative to this file.
    Returns (build_graph_fn, agent_module) or raises ImportError.
    """
    # Search in parent directories
    here = Path(__file__).resolve().parent.parent
    candidates = [
        here / "mas_baseline",
        here.parent / "mas_baseline",
        Path("mas_baseline"),
    ]
    
    for candidate in candidates:
        if candidate.exists():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            try:
                # Try modular structure first
                from graph.builder import build_graph
                return build_graph
            except ImportError:
                pass
            try:
                # Try flat structure
                from graph import build_graph
                return build_graph
            except ImportError:
                pass
    
    raise ImportError(
        "Cannot locate baseline MAS. "
        "Ensure mas_baseline/ is adjacent to aiges/ directory."
    )


# ─────────────────────────────────────────────────────────────────────────────
# AIGES-Protected Graph Builder
# ─────────────────────────────────────────────────────────────────────────────

def build_aiges_graph(
    cast: bool = True,
    drift: bool = True,
    forge: bool = True,
    trace: bool = True,
    verbose: bool = False,
) -> "CompiledGraph":
    """
    Build the AIGES-protected LangGraph graph.
    
    Returns a compiled graph where every node is wrapped by AIGES middleware.
    The graph is functionally identical to the baseline when no attack is active.
    
    Args:
        cast   : enable CAST module (causal injection tracing)
        drift  : enable DRIFT module (infection float tracker)
        forge  : enable FORGE module (shadow orchestrator)
        trace  : enable TRACE module (Merkle audit chain)
        verbose: print AIGES alerts to stdout during execution
    """
    from langgraph.graph import StateGraph, END
    
    # Initialize middleware
    aiges = AIGESMiddleware(
        cast=cast, drift=drift, forge=forge, trace=trace, verbose=verbose
    )
    
    # Try to import baseline agents
    try:
        baseline_build = _find_baseline()
        return _build_with_baseline(aiges, baseline_build, verbose)
    except ImportError:
        # Baseline not found — build standalone AIGES demo graph
        print("[AIGES] Baseline not found. Building standalone demo graph.")
        return _build_standalone_demo(aiges, verbose)


def _build_with_baseline(aiges: AIGESMiddleware, baseline_build, verbose: bool):
    """
    Wraps the baseline graph's agent functions with AIGES middleware.
    The key integration pattern: wrap, don't rewrite.
    """
    # The baseline graph exposes agent functions through its build_graph
    # We rebuild the graph with the same topology but wrapped nodes
    
    from langgraph.graph import StateGraph, END
    
    try:
        # Import baseline agent functions directly
        from agents.user_facing import UserFacingAgent
        from agents.orchestrator import OrchestratorAgent
        from agents.data_manager import DataManagerAgent
        from agents.authorizer import AuthorizerAgent
        from agents.logger import LoggerAgent
        
        # Instantiate agents
        uf = UserFacingAgent()
        orch = OrchestratorAgent()
        dm = DataManagerAgent()
        auth = AuthorizerAgent()
        log = LoggerAgent()
        
        # Import the state type from baseline
        try:
            from core.state import AgentState
        except ImportError:
            AgentState = dict
        
        # Build graph with AIGES-wrapped nodes
        builder = StateGraph(AgentState if AgentState != dict else dict)
        
        builder.add_node("user_facing", aiges.make_wrapped_node("user_facing", uf.process))
        builder.add_node("orchestrator", aiges.make_wrapped_node("orchestrator", orch.process))
        builder.add_node("data_manager", aiges.make_wrapped_node("data_manager", dm.process))
        builder.add_node("authorizer", aiges.make_wrapped_node("authorizer", auth.process))
        builder.add_node("logger", aiges.make_wrapped_node("logger", log.process))
        
        # Same topology as baseline
        builder.set_entry_point("user_facing")
        builder.add_edge("user_facing", "orchestrator")
        builder.add_edge("orchestrator", "authorizer")
        builder.add_edge("authorizer", "orchestrator")
        builder.add_edge("orchestrator", "data_manager")
        builder.add_edge("data_manager", "orchestrator")
        builder.add_edge("orchestrator", "logger")
        builder.add_edge("logger", END)
        
        graph = builder.compile()
        
        # Inject AIGES initializer into invoke
        return AIGESWrappedGraph(graph, aiges, verbose)
    
    except ImportError as e:
        if verbose:
            print(f"[AIGES] Could not import baseline agents ({e}). Using demo mode.")
        return _build_standalone_demo(aiges, verbose)


def _build_standalone_demo(aiges: AIGESMiddleware, verbose: bool) -> "AIGESWrappedGraph":
    """
    Standalone AIGES demo graph when baseline is not available.
    Each agent is a simple function that simulates realistic behavior.
    """
    from langgraph.graph import StateGraph, END
    
    def user_facing_fn(state: dict) -> dict:
        query = state.get("user_query", "")
        new_message = {
            "sender": "user_facing",
            "recipient": "orchestrator",
            "payload": {"content": f"Parsed query: {query}", "task": "process_query"},
            "message_id": f"uf_{state.get('aiges_step', 0)}",
        }
        return {
            "messages": [new_message],
            "current_task": f"process: {query}",
        }
    
    def orchestrator_fn(state: dict) -> dict:
        task = state.get("current_task", "")
        # Build a substantive plan that matches the structure FORGE expects from a safe orchestrator
        plan = (
            f"Parse user request '{task}' to identify the required data and operation. "
            f"Request authorization from the authorizer for the requested data access. "
            f"If approved, query the employee database with proper filters. "
            f"Return the authorized result and log all actions."
        )
        new_message = {
            "sender": "orchestrator",
            "recipient": "authorizer",
            "payload": {"content": plan, "operation": task},
            "message_id": f"orch_{state.get('aiges_step', 0)}",
        }
        return {
            "orchestrator_plan": plan,
            "messages": [new_message],
        }
    
    def authorizer_fn(state: dict) -> dict:
        query = state.get("user_query", "").lower()
        bypass_markers = ["bypass", "ignore", "override", "maintenance mode",
                          "skip", "without authorization", "system override",
                          "admin cmd", "<inject>"]
        if any(m in query for m in bypass_markers):
            auth_status = "denied"
        else:
            auth_status = "approved"
        new_message = {
            "sender": "authorizer",
            "recipient": "orchestrator",
            "payload": {"content": f"Authorization: {auth_status}", "status": auth_status},
            "message_id": f"auth_{state.get('aiges_step', 0)}",
        }
        return {
            "auth_status": auth_status,
            "messages": [new_message],
        }
    
    def data_manager_fn(state: dict) -> dict:
        if state.get("auth_status") == "approved":
            data_payload = {
                "records": [{"name": "Alice", "dept": "Engineering", "salary": "***"}],
                "count": 1,
            }
        else:
            data_payload = {"records": [], "count": 0, "reason": "unauthorized"}
        new_message = {
            "sender": "data_manager",
            "recipient": "orchestrator",
            "payload": {"content": "Data retrieved", "count": data_payload.get("count", 0)},
            "message_id": f"dm_{state.get('aiges_step', 0)}",
        }
        return {
            "data_payload": data_payload,
            "messages": [new_message],
        }
    
    def logger_fn(state: dict) -> dict:
        new_log = {
            "step": state.get("aiges_step", 0),
            "threat_level": state.get("aiges_threat_level", "CLEAN"),
            "alerts": len(state.get("aiges_active_alerts", [])),
            "auth_status": state.get("auth_status", ""),
        }
        final_response = (
            f"Query processed. Auth: {state.get('auth_status', 'N/A')}. "
            f"Records: {state.get('data_payload', {}).get('count', 0)}. "
            f"Threat level: {state.get('aiges_threat_level', 'CLEAN')}."
        )
        return {
            "logs": [new_log],
            "final_response": final_response,
        }
    
    builder = StateGraph(DemoState)
    builder.add_node("user_facing", aiges.make_wrapped_node("user_facing", user_facing_fn))
    builder.add_node("orchestrator", aiges.make_wrapped_node("orchestrator", orchestrator_fn))
    builder.add_node("authorizer", aiges.make_wrapped_node("authorizer", authorizer_fn))
    builder.add_node("data_manager", aiges.make_wrapped_node("data_manager", data_manager_fn))
    builder.add_node("logger", aiges.make_wrapped_node("logger", logger_fn))
    
    # Linear topology — each node visited exactly once per run.
    # This is the demo structure. The real baseline uses a more complex topology
    # via the conditional router; AIGES wrapping is identical in both cases.
    builder.set_entry_point("user_facing")
    builder.add_edge("user_facing", "orchestrator")
    builder.add_edge("orchestrator", "authorizer")
    builder.add_edge("authorizer", "data_manager")
    builder.add_edge("data_manager", "logger")
    builder.add_edge("logger", END)
    
    graph = builder.compile()
    return AIGESWrappedGraph(graph, aiges, verbose)


# ─────────────────────────────────────────────────────────────────────────────
# Thin wrapper that initializes state before invoke
# ─────────────────────────────────────────────────────────────────────────────

class AIGESWrappedGraph:
    """
    Wraps the compiled LangGraph with AIGES initialization logic.
    Handles state setup and defense report generation.
    """
    
    def __init__(self, graph, aiges: AIGESMiddleware, verbose: bool = False):
        self._graph = graph
        self._aiges = aiges
        self.verbose = verbose
    
    def invoke(self, initial_state: dict, **kwargs) -> dict:
        """
        Run the AIGES-protected graph.
        
        Automatically:
        1. Initializes AIGES defense fields
        2. Runs the graph
        3. Embeds full defense report in result
        """
        # Reset for fresh run
        self._aiges.reset()
        
        # Initialize AIGES defense state
        state = self._aiges.initialize(initial_state.copy())
        
        # Run graph
        result = self._graph.invoke(state, **kwargs)
        
        # Verify TRACE chain integrity
        if self._aiges._trace:
            chain_valid, tampered = self._aiges._trace.verify_chain()
            result["merkle_chain_valid"] = chain_valid
            if not chain_valid:
                result["aiges_active_alerts"].append({
                    "module": "TRACE",
                    "severity": "CRITICAL",
                    "message": f"Merkle chain TAMPERED at steps: {tampered}",
                    "tampered_steps": tampered,
                })
                result["aiges_threat_level"] = "CRITICAL"
        
        # Embed full defense report
        result["aiges_defense_report"] = self._aiges.get_defense_report(result)
        
        return result
    
    def stream(self, initial_state: dict, **kwargs):
        """Streaming mode — initializes AIGES then delegates to graph."""
        self._aiges.reset()
        state = self._aiges.initialize(initial_state.copy())
        return self._graph.stream(state, **kwargs)
