"""
graph.py
========
LangGraph graph definition for the 5-agent MAS baseline.

Graph topology:
  START
    → user_facing_node          (UserFacingAgent: parse + wrap query)
    → orchestrator_node         (OrchestratorAgent: build plan, emit A2A msgs)
    → authorizer_node           (AuthorizerAgent: policy check via MCP)
    → data_manager_node         (DataManagerAgent: data ops via MCP)
    → logger_node               (LoggerAgent: audit + baseline anomaly check)
    → orchestrator_assemble_node (OrchestratorAgent: assemble final response)
    → user_facing_respond_node  (UserFacingAgent: return to user)
    → END

Notes:
  - AuthorizerAgent and DataManagerAgent run sequentially (auth first)
  - LoggerAgent taps the state after data + auth complete
  - All inter-agent communication is via state["messages"] (A2A envelopes)
  - The graph is intentionally simple in Phase 1 so attack injections
    in Phase 2 are clearly attributable to the security layer, not topology
"""

from __future__ import annotations
from langgraph.graph import StateGraph, START, END

from research.mas_baseline.core.state import AgentState
from research.mas_baseline.agents.user_facing   import user_facing_agent, user_facing_respond
from research.mas_baseline.agents.orchestrator  import orchestrator_agent, orchestrator_assemble
from research.mas_baseline.agents.data_manager  import data_manager_agent
from research.mas_baseline.agents.authorizer    import authorizer_agent
from research.mas_baseline.agents.logger_agent  import logger_agent


def build_graph() -> StateGraph:
    """
    Construct and compile the 5-agent MAS graph.
    Returns a compiled LangGraph StateGraph ready for invocation.
    """
    builder = StateGraph(AgentState)

    # ── register nodes ────────────────────────────────────────────────────────
    builder.add_node("user_facing",           user_facing_agent)
    builder.add_node("orchestrator",          orchestrator_agent)
    builder.add_node("authorizer",            authorizer_agent)
    builder.add_node("data_manager",          data_manager_agent)
    builder.add_node("logger",                logger_agent)
    builder.add_node("orchestrator_assemble", orchestrator_assemble)
    builder.add_node("user_facing_respond",   user_facing_respond)

    # ── define edges ──────────────────────────────────────────────────────────
    builder.add_edge(START,                   "user_facing")
    builder.add_edge("user_facing",           "orchestrator")
    builder.add_edge("orchestrator",          "authorizer")
    builder.add_edge("authorizer",            "data_manager")
    builder.add_edge("data_manager",          "logger")
    builder.add_edge("logger",                "orchestrator_assemble")
    builder.add_edge("orchestrator_assemble", "user_facing_respond")
    builder.add_edge("user_facing_respond",   END)

    return builder.compile()


# ── convenience: expose a singleton graph ────────────────────────────────────
_graph = None

def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph
