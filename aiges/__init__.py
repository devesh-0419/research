"""
AIGES — Adaptive Infection-Graph Enhanced Security

A novel, real-time, LLM-free defense framework for LangGraph-based MAS,
defending against A1 (prompt injection), A2 (propagation), A3 (orchestrator compromise).

Four cooperating modules:
    CAST  — Causal Attack Surface Tracker
    DRIFT — Dynamic Runtime Infection Float Tracker
    FORGE — FOol-proof Runtime Guard Engine (shadow orchestrator)
    TRACE — Tamper-Resistant Audit Chain Engine (Merkle log)

Usage:
    from aiges import build_aiges_graph
    graph = build_aiges_graph(cast=True, drift=True, forge=True, trace=True)
    result = graph.invoke({"user_query": "..."})
"""

from .graph_builder import build_aiges_graph, AIGESWrappedGraph
from .middleware.aiges_middleware import AIGESMiddleware
from .core.defense_state import (
    InfectionVector, CausalEdge, CausalChain, MerkleNode, ForgePlan,
    make_initial_defense_state,
)
from .cast.cast_module import CAST
from .drift.drift_module import DRIFT
from .forge.forge_module import FORGE
from .trace.trace_module import TRACE

__version__ = "0.1.0"
