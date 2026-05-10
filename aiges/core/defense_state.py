"""
aiges/core/defense_state.py
============================
AIGES — Adaptive Infection-Graph Enhanced Security

Defense-augmented state schema. Extends the baseline AgentState with
security-tracking fields used across all four AIGES modules:
  - CAST  (Causal Attack Surface Tracker)
  - DRIFT (Dynamic Runtime Infection Float Tracker)
  - FORGE (FOol-proof Runtime Guard Engine — shadow orchestrator)
  - TRACE (Tamper-Resistant Audit Chain Engine — Merkle log)

DESIGN PRINCIPLE (from research plan):
    Detection is entirely LLM-free. All detection is deterministic:
    graph reachability (CAST), Bayesian + cosine math (DRIFT),
    embedding distance (FORGE), SHA-256 (TRACE).
    LLMs are used only in FORGE's shadow planning, isolated from the
    main context, and cannot change detection decisions already made.

    This makes AIGES immune to the same semantic manipulation used
    to attack the system — a property that distinguishes it from
    AgentSafe, G-Safeguard, and SentinelNet.
"""

from __future__ import annotations
from typing import TypedDict, Annotated, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import operator


# ─────────────────────────────────────────────────────────────────────────────
# Infection level type (the "float" in DRIFT — the key novelty over INFA-GUARD)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InfectionVector:
    """
    Continuous infection score per agent.
    
    NOVELTY vs SOTA:
        - INFA-GUARD: binary {benign, infected, attack}
        - AgentSafe: binary {benign, malicious}
        - SentinelNet: binary {in blacklist, not in blacklist}
        
        AIGES uses a float in [0, 1] per agent, updated each step via
        Bayesian update rule. This captures the *degree* of compromise,
        enabling proportional response (soft quarantine vs hard isolation)
        rather than binary switch-off.
    
    Fields:
        score       : float in [0.0, 1.0]. 0=clean, 1=confirmed attacker.
        trend       : "rising" | "stable" | "falling"
        last_updated: step count when last updated
        update_count: number of updates since initialization
        evidence    : list of evidence items (from which module, what type)
    """
    score: float = 0.0
    trend: str = "stable"      # "rising" | "stable" | "falling"
    last_updated: int = 0
    update_count: int = 0
    evidence: list = field(default_factory=list)
    
    def is_suspicious(self, threshold: float = 0.4) -> bool:
        return self.score >= threshold
    
    def is_compromised(self, threshold: float = 0.7) -> bool:
        return self.score >= threshold
    
    def bayesian_update(self, likelihood_malicious: float, step: int) -> None:
        """
        Bayesian update: P(malicious|evidence) ∝ P(evidence|malicious) × P(malicious)
        
        With decay factor: older evidence decays, preventing false long-term isolation.
        
        DECAY: score decays toward 0 over time if no new evidence.
        This allows recovery of a TEMPORARILY infected agent — a property
        INFA-GUARD achieves through LLM remediation, but AIGES achieves
        deterministically via score decay.
        """
        prior = self.score
        # Bayesian update
        posterior = (likelihood_malicious * prior + likelihood_malicious * (1 - prior) * 0.3)
        posterior = min(1.0, posterior)
        
        # Track trend
        if posterior > prior + 0.05:
            self.trend = "rising"
        elif posterior < prior - 0.05:
            self.trend = "falling"
        else:
            self.trend = "stable"
        
        self.score = round(posterior, 4)
        self.last_updated = step
        self.update_count += 1
    
    def decay(self, current_step: int, decay_rate: float = 0.05) -> None:
        """Apply temporal decay — reduces false positives over time."""
        steps_since_update = current_step - self.last_updated
        if steps_since_update > 2:
            decay_amount = decay_rate * (steps_since_update - 2)
            self.score = max(0.0, round(self.score - decay_amount, 4))
            if self.score < 0.1:
                self.trend = "falling"


# ─────────────────────────────────────────────────────────────────────────────
# CAST: Causal edge record (who sent what to whom, causal chain)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CausalEdge:
    """
    Records a single message passing event for causal graph construction.
    
    CAST builds a DAG of all message flows. When an anomaly is detected,
    CAST traces backward through this DAG to find the origin — the Causal
    Injection Source (CIS). This is the "Causal Injection Distance" metric
    in the research: how many hops from origin to detection point.
    """
    step: int
    sender: str
    recipient: str
    message_id: str
    content_hash: str       # SHA-256 of message content
    payload_risk: float     # CAST's inline risk score [0,1]
    contains_injection: bool
    injection_markers: list = field(default_factory=list)
    propagated_from: str | None = None  # which prior message caused this


@dataclass
class CausalChain:
    """
    Full causal chain for one detected injection.
    Constructed by CAST when anomaly_detected fires.
    """
    detection_step: int
    detection_agent: str
    source_agent: str           # CIS: Causal Injection Source
    causal_injection_distance: int  # hops from source to detection
    path: list[str]             # [source_agent, ..., detection_agent]
    edges: list[CausalEdge] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# TRACE: Merkle chain node
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MerkleNode:
    """
    Single node in the TRACE Merkle chain.
    
    NOVELTY vs BlockA2A:
        BlockA2A uses full blockchain infrastructure for tamper-evidence.
        TRACE achieves the same property using only in-process SHA-256
        chaining — zero external infrastructure, same tamper-evidence
        guarantee for the purpose of forensic audit.
    
    Tamper-evidence property:
        Any modification to node N invalidates the hash of N+1,
        which invalidates N+2, ... , which invalidates the chain head.
        A compromised orchestrator CANNOT silently alter past logs
        because the chain head hash would change.
    """
    step: int
    agent: str
    action: str
    data_hash: str          # SHA-256 of the state snapshot at this step
    prev_hash: str          # hash of previous MerkleNode
    node_hash: str          # SHA-256(step + agent + action + data_hash + prev_hash)
    timestamp: str
    defense_flags: dict = field(default_factory=dict)  # flags from CAST/DRIFT/FORGE
    
    @staticmethod
    def compute_hash(step: int, agent: str, action: str,
                     data_hash: str, prev_hash: str) -> str:
        content = f"{step}|{agent}|{action}|{data_hash}|{prev_hash}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def verify(self) -> bool:
        expected = MerkleNode.compute_hash(
            self.step, self.agent, self.action, self.data_hash, self.prev_hash
        )
        return self.node_hash == expected


# ─────────────────────────────────────────────────────────────────────────────
# FORGE: Shadow plan record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ForgePlan:
    """
    FORGE generates an independent "shadow" orchestration plan from the
    same task description, using an isolated LLM context that has never
    seen the main conversation (preventing context poisoning).
    
    If the main orchestrator's plan diverges significantly from the shadow
    plan (measured by cosine distance on plan embeddings), FORGE flags it.
    
    NOVELTY:
        No prior work applies shadow-plan divergence detection to
        LangGraph-native orchestrator compromise scenarios.
        PeerGuard uses peer cross-verification but requires multiple
        agent opinions. FORGE requires only one shadow plan and uses
        a deterministic distance metric — the LLM cannot argue with
        a number.
    """
    step: int
    task_description: str
    main_plan: str          # what the real orchestrator decided
    shadow_plan: str        # what FORGE's isolated LLM generated
    plan_embedding_distance: float  # cosine distance [0, 1]
    divergence_detected: bool
    divergence_reason: str = ""
    risk_actions_main: list = field(default_factory=list)   # risky actions in main
    risk_actions_shadow: list = field(default_factory=list) # risky actions in shadow


# ─────────────────────────────────────────────────────────────────────────────
# AIGES Defense State (merged into AgentState via TypedDict extension)
# ─────────────────────────────────────────────────────────────────────────────

class AIGESDefenseState(TypedDict, total=False):
    """
    Defense-layer fields injected into the base AgentState.
    
    Because Python TypedDicts support inheritance, the full runtime state is:
        AgentState + AIGESDefenseState
    
    This means zero rewiring of the baseline graph. AIGES middleware reads
    and writes only these fields; baseline agent code is never modified.
    """
    
    # ── CAST fields ──────────────────────────────────────────────────────────
    cast_enabled: bool
    causal_edges: list           # list[CausalEdge] serialized as dicts
    causal_chain: dict | None    # CausalChain serialized if injection found
    cast_risk_per_message: dict  # {message_id: float} — per-message risk
    cast_step_count: int         # increments each time a message is processed
    
    # ── DRIFT fields ─────────────────────────────────────────────────────────
    drift_enabled: bool
    infection_vectors: dict      # {agent_name: InfectionVector} serialized as dict
    drift_quarantine_list: list  # agents currently in soft quarantine
    drift_isolation_list: list   # agents currently hard-isolated (score > 0.85)
    role_centroids: dict         # {role: embedding_centroid} — baseline semantic center
    centroids_initialized: bool
    
    # ── FORGE fields ─────────────────────────────────────────────────────────
    forge_enabled: bool
    forge_plans: list            # list[ForgePlan] serialized as dicts
    forge_divergence_count: int  # cumulative divergences detected
    forge_last_distance: float   # most recent plan embedding distance
    
    # ── TRACE fields ─────────────────────────────────────────────────────────
    trace_enabled: bool
    merkle_chain: list           # list[MerkleNode] serialized as dicts
    merkle_chain_valid: bool     # result of last full chain verification
    trace_secondary_digest: str  # out-of-band hash the orchestrator cannot touch
    
    # ── Unified defense verdict ───────────────────────────────────────────────
    aiges_threat_level: str      # "CLEAN" | "SUSPICIOUS" | "COMPROMISED" | "CRITICAL"
    aiges_active_alerts: list    # list of alert dicts with {module, severity, message}
    aiges_response_taken: str    # what AIGES did: "none"|"logged"|"quarantine"|"isolate"|"halt"
    aiges_step: int              # global AIGES step counter


def make_initial_defense_state(
    cast: bool = True,
    drift: bool = True,
    forge: bool = True,
    trace: bool = True,
) -> AIGESDefenseState:
    """Returns an initialized AIGES defense state with all modules configured."""
    agents = ["user_facing", "orchestrator", "data_manager", "authorizer", "logger"]
    infection_vectors = {
        a: {"score": 0.0, "trend": "stable", "last_updated": 0,
            "update_count": 0, "evidence": []}
        for a in agents
    }
    return AIGESDefenseState(
        cast_enabled=cast,
        causal_edges=[],
        causal_chain=None,
        cast_risk_per_message={},
        cast_step_count=0,
        
        drift_enabled=drift,
        infection_vectors=infection_vectors,
        drift_quarantine_list=[],
        drift_isolation_list=[],
        role_centroids={},
        centroids_initialized=False,
        
        forge_enabled=forge,
        forge_plans=[],
        forge_divergence_count=0,
        forge_last_distance=0.0,
        
        trace_enabled=trace,
        merkle_chain=[],
        merkle_chain_valid=True,
        trace_secondary_digest="",
        
        aiges_threat_level="CLEAN",
        aiges_active_alerts=[],
        aiges_response_taken="none",
        aiges_step=0,
    )
