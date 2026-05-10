"""
aiges/drift/drift_module.py
============================
DRIFT — Dynamic Runtime Infection Float Tracker

PURPOSE:
    DRIFT maintains a continuous infection score [0.0, 1.0] per agent,
    updated at each message processing step using:
    
    1. BAYESIAN TRUST UPDATE: When CAST flags a message, DRIFT updates
       the sender's infection score using a Bayesian update rule.
    
    2. SEMANTIC DRIFT DETECTION: For each agent, DRIFT maintains a
       role-centroid embedding (baseline semantic center). If an agent's
       message embedding drifts significantly from its centroid, DRIFT
       raises the infection score even if CAST found no explicit markers.
       This catches A2 (propagating) and A3 (orchestrator compromise)
       where the injected content is paraphrased to avoid regex.
    
    3. PROPORTIONAL RESPONSE: Based on the score, DRIFT applies one of:
       - CLEAN [0, 0.4)    : no action
       - SUSPICIOUS [0.4, 0.7) : soft quarantine (messages flagged but passed)
       - COMPROMISED [0.7, 0.85): hard quarantine (messages held for FORGE review)
       - CRITICAL [0.85, 1.0]  : isolation (agent removed from execution graph)

NOVELTY vs SOTA:
    ALL SOTA uses binary classification. The continuous score is novel:
    
    - INFA-GUARD: binary {benign, infected, attack} per turn. No float.
    - AgentSafe: binary permission grant/deny. No gradual escalation.
    - SentinelNet: bottom-k blacklist. Binary in/out.
    - G-Safeguard: binary malicious/benign classifier.
    
    DRIFT's float allows:
    (a) Proportional response — don't nuke an agent for one suspicious message
    (b) Recovery — score decays if no further evidence (infected-but-not-source)
    (c) Trend detection — rising score is more dangerous than same score stable
    
    Semantic drift detection catches rephrased injections that evade CAST's regex,
    addressing the known limitation of pattern-matching defenses.
"""

from __future__ import annotations
import json
import math
from typing import Any
from dataclasses import asdict

try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False

from ..core.defense_state import InfectionVector


# ─────────────────────────────────────────────────────────────────────────────
# Role Semantic Profiles
# These are text descriptions of what each agent SHOULD produce.
# Used to initialize role centroids if no benign traffic is available.
# ─────────────────────────────────────────────────────────────────────────────

ROLE_SEMANTIC_PROFILES = {
    "user_facing": (
        "Parse the user's query, extract intent and entities, "
        "route to orchestrator for processing, return final response to user."
    ),
    "orchestrator": (
        "Coordinate agents to fulfill the request. Plan steps, "
        "delegate to data manager and authorizer, assemble results."
    ),
    "data_manager": (
        "Query the employee database for the requested information. "
        "Return structured data records with proper field names."
    ),
    "authorizer": (
        "Check permissions for the requested operation. "
        "Approve or deny based on the role and resource policies."
    ),
    "logger": (
        "Record the agent interactions and security events. "
        "Write structured audit log entries with timestamps."
    ),
}

# Thresholds for proportional response
SUSPICIOUS_THRESHOLD = 0.40
COMPROMISED_THRESHOLD = 0.70
CRITICAL_THRESHOLD = 0.85

# Semantic drift threshold: cosine distance from role centroid
# Above this = role-inconsistent message = raises infection score
SEMANTIC_DRIFT_THRESHOLD = 0.45


# ─────────────────────────────────────────────────────────────────────────────
# DRIFT Core
# ─────────────────────────────────────────────────────────────────────────────

class DRIFT:
    """
    Dynamic Runtime Infection Float Tracker.
    
    One instance per graph run. Called by AIGES middleware after CAST.
    """
    
    def __init__(self, use_embeddings: bool = True):
        """
        Args:
            use_embeddings: if True and sentence-transformers available,
                            uses semantic drift. If False, Bayesian-only.
        """
        self.use_embeddings = use_embeddings and EMBEDDINGS_AVAILABLE
        self._encoder = None
        self._centroids: dict[str, Any] = {}  # {agent_name: np.array}
        self._centroids_initialized = False
        self._infection_vectors: dict[str, InfectionVector] = {}
        self._step = 0
        
        agents = ["user_facing", "orchestrator", "data_manager", "authorizer", "logger"]
        for a in agents:
            self._infection_vectors[a] = InfectionVector()
    
    def initialize_centroids(self) -> None:
        """
        Build role centroids from ROLE_SEMANTIC_PROFILES.
        Called once at graph start, before any messages flow.
        
        In a production deployment this would be built from a corpus
        of benign traffic. For research/demo we use the role profiles.
        """
        if not self.use_embeddings:
            self._centroids_initialized = True
            return
        
        if self._encoder is None:
            # Use lightweight model — fast enough for real-time interception
            try:
                self._encoder = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception:
                self.use_embeddings = False
                self._centroids_initialized = True
                return
        
        import numpy as np
        for agent, profile in ROLE_SEMANTIC_PROFILES.items():
            self._centroids[agent] = self._encoder.encode(profile)
        
        self._centroids_initialized = True
    
    # ── Main entry point ─────────────────────────────────────────────────────
    
    def update(
        self,
        agent: str,
        message_content: str,
        cast_risk: float,
        cast_detected_injection: bool,
        step: int,
    ) -> tuple[InfectionVector, str, str]:
        """
        Update the infection vector for an agent after a message event.
        
        Returns:
            (updated_infection_vector, threat_level_str, response_action)
        
        Called by AIGES middleware for the SENDER of each message.
        """
        self._step = step
        iv = self._infection_vectors.get(agent, InfectionVector())
        
        # Apply temporal decay first
        iv.decay(step)
        
        # ── Step 1: Bayesian update from CAST ────────────────────────────────
        if cast_detected_injection:
            # High likelihood — CAST found explicit markers
            likelihood = min(1.0, cast_risk * 1.2)
            iv.bayesian_update(likelihood, step)
            iv.evidence.append({
                "step": step, "source": "CAST",
                "type": "injection_marker", "risk": cast_risk
            })
        elif cast_risk > 0.20:
            # Moderate risk — update with lower likelihood
            iv.bayesian_update(cast_risk * 0.5, step)
            iv.evidence.append({
                "step": step, "source": "CAST",
                "type": "elevated_risk", "risk": cast_risk
            })
        
        # ── Step 2: Semantic drift check ─────────────────────────────────────
        if self.use_embeddings and self._centroids_initialized:
            drift_score = self._compute_semantic_drift(agent, message_content)
            if drift_score > SEMANTIC_DRIFT_THRESHOLD:
                # Message content is semantically inconsistent with this agent's role
                # This catches paraphrased injections that evade CAST's regex
                semantic_likelihood = min(0.9, drift_score * 0.8)
                iv.bayesian_update(semantic_likelihood, step)
                iv.evidence.append({
                    "step": step, "source": "DRIFT",
                    "type": "semantic_drift", "drift": round(drift_score, 4)
                })
        
        # Store updated vector
        self._infection_vectors[agent] = iv
        
        # ── Step 3: Determine threat level and response ───────────────────────
        threat_level, response = self._assess_threat(iv)
        
        return iv, threat_level, response
    
    def get_infection_score(self, agent: str) -> float:
        """Returns current infection score for an agent."""
        return self._infection_vectors.get(agent, InfectionVector()).score
    
    def get_all_scores(self) -> dict[str, float]:
        """Returns {agent: score} for all agents."""
        return {a: iv.score for a, iv in self._infection_vectors.items()}
    
    def get_quarantine_list(self) -> list[str]:
        """Returns agents in soft quarantine (SUSPICIOUS level)."""
        return [
            a for a, iv in self._infection_vectors.items()
            if SUSPICIOUS_THRESHOLD <= iv.score < COMPROMISED_THRESHOLD
        ]
    
    def get_isolation_list(self) -> list[str]:
        """Returns agents at CRITICAL level — hard isolated."""
        return [
            a for a, iv in self._infection_vectors.items()
            if iv.score >= CRITICAL_THRESHOLD
        ]
    
    def get_state_update(self) -> dict:
        """Returns serializable state fields for AIGES defense state."""
        return {
            "infection_vectors": {
                a: asdict(iv) for a, iv in self._infection_vectors.items()
            },
            "drift_quarantine_list": self.get_quarantine_list(),
            "drift_isolation_list": self.get_isolation_list(),
            "centroids_initialized": self._centroids_initialized,
        }
    
    # ── Internal helpers ──────────────────────────────────────────────────────
    
    def _compute_semantic_drift(self, agent: str, content: str) -> float:
        """
        Compute cosine distance between message embedding and role centroid.
        
        Distance 0.0 = perfectly on-role
        Distance 1.0 = completely role-inconsistent
        
        This is a deterministic math operation — no LLM reasoning.
        The encoder is frozen (no fine-tuning), so it cannot be
        manipulated by input content.
        """
        if agent not in self._centroids:
            return 0.0
        if not content or len(content.strip()) < 10:
            return 0.0
        
        import numpy as np
        
        try:
            msg_embedding = self._encoder.encode(content)
            centroid = self._centroids[agent]
            
            # Cosine similarity → distance
            dot = np.dot(msg_embedding, centroid)
            norm_msg = np.linalg.norm(msg_embedding)
            norm_cen = np.linalg.norm(centroid)
            
            if norm_msg == 0 or norm_cen == 0:
                return 0.0
            
            cosine_sim = dot / (norm_msg * norm_cen)
            cosine_dist = 1.0 - cosine_sim
            return float(round(cosine_dist, 4))
        except Exception:
            return 0.0
    
    def _assess_threat(self, iv: InfectionVector) -> tuple[str, str]:
        """
        Map infection score to threat level string and response action.
        
        Returns (threat_level, response_action)
        """
        s = iv.score
        
        if s >= CRITICAL_THRESHOLD:
            return "CRITICAL", "isolate"
        elif s >= COMPROMISED_THRESHOLD:
            # Rising trend makes this more dangerous
            if iv.trend == "rising":
                return "CRITICAL", "isolate"
            return "COMPROMISED", "quarantine"
        elif s >= SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS", "flag"
        else:
            return "CLEAN", "none"
    
    def reset(self) -> None:
        """Reset for a new graph run."""
        agents = ["user_facing", "orchestrator", "data_manager", "authorizer", "logger"]
        self._infection_vectors = {a: InfectionVector() for a in agents}
        self._step = 0
