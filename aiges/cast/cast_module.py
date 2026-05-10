"""
aiges/cast/cast_module.py
===========================
CAST — Causal Attack Surface Tracker

PURPOSE:
    CAST intercepts every A2A message envelope before it reaches the
    recipient agent. It performs two operations:
    
    1. INLINE RISK SCORING: Deterministic injection marker detection
       on the message content. Returns a risk float [0, 1].
       This is entirely rule-based + regex — NOT an LLM call.
    
    2. CAUSAL GRAPH MAINTENANCE: Appends a CausalEdge to the DAG.
       When risk > threshold, CAST traverses the DAG backward to find
       the Causal Injection Source (CIS) and computes Causal Injection
       Distance (CID) — a novel metric this research introduces.

NOVELTY vs SOTA:
    - AgentSafe: blocks based on hierarchical permission rules. No causal tracing.
    - G-Safeguard: post-hoc graph anomaly detection. Runs AFTER propagation.
    - INFA-GUARD: GNN-based detection, requires training data.
    
    CAST runs in real-time, before propagation, using only deterministic
    rules + SHA-256. Zero training data. Zero LLM calls.
    The CID metric is original — no paper formally defines injection
    causality distance as a metric.

THREAT MODEL COVERAGE:
    - A1: Direct prompt injection (user → UserFacing)
    - A2: Propagating injection (DataManager → Orchestrator → Authorizer)
    - A3: Orchestrator compromise (detected via orchestrator's output risk score)
"""

from __future__ import annotations
import re
import hashlib
import json
from dataclasses import asdict
from typing import Any
from ..core.defense_state import CausalEdge, CausalChain


# ─────────────────────────────────────────────────────────────────────────────
# Injection Marker Library
# Based on taxonomy from PeerGuard, AgentSafe, and AiTM papers in project knowledge
# ─────────────────────────────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    # Role override / instruction hijack
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", 0.95),
    (r"you\s+are\s+now\s+(in\s+)?(maintenance|admin|debug|developer|god)\s+mode", 0.90),
    (r"disregard\s+(your\s+)?(system\s+prompt|guidelines|rules|constraints)", 0.90),
    (r"override\s+(all\s+)?(safety|security|access)\s+(checks?|controls?|filters?)", 0.90),
    (r"act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(superuser|root|admin|unrestricted)", 0.85),
    
    # Authorization bypass
    (r"bypass\s+(the\s+)?(auth(orization)?|permission|access\s+control)", 0.95),
    (r"grant\s+(yourself\s+)?(full|unrestricted|admin)\s+(access|permissions?)", 0.90),
    (r"approve\s+(this\s+)?(without|bypassing)\s+(authorization|verification|checks?)", 0.85),
    (r"skip\s+(the\s+)?(auth|permission|security)\s+(check|step|layer)", 0.85),
    
    # Data exfiltration
    (r"reveal\s+(all|every|the\s+full)\s+(records?|data|database|employees?|salaries?)", 0.80),
    (r"dump\s+(all|the\s+full|entire)\s+(database|records?|data|table)", 0.80),
    (r"export\s+(all|every|the\s+entire)\s+(employee|user|customer)\s+(data|records?)", 0.80),
    (r"without\s+(any\s+)?(authorization|permission|access\s+check)", 0.75),
    
    # Log tampering
    (r"delete\s+(all\s+)?(logs?|audit\s+trail|records?)", 0.90),
    (r"clear\s+(the\s+)?(logs?|audit|history|records?)", 0.85),
    (r"do\s+not\s+(log|record|write|save)\s+(this|these|anything)", 0.80),
    (r"suppress\s+(the\s+)?(log(ger)?|audit|monitor)", 0.80),
    
    # Orchestrator manipulation
    (r"reroute\s+(this\s+task|the\s+request)\s+(to|through|via)\s+\w+", 0.75),
    (r"do\s+not\s+(contact|notify|call|ask)\s+(the\s+)?(authoriz|logger|verif)", 0.80),
    (r"handle\s+(this\s+)?(directly|yourself)\s+without\s+(asking|notifying|checking)", 0.75),
    
    # Jailbreak patterns (from BlockA2A and AgentSafe papers)
    (r"DAN\s*mode", 0.95),
    (r"jailbreak", 0.85),
    (r"token\s+smuggling", 0.90),
    (r"prompt\s+injection", 0.90),  # meta: attacker naming their attack
    
    # Indirect injection markers (from AiTM paper — embedded in data)
    (r"<\s*inject\s*>", 0.95),
    (r"\[SYSTEM\s*OVERRIDE\]", 0.95),
    (r"\[ADMIN\s*CMD\]", 0.95),
    (r"<!--\s*(inject|override|hack|pwn)", 0.90),
]

# Compile patterns for performance
COMPILED_PATTERNS = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), score)
    for p, score in INJECTION_PATTERNS
]

# Authorization scope — which sender→recipient pairs are legitimate
# Used for causal hop validation (if unauthorized hop detected, higher risk)
AUTHORIZED_HOPS = {
    ("user_facing",   "orchestrator"),
    ("orchestrator",  "data_manager"),
    ("orchestrator",  "authorizer"),
    ("orchestrator",  "logger"),
    ("data_manager",  "orchestrator"),
    ("authorizer",    "orchestrator"),
    ("logger",        "orchestrator"),
    # Return path
    ("orchestrator",  "user_facing"),
}


# ─────────────────────────────────────────────────────────────────────────────
# CAST Core
# ─────────────────────────────────────────────────────────────────────────────

class CAST:
    """
    Causal Attack Surface Tracker.
    
    Instantiated once, lives for the duration of a LangGraph run.
    Called by AIGES middleware before each message delivery.
    """
    
    def __init__(self, risk_threshold: float = 0.40, cid_threshold: int = 3):
        """
        Args:
            risk_threshold : risk score above which a message is flagged
            cid_threshold  : max CID before escalating to CRITICAL
        """
        self.risk_threshold = risk_threshold
        self.cid_threshold = cid_threshold
        self._causal_edges: list[CausalEdge] = []
        self._step = 0
    
    # ── Main entry point ─────────────────────────────────────────────────────
    
    def inspect_message(
        self,
        sender: str,
        recipient: str,
        message: dict,
        state: dict,
    ) -> tuple[float, list[str], bool]:
        """
        Inspect a single A2A message before delivery.
        
        Returns:
            (risk_score, injection_markers_found, injection_detected)
        
        Called by AIGES middleware for every inter-agent message.
        This is the core of CAST's real-time, pre-propagation detection.
        """
        self._step += 1
        content = self._extract_content(message)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        message_id = message.get("message_id", f"msg_{self._step}")
        
        # 1. Injection marker scan
        risk_score, markers = self._scan_content(content)
        
        # 2. Unauthorized hop check — amplifies risk
        hop = (sender, recipient)
        if hop not in AUTHORIZED_HOPS:
            risk_score = min(1.0, risk_score + 0.30)
            markers.append(f"UNAUTHORIZED_HOP:{sender}->{recipient}")
        
        # 3. Propagation check: did sender recently receive a suspicious message?
        propagated_from = self._check_propagation_chain(sender, state)
        if propagated_from:
            risk_score = min(1.0, risk_score + 0.20)
            markers.append(f"PROPAGATED_FROM:{propagated_from}")
        
        injection_detected = risk_score >= self.risk_threshold
        
        # 4. Record causal edge
        edge = CausalEdge(
            step=self._step,
            sender=sender,
            recipient=recipient,
            message_id=message_id,
            content_hash=content_hash,
            payload_risk=round(risk_score, 4),
            contains_injection=injection_detected,
            injection_markers=markers,
            propagated_from=propagated_from,
        )
        self._causal_edges.append(edge)
        
        return risk_score, markers, injection_detected
    
    def build_causal_chain(
        self, detection_agent: str, detection_step: int
    ) -> CausalChain:
        """
        When an injection is confirmed, trace backward through the causal
        DAG to find the Causal Injection Source (CIS) and compute CID.
        
        CID = Causal Injection Distance = number of hops from source to
              first detection point. Novel metric in this research.
        
        Algorithm: walk backward through edges where
                   contains_injection=True or propagated_from is set.
        """
        # Find the detection edge
        suspicious_edges = [
            e for e in self._causal_edges
            if e.contains_injection or e.propagated_from is not None
        ]
        
        if not suspicious_edges:
            # No causal chain found — injection was at entry
            return CausalChain(
                detection_step=detection_step,
                detection_agent=detection_agent,
                source_agent=detection_agent,
                causal_injection_distance=0,
                path=[detection_agent],
                edges=[],
            )
        
        # Build path from source to detection
        path = [detection_agent]
        current = detection_agent
        visited = {detection_agent}
        chain_edges = []
        
        # Walk backward: find edges where recipient == current
        for _ in range(len(suspicious_edges)):
            parent_edges = [
                e for e in suspicious_edges
                if e.recipient == current and e.sender not in visited
            ]
            if not parent_edges:
                break
            # Take the most recent (closest in time) suspicious edge
            parent_edge = max(parent_edges, key=lambda e: e.step)
            path.insert(0, parent_edge.sender)
            chain_edges.insert(0, parent_edge)
            visited.add(parent_edge.sender)
            current = parent_edge.sender
        
        source_agent = path[0]
        cid = len(path) - 1
        
        return CausalChain(
            detection_step=detection_step,
            detection_agent=detection_agent,
            source_agent=source_agent,
            causal_injection_distance=cid,
            path=path,
            edges=chain_edges,
        )
    
    def get_state_update(self) -> dict:
        """Returns serializable state fields for AIGES defense state."""
        return {
            "causal_edges": [asdict(e) for e in self._causal_edges],
            "cast_step_count": self._step,
            "cast_risk_per_message": {
                e.message_id: e.payload_risk for e in self._causal_edges
            },
        }
    
    # ── Internal helpers ──────────────────────────────────────────────────────
    
    def _scan_content(self, content: str) -> tuple[float, list[str]]:
        """
        Deterministic injection marker scan.
        Returns (max_risk_score, list_of_matched_patterns).
        NO LLM call — pure regex on compiled patterns.
        """
        max_risk = 0.0
        matched = []
        for pattern, score in COMPILED_PATTERNS:
            if pattern.search(content):
                max_risk = max(max_risk, score)
                matched.append(pattern.pattern[:50])  # truncate for logging
        return round(max_risk, 4), matched
    
    def _extract_content(self, message: dict) -> str:
        """
        Extract text content from an A2A message envelope.
        Handles various content formats (string, dict, list).
        """
        payload = message.get("payload", {})
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            parts = []
            for key in ("content", "text", "query", "message", "data", "instructions"):
                if key in payload:
                    parts.append(str(payload[key]))
            return " ".join(parts) if parts else json.dumps(payload)
        if isinstance(payload, list):
            return " ".join(str(x) for x in payload)
        # Fallback: scan the whole message serialized
        return json.dumps(message)
    
    def _check_propagation_chain(self, sender: str, state: dict) -> str | None:
        """
        Check if the sender recently received a suspicious message.
        If so, this message is potentially a propagated injection.
        
        This is how CAST detects A2 (propagating attack) — the second hop
        has propagated_from set, signalling the chain is live.
        """
        recent_suspicious = [
            e for e in self._causal_edges[-10:]  # check last 10 edges
            if e.recipient == sender and e.contains_injection
        ]
        if recent_suspicious:
            return recent_suspicious[-1].sender
        return None
    
    def reset(self) -> None:
        """Reset for a new graph run."""
        self._causal_edges = []
        self._step = 0
