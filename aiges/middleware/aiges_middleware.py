"""
aiges/middleware/aiges_middleware.py
=====================================
AIGES Middleware — Central Coordinator

PURPOSE:
    The middleware is the single insertion point between every pair of
    LangGraph agents. It:
    
    1. Intercepts the A2A message BEFORE delivery
    2. Calls CAST (risk score + causal graph)
    3. Calls DRIFT (Bayesian infection update + semantic drift)
    4. Calls FORGE (shadow plan divergence) when orchestrator speaks
    5. Calls TRACE (append Merkle node)
    6. Determines unified threat level
    7. Applies response (log / quarantine / isolate / halt)
    8. Updates AIGES defense state fields
    
    ZERO REWIRING: The middleware wraps agent .process() calls via a
    decorator pattern. The baseline agent code is never modified.

INTEGRATION PATTERN:
    Instead of:
        result = orchestrator_agent.process(state)
    
    The graph builder (when AIGES is enabled) does:
        result = aiges.wrap(orchestrator_agent, "orchestrator").process(state)
    
    The middleware is transparent on clean runs — no performance impact
    until a threat is detected.

RESPONSE POLICY:
    CLEAN      → pass through, log silently
    SUSPICIOUS → pass through with flag, alert in aiges_active_alerts
    COMPROMISED→ hold message for FORGE review; if FORGE confirms: block
    CRITICAL   → halt agent, isolate from graph, generate CRITICAL alert
"""

from __future__ import annotations
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from ..core.defense_state import make_initial_defense_state
from ..cast.cast_module import CAST
from ..drift.drift_module import DRIFT
from ..forge.forge_module import FORGE
from ..trace.trace_module import TRACE


# ─────────────────────────────────────────────────────────────────────────────
# Threat level precedence
# ─────────────────────────────────────────────────────────────────────────────

THREAT_PRECEDENCE = {"CLEAN": 0, "SUSPICIOUS": 1, "COMPROMISED": 2, "CRITICAL": 3}


def highest_threat(levels: list[str]) -> str:
    return max(levels, key=lambda l: THREAT_PRECEDENCE.get(l, 0), default="CLEAN")


# ─────────────────────────────────────────────────────────────────────────────
# AIGES Middleware
# ─────────────────────────────────────────────────────────────────────────────

class AIGESMiddleware:
    """
    Central AIGES coordinator. One instance per graph run.
    
    Usage (in graph builder):
        aiges = AIGESMiddleware(cast=True, drift=True, forge=True, trace=True)
        aiges.initialize(state)  # sets up DRIFT centroids
        
        # Then wrap each agent:
        wrapped_orchestrator = aiges.make_wrapped_node("orchestrator", orchestrator_fn)
    """
    
    def __init__(
        self,
        cast: bool = True,
        drift: bool = True,
        forge: bool = True,
        trace: bool = True,
        verbose: bool = False,
    ):
        self.cast_enabled = cast
        self.drift_enabled = drift
        self.forge_enabled = forge
        self.trace_enabled = trace
        self.verbose = verbose
        
        # Module instances
        self._cast = CAST() if cast else None
        self._drift = DRIFT() if drift else None
        self._forge = FORGE() if forge else None
        self._trace = TRACE() if trace else None
        
        self._step = 0
        self._initialized = False
    
    def initialize(self, state: dict) -> dict:
        """
        Initialize AIGES for a new graph run.
        
        - Injects AIGES defense state fields into the base state
        - Initializes DRIFT centroids
        
        Must be called before the first agent execution.
        Returns a NEW dict — does not mutate input.
        """
        result = dict(state)  # copy
        defense_fields = make_initial_defense_state(
            cast=self.cast_enabled,
            drift=self.drift_enabled,
            forge=self.forge_enabled,
            trace=self.trace_enabled,
        )
        
        # Inject defense fields into base state (non-destructive)
        for key, value in defense_fields.items():
            if key not in result:
                result[key] = value
        
        if self._drift and not self._drift._centroids_initialized:
            self._drift.initialize_centroids()
        
        self._initialized = True
        return result
    
    def make_wrapped_node(self, agent_name: str, agent_fn: Callable) -> Callable:
        """
        Returns a wrapped version of an agent node function.
        The wrapped function runs AIGES inspection around the agent call.
        
        This is the zero-rewiring insertion point.
        """
        middleware = self  # capture for closure
        
        def wrapped_node(state: dict) -> dict:
            # Pre-execution: inspect incoming messages
            # _pre_agent reads `state` and returns a dict of AIGES updates
            aiges_pre_updates = middleware._pre_agent(agent_name, state)
            
            # Check if agent is isolated — if so, skip execution
            if agent_name in state.get("drift_isolation_list", []):
                isolation_updates = middleware._handle_isolated_agent(agent_name, state)
                # merge pre and isolation
                merged = {**aiges_pre_updates, **isolation_updates}
                return merged
            
            # Build a working copy of state that includes pre-updates so the
            # agent function sees the latest AIGES context (e.g., aiges_step)
            working_state = dict(state)
            working_state.update(aiges_pre_updates)
            
            # Execute the real agent — it returns only the fields it modifies
            agent_updates = agent_fn(working_state)
            if not isinstance(agent_updates, dict):
                agent_updates = {}
            
            # Build merged updates: AIGES pre-updates + agent updates
            merged_updates = {**aiges_pre_updates, **agent_updates}
            
            # Post-execution: orchestrator FORGE check
            if agent_name == "orchestrator" and middleware.forge_enabled:
                # Merge into a temp state so FORGE can see the orchestrator's plan
                temp_state = {**state, **merged_updates}
                forge_updates = middleware._post_orchestrator(temp_state)
                merged_updates.update(forge_updates)
            
            # Record to TRACE — also returns just the fields it touches
            temp_state = {**state, **merged_updates}
            trace_updates = middleware._record_trace(agent_name, temp_state)
            merged_updates.update(trace_updates)
            
            return merged_updates
        
        return wrapped_node
    
    # ── Pre-agent inspection ──────────────────────────────────────────────────
    
    def _pre_agent(self, agent_name: str, state: dict) -> dict:
        """
        Called BEFORE agent execution.
        Inspects the most recent incoming message to this agent.
        
        Returns a delta dict of AIGES state updates (no mutation of input).
        """
        self._step += 1
        updates: dict = {"aiges_step": self._step}
        
        # Find the most recent message directed to this agent
        messages = state.get("messages", [])
        incoming = None
        for msg in reversed(messages):
            if isinstance(msg, dict):
                recipient = msg.get("recipient") or msg.get("to")
                if recipient == agent_name or (agent_name == "user_facing" and not recipient):
                    incoming = msg
                    break
        
        if incoming is None:
            # No incoming message — just return step update
            return updates
        
        sender = incoming.get("sender") or incoming.get("from_agent", "unknown")
        
        # ── CAST: pre-delivery risk scoring ──────────────────────────────────
        cast_risk = 0.0
        cast_injection = False
        cast_markers = []
        
        if self._cast:
            cast_risk, cast_markers, cast_injection = self._cast.inspect_message(
                sender=sender,
                recipient=agent_name,
                message=incoming,
                state=state,
            )
            updates.update(self._cast.get_state_update())
        
        # ── DRIFT: infection vector update ────────────────────────────────────
        drift_threat = "CLEAN"
        drift_action = "none"
        
        if self._drift:
            content = self._extract_content_from_message(incoming)
            iv, drift_threat, drift_action = self._drift.update(
                agent=sender,
                message_content=content,
                cast_risk=cast_risk,
                cast_detected_injection=cast_injection,
                step=self._step,
            )
            updates.update(self._drift.get_state_update())
        
        # ── Unified threat level ──────────────────────────────────────────────
        threat_level = highest_threat([drift_threat, state.get("aiges_threat_level", "CLEAN")])
        updates["aiges_threat_level"] = threat_level
        
        # ── Generate alert if needed ──────────────────────────────────────────
        new_alerts = []
        if cast_injection:
            new_alerts.append({
                "step": self._step,
                "module": "CAST",
                "severity": "HIGH" if cast_risk > 0.7 else "MEDIUM",
                "message": f"Injection markers detected in {sender}->{agent_name}: {cast_markers[:3]}",
                "risk_score": cast_risk,
                "sender": sender,
                "recipient": agent_name,
            })
            # Build causal chain
            if self._cast:
                chain = self._cast.build_causal_chain(agent_name, self._step)
                updates["causal_chain"] = {
                    "source_agent": chain.source_agent,
                    "causal_injection_distance": chain.causal_injection_distance,
                    "path": chain.path,
                    "detection_step": chain.detection_step,
                    "detection_agent": chain.detection_agent,
                }
        
        if drift_threat in ("COMPROMISED", "CRITICAL"):
            new_alerts.append({
                "step": self._step,
                "module": "DRIFT",
                "severity": "CRITICAL" if drift_threat == "CRITICAL" else "HIGH",
                "message": f"Agent {sender} infection score elevated: {drift_threat}",
                "agent": sender,
            })
        
        if new_alerts:
            updates["aiges_active_alerts"] = new_alerts
        
        updates["aiges_response_taken"] = drift_action if drift_action != "none" else "logged"
        
        if self.verbose and (cast_injection or drift_threat != "CLEAN"):
            print(f"\n[AIGES] Step {self._step} | {sender}->{agent_name}")
            print(f"  CAST: risk={cast_risk:.3f}, injection={cast_injection}")
            print(f"  DRIFT: {sender} threat={drift_threat}, action={drift_action}")
            print(f"  Overall threat: {threat_level}")
        
        return updates
    
    # ── Post-orchestrator FORGE check ─────────────────────────────────────────
    
    def _post_orchestrator(self, state: dict) -> dict:
        """
        Called AFTER orchestrator execution to run FORGE shadow check.
        Returns a delta dict of updates.
        """
        updates: dict = {}
        if not self._forge:
            return updates
        
        # Extract the orchestrator's plan from state
        current_task = state.get("current_task", "")
        orchestrator_plan = state.get("orchestrator_plan", current_task)
        
        if not orchestrator_plan:
            return updates
        
        forge_plan = self._forge.check_orchestrator(
            task_description=state.get("user_query", ""),
            main_plan=orchestrator_plan,
            step=self._step,
        )
        
        updates.update(self._forge.get_state_update())
        
        if forge_plan.divergence_detected:
            # Proportional severity based on distance
            if forge_plan.plan_embedding_distance >= 0.80 or forge_plan.risk_actions_main:
                # Strong signal — risk actions present OR high distance
                forge_severity = "HIGH"
                threat_escalation = "COMPROMISED"
            else:
                # Weaker signal — divergent but no risk actions
                forge_severity = "MEDIUM"
                threat_escalation = "SUSPICIOUS"
            
            new_alert = {
                "step": self._step,
                "module": "FORGE",
                "severity": forge_severity,
                "message": (
                    f"Orchestrator plan divergence detected! "
                    f"distance={forge_plan.plan_embedding_distance:.3f} "
                    f"reason={forge_plan.divergence_reason[:100]}"
                ),
                "distance": forge_plan.plan_embedding_distance,
                "risk_actions_main": forge_plan.risk_actions_main,
            }
            updates["aiges_active_alerts"] = [new_alert]
            
            # Escalate threat level proportionally
            current = state.get("aiges_threat_level", "CLEAN")
            updates["aiges_threat_level"] = highest_threat([current, threat_escalation])
            
            # Update orchestrator's DRIFT score only if HIGH severity
            if self._drift and forge_severity == "HIGH":
                iv, threat, action = self._drift.update(
                    agent="orchestrator",
                    message_content=orchestrator_plan,
                    cast_risk=forge_plan.plan_embedding_distance,
                    cast_detected_injection=True,
                    step=self._step,
                )
                updates.update(self._drift.get_state_update())
            
            if self.verbose:
                print(f"\n[FORGE] Divergence detected at step {self._step}")
                print(f"  Distance: {forge_plan.plan_embedding_distance:.3f}")
                print(f"  Severity: {forge_severity}, escalation: {threat_escalation}")
                print(f"  Reason: {forge_plan.divergence_reason}")
        
        return updates
    
    # ── TRACE recording ───────────────────────────────────────────────────────
    
    def _record_trace(self, agent_name: str, state: dict) -> dict:
        """Append current step to Merkle chain. Returns delta dict."""
        if not self._trace:
            return {}
        
        # Defense flags snapshot for this node
        defense_flags = {
            "cast_detected": bool(state.get("causal_chain")),
            "drift_suspicious": agent_name in state.get("drift_quarantine_list", []),
            "drift_isolated": agent_name in state.get("drift_isolation_list", []),
            "forge_divergence": state.get("forge_divergence_count", 0) > 0,
            "threat_level": state.get("aiges_threat_level", "CLEAN"),
            "alerts_count": len(state.get("aiges_active_alerts", [])),
        }
        
        # State snapshot (lightweight — key fields only)
        snapshot = {
            "step": self._step,
            "agent": agent_name,
            "auth_status": state.get("auth_status", ""),
            "anomaly_detected": state.get("anomaly_detected", False),
            "threat_level": state.get("aiges_threat_level", "CLEAN"),
        }
        
        node = self._trace.record(
            step=self._step,
            agent=agent_name,
            action="execute",
            state_snapshot=snapshot,
            defense_flags=defense_flags,
        )
        
        # Return only TRACE-related state updates.
        # The merkle_chain field uses operator.add reducer in DemoState,
        # so we only return the NEW node, not the full chain.
        from dataclasses import asdict
        return {
            "merkle_chain": [asdict(node)],
            "merkle_chain_valid": self._trace._chain_valid,
            "trace_secondary_digest": self._trace._secondary_digest,
        }
    
    def _handle_isolated_agent(self, agent_name: str, state: dict) -> dict:
        """
        Handle an agent that has been hard-isolated.
        Skip its execution, generate CRITICAL alert.
        Returns delta dict.
        """
        new_alert = {
            "step": self._step,
            "module": "AIGES",
            "severity": "CRITICAL",
            "message": f"Agent {agent_name} is ISOLATED — execution skipped.",
            "agent": agent_name,
        }
        
        # Add a sentinel message so downstream agents know
        sentinel_msg = {
            "sender": "AIGES",
            "recipient": "orchestrator",
            "payload": {
                "content": f"[AIGES SECURITY] Agent {agent_name} has been isolated due to infection score > 0.85.",
                "action": "isolation_notice",
            },
            "message_id": f"aiges_isolation_{self._step}",
        }
        
        return {
            "aiges_active_alerts": [new_alert],
            "aiges_threat_level": "CRITICAL",
            "aiges_response_taken": "isolate",
            "anomaly_detected": True,
            "messages": [sentinel_msg],
        }
    
    def _extract_content_from_message(self, message: dict) -> str:
        """Extract text content from A2A envelope for semantic drift check."""
        payload = message.get("payload", {})
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            parts = []
            for key in ("content", "text", "query", "message", "data", "instructions"):
                if key in payload:
                    parts.append(str(payload[key]))
            return " ".join(parts) if parts else json.dumps(payload)
        return json.dumps(message)
    
    # ── Reporting / Export ────────────────────────────────────────────────────
    
    def get_defense_report(self, state: dict) -> dict:
        """
        Generate a full defense report for evaluation/paper metrics.
        
        This is the source for:
        - Detection Rate (DR)
        - False Positive Rate (FPR)  
        - Time-to-Detection (TTD) — from step 0 to first alert
        - Causal Injection Distance (CID)
        - Module-level attribution
        """
        alerts = state.get("aiges_active_alerts", [])
        infection_vectors = state.get("infection_vectors", {})
        merkle_valid, tampered = self._trace.verify_chain() if self._trace else (True, [])
        attack_timeline = self._trace.reconstruct_attack_timeline() if self._trace else []
        causal_chain = state.get("causal_chain")
        
        # TTD: step of first non-CLEAN alert
        ttd = None
        for alert in alerts:
            if alert.get("severity") in ("HIGH", "CRITICAL"):
                ttd = alert.get("step")
                break
        
        return {
            "run_summary": {
                "total_steps": self._step,
                "final_threat_level": state.get("aiges_threat_level", "CLEAN"),
                "response_taken": state.get("aiges_response_taken", "none"),
                "total_alerts": len(alerts),
                "merkle_chain_valid": merkle_valid,
                "tampered_steps": tampered,
            },
            "detection": {
                "injection_detected": any(a.get("module") == "CAST" for a in alerts),
                "drift_triggered": any(a.get("module") == "DRIFT" for a in alerts),
                "forge_triggered": any(a.get("module") == "FORGE" for a in alerts),
                "time_to_detection": ttd,
                "causal_injection_distance": (
                    causal_chain.get("causal_injection_distance") if causal_chain else None
                ),
                "injection_source": (
                    causal_chain.get("source_agent") if causal_chain else None
                ),
                "injection_path": (
                    causal_chain.get("path") if causal_chain else None
                ),
            },
            "infection_scores": infection_vectors,
            "alerts": alerts,
            "attack_timeline": attack_timeline,
            "forge_divergence_count": state.get("forge_divergence_count", 0),
        }
    
    def reset(self) -> None:
        """Reset all modules for a new run."""
        if self._cast: self._cast.reset()
        if self._drift: self._drift.reset()
        if self._forge: self._forge.reset()
        if self._trace: self._trace.reset()
        self._step = 0
        self._initialized = False
