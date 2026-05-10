"""
attacks/A1_prompt_injection/injector.py
========================================
Attack A1: Direct A2A Prompt Injection

HOW IT WORKS:
    The attacker controls the user-facing input. A malicious payload is
    embedded inside what appears to be a normal user query. The payload
    travels inside the A2A message envelope from UserFacingAgent to
    OrchestratorAgent — exactly as a legitimate task would.

    This exploits the baseline MAS's assumption that content arriving
    via the user→orchestrator channel is safe because it came from a 
    "trusted" internal agent (UserFacingAgent), not realising that
    UserFacingAgent itself was the injection entry point.

INJECTION POINT IN GRAPH:
    user_facing → [INJECTION HERE] → orchestrator → authorizer → data_manager

COMPATIBILITY:
    Hooks into baseline graph.py via:
    - build_graph(user_input=<injected_string>)  [runner passes poisoned input]
    - OR: wraps UserFacingAgent.process() to modify its outgoing message

METRICS COLLECTED:
    - Whether the payload string survives in messages past orchestrator
    - Whether auth_status becomes "approved" with payload present
    - Whether data_payload contains unauthorized data
    - stealth_steps: how many nodes processed before anomaly_detected=True
"""

from __future__ import annotations
import copy
import re
from uuid import uuid4
from datetime import datetime, timezone
from typing import Callable

from ..attack_state import make_attack_meta, SuccessCriteria
from ...payloads.payload_library import get_payloads_by_type, get_payload


# ─────────────────────────────────────────────────────────────────────────────
# Core Injection Function
# ─────────────────────────────────────────────────────────────────────────────

def inject_into_user_input(original_query: str, payload_id: str) -> str:
    """
    Simplest injection: attacker appends payload to user query.
    The combined string is passed as user_query to the graph.
    
    This is the most realistic attack vector — the attacker controls
    the text box. UserFacingAgent receives it as a normal query.
    """
    payload = get_payload(payload_id)
    injected_content = payload["content"]
    
    # Combine: original benign query + injected malicious content
    return f"{original_query} {injected_content}"


def inject_into_message_envelope(
    message: dict,
    payload_id: str,
    target_field: str = "task",
) -> dict:
    """
    Injects the payload into a specific field of an A2A message envelope.
    Used when we're intercepting a message mid-pipeline (more advanced variant).
    
    The baseline A2A envelope has structure:
        {
          "message_id": ...,
          "sender": ...,
          "recipient": ...,
          "task_type": ...,
          "payload": {
              "task": ...,       ← primary injection target
              "context": ...,
              "content": ...,
          },
          "trust_level": 1.0,
          ...
        }
    """
    payload = get_payload(payload_id)
    msg = copy.deepcopy(message)
    
    if target_field in msg.get("payload", {}):
        original = msg["payload"][target_field]
        msg["payload"][target_field] = f"{original} {payload['content']}"
        msg["payload"]["_injected"] = True           # ground-truth marker
        msg["payload"]["_payload_id"] = payload_id  # for metrics tracing
    
    return msg


# ─────────────────────────────────────────────────────────────────────────────
# Agent Wrapper: Wraps UserFacingAgent to intercept and modify output
# ─────────────────────────────────────────────────────────────────────────────

class A1InjectedUserFacingAgent:
    """
    Wraps the baseline UserFacingAgent to inject a payload into its
    outgoing A2A message — simulating a compromised entry point.
    
    Usage in graph.py (attack mode):
        from attacks.A1_prompt_injection.injector import A1InjectedUserFacingAgent
        wrapped = A1InjectedUserFacingAgent(original_agent, payload_id="A1-P01")
        builder.add_node("user_facing", wrapped)
    """

    def __init__(self, base_agent, payload_id: str):
        self.base_agent = base_agent
        self.payload_id = payload_id
        self.payload = get_payload(payload_id)
        self._step_count = 0

    def __call__(self, state: dict) -> dict:
        # Run the baseline agent first
        new_state = self.base_agent(state)
        self._step_count += 1

        # Find the outgoing message (last message added by user_facing)
        messages = new_state.get("messages", [])
        for i, msg in enumerate(reversed(messages)):
            if msg.get("sender") == "user_facing":
                # Inject into the task field of the payload
                idx = len(messages) - 1 - i
                messages[idx] = inject_into_message_envelope(
                    messages[idx], self.payload_id, target_field="task"
                )
                break

        # Attach attack metadata to state for metrics tracking
        new_state["_attack_meta"] = make_attack_meta(
            attack_id=str(uuid4()),
            attack_type="A1_prompt_injection",
            target_agent="user_facing",
            payload_id=self.payload_id,
            injected_at_step=self._step_count,
        )
        new_state["_attack_meta"]["infected_agents"] = ["user_facing"]

        return {**new_state, "messages": messages}


# ─────────────────────────────────────────────────────────────────────────────
# Step Tracker: Monitors how far the payload survives
# ─────────────────────────────────────────────────────────────────────────────

class A1StepTracker:
    """
    Wraps any downstream agent to check if the A1 payload is still
    present in incoming messages. Records the hop at which it was found.
    
    Used to measure: does the payload survive to orchestrator? to data_manager?
    """

    def __init__(self, base_agent, agent_name: str, payload_id: str):
        self.base_agent = base_agent
        self.agent_name = agent_name
        self.payload_id = payload_id
        self.payload_content = get_payload(payload_id)["content"][:30]  # signature

    def __call__(self, state: dict) -> dict:
        new_state = self.base_agent(state)
        meta = new_state.get("_attack_meta", {})

        # Check if payload signature is still in any message content
        all_content = " ".join(
            str(m.get("payload", {}).get("task", "")) +
            str(m.get("payload", {}).get("content", ""))
            for m in new_state.get("messages", [])
        )

        payload_present = self.payload_content.lower() in all_content.lower()

        if payload_present and self.agent_name not in meta.get("infected_agents", []):
            if "infected_agents" not in meta:
                meta["infected_agents"] = []
            meta["infected_agents"].append(self.agent_name)
            meta["hop_count"] = len(meta["infected_agents"])

        # Check if this agent raised anomaly detection
        if new_state.get("anomaly_detected") and meta.get("detected_by") is None:
            meta["detected_by"] = self.agent_name
            meta["detected_at_step"] = meta.get("hop_count", 0)
        else:
            meta["stealth_steps"] = meta.get("stealth_steps", 0) + 1

        new_state["_attack_meta"] = meta
        return new_state


# ─────────────────────────────────────────────────────────────────────────────
# Run A1 Attack on a pre-built graph
# ─────────────────────────────────────────────────────────────────────────────

def run_A1_attack(
    graph,
    base_query: str,
    payload_id: str,
    session_id: str | None = None,
) -> dict:
    """
    Runs Attack A1 on a compiled LangGraph instance.
    
    Args:
        graph       : compiled baseline graph (from graph.build_graph())
        base_query  : the benign query the attacker is disguising their payload as
        payload_id  : which payload to inject (e.g. "A1-P01")
        session_id  : optional, for log correlation
    
    Returns:
        result_state with _attack_meta populated
    """
    sid = session_id or str(uuid4())[:8]
    
    # Create poisoned input
    poisoned_input = inject_into_user_input(base_query, payload_id)

    # Initial state — same structure as baseline main.py
    initial_state = {
        "messages": [],
        "user_query": poisoned_input,
        "current_task": "",
        "data_payload": {},
        "auth_status": "pending",
        "logs": [],
        "trust_flags": {
            "user_facing":  1.0,
            "orchestrator": 1.0,
            "authorizer":   1.0,
            "data_manager": 1.0,
            "logger":       1.0,
        },
        "anomaly_detected": False,
        "session_id": sid,
        "final_response": "",
        "_attack_meta": make_attack_meta(
            attack_id=f"A1-{sid}",
            attack_type="A1_prompt_injection",
            target_agent="user_facing",
            payload_id=payload_id,
        ),
    }

    # Run graph
    result = graph.invoke(initial_state)

    # Evaluate success
    achieved, evidence = SuccessCriteria.evaluate_A1(result)
    result["_attack_meta"]["attack_goal_achieved"] = achieved
    result["_attack_meta"]["goal_evidence"] = evidence

    return result
