# mas_attack/__init__.py
"""
AEGIS-MAS Attack Harness
========================
Attack testing framework for the 5-agent LangGraph MAS.

Structure:
    payloads/       - 15 payloads across 3 attack types
    attacks/A1/     - Direct A2A Prompt Injection
    attacks/A2/     - Propagating Attack
    attacks/A3/     - Orchestrator Compromise
    metrics/        - Metrics engine (ASR, HC, DS, SS, TTD, FPR)
    harness/        - Master runner + CLI
    results/        - Output JSON (auto-created on run)
"""
