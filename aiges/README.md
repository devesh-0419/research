# AIGES — Adaptive Infection-Graph Enhanced Security

A novel, real-time, **LLM-free defense framework** for LangGraph-based
multi-agent systems. AIGES is the defense layer of the LangGraph MAS
security research project, built to defend against:

- **A1** — Direct A2A prompt injection (UserFacing → Orchestrator)
- **A2** — Propagating injection (multi-hop, indirect via data)
- **A3** — Orchestrator compromise (planning logic hijack)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       AIGES Middleware                          │
│                                                                 │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │  CAST   │  │  DRIFT   │  │  FORGE   │  │  TRACE   │          │
│  │ causal  │  │ infection│  │ shadow   │  │ Merkle   │          │
│  │ tracer  │  │ float    │  │ orches.  │  │ chain    │          │
│  └─────────┘  └──────────┘  └──────────┘  └──────────┘          │
│       ▲           ▲              ▲              ▲               │
│       └───────────┴──────────────┴──────────────┘               │
│                          │                                      │
│              wrapped node intercepts every                      │
│                  inter-agent A2A message                        │
└─────────────────────────────────────────────────────────────────┘
                           │
       ┌───────────────────┴───────────────────┐
       ▼          ▼          ▼          ▼      ▼
   user_facing → orchestrator → authorizer → data_manager → logger
              (the baseline 5-agent LangGraph MAS)
```

**Zero-rewiring guarantee:** AIGES wraps each baseline agent with a
middleware decorator. The baseline graph topology, agent code, and
state schema are never modified.

---

## The Four Modules

### CAST — Causal Attack Surface Tracker

**Purpose:** Real-time injection detection on every A2A message envelope, with
backward causal-graph traversal to find the **Causal Injection Source (CIS)**
and compute the novel **Causal Injection Distance (CID)** metric.

**How it works:**
- Deterministic regex match against a 35-pattern injection library
  (built from PeerGuard, AgentSafe, AiTM, BlockA2A taxonomies)
- Unauthorized-hop detection (sender→recipient pair not in policy)
- Causal DAG traversal when a downstream agent flags an anomaly

**LLM calls:** **zero**.

**Novelty vs SOTA:** AgentSafe and SentinelNet are post-hoc; G-Safeguard
is post-propagation. CAST is the only real-time, pre-propagation, causal-
trace defense for LangGraph. CID is an original metric — no paper
formally defines injection-causality distance.

### DRIFT — Dynamic Runtime Infection Float Tracker

**Purpose:** Maintains a **continuous infection score [0.0, 1.0]** per
agent, updated each step via Bayesian rule. Replaces SOTA's binary
"benign vs malicious" classification.

**How it works:**
- Bayesian posterior update from CAST risk scores
- Semantic-drift detection: cosine distance between message embedding
  and pre-computed role centroid (frozen MiniLM model)
- Temporal decay: scores fall over time without new evidence
- Proportional response: CLEAN → SUSPICIOUS → COMPROMISED → CRITICAL

**LLM calls:** **zero**.

**Novelty vs SOTA:**
- INFA-GUARD: binary {benign, infected, attack} per turn
- AgentSafe: binary permission grant/deny
- SentinelNet: bottom-k blacklist (binary in/out)
- G-Safeguard: binary classifier

DRIFT's continuous score enables proportional response, recovery via
score decay, and trend-aware detection (rising trend = more dangerous
than same score stable). This addresses the "infected-but-not-source"
problem INFA-GUARD identifies but doesn't operationalize in LangGraph.

### FORGE — FOol-proof Runtime Guard Engine (Shadow Orchestrator)

**Purpose:** Detects orchestrator compromise (Attack A3) by running an
**isolated shadow plan** and measuring divergence from the main plan.

**How it works:**
- Stage 1 (LLM, isolated): Shadow LLM generates an independent plan from
  task description only — no access to the main conversation history,
  preventing context poisoning
- Stage 2 (deterministic): Cosine distance between plan embeddings,
  PLUS risk-action keyword count comparison
- Detection decision = pure math, **not LLM judgment**

**LLM calls:** Yes (in shadow generation only); detection is LLM-free.

**Novelty vs SOTA:** PeerGuard requires multiple peer agents and can fail
if multiple peers are compromised. FORGE requires only one isolated
shadow plan and the detection is a number that cannot be argued with.
First application of shadow-plan divergence to LangGraph orchestrator
compromise.

### TRACE — Tamper-Resistant Audit Chain Engine

**Purpose:** Append-only Merkle chain of state snapshots; provides
tamper-evidence for the audit log, surviving even an orchestrator that
silences the LoggerAgent.

**How it works:**
- Each node = SHA-256 of (step, agent, action, snapshot, prev_hash)
- Any modification breaks the chain at that point — detected on verify
- Secondary out-of-band digest stored outside the LangGraph state dict
- `reconstruct_attack_timeline()` extracts security events for forensics

**LLM calls:** **zero**.

**Novelty vs SOTA:** BlockA2A achieves the same tamper-evidence using
full blockchain infrastructure (DID registration, ILC/ACC contracts,
gas costs). TRACE achieves the equivalent guarantee using only
in-process SHA-256 chaining — zero external infrastructure, zero
latency overhead.

---

## Quick Start

```python
from aiges import build_aiges_graph

# Build the protected graph
graph = build_aiges_graph(
    cast=True,    # enable Causal Attack Surface Tracker
    drift=True,   # enable Dynamic Runtime Infection Float Tracker
    forge=True,   # enable shadow orchestrator
    trace=True,   # enable Merkle audit chain
    verbose=False,
)

# Run a query
result = graph.invoke({
    "user_query": "What department is Alice in?"
})

# Inspect defense report
print(result["aiges_threat_level"])         # CLEAN | SUSPICIOUS | COMPROMISED | CRITICAL
print(result["aiges_active_alerts"])        # list of alert dicts
print(result["aiges_defense_report"])       # full report

# Causal chain for any detected injection
chain = result.get("causal_chain")
if chain:
    print(f"Injection source: {chain['source_agent']}")
    print(f"CID: {chain['causal_injection_distance']}")
    print(f"Path: {' → '.join(chain['path'])}")
```

---

## Running Evaluations

```bash
# Smoke test (validates all 4 modules + end-to-end)
python -m aiges.tests.test_smoke

# Full evaluation: clean + A1 + A2 + A3
python -m aiges.runner.run_aiges --mode all --reps 5 --output ./results

# Single attack
python -m aiges.runner.run_aiges --mode A1 --reps 10

# Module ablation (CAST-only, DRIFT-only, FORGE-only, full)
python -m aiges.runner.run_aiges --mode ablation --reps 5
```

---

## File Structure

```
aiges/
├── __init__.py
├── README.md                            ← this file
├── core/
│   └── defense_state.py                 ← state schema (InfectionVector, CausalEdge, MerkleNode, ForgePlan)
├── cast/
│   └── cast_module.py                   ← CAST — causal injection tracer
├── drift/
│   └── drift_module.py                  ← DRIFT — infection float tracker
├── forge/
│   └── forge_module.py                  ← FORGE — shadow orchestrator
├── trace/
│   └── trace_module.py                  ← TRACE — Merkle audit chain
├── middleware/
│   └── aiges_middleware.py              ← central coordinator (wraps each agent)
├── graph_builder.py                     ← AIGES-protected LangGraph builder
├── runner/
│   └── run_aiges.py                     ← evaluation runner (produces paper tables)
├── tests/
│   └── test_smoke.py                    ← end-to-end smoke test
└── results/                             ← evaluation output JSON files
```

---

## Integration With Baseline & Attack Suite

This package is designed to plug directly into the existing baseline
MAS (`mas_baseline/`) and attack harness (`mas_attack/`) without any
modifications:

```
research/
├── mas_baseline/        ← unchanged
├── mas_attack/          ← unchanged
└── aiges/               ← this package — wraps baseline at runtime
```

When `mas_baseline/` is present, `build_aiges_graph()` automatically
imports the real baseline agents and wraps them. When the baseline is
not present (e.g., during isolated AIGES development), it falls back
to a built-in demo graph with the same topology.

---

## Research Positioning

AIGES is the defense system for the *LangGraph MAS Security Research*
project. It is designed to be compared head-to-head with:

- **AgentSafe** — hierarchical permissions baseline
- **G-Safeguard** — graph-anomaly post-hoc baseline
- **INFA-GUARD** — GNN-based infection detection baseline
- **SentinelNet** — runtime credit scoring + bottom-k baseline
- **PeerGuard** — peer cross-verification baseline

The paper-target comparison metrics are all built into `runner/run_aiges.py`:

- **ASR** — Attack Success Rate
- **DR**  — Detection Rate
- **FPR** — False Positive Rate (on clean queries)
- **TTD** — Time-to-Detection (in graph steps)
- **CID** — Causal Injection Distance (novel to this research)
- **Per-module detection rates** (CAST DR, DRIFT DR, FORGE DR)
- **Chain integrity rate** (Merkle tamper detection)

---

## Design Principle: LLM-Free Detection

AIGES's detection components are deliberately LLM-free. They are
grounded in:

- **CAST** — deterministic regex + DAG traversal
- **DRIFT** — Bayesian math + frozen-embedding cosine distance
- **FORGE** — frozen-embedding cosine distance + risk-keyword counting
- **TRACE** — SHA-256 cryptographic primitives

LLMs are used only in FORGE's shadow plan generation, in an isolated
context that cannot be reached by injected prompts. This ensures the
defense cannot be compromised by the same semantic manipulation
techniques used to attack the system — a known failure mode of
LLM-based defense architectures.
