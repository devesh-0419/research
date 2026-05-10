# MAS Security Research — Baseline System

A 5-agent multi-agent system (MAS) built with LangGraph for security research.  
Implements a baseline MAS, 3 attack vectors, and a passive anomaly detection layer.  
**No LLM required to run** — works fully out of the box in deterministic mode.

---

## Project Structure

```
mas_baseline/
├── core/
│   ├── state.py          # AgentState schema + A2A message envelope
│   └── llm_config.py     # LLM provider config (Anthropic / OpenAI / Groq / Ollama / none)
├── agents/
│   ├── user_facing.py    # UserFacingAgent  — entry/exit, intent parsing
│   ├── orchestrator.py   # OrchestratorAgent — routing, plan, final assembly
│   ├── data_manager.py   # DataManagerAgent — data ops via mock MCP
│   ├── authorizer.py     # AuthorizerAgent  — policy enforcement via mock MCP
│   └── logger_agent.py   # LoggerAgent      — passive audit + anomaly detection
├── mcp_mock/
│   └── clients.py        # Mock MCP servers: DB + Policy
├── attacks/
│   ├── attack_layer.py   # 3 attack implementations
│   └── run_attacks.py    # Attack scenario runner
├── utils/
│   └── logger.py         # Shared structured logging utility
├── graph.py              # LangGraph graph definition (wires all 5 agents)
├── main.py               # Baseline test runner
├── .env.example          # Environment variable template
└── requirements.txt      # Python dependencies
```

---

## Quick Start

### 1. Clone / download the project

```bash
cd mas_baseline
```

### 2. Create and activate a virtual environment

```bash
# Create venv (Python 3.10+ required)
python -m venv venv

# Activate — Linux / macOS
source venv/bin/activate

# Activate — Windows (Command Prompt)
venv\Scripts\activate.bat

# Activate — Windows (PowerShell)
venv\Scripts\Activate.ps1
```

You should see `(venv)` in your terminal prompt.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env with your chosen LLM provider (or leave as-is for no-LLM mode)
```

### 5. Run the baseline

```bash
python main.py
```

Expected output:
```
ID     Expected     Actual       Pass     Anomaly
S1     approved     approved     ✓        -
S2     approved     approved     ✓        -
S3     denied       denied       ✓        -
S4     denied       denied       ✓        -
Result: ALL PASSED ✓
```

### 6. Run the attacks

```bash
python -m attacks.run_attacks
```

---

## LLM Configuration

The system supports 5 modes via `LLM_PROVIDER` in your `.env` file.

### Mode 1 — No LLM (default)

```env
LLM_PROVIDER=none
```

All agents use rule-based logic. Fully deterministic, no internet required.
Best for reproducible experiments and quick iteration.

---

### Mode 2 — Anthropic (Claude)

```bash
pip install langchain-anthropic
```

```env
LLM_PROVIDER=anthropic
LLM_MODEL=claude-3-haiku-20240307
ANTHROPIC_API_KEY=sk-ant-api03-...
```

Model options: `claude-3-haiku-20240307` · `claude-3-5-sonnet-20241022` · `claude-opus-4-20250514`

Get your key: https://console.anthropic.com

---

### Mode 3 — OpenAI

```bash
pip install langchain-openai
```

```env
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...
```

Model options: `gpt-4o-mini` · `gpt-4o` · `gpt-4-turbo`

---

### Mode 4 — Groq (fast, free tier available)

```bash
pip install langchain-groq
```

```env
LLM_PROVIDER=groq
LLM_MODEL=llama3-8b-8192
GROQ_API_KEY=gsk_...
```

Model options: `llama3-8b-8192` · `llama3-70b-8192` · `mixtral-8x7b-32768`

Free key: https://console.groq.com

---

### Mode 5 — Ollama (fully local, no API key)

**Step 1:** Install Ollama from https://ollama.com

**Step 2:** Pull a model

```bash
ollama pull llama3          # recommended (~4 GB)
ollama pull phi3            # lighter (~2 GB), good for low-spec machines
ollama pull mistral         # alternative
```

**Step 3:** Start Ollama (if not already running as a service)

```bash
ollama serve
```

**Step 4:** Install the Python package and set `.env`

```bash
pip install langchain-ollama
```

```env
LLM_PROVIDER=local_ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

---

### Verify your LLM config

```bash
python -c "
from core.llm_config import print_llm_config, get_llm
print_llm_config()
llm = get_llm()
if llm:
    print(llm.invoke('Say hello in one word.').content)
else:
    print('Running in no-LLM (deterministic) mode.')
"
```

---

## Running the Frontend (with real backend)

The frontend connects to `server.py` — a Flask server that runs the **actual LangGraph pipeline** and streams real agent events to the browser via SSE.

### Start the backend server

```bash
# Make sure your venv is active
source venv/bin/activate

python server.py
```

You'll see:
```
=======================================================
  AEGIS-MAS  —  Backend Server
=======================================================
[LLM Config]  provider=none  model=N/A  enabled=False

  Frontend:  http://localhost:5000
  API:       http://localhost:5000/api/run
  Health:    http://localhost:5000/api/health
=======================================================
```

Then open **http://localhost:5000** in your browser.  
The frontend auto-detects the backend on load and will show "Backend connected" in the log.

### API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/run` | POST `{"query": "..."}` | Full pipeline run, returns JSON result |
| `/api/stream?q=...` | GET | SSE stream of per-agent events as they happen |
| `/api/health` | GET | Server health + LLM config |

### How the real integration works

```
Browser                     Flask (server.py)           LangGraph (graph.py)
──────────────────────────────────────────────────────────────────────────
[RUN clicked]
  POST /api/stream?q=... →  graph.stream(state)   →   UserFacingAgent
                                                   →   OrchestratorAgent
  ← SSE: node_complete ←    yield each node        →   AuthorizerAgent
  ← SSE: node_complete ←    update as it fires     →   DataManagerAgent
  ← SSE: node_complete ←                           →   LoggerAgent
  ← SSE: done          ←    final result           →   (complete)
```

Each SSE event carries the real A2A messages, real log entries, and real state from Python — the frontend renders exactly what the Python agents produced.



```bash
# All 3 attack scenarios:
python -m attacks.run_attacks

# Use a single attack in your own code:
python -c "
from core.state import initial_state
from attacks.attack_layer import apply_attack
state = initial_state('Delete record R001')
updates = apply_attack(state, 'orchestrator_compromise')
print('attack_type:', updates['attack_type'])
print('compromised:', updates['compromised_agents'])
"
```

Available attack names: `a2a_injection` · `propagation` · `orchestrator_compromise`

---

## Custom Queries

```bash
# Single query
python main.py --query "Get all users from the system"

# With full A2A message bus printed
python main.py --query "Save a new record" --verbose-messages
```

---

## Deactivating the venv

```bash
deactivate
```

---

## Requirements

- Python 3.10 or higher
- No GPU required (Ollama works on CPU; GPU speeds it up)
- Ollama `llama3` needs ~4–8 GB RAM; use `phi3` on lower-spec machines

---

## Phase Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Done | Baseline MAS — 5 agents, A2A envelopes, mock MCP |
| Phase 2 | ✅ Done | 3 attacks — A2A injection, propagation, orchestrator compromise |
| Phase 3 | 🔜 Next | AEGIS defense — DRIFT, CAST, FORGE, TRACE modules |
