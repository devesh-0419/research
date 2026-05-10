"""
core/llm_config.py
==================
Unified LLM provider configuration for the MAS.

Supported backends
------------------
  local_ollama   : Ollama running locally  (no API key needed)
  anthropic      : Claude via Anthropic API
  openai         : GPT-* via OpenAI API
  groq           : Fast inference via Groq API
  none           : No LLM — fully rule-based / deterministic (default)

Configuration
-------------
Set environment variables (or put them in a .env file):

  LLM_PROVIDER=anthropic          # or: local_ollama | openai | groq | none
  LLM_MODEL=claude-3-haiku-20240307

  # API keys (only needed for the relevant provider)
  ANTHROPIC_API_KEY=sk-ant-...
  OPENAI_API_KEY=sk-...
  GROQ_API_KEY=gsk_...

  # Ollama (only needed if using local_ollama)
  OLLAMA_BASE_URL=http://localhost:11434   # default
  OLLAMA_MODEL=llama3                      # default

Usage in agents
---------------
  from core.llm_config import get_llm, LLM_ENABLED

  if LLM_ENABLED:
      llm = get_llm()
      response = llm.invoke("your prompt here")
  else:
      # fall back to rule-based logic
      ...
"""

from __future__ import annotations
import os
from dotenv import load_dotenv

load_dotenv()   # loads .env from project root if present

# ─────────────────────────────────────────────────────────────────────────────
# Read config from environment
# ─────────────────────────────────────────────────────────────────────────────

LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "none").lower().strip()
LLM_MODEL:    str = os.getenv("LLM_MODEL", "").strip()
LLM_ENABLED:  bool = LLM_PROVIDER != "none"

# Provider-specific defaults
_DEFAULTS = {
    "anthropic":    "claude-3-haiku-20240307",
    "openai":       "gpt-4o-mini",
    "groq":         "llama3-8b-8192",
    "local_ollama": "llama3",
}


# ─────────────────────────────────────────────────────────────────────────────
# LLM factory
# ─────────────────────────────────────────────────────────────────────────────

def get_llm(
    temperature: float = 0.0,
    max_tokens:  int   = 512,
):
    """
    Returns a LangChain-compatible chat model based on LLM_PROVIDER.
    
    All returned objects support .invoke(str) and .stream(str).
    Returns None if LLM_PROVIDER == "none".
    """
    if not LLM_ENABLED:
        return None

    model = LLM_MODEL or _DEFAULTS.get(LLM_PROVIDER, "")

    if LLM_PROVIDER == "anthropic":
        return _build_anthropic(model, temperature, max_tokens)

    elif LLM_PROVIDER == "openai":
        return _build_openai(model, temperature, max_tokens)

    elif LLM_PROVIDER == "groq":
        return _build_groq(model, temperature, max_tokens)

    elif LLM_PROVIDER == "local_ollama":
        return _build_ollama(model, temperature)

    else:
        raise ValueError(
            f"Unknown LLM_PROVIDER={LLM_PROVIDER!r}. "
            f"Valid options: anthropic | openai | groq | local_ollama | none"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Per-provider builders
# ─────────────────────────────────────────────────────────────────────────────

def _build_anthropic(model, temperature, max_tokens):
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:
        raise ImportError("Run: pip install langchain-anthropic")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY not set in environment / .env")
    return ChatAnthropic(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        api_key=api_key,
    )


def _build_openai(model, temperature, max_tokens):
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        raise ImportError("Run: pip install langchain-openai")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError("OPENAI_API_KEY not set in environment / .env")
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        api_key=api_key,
    )


def _build_groq(model, temperature, max_tokens):
    try:
        from langchain_groq import ChatGroq
    except ImportError:
        raise ImportError("Run: pip install langchain-groq")
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise EnvironmentError("GROQ_API_KEY not set in environment / .env")
    return ChatGroq(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        api_key=api_key,
    )


def _build_ollama(model, temperature):
    try:
        from langchain_ollama import ChatOllama
    except ImportError:
        raise ImportError("Run: pip install langchain-ollama")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model    = model or os.getenv("OLLAMA_MODEL", "llama3")
    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=temperature,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Config summary (printed on startup if verbose)
# ─────────────────────────────────────────────────────────────────────────────

def print_llm_config():
    model = LLM_MODEL or _DEFAULTS.get(LLM_PROVIDER, "N/A")
    print(f"[LLM Config]  provider={LLM_PROVIDER}  model={model}  enabled={LLM_ENABLED}")
