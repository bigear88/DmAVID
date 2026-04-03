"""Model compatibility layer for GPT-4.x and GPT-4.1-mini series."""
import os

MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")

def is_gpt5_model(model=None):
    """Check if model requires max_completion_tokens (future-proofing)."""
    m = model or MODEL
    return m.startswith("gpt-5") or m.startswith("o1") or m.startswith("o3")

def token_param(max_tokens, model=None):
    """Return correct token limit parameter for the model."""
    if is_gpt5_model(model):
        return {"max_completion_tokens": max_tokens}
    return {"max_tokens": max_tokens}
