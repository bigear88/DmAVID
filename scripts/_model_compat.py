"""Model compatibility layer for GPT-4.x and GPT-5.x series."""
import os

MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")

def is_gpt5_model(model=None):
    """Check if model is GPT-5 series (requires max_completion_tokens)."""
    m = model or MODEL
    return m.startswith("gpt-5") or m.startswith("o1") or m.startswith("o3")

def token_param(max_tokens, model=None):
    """Return correct token limit parameter for the model."""
    if is_gpt5_model(model):
        return {"max_completion_tokens": max_tokens}
    return {"max_tokens": max_tokens}
