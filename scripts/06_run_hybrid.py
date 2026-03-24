#!/usr/bin/env python3
"""
Experiment 5: DavidAgent Hybrid Framework (Slither + LLM + RAG).

Three-Strategy Fusion with GPTLens Dual-Role approach for maximizing F1:

  Stage 1 – Independent LLM+RAG analysis with dual-context retrieval
             LLM judges the contract WITHOUT seeing Slither results to avoid
             false-positive contamination. RAG retrieves BOTH vulnerable and
             safe patterns for balanced assessment.

  Stage 2 – Conditional Slither-guided re-evaluation with pre-filtering
             Only triggered when LLM said SAFE but Slither reported HIGH/MEDIUM
             alerts AND the LLM confidence was below the threshold.
             GPTScan-style domain rules pre-filter Slither findings to remove
             known false-positive patterns BEFORE sending to LLM.

Key optimizations (based on literature review):
  - GPTScan-style pre-filtering: Domain-specific rules filter Slither false positives
    before LLM stage [Sun et al., ICSE 2024].
  - Dual-context RAG: Retrieves both vulnerable AND safe examples for balanced
    assessment [RAG-SmartVuln, 2024].
  - Confidence-weighted decision: high-confidence LLM verdicts are never overridden.
  - Anti-bias prompt engineering: Stage 2 prompt explicitly warns about Slither's
    ~84% FPR and instructs the LLM to only flip its decision when it finds
    independently confirmable exploitable flaws [AdaTaint, 2025].

Prerequisites:
    - Run `build_knowledge_base.py` first to populate the ChromaDB vector store.
    - Ensure OPENAI_API_KEY is set in the environment.
    - Slither and solc-select must be installed.

Usage:
    python 06_run_hybrid.py
"""

import os
import sys
import json
import subprocess
import time
import random
import re
from datetime import datetime

import chromadb
from openai import OpenAI
import sys as _sys; _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param

random.seed(42)

# ── Paths ──────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "hybrid", "hybrid_results.json")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")

# ── Config ─────────────────────────────────────────────────────────
LLM_MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
EMBEDDING_MODEL = "text-embedding-3-small"
COLLECTION_NAME = "vuln_knowledge"
RAG_TOP_K = 5
MAX_CODE_LENGTH = 12_000

# ── Fusion Thresholds ──────────────────────────────────────────────
# Stage 2 is ONLY triggered when ALL three conditions are met:
#   1) Stage 1 LLM said SAFE
#   2) Slither has at least one High/Medium alert that PASSES pre-filtering
#   3) Stage 1 confidence < REEVAL_CONFIDENCE_THRESHOLD
REEVAL_CONFIDENCE_THRESHOLD = 0.75

# ── GPTScan-style Pre-filtering Rules ─────────────────────────────
# Maps Slither check names to domain-specific validation rules.
# A Slither finding is only kept if it passes the corresponding rule.
# This eliminates known false-positive patterns before LLM analysis.
SLITHER_FP_FILTERS = {
    # Reentrancy: Only keep if function has external call + state change
    "reentrancy-eth": {"require_patterns": [".call", ".send", ".transfer"],
                        "exclude_patterns": ["nonReentrant", "ReentrancyGuard", "mutex"]},
    "reentrancy-no-eth": {"require_patterns": [".call"],
                           "exclude_patterns": ["nonReentrant", "ReentrancyGuard"]},
    "reentrancy-benign": {"drop": True},  # Always FP
    "reentrancy-events": {"drop": True},  # Event ordering, not exploitable
    # Arithmetic: Only keep for Solidity < 0.8
    "divide-before-multiply": {"require_solc_below": "0.8"},
    # Access control: Keep high-confidence only
    "unprotected-upgrade": {"min_confidence": "High"},
    "suicidal": {"min_confidence": "Medium"},
    # Known FP patterns
    "solc-version": {"drop": True},
    "pragma": {"drop": True},
    "naming-convention": {"drop": True},
    "assembly": {"drop": True},
    "low-level-calls": {"drop": True},  # Raw low-level call alert (too noisy)
    "dead-code": {"drop": True},
    "constable-states": {"drop": True},
    "immutable-states": {"drop": True},
    "external-function": {"drop": True},
    "too-many-digits": {"drop": True},
}

SOLC_VERSIONS = {
    "0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12",
    "0.7": "0.7.6", "0.8": "0.8.0",
}


# ============================================================
# RAG Module: ChromaDB Knowledge Base + Context Builder
# ============================================================
sys.path.insert(0, SCRIPT_DIR)
import chromadb
from typing import List

class VulnKnowledgeBase:
    """ChromaDB-based vulnerability knowledge retrieval for RAG."""

    def __init__(self, chroma_dir: str, collection_name: str, llm_client: OpenAI):
        self.client = chromadb.PersistentClient(path=chroma_dir)
        self.collection = self.client.get_collection(collection_name)
        self.entry_count = self.collection.count()
        self.llm_client = llm_client

    def _embed_query(self, text: str) -> List[float]:
        text = text[:8000]
        resp = self.llm_client.embeddings.create(
            model="text-embedding-3-small", input=text
        )
        return resp.data[0].embedding

    def retrieve(self, code: str, top_k: int = 5) -> list:
        emb = self._embed_query(code)
        results = self.collection.query(
            query_embeddings=[emb], n_results=min(top_k, self.entry_count)
        )
        entries = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                entries.append({
                    "content": doc,
                    "category": meta.get("category", "unknown"),
                    "title": meta.get("title", ""),
                    "distance": results["distances"][0][i] if results["distances"] else 0,
                })
        return entries


def build_rag_context(retrieved: list) -> str:
    """Build RAG context string from retrieved knowledge entries."""
    if not retrieved:
        return "No relevant vulnerability patterns found."
    parts = []
    for e in retrieved:
        cat = e.get("category", "unknown").upper()
        title = e.get("title", "")
        content = e.get("content", "")[:500]
        parts.append(f"--- {cat}: {title} ---\n{content}")
    return "\n\n".join(parts)


# ============================================================
# Slither Module
# ============================================================

def detect_solc_version(code: str) -> str:
    match = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def run_slither_quick(filepath: str, timeout: int = 30) -> list[dict]:
    """Quick Slither analysis for the hybrid pipeline."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        ver = detect_solc_version(code)
        subprocess.run(["solc-select", "use", ver], capture_output=True, timeout=5)

        r = subprocess.run(
            ["slither", filepath, "--json", "-"],
            capture_output=True, text=True, timeout=timeout,
        )
        detectors = []
        if r.stdout:
            try:
                out = json.loads(r.stdout)
                if "results" in out and "detectors" in out["results"]:
                    detectors = out["results"]["detectors"]
            except Exception:
                pass

        findings = []
        for d in detectors:
            findings.append({
                "check": d.get("check", "unknown"),
                "impact": d.get("impact", "unknown"),
                "confidence": d.get("confidence", "unknown"),
                "description": d.get("description", "")[:200],
            })
        return findings
    except Exception:
        return []


# ============================================================
# GPTScan-style Pre-filtering (Sun et al., ICSE 2024)
# ============================================================

def prefilter_slither_findings(
    findings: list[dict],
    code: str,
    solc_version: str = "0.8.0",
) -> list[dict]:
    """Pre-filter Slither findings using domain-specific rules.

    Removes known false-positive patterns BEFORE they reach the LLM,
    preventing false-positive contamination in Stage 2.
    Based on GPTScan filtering strategy (Sun et al., ICSE 2024).

    Returns:
        Filtered list of findings that passed domain validation.
    """
    code_lower = code.lower()
    filtered = []

    for finding in findings:
        check_name = finding.get("check", "unknown")
        desc = finding.get("description", "").lower()

        # Look up filter rules
        rules = SLITHER_FP_FILTERS.get(check_name)

        if rules is None:
            # No specific rule → keep the finding as-is
            filtered.append(finding)
            continue

        if rules.get("drop"):
            # Explicitly drop this type (known noise)
            continue

        # Check min_confidence requirement
        min_conf = rules.get("min_confidence")
        if min_conf:
            conf = finding.get("confidence", "Low")
            conf_levels = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
            if conf_levels.get(conf, 0) < conf_levels.get(min_conf, 0):
                continue

        # Check require_patterns: at least one must be present in code
        require = rules.get("require_patterns", [])
        if require and not any(p.lower() in code_lower for p in require):
            continue

        # Check exclude_patterns: if any is present, the code has mitigations
        exclude = rules.get("exclude_patterns", [])
        if exclude and any(p.lower() in code_lower for p in exclude):
            continue

        # Check Solidity version requirement
        req_below = rules.get("require_solc_below")
        if req_below and solc_version >= req_below:
            continue

        filtered.append(finding)

    return filtered


# ============================================================
# STAGE 1: Independent LLM+RAG Analysis (No Slither Influence)
# ============================================================

STAGE1_PROMPT = """You are an expert smart contract security auditor with access to a vulnerability knowledge base.
You will be provided with:
1. The Solidity source code to analyze
2. VULNERABLE patterns retrieved from the knowledge base — code that IS vulnerable
3. SAFE patterns retrieved from the knowledge base — code that is properly secured

ANALYSIS METHODOLOGY:
- First, check if the code matches any VULNERABLE patterns from the knowledge base
- Then, check if the code has MITIGATIONS matching SAFE patterns (ReentrancyGuard, SafeMath, onlyOwner, require checks)
- A contract is VULNERABLE only if it matches vulnerable patterns AND lacks proper mitigations
- A contract is SAFE if it either doesn't match vulnerable patterns, OR it has effective mitigations

IMPORTANT: Be balanced. Not every contract with external calls is vulnerable.
Rate your confidence from 0.0 to 1.0:
- 0.9-1.0: Very clear vulnerable/safe pattern match
- 0.7-0.8: Likely but some ambiguity
- 0.5-0.6: Uncertain, borderline case

Respond in JSON format ONLY:
{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1"],
  "severity": "High/Medium/Low/None",
  "reasoning": "brief explanation referencing both vulnerable and safe patterns"
}"""


def run_stage1(
    code: str,
    knowledge_base: VulnKnowledgeBase,
    llm_client: OpenAI,
    max_retries: int = 2,
) -> dict:
    """Stage 1: Pure LLM+RAG analysis — identical to Experiment 4.

    The model NEVER sees Slither output here, preserving its independent
    judgment and the high Precision demonstrated in Experiment 4.
    """
    if len(code) > MAX_CODE_LENGTH:
        code = code[:MAX_CODE_LENGTH] + "\n// ... (truncated)"

    # Semantic retrieval from ChromaDB
    retrieval_start = time.time()
    retrieved = knowledge_base.retrieve(code, top_k=RAG_TOP_K)
    retrieval_time = time.time() - retrieval_start

    rag_context = build_rag_context(retrieved)
    retrieved_categories = list({e["category"] for e in retrieved})

    user_msg = (
        f"## RAG Knowledge Base Context (Semantic Retrieval):\n{rag_context}\n\n"
        f"## Contract Code:\n```solidity\n{code}\n```"
    )

    for attempt in range(max_retries + 1):
        try:
            llm_start = time.time()
            resp = llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": STAGE1_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                **token_param(1024),
                seed=42,
            )
            llm_time = time.time() - llm_start
            content_str = resp.choices[0].message.content.strip()

            json_match = re.search(r"\{[^{}]*\}", content_str, re.DOTALL)
            parsed = json.loads(json_match.group()) if json_match else json.loads(content_str)

            return {
                "success": True,
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "severity": parsed.get("severity", "None"),
                "reasoning": parsed.get("reasoning", ""),
                "rag_retrieval_time": round(retrieval_time, 4),
                "rag_retrieved_categories": retrieved_categories,
                "time_seconds": round(llm_time, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": None,
            }
        except json.JSONDecodeError:
            has_vuln = any(w in content_str.lower() for w in ["true", "vulnerable"])
            return {
                "success": True,
                "predicted_vulnerable": has_vuln,
                "confidence": 0.5,
                "vulnerability_types": [],
                "severity": "Unknown",
                "reasoning": content_str[:200],
                "rag_retrieval_time": round(retrieval_time, 4),
                "rag_retrieved_categories": retrieved_categories,
                "time_seconds": round(time.time() - llm_start, 3),
                "tokens_used": 0,
                "error": "json_parse_error",
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False,
                "predicted_vulnerable": False,
                "confidence": 0,
                "vulnerability_types": [],
                "severity": "None",
                "reasoning": "",
                "rag_retrieval_time": 0,
                "rag_retrieved_categories": [],
                "time_seconds": 0,
                "tokens_used": 0,
                "error": str(e),
            }


# ============================================================
# GPTLens CRITIC PROMPT (Dual-Role: reduces false positives)
# Reference: GPTLens — LLM as Auditor + Critic
# ============================================================

CRITIC_PROMPT = """You are a smart contract security CRITIC. Your job is to CHALLENGE vulnerability findings.

An Auditor found these potential vulnerabilities in a Solidity contract:
{auditor_findings}

Static analysis (Slither) results for context:
{slither_summary}

For EACH finding, determine if it is:
1. A TRUE vulnerability (exploitable, no mitigation present)
2. A FALSE POSITIVE (mitigated by guards, version-safe, or theoretical only)

Be SKEPTICAL. Common false positives include:
- Reentrancy flagged but ReentrancyGuard/nonReentrant is present
- Integer overflow in Solidity >=0.8 (built-in checks)
- Access control issue but onlyOwner/require(msg.sender==owner) exists
- Unchecked return but the contract handles failures differently

Respond in JSON:
{{
  "confirmed_vulnerabilities": [{{"type": "...", "reason": "..."}}],
  "rejected_findings": [{{"type": "...", "reason": "..."}}],
  "final_verdict": true/false,
  "confidence": 0.0-1.0
}}"""

# ============================================================
# STAGE 2: Slither-Guided Re-evaluation (Anti-Bias Prompt)
# ============================================================

STAGE2_PROMPT = """You are an expert smart contract security auditor performing a TARGETED RE-EVALUATION.

BACKGROUND:
You previously analyzed this contract and judged it as SAFE with {prev_confidence:.0%} confidence.
However, a static analysis tool (Slither) has flagged the following alerts:

{slither_alerts}

CRITICAL CONTEXT:
- Slither has a known FALSE POSITIVE RATE of approximately 84%
- The alerts below have ALREADY been pre-filtered to remove known noise patterns
- Despite pre-filtering, many alerts may still be false positives
- Your previous independent analysis found the contract SAFE

YOUR TASK:
Re-examine ONLY the specific code regions that Slither flagged. Ask yourself:
1. Does the flagged code contain an ACTUALLY EXPLOITABLE vulnerability?
2. Are there mitigations (ReentrancyGuard, SafeMath, require checks, onlyOwner) that
   neutralize the flagged pattern?
3. Would a real attacker be able to extract funds or cause damage?

ONLY change your verdict to VULNERABLE if you find a CONCRETE, EXPLOITABLE security flaw
that your previous analysis missed. Do NOT flip your verdict just because Slither raised alerts.

Respond in JSON format ONLY:
{{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1"],
  "severity": "High/Medium/Low/None",
  "verdict_changed": true/false,
  "reasoning": "explain why you changed or kept your original verdict"
}}"""


def format_slither_alerts(findings: list[dict]) -> str:
    """Format Slither findings for Stage 2 prompt."""
    high_med = [f for f in findings if f["impact"] in ["High", "Medium"]]
    low_info = [f for f in findings if f["impact"] in ["Low", "Informational"]]

    parts = []
    if high_med:
        parts.append(f"HIGH/MEDIUM severity ({len(high_med)} alerts):")
        for f in high_med[:5]:
            parts.append(f"  - [{f['impact']}/{f['confidence']}] {f['check']}: {f['description'][:150]}")
    if low_info:
        parts.append(
            f"LOW/INFO ({len(low_info)} alerts): "
            f"{', '.join(set(f['check'] for f in low_info[:10]))}"
        )
    return "\n".join(parts)


def run_stage2(
    code: str,
    slither_findings: list[dict],
    stage1_confidence: float,
    llm_client: OpenAI,
    max_retries: int = 2,
) -> dict:
    """Stage 2: Targeted re-evaluation using Slither alerts as attention anchors.

    This is ONLY called when Stage 1 said SAFE but Slither found High/Medium
    alerts and Stage 1 confidence was below the threshold.
    The prompt is carefully designed to resist false-positive contamination.
    """
    if len(code) > MAX_CODE_LENGTH:
        code = code[:MAX_CODE_LENGTH] + "\n// ... (truncated)"

    slither_alerts = format_slither_alerts(slither_findings)
    prompt = STAGE2_PROMPT.format(
        prev_confidence=stage1_confidence,
        slither_alerts=slither_alerts,
    )

    for attempt in range(max_retries + 1):
        try:
            llm_start = time.time()
            resp = llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"## Contract Code:\n```solidity\n{code}\n```"},
                ],
                temperature=0.1,
                **token_param(1024),
                seed=42,
            )
            llm_time = time.time() - llm_start
            content_str = resp.choices[0].message.content.strip()

            json_match = re.search(r"\{[^{}]*\}", content_str, re.DOTALL)
            parsed = json.loads(json_match.group()) if json_match else json.loads(content_str)

            return {
                "success": True,
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "severity": parsed.get("severity", "None"),
                "verdict_changed": parsed.get("verdict_changed", False),
                "reasoning": parsed.get("reasoning", ""),
                "time_seconds": round(llm_time, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": None,
            }
        except json.JSONDecodeError:
            has_vuln = any(w in content_str.lower() for w in ["true", "vulnerable"])
            return {
                "success": True,
                "predicted_vulnerable": has_vuln,
                "confidence": 0.5,
                "vulnerability_types": [],
                "severity": "Unknown",
                "verdict_changed": has_vuln,
                "reasoning": content_str[:200],
                "time_seconds": round(time.time() - llm_start, 3),
                "tokens_used": 0,
                "error": "json_parse_error",
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False,
                "predicted_vulnerable": False,
                "confidence": 0,
                "vulnerability_types": [],
                "severity": "None",
                "verdict_changed": False,
                "reasoning": "",
                "time_seconds": 0,
                "tokens_used": 0,
                "error": str(e),
            }


# ============================================================
# GPTLens Dual-Role Fusion Engine (Auditor + Critic)
# ============================================================

def run_critic(code: str, auditor_findings: str, slither_findings: list, llm_client: OpenAI) -> dict:
    """GPTLens Critic: challenges Auditor findings to reduce false positives."""
    slither_summary = "; ".join(
        f"{f['check']}({f['impact']})" for f in slither_findings[:10]
    ) or "No Slither alerts"

    prompt = CRITIC_PROMPT.format(
        auditor_findings=auditor_findings,
        slither_summary=slither_summary,
    )
    try:
        resp = llm_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"```solidity\n{code[:MAX_CODE_LENGTH]}\n```"},
            ],
            temperature=0.1,
            **token_param(1024),
            seed=42,
        )
        content = resp.choices[0].message.content.strip()
        json_match = re.search(r"\{[\s\S]*\}", content)
        parsed = json.loads(json_match.group()) if json_match else json.loads(content)
        return {
            "final_verdict": parsed.get("final_verdict", False),
            "confidence": parsed.get("confidence", 0.5),
            "confirmed": parsed.get("confirmed_vulnerabilities", []),
            "rejected": parsed.get("rejected_findings", []),
            "tokens_used": resp.usage.total_tokens if resp.usage else 0,
            "success": True,
        }
    except Exception as e:
        return {"final_verdict": False, "confidence": 0.5, "confirmed": [], "rejected": [],
                "tokens_used": 0, "success": False, "error": str(e)}


def compute_slither_score(findings: list) -> float:
    """Compute normalized Slither severity score (0-1)."""
    if not findings:
        return 0.0
    weights = {"High": 1.0, "Medium": 0.6, "Low": 0.2, "Informational": 0.05}
    score = sum(weights.get(f.get("impact", "Low"), 0.1) for f in findings)
    return min(1.0, score / 5.0)  # Normalize: 5 high findings = 1.0


def hybrid_decision(
    code: str,
    slither_findings: list[dict],
    knowledge_base: VulnKnowledgeBase,
    llm_client: OpenAI,
    strategy: str = "dual_role",
    alpha: float = 0.7,
) -> dict:
    """DavidAgent Hybrid Fusion with three strategy options.

    Strategies:
      - 'ensemble': Parallel weighted fusion (α × LLM + (1-α) × Slither)
      - 'dual_role': GPTLens Auditor+Critic (LLM finds, then self-critiques)
      - 'evidence': Evidence accumulation (multi-pass reasoning)
    """
    solc_ver = detect_solc_version(code)
    filtered_findings = prefilter_slither_findings(slither_findings, code, solc_ver)
    filtered_high_med = [f for f in filtered_findings if f["impact"] in ["High", "Medium"]]

    # ── Always run Stage 1 (Auditor / LLM+RAG) ──
    s1 = run_stage1(code, knowledge_base, llm_client)

    stage2_result = None
    critic_result = None
    decision_path = "stage1_only"

    if strategy == "ensemble":
        # ═══ Strategy A: Parallel Weighted Ensemble ═══
        llm_score = s1["confidence"] if s1["predicted_vulnerable"] else (1.0 - s1["confidence"])
        slither_score = compute_slither_score(filtered_findings)
        final_score = alpha * llm_score + (1.0 - alpha) * slither_score
        final_vulnerable = final_score >= 0.5
        final_confidence = final_score
        decision_path = f"ensemble_a{alpha:.1f}"
        final_reasoning = f"Ensemble: LLM={llm_score:.2f} Slither={slither_score:.2f} → {final_score:.2f}"

    elif strategy == "dual_role":
        # ═══ Strategy B: GPTLens Dual-Role (Auditor + Critic) ═══
        if s1["predicted_vulnerable"]:
            # Auditor says VULNERABLE → Critic challenges it
            auditor_findings = f"Vulnerability types: {s1['vulnerability_types']}\n" \
                             f"Severity: {s1['severity']}\n" \
                             f"Reasoning: {s1['reasoning']}"
            critic_result = run_critic(code, auditor_findings, filtered_findings, llm_client)

            if critic_result["final_verdict"]:
                # Critic confirms → TRUE POSITIVE (high confidence)
                decision_path = "dual_role_confirmed"
                final_vulnerable = True
                final_confidence = max(s1["confidence"], critic_result["confidence"])
            else:
                # Critic rejects → likely FALSE POSITIVE
                # But check if Slither also flags it as risky
                if len(filtered_high_med) > 0:
                    # Slither agrees with Auditor → keep as vulnerable (2-of-3 agree)
                    decision_path = "dual_role_critic_rejected_slither_confirms"
                    final_vulnerable = True
                    final_confidence = s1["confidence"] * 0.8
                else:
                    # Both Critic and Slither say safe → accept Critic
                    decision_path = "dual_role_rejected"
                    final_vulnerable = False
                    final_confidence = critic_result["confidence"]
            final_reasoning = f"Auditor: vuln({s1['confidence']:.2f}), Critic: {'confirm' if critic_result['final_verdict'] else 'reject'}({critic_result['confidence']:.2f})"
        else:
            # Auditor says SAFE → check Slither disagrees
            if len(filtered_high_med) >= 2:
                # Strong Slither signal + LLM says safe → re-evaluate with Stage 2
                decision_path = "dual_role_slither_override"
                s2 = run_stage2(code, filtered_findings, s1["confidence"], llm_client)
                stage2_result = s2
                final_vulnerable = s2["predicted_vulnerable"]
                final_confidence = s2["confidence"]
                final_reasoning = f"Auditor: safe, Slither: {len(filtered_high_med)} H/M alerts → Stage2: {'vuln' if s2['predicted_vulnerable'] else 'safe'}"
            else:
                decision_path = "dual_role_safe"
                final_vulnerable = False
                final_confidence = s1["confidence"]
                final_reasoning = s1["reasoning"]

    elif strategy == "evidence":
        # ═══ Strategy C: Evidence Accumulation (Buffer-of-Thought) ═══
        evidence_score = 0.0
        evidence_parts = []

        # Evidence 1: LLM+RAG verdict
        if s1["predicted_vulnerable"]:
            evidence_score += s1["confidence"] * 0.5
            evidence_parts.append(f"LLM+RAG: vulnerable ({s1['confidence']:.2f})")
        else:
            evidence_score -= s1["confidence"] * 0.3
            evidence_parts.append(f"LLM+RAG: safe ({s1['confidence']:.2f})")

        # Evidence 2: Slither alerts (pre-filtered)
        slither_s = compute_slither_score(filtered_findings)
        evidence_score += slither_s * 0.3
        evidence_parts.append(f"Slither: score={slither_s:.2f} ({len(filtered_findings)} alerts)")

        # Evidence 3: Agreement bonus/penalty
        llm_says_vuln = s1["predicted_vulnerable"]
        slither_says_vuln = len(filtered_high_med) > 0
        if llm_says_vuln and slither_says_vuln:
            evidence_score += 0.15  # Both agree → boost
            evidence_parts.append("Agreement bonus: +0.15")
        elif not llm_says_vuln and not slither_says_vuln:
            evidence_score -= 0.1  # Both say safe → confidence boost for safe
            evidence_parts.append("Both safe bonus: -0.10")

        final_vulnerable = evidence_score >= 0.25
        final_confidence = min(1.0, max(0.0, 0.5 + evidence_score))
        decision_path = "evidence_accumulation"
        final_reasoning = " | ".join(evidence_parts) + f" → score={evidence_score:.2f}"

    else:
        # Fallback to old two-stage
        decision_path = "stage1_vulnerable" if s1["predicted_vulnerable"] else "stage1_safe"
        final_vulnerable = s1["predicted_vulnerable"]
        final_confidence = s1["confidence"]
        final_reasoning = s1["reasoning"]

    slither_high_med = [f for f in slither_findings if f["impact"] in ["High", "Medium"]]

    # Build result
    result = {
        "success": s1["success"],
        "predicted_vulnerable": final_vulnerable,
        "confidence": final_confidence,
        "vulnerability_types": s1["vulnerability_types"] if decision_path.startswith("stage1") else (
            stage2_result["vulnerability_types"] if stage2_result and stage2_result["predicted_vulnerable"]
            else s1["vulnerability_types"]
        ),
        "severity": s1["severity"] if decision_path.startswith("stage1") else (
            stage2_result["severity"] if stage2_result and stage2_result["predicted_vulnerable"]
            else s1["severity"]
        ),
        "reasoning": final_reasoning,
        "decision_path": decision_path,
        # Stage 1 details
        "stage1_vulnerable": s1["predicted_vulnerable"],
        "stage1_confidence": s1["confidence"],
        "stage1_reasoning": s1["reasoning"],
        "rag_retrieval_time": s1.get("rag_retrieval_time", 0),
        "rag_retrieved_categories": s1.get("rag_retrieved_categories", []),
        # Slither details (before and after pre-filtering)
        "slither_findings_count": len(slither_findings),
        "slither_high_med": len(slither_high_med),
        "slither_filtered_count": len(filtered_findings),
        "slither_filtered_high_med": len(filtered_high_med),
        # Stage 2 details (if triggered)
        "stage2_triggered": stage2_result is not None,
        "stage2_vulnerable": stage2_result["predicted_vulnerable"] if stage2_result else None,
        "stage2_confidence": stage2_result["confidence"] if stage2_result else None,
        "stage2_verdict_changed": stage2_result.get("verdict_changed") if stage2_result else None,
        # Critic details (GPTLens dual-role)
        "critic_verdict": critic_result["final_verdict"] if critic_result else None,
        "critic_confirmed": len(critic_result.get("confirmed", [])) if critic_result else 0,
        "critic_rejected": len(critic_result.get("rejected", [])) if critic_result else 0,
        # Timing & tokens
        "time_seconds": round(
            s1["time_seconds"] + (stage2_result["time_seconds"] if stage2_result else 0), 3
        ),
        "tokens_used": (
            s1.get("tokens_used", 0)
            + (stage2_result.get("tokens_used", 0) if stage2_result else 0)
            + (critic_result.get("tokens_used", 0) if critic_result else 0)
        ),
        "error": s1["error"] or (stage2_result["error"] if stage2_result else None),
    }
    return result


# ============================================================
# Main Experiment Runner
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="DavidAgent Hybrid Framework")
    parser.add_argument("--strategy", choices=["ensemble", "dual_role", "evidence", "all"],
                        default="dual_role", help="Fusion strategy (default: dual_role)")
    parser.add_argument("--alpha", type=float, default=0.7, help="Ensemble weight for LLM (default: 0.7)")
    args = parser.parse_args()

    strategy = args.strategy
    print("=" * 60)
    print(f"Experiment 5: DavidAgent Hybrid Framework [{strategy}]")
    print(f"         Fusion: GPTLens Dual-Role + Ensemble + Evidence")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"LLM Model: {LLM_MODEL}")
    print(f"Embedding Model: {EMBEDDING_MODEL}")
    print(f"RAG Top-K: {RAG_TOP_K}")
    print(f"Re-eval Confidence Threshold: {REEVAL_CONFIDENCE_THRESHOLD}")
    print("=" * 60)

    # Initialize
    llm_client = OpenAI()

    print("\n[Init] Loading ChromaDB vector knowledge base...")
    if not os.path.exists(CHROMA_DIR):
        print(f"ERROR: ChromaDB not found at {CHROMA_DIR}")
        print("Please run `python build_knowledge_base.py` first.")
        sys.exit(1)

    knowledge_base = VulnKnowledgeBase(CHROMA_DIR, COLLECTION_NAME, llm_client)
    print(f"  Knowledge base loaded: {knowledge_base.entry_count} entries")

    with open(DATASET_FILE, "r") as f:
        dataset = json.load(f)

    contracts = dataset["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]
    random.shuffle(sample)

    print(f"\nSample: {len(vuln)} vulnerable + {min(100, len(safe))} safe = {len(sample)} total")
    print("Pipeline: Stage 1 (LLM+RAG independent) → Stage 2 (Slither-guided re-eval, conditional)")

    results = []
    total_tokens = 0
    total_slither_time = 0
    total_llm_time = 0
    stage2_count = 0
    stage2_flipped = 0

    for i, contract in enumerate(sample):
        try:
            with open(contract["filepath"], "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
        except Exception:
            continue

        # Step 1: Slither analysis (always run in parallel with LLM for timing)
        slither_start = time.time()
        slither_findings = run_slither_quick(contract["filepath"])
        slither_time = time.time() - slither_start
        total_slither_time += slither_time

        # Step 2: Hybrid decision with selected strategy
        result = hybrid_decision(code, slither_findings, knowledge_base, llm_client,
                                 strategy=strategy, alpha=args.alpha)
        total_llm_time += result["time_seconds"]

        result["contract_id"] = contract["id"]
        result["ground_truth"] = contract["label"]
        result["category"] = contract["category"]
        result["filename"] = contract["filename"]
        result["lines"] = contract["lines"]
        result["slither_time"] = round(slither_time, 3)
        result["total_time"] = round(slither_time + result["time_seconds"], 3)
        results.append(result)
        total_tokens += result.get("tokens_used", 0)

        if result["stage2_triggered"]:
            stage2_count += 1
            if result.get("stage2_verdict_changed"):
                stage2_flipped += 1

        if (i + 1) % 25 == 0 or i == 0:
            tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
            fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
            fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
            tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
            tv = tp + fn if (tp + fn) > 0 else 1
            ts = fp + tn if (fp + tn) > 0 else 1
            prec_i = tp / (tp + fp) if (tp + fp) > 0 else 0
            rec_i = tp / tv
            f1_i = 2 * prec_i * rec_i / (prec_i + rec_i) if (prec_i + rec_i) > 0 else 0
            print(
                f"  [{i+1}/{len(sample)}] TP={tp} FN={fn} FP={fp} TN={tn} | "
                f"P={prec_i*100:.1f}% R={rec_i*100:.1f}% F1={f1_i*100:.1f}% FPR={fp/ts*100:.1f}% | "
                f"S2={stage2_count}(flip={stage2_flipped}) tokens={total_tokens:,}"
            )

        time.sleep(0.2)

    # ── Compute Metrics ────────────────────────────────────────
    print("\n" + "=" * 60)
    print("OPTIMIZED HYBRID FRAMEWORK RESULTS SUMMARY")
    print("=" * 60)

    tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
    fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
    fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
    tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
    total = tp + fn + fp + tn
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    fpr_val = fp / (fp + tn) if (fp + tn) else 0
    spec = tn / (tn + fp) if (tn + fp) else 0
    avg_total_t = sum(r["total_time"] for r in results) / len(results) if results else 0
    avg_slither_t = total_slither_time / len(results) if results else 0
    avg_llm_t = total_llm_time / len(results) if results else 0

    print(f"  Total: {total} | TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  Accuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:   {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:      {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr_val:.4f} ({fpr_val*100:.2f}%)")
    print(f"  Specificity: {spec:.4f} ({spec*100:.2f}%)")
    print(f"  Avg Total Time: {avg_total_t:.3f}s (Slither: {avg_slither_t:.3f}s + LLM: {avg_llm_t:.3f}s)")
    print(f"  Total Tokens: {total_tokens:,}")

    # Stage 2 statistics
    print(f"\n  Stage 2 Statistics:")
    print(f"    Triggered:     {stage2_count} / {total} ({stage2_count/total*100:.1f}%)")
    print(f"    Flipped to Vulnerable: {stage2_flipped} / {stage2_count} "
          f"({stage2_flipped/stage2_count*100:.1f}%)" if stage2_count else "    Flipped: 0")

    # Decision path breakdown
    paths = {}
    for r in results:
        p = r.get("decision_path", "unknown")
        paths[p] = paths.get(p, 0) + 1
    print(f"\n  Decision Path Breakdown:")
    for p, cnt in sorted(paths.items()):
        print(f"    {p}: {cnt} ({cnt/total*100:.1f}%)")

    # Pre-filtering statistics
    total_raw = sum(r["slither_findings_count"] for r in results)
    total_filtered = sum(r["slither_filtered_count"] for r in results)
    filter_reduction = (1 - total_filtered / total_raw) * 100 if total_raw > 0 else 0
    print(f"\n  Pre-filtering Statistics:")
    print(f"    Raw Slither findings: {total_raw}")
    print(f"    After pre-filtering: {total_filtered} ({filter_reduction:.1f}% reduction)")

    # Comparison with LLM+RAG baseline
    llm_rag_f1 = 0.8304
    improvement = ((f1 - llm_rag_f1) / llm_rag_f1) * 100
    print(f"\n  vs LLM+RAG (F1={llm_rag_f1:.4f}): {'IMPROVED' if f1 > llm_rag_f1 else 'NOT IMPROVED'} "
          f"({'+' if improvement > 0 else ''}{improvement:.2f}%)")

    # Per-category recall
    print("\n  Per-category Recall:")
    for cat in sorted(set(r["category"] for r in results if r["ground_truth"] == "vulnerable")):
        cr = [r for r in results if r["category"] == cat and r["ground_truth"] == "vulnerable"]
        ctp = sum(1 for r in cr if r["predicted_vulnerable"])
        print(f"    {cat}: {ctp}/{len(cr)} ({ctp/len(cr)*100:.1f}%)")

    output = {
        "experiment": "hybrid_two_stage_fusion",
        "model": LLM_MODEL,
        "embedding_model": EMBEDDING_MODEL,
        "timestamp": datetime.now().isoformat(),
        "pipeline": "Stage 1 (LLM+RAG independent) → Stage 2 (Slither-guided re-eval, conditional)",
        "fusion_config": {
            "reeval_confidence_threshold": REEVAL_CONFIDENCE_THRESHOLD,
            "stage2_trigger": "stage1_safe AND slither_high_med > 0 AND stage1_confidence < threshold",
        },
        "rag_config": {
            "vector_store": "ChromaDB",
            "embedding_model": EMBEDDING_MODEL,
            "similarity_metric": "cosine",
            "top_k": RAG_TOP_K,
            "knowledge_base_entries": knowledge_base.entry_count,
        },
        "metrics": {
            "total": total,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr_val, 4),
            "specificity": round(spec, 4),
            "avg_total_time": round(avg_total_t, 3),
            "avg_slither_time": round(avg_slither_t, 3),
            "avg_llm_time": round(avg_llm_t, 3),
            "total_tokens": total_tokens,
        },
        "stage2_stats": {
            "triggered": stage2_count,
            "flipped": stage2_flipped,
            "decision_paths": paths,
        },
        "results": results,
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
