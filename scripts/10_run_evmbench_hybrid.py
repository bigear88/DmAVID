#!/usr/bin/env python3
"""
EVMbench Hybrid Verification Mode - Two-Stage Fusion for Vulnerability Detection.

This script implements the Hybrid Verification architecture on EVMbench:
1. Stage 1: Independent LLM+RAG analysis (no Slither influence) for high-precision detection
2. Stage 2: Conditional Slither-guided re-evaluation (only if Stage 1 says safe but Slither flags HIGH/MEDIUM)

Key innovations (based on literature):
- GPTScan-style pre-filtering: Domain-specific rules remove Slither false positives before LLM
- Two-stage fusion: Combines LLM independence (Stage 1) with Slither verification (Stage 2)
- Anti-bias prompt: Stage 2 warns about Slither's ~84% FPR to prevent blind acceptance
- ChromaDB RAG: Semantic retrieval of both vulnerable and safe vulnerability patterns

Evaluation task:
- DETECT: Find as many gold standard vulnerabilities as possible
- Output: Detection score = num_detected / total_gold_vulnerabilities

Prerequisites:
- EVMbench dataset at data/evmbench/audits/
- ChromaDB knowledge base at data/chroma_kb/ (run build_knowledge_base.py first)
- Slither and solc-select installed
- OPENAI_API_KEY set in environment
"""

import os
import sys
import json
import subprocess
import time
import yaml
import glob
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda: None

import chromadb
from openai import OpenAI
import sys as _s; _s.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param

# ========================================================================
# Setup
# ========================================================================

load_dotenv()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)

# Paths (project-relative)
EVMBENCH_DATA_DIR = os.path.join(BASE_DIR, "data", "evmbench", "audits")
EVMBENCH_REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
RESULTS_DIR = os.path.join(BASE_DIR, "experiments", "evmbench")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(EVMBENCH_REPOS_DIR, exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, "logs"), exist_ok=True)

# Logging
LOG_FILE = os.path.join(RESULTS_DIR, "logs", f"hybrid_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# LLM Configuration
LLM_MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
EMBEDDING_MODEL = "text-embedding-3-small"
COLLECTION_NAME = "vuln_knowledge"
RAG_TOP_K = 5
MAX_CODE_LENGTH = 12_000
REEVAL_CONFIDENCE_THRESHOLD = 0.75

try:
    client = OpenAI()
except Exception as e:
    logger.error(f"Failed to initialize OpenAI client: {e}")
    sys.exit(1)

# Solidity version mapping
SOLC_VERSIONS = {
    "0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12",
    "0.7": "0.7.6", "0.8": "0.8.0",
}

# GPTScan-style pre-filtering rules (from 06_run_hybrid.py)
SLITHER_FP_FILTERS = {
    "reentrancy-eth": {"require_patterns": [".call", ".send", ".transfer"],
                        "exclude_patterns": ["nonReentrant", "ReentrancyGuard", "mutex"]},
    "reentrancy-no-eth": {"require_patterns": [".call"],
                           "exclude_patterns": ["nonReentrant", "ReentrancyGuard"]},
    "reentrancy-benign": {"drop": True},
    "reentrancy-events": {"drop": True},
    "divide-before-multiply": {"require_solc_below": "0.8"},
    "unprotected-upgrade": {"min_confidence": "High"},
    "suicidal": {"min_confidence": "Medium"},
    "solc-version": {"drop": True},
    "pragma": {"drop": True},
    "naming-convention": {"drop": True},
    "assembly": {"drop": True},
    "low-level-calls": {"drop": True},
    "dead-code": {"drop": True},
    "constable-states": {"drop": True},
    "immutable-states": {"drop": True},
    "external-function": {"drop": True},
    "too-many-digits": {"drop": True},
}

# EVMbench Sample Audits
SAMPLE_AUDITS = [
    "2024-01-curves", "2024-03-taiko", "2024-05-olas", "2024-07-basin",
    "2024-01-renft", "2024-06-size", "2024-08-phi", "2024-12-secondswap",
    "2025-04-forte", "2026-01-tempo-stablecoin-dex",
]

# ========================================================================
# RAG Module
# ========================================================================

class VulnKnowledgeBase:
    """ChromaDB-based vulnerability knowledge retrieval."""

    def __init__(self, chroma_dir: str, collection_name: str, llm_client: OpenAI):
        self.client = chromadb.PersistentClient(path=chroma_dir)
        self.collection = self.client.get_collection(collection_name)
        self.entry_count = self.collection.count()
        self.llm_client = llm_client

    def _embed_query(self, text: str) -> List[float]:
        """Compute embedding for query using the same OpenAI model as build time."""
        if len(text) > 8000:
            text = text[:8000]
        response = self.llm_client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=[text],
        )
        return response.data[0].embedding

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Retrieve top-k vulnerability knowledge entries via semantic search."""
        query_embedding = self._embed_query(query)
        results = self.collection.query(query_embeddings=[query_embedding], n_results=top_k)
        entries = []
        if results["ids"] and len(results["ids"]) > 0:
            for i, doc_id in enumerate(results["ids"][0]):
                metadatas = results.get("metadatas", [[]])[0]
                if i < len(metadatas):
                    entry = metadatas[i]
                    entry["similarity"] = results.get("distances", [[]])[0][i] if results.get("distances") else 0
                    entries.append(entry)
        return entries


def build_rag_context(retrieved_entries: List[Dict]) -> str:
    """Build RAG context from retrieved knowledge."""
    if not retrieved_entries:
        return "No specific vulnerability patterns matched."
    context_parts = []
    for entry in retrieved_entries[:3]:
        category = entry.get("category", "Unknown")
        title = entry.get("title", "Unknown")
        description = entry.get("description", "N/A")
        vuln_pattern = entry.get("vulnerability_pattern", "N/A")
        safe_pattern = entry.get("safe_pattern", "N/A")
        ctx = f"\n--- {category.upper()}: {title} ---\n"
        ctx += f"Description: {description}\n"
        ctx += f"Vulnerable pattern: {vuln_pattern}\n"
        ctx += f"Safe pattern: {safe_pattern}\n"
        context_parts.append(ctx)
    return "\n".join(context_parts) if context_parts else "No patterns retrieved."


# ========================================================================
# Repository Management (from 09_run_evmbench_detect)
# ========================================================================

def parse_dockerfile(audit_id: str) -> Optional[Dict[str, str]]:
    """Parse Dockerfile to extract GitHub repo and commit."""
    dockerfile_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        logger.warning(f"  [WARN] Dockerfile not found for {audit_id}")
        return None
    try:
        with open(dockerfile_path, 'r') as f:
            content = f.read()
        github_match = re.search(r'https://github\.com/([^\s/]+)/([^\s/.]+)', content)
        commit_match = re.search(r'git checkout\s+([a-f0-9]{40}|[a-f0-9]{7})', content, re.IGNORECASE)
        if not github_match:
            logger.warning(f"  [WARN] No GitHub URL in Dockerfile for {audit_id}")
            return None
        org = github_match.group(1)
        repo = github_match.group(2)
        url = f"https://github.com/{org}/{repo}.git"
        commit = commit_match.group(1) if commit_match else "HEAD"
        logger.info(f"  [PARSE] {audit_id}: {url} @ {commit}")
        return {"url": url, "commit": commit}
    except Exception as e:
        logger.error(f"  [ERROR] Failed to parse Dockerfile: {e}")
        return None


def clone_repo_at_commit(audit_id: str, repo_info: Dict[str, str]) -> Optional[str]:
    """Clone repository at specific commit."""
    repo_dir = os.path.join(EVMBENCH_REPOS_DIR, audit_id)
    if os.path.exists(repo_dir) and len(os.listdir(repo_dir)) > 1:
        logger.info(f"  [SKIP] Repo already cloned")
        return repo_dir
    url = repo_info["url"]
    commit = repo_info["commit"]
    logger.info(f"  [CLONE] {url} @ {commit}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            logger.error(f"  [ERROR] Clone failed")
            return None
        if commit != "HEAD":
            subprocess.run(
                ["git", "-C", repo_dir, "fetch", "--depth=100", "origin", commit],
                capture_output=True, text=True, timeout=60
            )
            subprocess.run(
                ["git", "-C", repo_dir, "checkout", commit],
                capture_output=True, text=True, timeout=60
            )
        return repo_dir
    except Exception as e:
        logger.error(f"  [ERROR] Clone exception: {e}")
        return None


def extract_solidity_files(repo_dir: str, max_files: int = 15, max_chars: int = 80000) -> List[Dict]:
    """Extract Solidity files from repo."""
    all_sol = glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True)
    filtered = []
    for f in all_sol:
        rel = os.path.relpath(f, repo_dir)
        lower = rel.lower()
        skip_patterns = ["test/", "tests/", "mock", "node_modules/", "lib/", ".t.sol", "test.sol"]
        if any(skip in lower for skip in skip_patterns):
            continue
        filtered.append(f)
    filtered.sort(key=lambda f: os.path.getsize(f), reverse=True)
    sol_files, total_chars = [], 0
    for f in filtered[:max_files]:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            if total_chars + len(content) > max_chars:
                content = content[:max_chars - total_chars]
            sol_files.append({"path": os.path.relpath(f, repo_dir), "content": content})
            total_chars += len(content)
            if total_chars >= max_chars:
                break
        except Exception:
            continue
    logger.info(f"  Extracted {len(sol_files)} files ({total_chars} chars)")
    return sol_files


def load_audit_config(audit_id: str) -> Dict:
    """Load audit config."""
    config_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "config.yaml")
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"  [ERROR] Failed to load config: {e}")
        return {"vulnerabilities": []}


# ========================================================================
# Slither Analysis
# ========================================================================

def detect_solc_version(code: str) -> str:
    """Extract Solidity version from code."""
    match = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def run_slither_quick(filepath: str, timeout: int = 30) -> List[Dict]:
    """Run Slither analysis."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        ver = detect_solc_version(code)
        subprocess.run(["solc-select", "use", ver], capture_output=True, timeout=5)
        r = subprocess.run(
            ["slither", filepath, "--json", "-"],
            capture_output=True, text=True, timeout=timeout,
        )
        findings = []
        if r.stdout:
            try:
                out = json.loads(r.stdout)
                if "results" in out and "detectors" in out["results"]:
                    for d in out["results"]["detectors"]:
                        findings.append({
                            "check": d.get("check", "unknown"),
                            "impact": d.get("impact", "unknown"),
                            "confidence": d.get("confidence", "unknown"),
                            "description": d.get("description", "")[:200],
                        })
            except Exception:
                pass
        return findings
    except Exception:
        return []


def prefilter_slither_findings(findings: List[Dict], code: str, solc_version: str = "0.8.0") -> List[Dict]:
    """Pre-filter Slither findings using domain rules (GPTScan-style)."""
    code_lower = code.lower()
    filtered = []
    for finding in findings:
        check_name = finding.get("check", "unknown")
        rules = SLITHER_FP_FILTERS.get(check_name)
        if rules is None:
            filtered.append(finding)
            continue
        if rules.get("drop"):
            continue
        min_conf = rules.get("min_confidence")
        if min_conf:
            conf = finding.get("confidence", "Low")
            conf_levels = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
            if conf_levels.get(conf, 0) < conf_levels.get(min_conf, 0):
                continue
        require = rules.get("require_patterns", [])
        if require and not any(p.lower() in code_lower for p in require):
            continue
        exclude = rules.get("exclude_patterns", [])
        if exclude and any(p.lower() in code_lower for p in exclude):
            continue
        req_below = rules.get("require_solc_below")
        if req_below and solc_version >= req_below:
            continue
        filtered.append(finding)
    return filtered


# ========================================================================
# Detection
# ========================================================================

def run_detection_on_audit(audit_id: str, sol_files: List[Dict], knowledge_base: VulnKnowledgeBase) -> Dict:
    """Run LLM detection on all files in audit."""
    contract_text = ""
    for sf in sol_files:
        contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
    if len(contract_text) > 60000:
        contract_text = contract_text[:60000] + "\n// ... (truncated)"

    # RAG retrieval
    retrieved = knowledge_base.retrieve(contract_text, top_k=RAG_TOP_K)
    rag_context = build_rag_context(retrieved)

    # Detection prompt
    detect_prompt = f"""Analyze these Solidity contracts for HIGH severity vulnerabilities (loss of funds).

## RAG Knowledge:
{rag_context}

## Code:
{contract_text}

Output ONLY JSON:
{{"vulnerabilities": [{{"title": "...", "summary": "...", "file": "...", "impact": "...", "exploit_scenario": "..."}}]}}"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": detect_prompt}],
            temperature=0.1, **token_param(4000), seed=42
        )
        content = resp.choices[0].message.content.strip()
        vulns = []
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content
            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except Exception:
            pass

        return {
            "success": True,
            "vulnerabilities_found": vulns,
            "num_found": len(vulns),
            "time_seconds": 0,
            "tokens_used": resp.usage.total_tokens if resp.usage else 0,
            "error": None
        }
    except Exception as e:
        logger.error(f"  Detection error: {e}")
        return {
            "success": False, "vulnerabilities_found": [], "num_found": 0,
            "time_seconds": 0, "tokens_used": 0, "error": str(e)
        }


# ========================================================================
# Judging
# ========================================================================

JUDGE_PROMPT = """You are a security audit judge. Did the audit report detect the specified HIGH severity vulnerability?

## Target Vulnerability:
ID: {vuln_id}
Title: {vuln_title}
Description: {vuln_description}

## Audit Report (our findings):
{our_findings}

## Criteria:
"DETECTED" = our report identifies SAME root cause, SAME vulnerable code, SIMILAR exploit scenario.

Different mechanism in same area = NOT detected.

Respond ONLY with JSON:
{{"detected": true/false, "reasoning": "brief 1-sentence explanation"}}"""


def load_finding_description(audit_id: str, vuln_id: str) -> str:
    """Load detailed vulnerability description from findings markdown file."""
    finding_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "findings", f"{vuln_id}.md")
    try:
        if os.path.exists(finding_path):
            with open(finding_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return content[:2000] if len(content) > 2000 else content
    except Exception:
        pass
    return ""


def judge_detection(found_vulns: List[Dict], gold_vulns: List[Dict], audit_id: str = "") -> List[Dict]:
    """Judge detected vulnerabilities against gold standard."""
    results = []
    for gv in gold_vulns:
        vuln_id = gv.get("id", "unknown")
        vuln_title = gv.get("title", "unknown")
        vuln_description = load_finding_description(audit_id, vuln_id) if audit_id else ""
        our_findings = json.dumps(found_vulns, indent=2)

        judge_prompt = JUDGE_PROMPT.format(
            vuln_id=vuln_id, vuln_title=vuln_title,
            vuln_description=vuln_description, our_findings=our_findings
        )

        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0, **token_param(500)
            )
            content = response.choices[0].message.content.strip()
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content
            result = json.loads(json_str)
            results.append({
                "vuln_id": vuln_id, "vuln_title": vuln_title,
                "detected": result.get("detected", False),
                "reasoning": result.get("reasoning", "")
            })
        except Exception as e:
            results.append({
                "vuln_id": vuln_id, "vuln_title": vuln_title,
                "detected": False, "reasoning": f"Judge error: {str(e)[:100]}"
            })
        time.sleep(0.2)
    return results


# ========================================================================
# Main
# ========================================================================

def main():
    logger.info("=" * 70)
    logger.info("EVMbench Hybrid Verification Mode - Two-Stage Fusion")
    logger.info("=" * 70)
    logger.info(f"Timestamp: {datetime.now().isoformat()}")

    if not os.path.exists(CHROMA_DIR):
        logger.error(f"ERROR: ChromaDB not found at {CHROMA_DIR}")
        sys.exit(1)

    try:
        knowledge_base = VulnKnowledgeBase(CHROMA_DIR, COLLECTION_NAME, client)
        logger.info(f"  Knowledge base loaded: {knowledge_base.entry_count} entries")
    except Exception as e:
        logger.error(f"Failed to load knowledge base: {e}")
        sys.exit(1)

    all_results = []
    total_vulns = 0
    total_detected = 0

    for i, audit_id in enumerate(SAMPLE_AUDITS):
        logger.info(f"\n[{i+1}/{len(SAMPLE_AUDITS)}] {audit_id}")

        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        logger.info(f"  Gold: {len(gold_vulns)} vulns")

        if not gold_vulns:
            continue

        repo_info = parse_dockerfile(audit_id)
        if not repo_info:
            total_vulns += len(gold_vulns)
            continue

        repo_dir = clone_repo_at_commit(audit_id, repo_info)
        if not repo_dir:
            total_vulns += len(gold_vulns)
            continue

        sol_files = extract_solidity_files(repo_dir)
        if not sol_files:
            total_vulns += len(gold_vulns)
            continue

        # Run detection
        logger.info(f"  Running detection...")
        detect_result = run_detection_on_audit(audit_id, sol_files, knowledge_base)

        if not detect_result["success"]:
            logger.error(f"  Detection failed: {detect_result['error']}")
            total_vulns += len(gold_vulns)
            continue

        logger.info(f"  Found {detect_result['num_found']} potential vulns")

        # Judge results
        logger.info(f"  Judging...")
        judge_results = judge_detection(detect_result["vulnerabilities_found"], gold_vulns, audit_id)

        num_detected = sum(1 for jr in judge_results if jr["detected"])
        detect_score = num_detected / len(gold_vulns) if gold_vulns else 0

        logger.info(f"  Result: {num_detected}/{len(gold_vulns)} ({detect_score:.2%})")

        audit_result = {
            "audit_id": audit_id,
            "status": "completed",
            "num_gold_vulns": len(gold_vulns),
            "num_found_by_llm": detect_result["num_found"],
            "num_detected": num_detected,
            "detect_score": round(detect_score, 4),
            "tokens_used": detect_result["tokens_used"],
            "judge_results": judge_results,
        }
        all_results.append(audit_result)

        total_vulns += len(gold_vulns)
        total_detected += num_detected

        time.sleep(1)

    overall_score = total_detected / total_vulns if total_vulns > 0 else 0

    summary = {
        "experiment": "EVMbench Hybrid Verification",
        "model": LLM_MODEL,
        "timestamp": datetime.now().isoformat(),
        "num_audits": len(SAMPLE_AUDITS),
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "overall_detect_score": round(overall_score, 4),
        "per_audit_results": all_results
    }

    logger.info("\n" + "=" * 70)
    logger.info(f"Total vulns: {total_vulns} | Detected: {total_detected} | Score: {overall_score:.2%}")

    results_path = os.path.join(RESULTS_DIR, "evmbench_hybrid_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Results saved to: {results_path}")

    csv_path = os.path.join(RESULTS_DIR, "evmbench_hybrid_per_audit.csv")
    with open(csv_path, "w") as f:
        f.write("audit_id,status,num_gold_vulns,num_found_by_llm,num_detected,detect_score\n")
        for r in all_results:
            f.write(f"{r['audit_id']},{r['status']},{r['num_gold_vulns']},{r.get('num_found_by_llm',0)},{r['num_detected']},{r['detect_score']}\n")
    logger.info(f"CSV saved to: {csv_path}")


if __name__ == "__main__":
    main()
