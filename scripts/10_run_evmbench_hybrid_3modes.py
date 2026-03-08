#!/usr/bin/env python3
"""
EVMbench Hybrid Three-Mode Comparison Experiment.

Compares three Hybrid integration strategies on EVMbench:
1. ORIGINAL MODE: Slither context fed to LLM, LLM tends to follow Slither
2. VERIFICATION MODE: Slither pre-filter -> LLM as final judge/verifier
3. CONTEXT MODE: LLM always decides, Slither report as advisory reference only

Evaluation metric: detect_score = detected_vulns / total_gold_vulns

This allows measuring how different Slither-LLM integration patterns affect
vulnerability detection on real-world audits.

Prerequisites:
- EVMbench dataset at data/evmbench/audits/
- ChromaDB knowledge base at data/chroma_kb/
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
from datetime import datetime
from typing import Optional, Dict, List, Any

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda: None

import chromadb
from openai import OpenAI

# ========================================================================
# Setup
# ========================================================================

load_dotenv()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)

# Paths
EVMBENCH_DATA_DIR = os.path.join(BASE_DIR, "data", "evmbench", "audits")
EVMBENCH_REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
RESULTS_DIR = os.path.join(BASE_DIR, "experiments", "evmbench")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(EVMBENCH_REPOS_DIR, exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, "logs"), exist_ok=True)

# Logging
LOG_FILE = os.path.join(RESULTS_DIR, "logs", f"3modes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Config
LLM_MODEL = "gpt-4.1-mini"
EMBEDDING_MODEL = "text-embedding-3-small"
COLLECTION_NAME = "vuln_knowledge"
RAG_TOP_K = 5

try:
    client = OpenAI()
except Exception as e:
    logger.error(f"Failed to initialize OpenAI client: {e}")
    sys.exit(1)

SOLC_VERSIONS = {
    "0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12",
    "0.7": "0.7.6", "0.8": "0.8.0",
}

# Shared pre-filters for all modes
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
        """Retrieve top-k vulnerability knowledge entries."""
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
# Repository and File Management
# ========================================================================

def parse_dockerfile(audit_id: str) -> Optional[Dict[str, str]]:
    """Parse Dockerfile for repo URL and commit."""
    dockerfile_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        return None
    try:
        with open(dockerfile_path, 'r') as f:
            content = f.read()
        github_match = re.search(r'https://github\.com/([^\s/]+)/([^\s/.]+)', content)
        commit_match = re.search(r'git checkout\s+([a-f0-9]{40}|[a-f0-9]{7})', content, re.IGNORECASE)
        if not github_match:
            return None
        org = github_match.group(1)
        repo = github_match.group(2)
        url = f"https://github.com/{org}/{repo}.git"
        commit = commit_match.group(1) if commit_match else "HEAD"
        return {"url": url, "commit": commit}
    except Exception:
        return None


def clone_repo_at_commit(audit_id: str, repo_info: Dict[str, str]) -> Optional[str]:
    """Clone repository at specific commit."""
    repo_dir = os.path.join(EVMBENCH_REPOS_DIR, audit_id)
    if os.path.exists(repo_dir) and len(os.listdir(repo_dir)) > 1:
        return repo_dir
    url = repo_info["url"]
    commit = repo_info["commit"]
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_dir],
            capture_output=True, text=True, timeout=120
        )
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
    except Exception:
        return None


def extract_solidity_files(repo_dir: str, max_files: int = 15, max_chars: int = 80000) -> List[Dict]:
    """Extract Solidity files from repo."""
    all_sol = glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True)
    filtered = [f for f in all_sol if not any(
        skip in os.path.relpath(f, repo_dir).lower()
        for skip in ["test/", "tests/", "mock", "node_modules/", "lib/", ".t.sol"]
    )]
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
    return sol_files


def load_audit_config(audit_id: str) -> Dict:
    """Load audit config with gold vulnerabilities."""
    try:
        config_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "config.yaml")
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception:
        return {"vulnerabilities": []}


# ========================================================================
# Slither Analysis (Shared)
# ========================================================================

def detect_solc_version(code: str) -> str:
    """Extract Solidity version from code."""
    match = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def run_slither_quick(filepath: str) -> List[Dict]:
    """Run Slither analysis on single file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        ver = detect_solc_version(code)
        subprocess.run(["solc-select", "use", ver], capture_output=True, timeout=5)
        r = subprocess.run(
            ["slither", filepath, "--json", "-"],
            capture_output=True, text=True, timeout=30,
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
    """Pre-filter Slither findings (shared across modes)."""
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


def run_slither_all_files(sol_files: List[Dict], repo_dir: str) -> Dict[str, List[Dict]]:
    """Run Slither on all source files, return findings per file."""
    all_findings = {}
    for sf in sol_files:
        file_path = os.path.join(repo_dir, sf["path"])
        findings = run_slither_quick(file_path)
        all_findings[sf["path"]] = prefilter_slither_findings(
            findings, sf["content"], detect_solc_version(sf["content"])
        )
    return all_findings


# ========================================================================
# Mode Implementations
# ========================================================================

def run_mode_original(contract_text: str, slither_findings_text: str, knowledge_base: VulnKnowledgeBase) -> Dict:
    """Mode 1: Original - Slither context directly to LLM."""
    retrieved = knowledge_base.retrieve(contract_text, top_k=RAG_TOP_K)
    rag_context = build_rag_context(retrieved)

    prompt = f"""You are an expert auditor. Analyze this code for HIGH severity vulnerabilities.

## RAG Knowledge:
{rag_context}

## Static Analysis (Slither) Findings:
{slither_findings_text}

## Code:
{contract_text[:5000]}

Based on the code and Slither findings, identify vulnerabilities.

Output JSON:
{{"vulnerabilities": [{{"title": "...", "summary": "..."}}]}}"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=2000, seed=42
        )
        content = resp.choices[0].message.content.strip()
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            else:
                json_str = content
            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except Exception:
            vulns = []
        return {"success": True, "vulns": vulns}
    except Exception as e:
        return {"success": False, "vulns": [], "error": str(e)}


def run_mode_verification(contract_text: str, slither_findings_text: str, knowledge_base: VulnKnowledgeBase) -> Dict:
    """Mode 2: Verification - LLM is final judge with pre-filtered Slither."""
    retrieved = knowledge_base.retrieve(contract_text, top_k=RAG_TOP_K)
    rag_context = build_rag_context(retrieved)

    prompt = f"""You are a security auditor. Verify if this code has HIGH severity vulnerabilities.

## RAG Knowledge:
{rag_context}

## Code:
{contract_text[:5000]}

## Slither Pre-Filtered Alerts (for reference only):
{slither_findings_text}

Make your own assessment. Slither alerts are hints only, not definitive.

Output JSON:
{{"vulnerabilities": [{{"title": "...", "summary": "..."}}]}}"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=2000, seed=42
        )
        content = resp.choices[0].message.content.strip()
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            else:
                json_str = content
            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except Exception:
            vulns = []
        return {"success": True, "vulns": vulns}
    except Exception as e:
        return {"success": False, "vulns": [], "error": str(e)}


def run_mode_context(contract_text: str, slither_findings_text: str, knowledge_base: VulnKnowledgeBase) -> Dict:
    """Mode 3: Context - LLM primary, Slither as context."""
    retrieved = knowledge_base.retrieve(contract_text, top_k=RAG_TOP_K)
    rag_context = build_rag_context(retrieved)

    prompt = f"""You are a security auditor. Analyze this code independently for vulnerabilities.

## RAG Knowledge:
{rag_context}

## Code:
{contract_text[:5000]}

Note: Slither output below is CONTEXT only. Make your own assessment.

## Slither Output:
{slither_findings_text}

Output JSON:
{{"vulnerabilities": [{{"title": "...", "summary": "..."}}]}}"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=2000, seed=42
        )
        content = resp.choices[0].message.content.strip()
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            else:
                json_str = content
            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except Exception:
            vulns = []
        return {"success": True, "vulns": vulns}
    except Exception as e:
        return {"success": False, "vulns": [], "error": str(e)}


# ========================================================================
# Judging
# ========================================================================

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


def judge_detection(found_vulns: List[Dict], gold_vulns: List[Dict], audit_id: str = "") -> int:
    """Judge how many gold vulns were detected."""
    detected = 0
    for gv in gold_vulns:
        vuln_id = gv.get("id", "unknown")
        vuln_title = gv.get("title", "unknown")
        vuln_description = load_finding_description(audit_id, vuln_id) if audit_id else ""
        our_findings = json.dumps(found_vulns, indent=2)

        judge_prompt = f"""Did we detect this vulnerability?

Target: {vuln_id} - {vuln_title}
Description: {vuln_description}

Our findings: {our_findings}

Criteria: DETECTED = identifies SAME root cause and vulnerable code.

Respond JSON: {{"detected": true/false, "reasoning": "brief explanation"}}"""

        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0, max_tokens=300
            )
            content = response.choices[0].message.content.strip()
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content
            result = json.loads(json_str)
            if result.get("detected"):
                detected += 1
        except Exception:
            pass
        time.sleep(0.1)

    return detected


# ========================================================================
# Main
# ========================================================================

def main():
    logger.info("=" * 70)
    logger.info("EVMbench Three-Mode Hybrid Comparison")
    logger.info("=" * 70)

    if not os.path.exists(CHROMA_DIR):
        logger.error(f"ERROR: ChromaDB not found at {CHROMA_DIR}")
        sys.exit(1)

    try:
        knowledge_base = VulnKnowledgeBase(CHROMA_DIR, COLLECTION_NAME, client)
        logger.info(f"Knowledge base loaded: {knowledge_base.entry_count} entries")
    except Exception as e:
        logger.error(f"Failed to load knowledge base: {e}")
        sys.exit(1)

    all_results = {
        "original": {"total_vulns": 0, "total_detected": 0, "audits": []},
        "verification": {"total_vulns": 0, "total_detected": 0, "audits": []},
        "context": {"total_vulns": 0, "total_detected": 0, "audits": []},
    }

    for i, audit_id in enumerate(SAMPLE_AUDITS):
        logger.info(f"\n[{i+1}/{len(SAMPLE_AUDITS)}] {audit_id}")

        # Load config
        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        if not gold_vulns:
            continue

        # Clone and extract files
        repo_info = parse_dockerfile(audit_id)
        if not repo_info:
            continue

        repo_dir = clone_repo_at_commit(audit_id, repo_info)
        if not repo_dir:
            continue

        sol_files = extract_solidity_files(repo_dir)
        if not sol_files:
            continue

        # Build contract text
        contract_text = ""
        for sf in sol_files:
            contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
        if len(contract_text) > 60000:
            contract_text = contract_text[:60000] + "\n// (truncated)"

        # Run Slither once for all modes (shared)
        logger.info("  Running Slither...")
        slither_all_findings = run_slither_all_files(sol_files, repo_dir)
        slither_text = json.dumps(slither_all_findings, indent=2)

        # Run three modes
        logger.info("  Mode 1: Original...")
        mode1 = run_mode_original(contract_text, slither_text, knowledge_base)
        detected1 = judge_detection(mode1.get("vulns", []), gold_vulns, audit_id) if mode1["success"] else 0

        logger.info("  Mode 2: Verification...")
        mode2 = run_mode_verification(contract_text, slither_text, knowledge_base)
        detected2 = judge_detection(mode2.get("vulns", []), gold_vulns, audit_id) if mode2["success"] else 0

        logger.info("  Mode 3: Context...")
        mode3 = run_mode_context(contract_text, slither_text, knowledge_base)
        detected3 = judge_detection(mode3.get("vulns", []), gold_vulns, audit_id) if mode3["success"] else 0

        logger.info(f"  Results: Original={detected1}/{len(gold_vulns)} Verification={detected2}/{len(gold_vulns)} Context={detected3}/{len(gold_vulns)}")

        all_results["original"]["total_vulns"] += len(gold_vulns)
        all_results["original"]["total_detected"] += detected1
        all_results["original"]["audits"].append({
            "audit_id": audit_id,
            "num_gold": len(gold_vulns),
            "detected": detected1
        })

        all_results["verification"]["total_vulns"] += len(gold_vulns)
        all_results["verification"]["total_detected"] += detected2
        all_results["verification"]["audits"].append({
            "audit_id": audit_id,
            "num_gold": len(gold_vulns),
            "detected": detected2
        })

        all_results["context"]["total_vulns"] += len(gold_vulns)
        all_results["context"]["total_detected"] += detected3
        all_results["context"]["audits"].append({
            "audit_id": audit_id,
            "num_gold": len(gold_vulns),
            "detected": detected3
        })

        time.sleep(2)

    # Calculate scores
    for mode in all_results:
        total = all_results[mode]["total_vulns"]
        detected = all_results[mode]["total_detected"]
        all_results[mode]["score"] = round(detected / total, 4) if total > 0 else 0

    summary = {
        "experiment": "EVMbench Three-Mode Comparison",
        "model": LLM_MODEL,
        "timestamp": datetime.now().isoformat(),
        "results": all_results,
        "comparison": {
            "original_score": all_results["original"]["score"],
            "verification_score": all_results["verification"]["score"],
            "context_score": all_results["context"]["score"],
            "best_mode": max(
                [("original", all_results["original"]["score"]),
                 ("verification", all_results["verification"]["score"]),
                 ("context", all_results["context"]["score"])],
                key=lambda x: x[1]
            )[0]
        }
    }

    logger.info("\n" + "=" * 70)
    logger.info("COMPARISON SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Original:     {all_results['original']['total_detected']}/{all_results['original']['total_vulns']} ({all_results['original']['score']:.2%})")
    logger.info(f"Verification: {all_results['verification']['total_detected']}/{all_results['verification']['total_vulns']} ({all_results['verification']['score']:.2%})")
    logger.info(f"Context:      {all_results['context']['total_detected']}/{all_results['context']['total_vulns']} ({all_results['context']['score']:.2%})")
    logger.info(f"Best: {summary['comparison']['best_mode']}")

    results_path = os.path.join(RESULTS_DIR, "evmbench_3modes_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
