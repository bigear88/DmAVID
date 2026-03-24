#!/usr/bin/env python3
"""
EVMbench Detect Task - LLM+RAG Enhanced Detection on Gold Standard Vulnerabilities.

This script:
1. Loads EVMbench audits from the dataset (parsing Dockerfile for GitHub repo + commit)
2. Clones repositories at the specified commit hash
3. Extracts Solidity source files
4. Runs LLM+RAG detection to find vulnerabilities
5. Uses an LLM judge to evaluate if detected vulnerabilities match gold standard findings
6. Reports detection score (detected / total_gold_vulnerabilities) per audit and overall

Architecture:
- Uses ChromaDB for RAG knowledge retrieval (semantic vector search)
- Implements GPTScan-style pre-filtering patterns
- Supports project-relative paths (SCRIPT_DIR/BASE_DIR pattern)
- Uses dotenv for OPENAI_API_KEY

Output:
- JSON results with per-audit detection scores
- CSV summary for analysis
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

# Logging setup
LOG_FILE = os.path.join(RESULTS_DIR, "logs", f"detect_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
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

try:
    client = OpenAI()
except Exception as e:
    logger.error(f"Failed to initialize OpenAI client: {e}")
    sys.exit(1)

# EVMbench Sample Audits (10 selected, 25% of 40)
SAMPLE_AUDITS = [
    "2024-01-curves",                  # 4 vulns, DeFi curves
    "2024-03-taiko",                   # 5 vulns, L2
    "2024-05-olas",                    # 2 vulns, tokenomics
    "2024-07-basin",                   # 2 vulns, DeFi
    "2024-01-renft",                   # 6 vulns, NFT rental
    "2024-06-size",                    # 4 vulns, lending
    "2024-08-phi",                     # 6 vulns, social
    "2024-12-secondswap",              # 3 vulns, DEX
    "2025-04-forte",                   # 5 vulns, recent
    "2026-01-tempo-stablecoin-dex",    # 2 vulns, latest
]

# ========================================================================
# RAG Module Integration (from 05_run_llm_rag)
# ========================================================================

class VulnKnowledgeBase:
    """ChromaDB-based vulnerability knowledge retrieval for RAG."""

    def __init__(self, chroma_dir: str, collection_name: str, llm_client: OpenAI):
        """Initialize ChromaDB client and load collection."""
        self.client = chromadb.PersistentClient(path=chroma_dir)
        self.collection = self.client.get_collection(collection_name)
        self.entry_count = self.collection.count()
        self.llm_client = llm_client

    def _embed_query(self, text: str) -> List[float]:
        """Compute embedding for query using the same OpenAI model as build time."""
        # Truncate very long queries to avoid token limits
        if len(text) > 8000:
            text = text[:8000]
        response = self.llm_client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=[text],
        )
        return response.data[0].embedding

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Retrieve top-k most similar vulnerability knowledge entries."""
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
    """Build RAG context from retrieved vulnerability knowledge entries."""
    if not retrieved_entries:
        return "No specific vulnerability patterns matched in knowledge base."

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

    return "\n".join(context_parts) if context_parts else "No vulnerability patterns retrieved."


# ========================================================================
# Dockerfile Parsing and Repository Cloning
# ========================================================================

def parse_dockerfile(audit_id: str) -> Optional[Dict[str, str]]:
    """Parse Dockerfile to extract GitHub repo URL and commit hash.

    Returns:
        Dict with 'url' and 'commit' keys, or None if not found
    """
    dockerfile_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "Dockerfile")

    if not os.path.exists(dockerfile_path):
        logger.warning(f"  [WARN] Dockerfile not found for {audit_id}")
        return None

    try:
        with open(dockerfile_path, 'r') as f:
            content = f.read()

        # Parse GitHub URL and commit hash from Dockerfile
        # Look for lines like: RUN git clone https://github.com/org/repo.git /app && \
        #                      cd /app && git checkout abc123def456...

        github_match = re.search(r'https://github\.com/([^\s/]+)/([^\s/.]+)', content)
        commit_match = re.search(r'git checkout\s+([a-f0-9]{40}|[a-f0-9]{7})', content, re.IGNORECASE)

        if not github_match:
            logger.warning(f"  [WARN] No GitHub URL found in Dockerfile for {audit_id}")
            return None

        org = github_match.group(1)
        repo = github_match.group(2)
        url = f"https://github.com/{org}/{repo}.git"

        commit = commit_match.group(1) if commit_match else "HEAD"

        logger.info(f"  [PARSE] {audit_id}: {url} @ {commit}")
        return {"url": url, "commit": commit}

    except Exception as e:
        logger.error(f"  [ERROR] Failed to parse Dockerfile for {audit_id}: {e}")
        return None


def clone_repo_at_commit(audit_id: str, repo_info: Dict[str, str]) -> Optional[str]:
    """Clone repository at specific commit hash."""
    repo_dir = os.path.join(EVMBENCH_REPOS_DIR, audit_id)

    if os.path.exists(repo_dir) and len(os.listdir(repo_dir)) > 1:
        logger.info(f"  [SKIP] Repo already cloned: {audit_id}")
        return repo_dir

    url = repo_info["url"]
    commit = repo_info["commit"]

    logger.info(f"  [CLONE] {url} @ {commit}")

    try:
        # Clone with depth=1 for speed, then checkout specific commit
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_dir],
            capture_output=True, text=True, timeout=120
        )

        if result.returncode != 0:
            logger.error(f"  [ERROR] Clone failed: {result.stderr[:200]}")
            return None

        # Checkout specific commit if not HEAD
        if commit != "HEAD":
            result = subprocess.run(
                ["git", "-C", repo_dir, "fetch", "--depth=100", "origin", commit],
                capture_output=True, text=True, timeout=60
            )

            result = subprocess.run(
                ["git", "-C", repo_dir, "checkout", commit],
                capture_output=True, text=True, timeout=60
            )

            if result.returncode != 0:
                logger.warning(f"  [WARN] Failed to checkout {commit}, using HEAD")

        return repo_dir

    except subprocess.TimeoutExpired:
        logger.error(f"  [ERROR] Clone timeout for {audit_id}")
        return None
    except Exception as e:
        logger.error(f"  [ERROR] Clone exception: {e}")
        return None


# ========================================================================
# Solidity File Extraction
# ========================================================================

def extract_solidity_files(repo_dir: str, max_files: int = 15, max_chars: int = 80000) -> List[Dict]:
    """Extract Solidity source files from the repository."""
    sol_files = []

    # Find all .sol files recursively
    all_sol = glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True)

    # Filter out test files, mocks, interfaces, vendor code
    filtered = []
    for f in all_sol:
        rel = os.path.relpath(f, repo_dir)
        lower = rel.lower()

        skip_patterns = [
            "test/", "tests/", "mock", "node_modules/", "lib/",
            ".t.sol", "test.sol", "hardhat", "truffle", "contracts/test",
            ".d.ts"  # TypeScript declaration files
        ]

        if any(skip in lower for skip in skip_patterns):
            continue

        filtered.append(f)

    if not filtered:
        logger.warning(f"  [WARN] No Solidity files found in {repo_dir}")
        return []

    # Sort by file size (larger files first, more likely to contain main logic)
    filtered.sort(key=lambda f: os.path.getsize(f), reverse=True)

    total_chars = 0
    for f in filtered[:max_files]:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()

            if total_chars + len(content) > max_chars:
                content = content[:max_chars - total_chars]

            sol_files.append({
                "path": os.path.relpath(f, repo_dir),
                "content": content
            })

            total_chars += len(content)
            if total_chars >= max_chars:
                break

        except Exception as e:
            logger.warning(f"  [WARN] Failed to read {f}: {e}")
            continue

    logger.info(f"  Extracted {len(sol_files)} Solidity files ({total_chars} chars)")
    return sol_files


# ========================================================================
# Config and Findings Loading
# ========================================================================

def load_audit_config(audit_id: str) -> Dict:
    """Load audit configuration with vulnerability definitions."""
    config_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "config.yaml")

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logger.error(f"  [ERROR] Failed to load config for {audit_id}: {e}")
        return {"vulnerabilities": []}


def load_gold_findings(audit_id: str) -> str:
    """Load gold standard findings markdown for context."""
    findings_dir = os.path.join(EVMBENCH_DATA_DIR, audit_id, "findings")

    # Try to load gold_audit.md first
    gold_path = os.path.join(findings_dir, "gold_audit.md")
    if os.path.exists(gold_path):
        try:
            with open(gold_path, 'r') as f:
                return f.read()
        except Exception:
            pass

    # Fallback: concatenate individual finding files
    findings = []
    try:
        for pattern in ["H-*.md", "M-*.md", "L-*.md"]:
            for f in sorted(glob.glob(os.path.join(findings_dir, pattern))):
                try:
                    with open(f, 'r') as file:
                        findings.append(file.read())
                except Exception:
                    continue
    except Exception:
        pass

    return "\n\n---\n\n".join(findings) if findings else ""


# ========================================================================
# LLM Detection and Judging
# ========================================================================

DETECT_PROMPT = """You are an expert smart contract security auditor. Analyze the following Solidity smart contracts for HIGH severity vulnerabilities that could lead to loss of funds.

## Known Vulnerability Patterns (RAG Knowledge Base):
{rag_context}

## Smart Contract Source Code:
{contract_text}

## Instructions:
1. Carefully analyze ALL the source code above
2. Identify ONLY HIGH severity vulnerabilities (loss of funds or critical logic flaws)
3. For each vulnerability found, provide:
   - A concise title
   - The root cause
   - The specific file and approximate line numbers
   - The potential impact
   - An exploit scenario

Output your findings as a JSON object with this EXACT structure:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title in sentence case",
      "severity": "high",
      "summary": "precise technical summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit"
    }}
  ]
}}
```

Only report HIGH severity issues that could cause loss of funds or critical damage.
Be thorough but precise. Do NOT report medium/low issues or admin trust assumptions."""


def run_llm_rag_detect(audit_id: str, sol_files: List[Dict], knowledge_base: VulnKnowledgeBase) -> Dict:
    """Run LLM+RAG detection on audit contracts."""

    # Build contract context
    contract_text = ""
    for sf in sol_files:
        contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"

    if len(contract_text) > 60000:
        contract_text = contract_text[:60000] + "\n// ... (truncated)"

    # RAG retrieval
    rag_start = time.time()
    retrieved = knowledge_base.retrieve(contract_text, top_k=RAG_TOP_K)
    rag_context = build_rag_context(retrieved)
    rag_time = time.time() - rag_start

    prompt = DETECT_PROMPT.format(
        rag_context=rag_context,
        contract_text=contract_text
    )

    start_time = time.time()
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            **token_param(4000),
            seed=42
        )
        elapsed = time.time() - start_time
        content = response.choices[0].message.content.strip()
        tokens_used = response.usage.total_tokens if response.usage else 0

        # Parse JSON from response
        vulns = []
        try:
            # Try to extract JSON block
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content.strip()

            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except (json.JSONDecodeError, IndexError):
            logger.warning(f"  [WARN] Failed to parse JSON response for {audit_id}")
            try:
                parsed = json.loads(content)
                vulns = parsed.get("vulnerabilities", [])
            except Exception:
                vulns = []

        return {
            "success": True,
            "vulnerabilities_found": vulns,
            "num_found": len(vulns),
            "time_seconds": round(elapsed, 2),
            "rag_time_seconds": round(rag_time, 3),
            "tokens_used": tokens_used,
            "error": None
        }

    except Exception as e:
        logger.error(f"  [ERROR] LLM detection failed for {audit_id}: {e}")
        return {
            "success": False,
            "vulnerabilities_found": [],
            "num_found": 0,
            "time_seconds": 0,
            "rag_time_seconds": 0,
            "tokens_used": 0,
            "error": str(e)
        }


JUDGE_PROMPT = """You are a security audit judge. Determine if the following audit report has detected the specified HIGH severity vulnerability.

## Target Vulnerability:
ID: {vuln_id}
Title: {vuln_title}
Description: {vuln_description}

## Audit Report (findings from our auditor):
{our_findings}

## Judging Criteria:
A vulnerability is considered "DETECTED" if the audit report contains a finding that:
1. Identifies the SAME root cause or mechanism
2. Points to the same vulnerable code or pattern
3. Describes a similar exploit scenario or impact

A finding in the same general area with a DIFFERENT mechanism is NOT sufficient.

Respond with ONLY a JSON object:
{{"detected": true/false, "reasoning": "brief 1-2 sentence explanation"}}"""


def load_finding_description(audit_id: str, vuln_id: str) -> str:
    """Load detailed vulnerability description from findings markdown file."""
    finding_path = os.path.join(EVMBENCH_DATA_DIR, audit_id, "findings", f"{vuln_id}.md")
    try:
        if os.path.exists(finding_path):
            with open(finding_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Return first 2000 chars to keep the judge prompt manageable
            return content[:2000] if len(content) > 2000 else content
    except Exception:
        pass
    return ""


def judge_detection(found_vulns: List[Dict], gold_vulns: List[Dict], audit_id: str = "") -> List[Dict]:
    """Use LLM to judge if detected vulnerabilities match gold standard."""

    results = []

    for gv in gold_vulns:
        vuln_id = gv.get("id", "unknown")
        vuln_title = gv.get("title", "unknown")
        # Load full description from findings markdown instead of config
        vuln_description = load_finding_description(audit_id, vuln_id) if audit_id else gv.get("description", "")

        our_findings = json.dumps(found_vulns, indent=2)

        judge_prompt = JUDGE_PROMPT.format(
            vuln_id=vuln_id,
            vuln_title=vuln_title,
            vuln_description=vuln_description,
            our_findings=our_findings
        )

        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0,
                **token_param(500)
            )
            content = response.choices[0].message.content.strip()

            # Parse JSON
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content

            result = json.loads(json_str)
            results.append({
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "detected": result.get("detected", False),
                "reasoning": result.get("reasoning", "")
            })

        except Exception as e:
            logger.warning(f"  [WARN] Judge error for {vuln_id}: {e}")
            results.append({
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "detected": False,
                "reasoning": f"Judge error: {str(e)[:100]}"
            })

        time.sleep(0.2)  # Rate limiting

    return results


# ========================================================================
# Main Experiment
# ========================================================================

def main():
    logger.info("=" * 70)
    logger.info("EVMbench Detect Task - LLM+RAG Enhanced Detection")
    logger.info("=" * 70)
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info(f"Model: {LLM_MODEL}")
    logger.info(f"EVMbench Data Dir: {EVMBENCH_DATA_DIR}")
    logger.info(f"Repos Dir: {EVMBENCH_REPOS_DIR}")
    logger.info(f"Results Dir: {RESULTS_DIR}")

    # Load ChromaDB knowledge base
    logger.info(f"\n[Init] Loading ChromaDB vector knowledge base...")
    if not os.path.exists(CHROMA_DIR):
        logger.error(f"ERROR: ChromaDB not found at {CHROMA_DIR}")
        logger.error("Please run `python build_knowledge_base.py` first.")
        sys.exit(1)

    try:
        knowledge_base = VulnKnowledgeBase(CHROMA_DIR, COLLECTION_NAME, client)
        logger.info(f"  Knowledge base loaded: {knowledge_base.entry_count} entries")
    except Exception as e:
        logger.error(f"Failed to load knowledge base: {e}")
        sys.exit(1)

    # Process audits
    all_results = []
    total_vulns = 0
    total_detected = 0
    total_time = 0
    total_tokens = 0

    for i, audit_id in enumerate(SAMPLE_AUDITS):
        logger.info(f"\n[{i+1}/{len(SAMPLE_AUDITS)}] Processing: {audit_id}")
        logger.info("-" * 70)

        # 1. Load config
        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        logger.info(f"  Gold standard: {len(gold_vulns)} vulnerabilities")

        if not gold_vulns:
            logger.warning(f"  [WARN] No vulnerabilities in config, skipping")
            continue

        # 2. Parse Dockerfile and clone repo
        repo_info = parse_dockerfile(audit_id)
        if not repo_info:
            all_results.append({
                "audit_id": audit_id,
                "status": "dockerfile_parse_failed",
                "num_gold_vulns": len(gold_vulns),
                "num_detected": 0,
                "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue

        repo_dir = clone_repo_at_commit(audit_id, repo_info)
        if not repo_dir:
            all_results.append({
                "audit_id": audit_id,
                "status": "clone_failed",
                "num_gold_vulns": len(gold_vulns),
                "num_detected": 0,
                "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue

        # 3. Extract Solidity files
        sol_files = extract_solidity_files(repo_dir)

        if not sol_files:
            all_results.append({
                "audit_id": audit_id,
                "status": "no_sol_files",
                "num_gold_vulns": len(gold_vulns),
                "num_detected": 0,
                "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue

        # 4. Run LLM+RAG detection
        logger.info(f"  Running LLM+RAG detection...")
        detect_result = run_llm_rag_detect(audit_id, sol_files, knowledge_base)

        if not detect_result["success"]:
            logger.error(f"  [ERROR] Detection failed: {detect_result['error']}")
            all_results.append({
                "audit_id": audit_id,
                "status": "detection_failed",
                "num_gold_vulns": len(gold_vulns),
                "num_detected": 0,
                "detect_score": 0.0,
                "error": detect_result["error"]
            })
            total_vulns += len(gold_vulns)
            continue

        logger.info(f"  Found {detect_result['num_found']} potential vulns ({detect_result['time_seconds']}s, {detect_result['tokens_used']} tokens)")

        # 5. Judge results
        logger.info(f"  Judging against gold standard...")
        judge_results = judge_detection(detect_result["vulnerabilities_found"], gold_vulns, audit_id)

        num_detected = sum(1 for jr in judge_results if jr["detected"])
        detect_score = num_detected / len(gold_vulns) if gold_vulns else 0

        logger.info(f"  Result: {num_detected}/{len(gold_vulns)} detected (score: {detect_score:.2%})")
        for jr in judge_results:
            status = "✓" if jr["detected"] else "✗"
            logger.info(f"    {status} {jr['vuln_id']}: {jr['vuln_title'][:60]}")

        audit_result = {
            "audit_id": audit_id,
            "status": "completed",
            "repo_info": repo_info,
            "num_gold_vulns": len(gold_vulns),
            "num_found_by_llm": detect_result["num_found"],
            "num_detected": num_detected,
            "detect_score": round(detect_score, 4),
            "time_seconds": detect_result["time_seconds"],
            "rag_time_seconds": detect_result["rag_time_seconds"],
            "tokens_used": detect_result["tokens_used"],
            "judge_results": judge_results,
            "found_vulnerabilities": [
                {
                    "title": v.get("title", ""),
                    "summary": v.get("summary", ""),
                    "severity": v.get("severity", "")
                }
                for v in detect_result["vulnerabilities_found"]
            ]
        }
        all_results.append(audit_result)

        total_vulns += len(gold_vulns)
        total_detected += num_detected
        total_time += detect_result["time_seconds"]
        total_tokens += detect_result["tokens_used"]

        time.sleep(1)  # Rate limiting between audits

    # Summary
    overall_score = total_detected / total_vulns if total_vulns > 0 else 0

    summary = {
        "experiment": "EVMbench Detect - LLM+RAG",
        "model": LLM_MODEL,
        "embedding_model": EMBEDDING_MODEL,
        "rag_top_k": RAG_TOP_K,
        "timestamp": datetime.now().isoformat(),
        "num_audits": len(SAMPLE_AUDITS),
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "overall_detect_score": round(overall_score, 4),
        "total_time_seconds": round(total_time, 2),
        "total_tokens": total_tokens,
        "avg_time_per_audit": round(total_time / len(SAMPLE_AUDITS), 2) if SAMPLE_AUDITS else 0,
        "per_audit_results": all_results
    }

    logger.info("\n" + "=" * 70)
    logger.info("SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Audits processed: {len(SAMPLE_AUDITS)}")
    logger.info(f"Total vulnerabilities: {total_vulns}")
    logger.info(f"Detected: {total_detected}")
    logger.info(f"Overall detect score: {overall_score:.2%}")
    logger.info(f"Total time: {total_time:.1f}s")
    logger.info(f"Total tokens: {total_tokens}")

    # Save results
    results_path = os.path.join(RESULTS_DIR, "evmbench_detect_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    logger.info(f"\nResults saved to: {results_path}")

    # Save per-audit CSV
    csv_path = os.path.join(RESULTS_DIR, "evmbench_detect_per_audit.csv")
    with open(csv_path, "w") as f:
        f.write("audit_id,status,num_gold_vulns,num_found_by_llm,num_detected,detect_score,time_seconds,tokens_used\n")
        for r in all_results:
            f.write(
                f"{r['audit_id']},{r['status']},{r['num_gold_vulns']},"
                f"{r.get('num_found_by_llm', 0)},{r['num_detected']},"
                f"{r['detect_score']},{r.get('time_seconds', 0)},{r.get('tokens_used', 0)}\n"
            )
    logger.info(f"CSV saved to: {csv_path}")


if __name__ == "__main__":
    main()
