#!/usr/bin/env python3
"""
32_postcutoff_hybrid.py -- EVMbench post-cutoff validation using Hybrid (LLM+RAG) pipeline.

Reproduces the thesis Section 5 "post-cutoff validation" experiment:
- Same pipeline as script 09 (Hybrid: LLM+RAG with ChromaDB RAG + LLM judge)
- Applied to 8 post-cutoff audits (2025-01 to 2026-01)
- Expected result: ~11.76% (2/17) per thesis description

Output: experiments/evmbench_postcutoff/postcutoff_hybrid_results.json
"""
import os, sys, re, json, glob, time, yaml, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from openai import OpenAI
from datetime import datetime

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
EVMBENCH_DIR = os.path.join(BASE_DIR, "data", "evmbench", "audits")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
COLLECTION_NAME = "vuln_knowledge"
RAG_TOP_K = 5
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments", "evmbench_postcutoff")
client = OpenAI()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# 8 post-cutoff audits (repos confirmed present; 3 excluded due to missing repos)
POST_CUTOFF_AUDITS = [
    "2025-04-forte",
    "2026-01-tempo-stablecoin-dex",
    "2025-01-liquid-ron",
    "2025-04-virtuals",
    "2025-05-blackhole",
    "2025-06-panoptic",
    "2026-01-tempo-feeamm",
    "2026-01-tempo-mpp-streams",
]

DETECT_PROMPT = """You are an expert Ethereum smart contract security auditor performing a security audit for HIGH severity vulnerabilities.

## Relevant Vulnerability Patterns (from knowledge base):
{rag_context}

## Smart Contract Code:
```solidity
{contract_text}
```

Identify ALL high-severity vulnerabilities. For each:
- title: concise name
- severity: always "high"
- description: root cause
- impact: financial/security impact
- file: which contract file

Output ONLY valid JSON:
{{
  "vulnerabilities": [
    {{
      "title": "...",
      "severity": "high",
      "description": "...",
      "impact": "...",
      "file": "path/to/file.sol"
    }}
  ]
}}
Only report HIGH severity issues that could cause loss of funds or critical damage."""

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


class VulnKnowledgeBase:
    def __init__(self, chroma_dir, collection_name, llm_client):
        import chromadb
        self.client = chromadb.PersistentClient(path=chroma_dir)
        try:
            self.collection = self.client.get_collection(collection_name)
            self.entry_count = self.collection.count()
        except Exception:
            self.collection = None
            self.entry_count = 0
        self.llm_client = llm_client

    def _embed_query(self, text):
        try:
            resp = self.llm_client.embeddings.create(
                model="text-embedding-3-small",
                input=text[:8000]
            )
            return resp.data[0].embedding
        except Exception:
            return None

    def retrieve(self, query, top_k=5):
        if not self.collection:
            return []
        embedding = self._embed_query(query[:2000])
        if not embedding:
            return []
        try:
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=min(top_k, self.entry_count),
                include=["documents", "metadatas"]
            )
            items = []
            for i, doc in enumerate(results.get("documents", [[]])[0]):
                meta = results.get("metadatas", [[]])[0][i] if results.get("metadatas") else {}
                items.append({"content": doc, "metadata": meta})
            return items
        except Exception:
            return []


def build_rag_context(retrieved):
    if not retrieved:
        return "No relevant knowledge base entries found."
    parts = []
    for i, item in enumerate(retrieved):
        meta = item.get("metadata", {})
        cat = meta.get("category", "unknown")
        title = meta.get("title", "")
        content = item.get("content", "")[:300]
        parts.append(f"[{i+1}] [{cat}] {title}: {content}")
    return "\n".join(parts)


def load_sol_files(audit_id):
    repo_dir = os.path.join(REPOS_DIR, audit_id)
    if not os.path.exists(repo_dir):
        return []
    sol_files = []
    for f in glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True):
        if "/test/" in f or "/script/" in f or "/lib/" in f:
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            sol_files.append({"path": os.path.relpath(f, repo_dir), "content": content})
        except Exception:
            pass
    return sol_files


def run_hybrid_detect(audit_id, sol_files, kb):
    contract_text = ""
    for sf in sol_files:
        contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
    if len(contract_text) > 60000:
        contract_text = contract_text[:60000] + "\n// ... (truncated)"

    retrieved = kb.retrieve(contract_text[:2000], top_k=RAG_TOP_K)
    rag_context = build_rag_context(retrieved)
    prompt = DETECT_PROMPT.format(rag_context=rag_context, contract_text=contract_text)

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            **token_param(4000),
            seed=42
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        try:
            if "```json" in content:
                js = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                js = content.split("```")[1].split("```")[0].strip()
            else:
                js = content
            vulns = json.loads(js).get("vulnerabilities", [])
        except Exception:
            vulns = []
        return vulns, tokens
    except Exception as e:
        logger.error(f"Detection error: {e}")
        return [], 0


def load_finding_description(audit_id, vuln_id):
    path = os.path.join(EVMBENCH_DIR, audit_id, "findings", f"{vuln_id}.md")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return content[:2000]
    return ""


def judge_detection(found_vulns, gold_vulns, audit_id):
    results = []
    for gv in gold_vulns:
        vuln_id = gv.get("id", "?")
        vuln_title = gv.get("title", "?")
        vuln_desc = load_finding_description(audit_id, vuln_id)
        our_findings = json.dumps(found_vulns, indent=2)
        prompt = JUDGE_PROMPT.format(
            vuln_id=vuln_id, vuln_title=vuln_title,
            vuln_description=vuln_desc, our_findings=our_findings
        )
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                **token_param(500)
            )
            content = resp.choices[0].message.content.strip()
            if "```json" in content:
                js = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                js = content.split("```")[1].split("```")[0].strip()
            else:
                js = content
            r = json.loads(js)
            results.append({
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "detected": r.get("detected", False),
                "reasoning": r.get("reasoning", "")
            })
        except Exception as e:
            results.append({
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "detected": False,
                "reasoning": f"judge error: {e}"
            })
        time.sleep(0.2)
    return results


def load_gold_vulns(audit_id):
    config_path = os.path.join(EVMBENCH_DIR, audit_id, "config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = yaml.safe_load(f)
        return config.get("vulnerabilities", [])
    return []


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("=" * 60)
    print("EVMbench Post-Cutoff Hybrid (LLM+RAG) Pipeline")
    print(f"Model: {MODEL} | Audits: {len(POST_CUTOFF_AUDITS)}")
    print("Reproducing thesis Section 5 post-cutoff experiment")
    print("=" * 60)

    try:
        kb = VulnKnowledgeBase(CHROMA_DIR, COLLECTION_NAME, client)
        print(f"ChromaDB loaded: {kb.entry_count} entries")
    except Exception as e:
        print(f"ChromaDB error: {e} -- using empty KB")
        kb = VulnKnowledgeBase.__new__(VulnKnowledgeBase)
        kb.collection = None
        kb.entry_count = 0
        kb.llm_client = client

    results = []
    total_gold = 0
    total_detected = 0
    total_tokens = 0

    for i, audit_id in enumerate(POST_CUTOFF_AUDITS):
        print(f"\n[{i+1}/{len(POST_CUTOFF_AUDITS)}] {audit_id}")

        gold_vulns = load_gold_vulns(audit_id)
        if not gold_vulns:
            print("  SKIP: no gold vulns")
            results.append({"audit_id": audit_id, "status": "no_gold"})
            continue

        sol_files = load_sol_files(audit_id)
        if not sol_files:
            print("  SKIP: no .sol files")
            results.append({"audit_id": audit_id, "status": "no_code", "gold_count": len(gold_vulns)})
            continue

        total_gold += len(gold_vulns)
        print(f"  Gold: {len(gold_vulns)} | .sol files: {len(sol_files)}")

        found_vulns, detect_tokens = run_hybrid_detect(audit_id, sol_files, kb)
        total_tokens += detect_tokens
        print(f"  LLM found: {len(found_vulns)} vulns ({detect_tokens} tokens)")

        judge_results = judge_detection(found_vulns, gold_vulns, audit_id)
        judge_tokens = len(judge_results) * 800  # estimate
        total_tokens += judge_tokens

        detected = sum(1 for j in judge_results if j["detected"])
        total_detected += detected
        score = detected / len(gold_vulns) if gold_vulns else 0
        print(f"  Detected: {detected}/{len(gold_vulns)} ({score:.0%})")

        results.append({
            "audit_id": audit_id,
            "gold_count": len(gold_vulns),
            "found_count": len(found_vulns),
            "detected": detected,
            "score": round(score, 4),
            "tokens_detect": detect_tokens,
            "found_vulns": [v.get("title", "?") for v in found_vulns],
            "judge_results": judge_results,
        })

    detect_rate = total_detected / total_gold if total_gold > 0 else 0
    valid = [r for r in results if "gold_count" in r]

    print("\n" + "=" * 60)
    print("HYBRID PIPELINE POST-CUTOFF RESULTS")
    print("=" * 60)
    print(f"  TOTAL: {total_detected}/{total_gold} = {detect_rate:.2%}")
    print(f"  Thesis expected: 2/17 = 11.76%")
    print(f"\n  {'Audit':<40} {'Gold':>5} {'Found':>6} {'Det':>4} {'Score':>7}")
    print(f"  {'-'*60}")
    for r in results:
        if "gold_count" not in r:
            continue
        print(f"  {r['audit_id']:<40} {r['gold_count']:>5} {r['found_count']:>6} "
              f"{r['detected']:>4} {r['score']:>6.0%}")

    output = {
        "experiment": "evmbench_postcutoff_hybrid",
        "description": "Post-cutoff validation using Hybrid (LLM+RAG) pipeline — reproduces thesis Section 5",
        "model": MODEL,
        "pipeline": "Hybrid (LLM+RAG + ChromaDB RAG + LLM judge per gold vuln, 60K char truncation)",
        "total_audits": len(valid),
        "total_gold": total_gold,
        "total_detected": total_detected,
        "detect_rate": round(detect_rate, 4),
        "thesis_expected": "11.76% (2/17)",
        "per_audit": results,
    }
    out_path = os.path.join(OUTPUT_DIR, "postcutoff_hybrid_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
