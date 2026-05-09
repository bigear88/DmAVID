#!/usr/bin/env python3
"""
31_postcutoff_validation.py -- EVMbench post-cutoff generalization validation.

Runs smart_preprocess detection on 6 NEW post-cutoff audits (repos confirmed present),
then combines with existing forte + tempo-stablecoin-dex results to form an
8-audit post-cutoff validation set (2025-01 to 2026-01).

Audits with repos (6 new):
  2025-01-liquid-ron, 2025-04-virtuals, 2025-05-blackhole,
  2025-06-panoptic, 2026-01-tempo-feeamm, 2026-01-tempo-mpp-streams

Already run (from evmbench_smart/smart_preprocess_results.json):
  2025-04-forte, 2026-01-tempo-stablecoin-dex

Missing repos (skip): 2025-01-next-generation, 2025-02-thorwallet, 2025-10-sequence
"""
import os, sys, re, json, glob, time, yaml
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from openai import OpenAI

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
EVMBENCH_DIR = os.path.join(BASE_DIR, "data", "evmbench")
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments", "evmbench_postcutoff")
client = OpenAI()

NEW_AUDITS = [
    "2025-01-liquid-ron",
    "2025-04-virtuals",
    "2025-05-blackhole",
    "2025-06-panoptic",
    "2026-01-tempo-feeamm",
    "2026-01-tempo-mpp-streams",
]

EXISTING_AUDIT_IDS = ["2025-04-forte", "2026-01-tempo-stablecoin-dex"]

MAX_DEEP_CHARS = 8000
MAX_TOTAL_CHARS = 25000


def extract_interfaces(code):
    lines = code.split("\n")
    interfaces = []
    for line in lines:
        stripped = line.strip()
        if re.match(r"^\s*function\s+\w+", stripped):
            sig = stripped.split("{")[0].strip()
            if sig:
                interfaces.append(sig)
        elif re.match(r"^\s*event\s+", stripped):
            interfaces.append(stripped.rstrip(";").strip())
        elif re.match(r"^\s*modifier\s+", stripped):
            interfaces.append(stripped.split("{")[0].strip())
        elif re.match(r"^\s*(contract|interface|library|abstract)\s+", stripped):
            interfaces.append(stripped.split("{")[0].strip())
    return interfaces


def score_security_relevance(code, filename):
    score = 0
    low = code.lower()
    for pattern, weight in [
        (".call", 5), (".send", 4), (".transfer", 4),
        ("delegatecall", 6), ("selfdestruct", 5),
        ("msg.value", 4), ("msg.sender", 2),
        ("external", 3), ("payable", 3),
        ("withdraw", 5), ("deposit", 4), ("swap", 5),
        ("liquidat", 6), ("borrow", 5), ("repay", 4),
        ("oracle", 5), ("price", 4), ("flash", 6),
        ("approve", 3), ("transferfrom", 4),
        ("onlyowner", -2), ("nonreentrant", -2),
        ("require(", 1), ("assert(", 1),
    ]:
        score += low.count(pattern) * weight
    if len(code) < 5000:
        score += 10
    return score


def smart_preprocess(audit_id):
    repo_dir = os.path.join(REPOS_DIR, audit_id)
    if not os.path.exists(repo_dir):
        return None
    sol_files = []
    for f in glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True):
        if "/test/" in f or "/script/" in f or "/lib/" in f:
            continue
        if not os.path.isfile(f):
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
            sol_files.append((f, code, os.path.relpath(f, repo_dir)))
        except Exception:
            pass
    if not sol_files:
        return None
    total_chars = sum(len(c) for _, c, _ in sol_files)
    all_interfaces = []
    for filepath, code, relpath in sol_files:
        ifaces = extract_interfaces(code)
        if ifaces:
            all_interfaces.append(f"// File: {relpath}")
            all_interfaces.extend(ifaces)
    interface_summary = "\n".join(all_interfaces)
    scored = [(score_security_relevance(code, relpath), filepath, code, relpath)
              for filepath, code, relpath in sol_files]
    scored.sort(key=lambda x: x[0], reverse=True)
    deep_analysis = []
    remaining_budget = MAX_TOTAL_CHARS - min(len(interface_summary), 5000)
    for score, filepath, code, relpath in scored:
        if remaining_budget <= 0:
            break
        chunk = code[:min(MAX_DEEP_CHARS, remaining_budget)]
        deep_analysis.append(f"// === {relpath} (security score: {score}) ===\n{chunk}")
        remaining_budget -= len(chunk)
    preprocessed = (
        f"// PROJECT: {audit_id}\n"
        f"// Total: {len(sol_files)} source files, {total_chars:,} chars\n"
        f"// Preprocessing: Interface Summary + Top {len(deep_analysis)} Security-Critical Modules\n\n"
        f"// === INTERFACE SUMMARY (all files) ===\n"
        f"{interface_summary[:5000]}\n\n"
        f"// === SECURITY-CRITICAL MODULES (deep analysis) ===\n"
        + "\n\n".join(deep_analysis)
    )
    return preprocessed[:MAX_TOTAL_CHARS]


def detect_with_smart_preprocess(preprocessed_code, knowledge_base, gold_vulns):
    prompt = (
        "You are an expert DeFi security auditor. Analyze this smart contract project for HIGH severity vulnerabilities.\n\n"
        "## DeFi Vulnerability Knowledge Base:\n"
        f"{knowledge_base[:3000]}\n\n"
        "## Smart Contract Project (preprocessed: interface summary + security-critical modules):\n"
        "```solidity\n"
        f"{preprocessed_code}\n"
        "```\n\n"
        "## Task:\n"
        "1. Identify ALL high-severity vulnerabilities\n"
        "2. For each, provide: title, severity, root cause, exploit scenario\n"
        "3. Focus on DeFi-specific issues: flash loan, oracle manipulation, reentrancy, access control, precision loss\n\n"
        'Output JSON only:\n{"vulnerabilities": [{"title": "...", "severity": "high", "summary": "...", "exploit_scenario": "..."}]}'
    )
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            **token_param(2000),
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            parsed = json.loads(match.group())
            return parsed.get("vulnerabilities", []), tokens
        return [], tokens
    except Exception as e:
        print(f"  API error: {e}")
        return [], 0


def load_gold_vulns(audit_id):
    config_path = os.path.join(EVMBENCH_DIR, "audits", audit_id, "config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = yaml.safe_load(f)
        return config.get("vulnerabilities", [])
    return []


def load_knowledge_base():
    kb_path = os.path.join(BASE_DIR, "scripts", "knowledge", "vulnerability_knowledge.json")
    if os.path.exists(kb_path):
        with open(kb_path) as f:
            kb = json.load(f)
        entries = kb.get("entries", [])
        parts = []
        for e in entries[:20]:
            parts.append(f"[{e.get('category','?')}] {e.get('title','')}: {e.get('description','')[:200]}")
        return "\n".join(parts)
    return ""


def judge_detection(found_vulns, gold_vulns):
    detected = 0
    for gv in gold_vulns:
        gold_title = gv.get("title", "").lower()
        gold_id = gv.get("id", "").lower()
        for fv in found_vulns:
            found_title = fv.get("title", "").lower()
            found_summary = fv.get("summary", "").lower()
            gold_words = set(gold_title.split())
            found_words = set(found_title.split()) | set(found_summary.split())
            overlap = len(gold_words & found_words)
            if overlap >= 2 or gold_id in found_summary:
                detected += 1
                break
    return detected


def load_existing_results():
    path = os.path.join(BASE_DIR, "experiments", "evmbench_smart", "smart_preprocess_results.json")
    if not os.path.exists(path):
        print(f"WARNING: {path} not found, skipping existing results")
        return []
    with open(path) as f:
        data = json.load(f)
    existing = []
    for r in data.get("per_audit", []):
        if r.get("audit_id") in EXISTING_AUDIT_IDS:
            existing.append(r)
    return existing


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 60)
    print("EVMbench Post-Cutoff Validation (2025-01 to 2026-01)")
    print(f"Model: {MODEL}")
    print(f"New audits: {len(NEW_AUDITS)} | Existing: {len(EXISTING_AUDIT_IDS)}")
    print("=" * 60)

    kb = load_knowledge_base()
    new_results = []
    total_new_gold = 0
    total_new_detected = 0
    total_tokens = 0

    for i, audit_id in enumerate(NEW_AUDITS):
        print(f"\n[{i+1}/{len(NEW_AUDITS)}] {audit_id}")

        gold_vulns = load_gold_vulns(audit_id)
        if not gold_vulns:
            print("  SKIP: no gold vulnerabilities in config.yaml")
            new_results.append({"audit_id": audit_id, "status": "no_gold"})
            continue

        total_new_gold += len(gold_vulns)
        print(f"  Gold vulnerabilities: {len(gold_vulns)}")

        preprocessed = smart_preprocess(audit_id)
        if not preprocessed:
            print("  SKIP: no Solidity code found")
            new_results.append({"audit_id": audit_id, "status": "no_code", "gold_count": len(gold_vulns)})
            continue

        print(f"  Preprocessed: {len(preprocessed):,} chars")

        found_vulns, tokens = detect_with_smart_preprocess(preprocessed, kb, gold_vulns)
        total_tokens += tokens
        detected = judge_detection(found_vulns, gold_vulns)
        total_new_detected += detected

        score = detected / len(gold_vulns) if gold_vulns else 0
        print(f"  Found: {len(found_vulns)} vulns, Matched: {detected}/{len(gold_vulns)} ({score:.0%})")
        print(f"  Tokens: {tokens}")

        new_results.append({
            "audit_id": audit_id,
            "gold_count": len(gold_vulns),
            "found_count": len(found_vulns),
            "detected": detected,
            "score": round(score, 4),
            "tokens": tokens,
            "found_vulns": [v.get("title", "?") for v in found_vulns],
        })

    existing_results = load_existing_results()
    total_existing_gold = sum(r.get("gold_count", 0) for r in existing_results)
    total_existing_detected = sum(r.get("detected", 0) for r in existing_results)

    all_results = existing_results + new_results
    total_gold = total_existing_gold + total_new_gold
    total_detected = total_existing_detected + total_new_detected
    detect_rate = total_detected / total_gold if total_gold > 0 else 0

    valid_results = [r for r in all_results if "gold_count" in r]

    print("\n" + "=" * 60)
    print("POST-CUTOFF VALIDATION RESULTS (8 audits)")
    print("=" * 60)
    print(f"  Existing (forte + tempo-stablecoin-dex): {total_existing_detected}/{total_existing_gold}")
    print(f"  New (6 audits): {total_new_detected}/{total_new_gold}")
    print(f"  COMBINED: {total_detected}/{total_gold} ({detect_rate:.2%})")
    print(f"  Total tokens (new only): {total_tokens:,}")

    print(f"\n  {'Audit':<40} {'Gold':>5} {'Match':>6} {'Score':>7} {'Source':>8}")
    print(f"  {'-'*65}")
    for r in all_results:
        if "gold_count" not in r:
            continue
        src = "existing" if r["audit_id"] in EXISTING_AUDIT_IDS else "new"
        print(f"  {r['audit_id']:<40} {r['gold_count']:>5} {r.get('detected',0):>6} "
              f"{r.get('score',0):>6.0%} {src:>8}")

    output = {
        "experiment": "evmbench_postcutoff_validation",
        "description": "Post-cutoff generalization: 8 audits from 2025-01 to 2026-01",
        "model": MODEL,
        "total_audits": len(valid_results),
        "total_gold": total_gold,
        "total_detected": total_detected,
        "detect_rate": round(detect_rate, 4),
        "total_tokens_new": total_tokens,
        "existing_audits": EXISTING_AUDIT_IDS,
        "new_audits": NEW_AUDITS,
        "missing_repo": ["2025-01-next-generation", "2025-02-thorwallet", "2025-10-sequence"],
        "per_audit": all_results,
    }
    out_path = os.path.join(OUTPUT_DIR, "postcutoff_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
