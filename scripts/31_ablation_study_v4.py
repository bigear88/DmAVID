#!/usr/bin/env python3
"""
DmAVID Ablation Study v4 — Redesigned Multi-Agent Pipeline.

Pipeline: Baseline → Self-Verify → Critique → Debate (on disagreement)

Key changes from v3:
  - Self-Verify: structured exploit path extraction (no confidence scores)
  - Critique: FP-focused auditor persona with few-shot examples
  - Debate: triggered by Stage2 vs Stage3 disagreement, not confidence

Author: Curtis Chang
"""

import os, sys, json, time, random, re
from datetime import datetime
from typing import Dict, List, Any

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
from _model_compat import token_param
from openai import OpenAI

# Import baseline detection
from importlib import util as ilu
_spec = ilu.spec_from_file_location("llm_rag", os.path.join(BASE_DIR, "scripts", "05_run_llm_rag.py"))
_rag_mod = ilu.module_from_spec(_spec)
_spec.loader.exec_module(_rag_mod)
analyze_with_rag = _rag_mod.analyze_with_rag

random.seed(42)
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/ablation")

# ============================================================
# Stage 2: Structured Self-Verify
# ============================================================

SELF_VERIFY_SYSTEM = """You are an expert Smart Contract Security Analyst. Your task is to verify if a flagged vulnerability is genuinely exploitable.

Do NOT output a confidence score. Instead, you must explicitly extract the components required for an exploit. For a Reentrancy or State Manipulation vulnerability to be valid, you MUST identify:
1. The target state variable that is manipulated.
2. The exact line or function where the unsafe external call occurs.
3. The exact state update that happens AFTER the external call.

If ANY of these components are missing, protected by a modifier (e.g., `nonReentrant`), or restricted by strict access control (e.g., `onlyOwner`), you MUST classify the contract as SAFE.

Respond strictly in the following JSON format:
{
  "target_state_variable": "<name of variable, or null if none>",
  "external_call_line": "<code snippet or line, or null if none>",
  "state_update_after_call": "<code snippet or line, or null if none>",
  "reasoning": "<brief explanation of the exploit path or why it fails>",
  "verdict": "VULNERABLE" or "SAFE"
}"""


def run_self_verify(baseline_results, code_loader):
    """Stage 2: Structured exploit path verification."""
    verified = []
    flipped = 0
    total_tokens = 0

    for r in baseline_results:
        new_r = dict(r)
        new_r["sv_flipped"] = False

        if not r.get("predicted_vulnerable"):
            verified.append(new_r)
            continue

        cid = r.get("contract_id", "")
        code = code_loader(cid)
        if not code:
            verified.append(new_r)
            continue

        code_short = code[:8000]
        vuln_types = r.get("vulnerability_types", [])
        reasoning = r.get("reasoning", "")[:1500]

        user_msg = (
            f"The previous analysis flagged this contract as VULNERABLE.\n"
            f"Claimed vulnerability types: {', '.join(vuln_types) if vuln_types else 'unspecified'}\n"
            f"Previous reasoning: \"{reasoning}\"\n\n"
            f"## Contract Code:\n```solidity\n{code_short}\n```\n\n"
            f"Verify: extract the exploit path components or classify as SAFE."
        )

        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SELF_VERIFY_SYSTEM},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                **token_param(800),
                seed=42,
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            total_tokens += tokens

            # Parse JSON
            jm = re.search(r"\{[\s\S]*\}", content)
            if jm:
                parsed = json.loads(jm.group())
            else:
                parsed = {"verdict": "VULNERABLE"}

            # Structured validation: any null field → SAFE
            target_var = parsed.get("target_state_variable")
            ext_call = parsed.get("external_call_line")
            state_update = parsed.get("state_update_after_call")
            verdict = parsed.get("verdict", "VULNERABLE").upper()

            is_safe = (
                verdict == "SAFE"
                or target_var is None or target_var == "null"
                or ext_call is None or ext_call == "null"
                or state_update is None or state_update == "null"
            )

            if is_safe:
                new_r["predicted_vulnerable"] = False
                new_r["sv_flipped"] = True
                new_r["sv_reason"] = parsed.get("reasoning", "")
                flipped += 1

        except Exception as e:
            pass  # keep original prediction on error

        verified.append(new_r)
        time.sleep(0.1)

    print(f"    Self-Verify: flipped {flipped}/{sum(1 for r in baseline_results if r.get('predicted_vulnerable'))} vuln predictions to SAFE")
    print(f"    Tokens: {total_tokens:,}")
    return verified, total_tokens


# ============================================================
# Stage 3: FP-Focused Critique
# ============================================================

CRITIQUE_SYSTEM = """You are a strict Security Auditor reviewing vulnerability reports. Your primary KPI is to REDUCE FALSE POSITIVES. Developers are annoyed by useless alerts.

Your task is to aggressively challenge the "VULNERABLE" claim made by the previous analysis. You must act as a filter. If the vulnerability path is merely theoretical and cannot be triggered in reality, you must mark it as SAFE.

Pay special attention to these common False Positives:
- External calls exist, but there is NO state update afterwards (Read-only reentrancy is only valid if another function relies on it).
- State variables are updated, but the function is protected by `onlyOwner` or a Role-based access control.
- Reentrancy pattern exists, but a `nonReentrant` guard is correctly applied.

Here are examples of how you should evaluate:

[Example 1: External Call without State Update]
Code snippet:
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
Previous Claim: VULNERABLE (Reentrancy risk on external call).
Your Critique: SAFE. Although there is an external call to `msg.sender`, the contract DOES NOT update any state variables (like `balances[msg.sender] -= amount`) after the call. Furthermore, it doesn't even update the state before the call, making it a logic error rather than a classic exploitable reentrancy. Verdict: SAFE.

[Example 2: Access Control Protection]
Code snippet:
function emergencyWithdraw() external onlyOwner {
    (bool success, ) = owner.call{value: address(this).balance}("");
    require(success);
}
Previous Claim: VULNERABLE (Arbitrary external call).
Your Critique: SAFE. The function has an external call, but it is strictly protected by the `onlyOwner` modifier. An attacker cannot bypass this access control to trigger the call. The risk is theoretical and acceptable. Verdict: SAFE.

Respond in JSON:
{
  "critique": "<your analysis>",
  "verdict": "VULNERABLE" or "SAFE"
}"""


def run_critique(stage2_results, code_loader):
    """Stage 3: FP-focused critique on remaining VULNERABLE predictions."""
    critiqued = []
    flipped = 0
    total_tokens = 0

    for r in stage2_results:
        new_r = dict(r)
        new_r["critique_flipped"] = False

        if not r.get("predicted_vulnerable"):
            critiqued.append(new_r)
            continue

        cid = r.get("contract_id", "")
        code = code_loader(cid)
        if not code:
            critiqued.append(new_r)
            continue

        code_short = code[:8000]
        vuln_types = r.get("vulnerability_types", [])
        reasoning = r.get("reasoning", "")[:1500]

        user_msg = (
            f"## Previous Analysis Claim: VULNERABLE\n"
            f"Vulnerability types: {', '.join(vuln_types) if vuln_types else 'unspecified'}\n"
            f"Reasoning: \"{reasoning}\"\n\n"
            f"## Contract Code:\n```solidity\n{code_short}\n```\n\n"
            f"Challenge this claim. Is this truly exploitable?"
        )

        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": CRITIQUE_SYSTEM},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                **token_param(800),
                seed=42,
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            total_tokens += tokens

            jm = re.search(r"\{[\s\S]*\}", content)
            if jm:
                parsed = json.loads(jm.group())
            else:
                parsed = {"verdict": "VULNERABLE"}

            verdict = parsed.get("verdict", "VULNERABLE").upper()
            new_r["critique_verdict"] = verdict
            new_r["critique_reasoning"] = parsed.get("critique", "")

            if verdict == "SAFE":
                new_r["predicted_vulnerable"] = False
                new_r["critique_flipped"] = True
                flipped += 1

        except Exception as e:
            pass

        critiqued.append(new_r)
        time.sleep(0.1)

    remaining_vuln = sum(1 for r in stage2_results if r.get("predicted_vulnerable"))
    print(f"    Critique: flipped {flipped}/{remaining_vuln} vuln predictions to SAFE")
    print(f"    Tokens: {total_tokens:,}")
    return critiqued, total_tokens


# ============================================================
# Stage 4: Disagreement-Triggered Debate
# ============================================================

RED_TEAM_PROMPT = """You are the Defense Counsel (Red Team). The current contract is under dispute. One agent flagged it as VULNERABLE, but another flagged it as SAFE.
Your specific goal is to prove the contract is **SAFE**.
Find evidence in the code that mitigates the risk: look for access controls, checks-effects-interactions compliance, missing state updates, or mathematical impossibility. Present your defense strongly."""

BLUE_TEAM_PROMPT = """You are the Security Prosecutor (Blue Team). The current contract is under dispute.
Your specific goal is to prove the contract is **VULNERABLE**.
Focus purely on how an attacker could bypass restrictions. Describe the exact sequence of transactions needed to exploit the contract. If you cannot formulate a realistic attack sequence, you must concede."""

COORDINATOR_PROMPT = """You are the Chief Judge (Coordinator). You have read the arguments from the Defense (Red Team) and the Prosecutor (Blue Team).
Evaluate their evidences.
Rule 1: If the Prosecutor (Blue Team) failed to provide a concrete, step-by-step transaction sequence that bypasses access controls, you MUST rule in favor of the Defense (SAFE).
Rule 2: If the Defense proved the existence of valid modifiers (e.g., onlyOwner) that strictly prevent public exploitation, you MUST rule SAFE.
Output your final verdict strictly as JSON: {"final_verdict": "VULNERABLE"} or {"final_verdict": "SAFE"}."""


def _llm_call(system_msg, user_msg, max_tokens=800):
    """Helper for debate LLM calls."""
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
            **token_param(max_tokens),
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        return content, tokens
    except Exception as e:
        return json.dumps({"error": str(e)}), 0


def find_disagreements(stage2_results, stage3_results):
    """Find cases where Stage 2 and Stage 3 disagree."""
    disagreements = []
    for s2, s3 in zip(stage2_results, stage3_results):
        s2_vuln = s2.get("predicted_vulnerable", False)
        # Stage 3 may have flipped some; check if critique changed the verdict
        s3_vuln = s3.get("predicted_vulnerable", False)
        # Disagreement: Stage 2 said VULNERABLE but Stage 3 flipped to SAFE
        # (or vice versa, though unlikely in our pipeline)
        if s2_vuln != s3_vuln:
            disagreements.append({
                "contract_id": s2.get("contract_id", ""),
                "stage2_vulnerable": s2_vuln,
                "stage3_vulnerable": s3_vuln,
                "reasoning": s2.get("reasoning", ""),
                "critique_reasoning": s3.get("critique_reasoning", ""),
                "vulnerability_types": s2.get("vulnerability_types", []),
            })
    return disagreements


def run_debate(stage2_results, stage3_results, code_loader, max_cases=20):
    """Stage 4: Debate on cases where Stage 2 and Stage 3 disagree."""
    disagreements = find_disagreements(stage2_results, stage3_results)
    print(f"    Disagreements (S2 vs S3): {len(disagreements)}")

    if not disagreements:
        print(f"    No debates needed — S2 and S3 agree on all cases")
        return stage3_results, 0, {"total_debates": 0, "flips": {}}

    cases = disagreements[:max_cases]
    total_tokens = 0
    flip_map = {}  # contract_id -> final verdict (bool)
    debate_details = []

    for i, case in enumerate(cases):
        cid = case["contract_id"]
        code = code_loader(cid)
        if not code:
            continue

        code_short = code[:6000]
        print(f"    Debate {i+1}/{len(cases)}: {cid}", end="")

        context = (
            f"## Contract Code:\n```solidity\n{code_short}\n```\n\n"
            f"## Dispute Context:\n"
            f"One agent says VULNERABLE: {case.get('reasoning', '')[:800]}\n"
            f"Another agent says SAFE: {case.get('critique_reasoning', '')[:800]}"
        )

        # Red Team (Defense → argues SAFE)
        red_content, red_tokens = _llm_call(RED_TEAM_PROMPT,
            f"{context}\n\nPresent your defense that this contract is SAFE.")
        total_tokens += red_tokens

        # Blue Team (Prosecution → argues VULNERABLE)
        blue_content, blue_tokens = _llm_call(BLUE_TEAM_PROMPT,
            f"{context}\n\nPresent your prosecution that this contract is VULNERABLE.")
        total_tokens += blue_tokens

        # Coordinator adjudicates
        coord_input = (
            f"## Contract Code:\n```solidity\n{code_short}\n```\n\n"
            f"## Defense (Red Team) Argument:\n{red_content[:1500]}\n\n"
            f"## Prosecution (Blue Team) Argument:\n{blue_content[:1500]}\n\n"
            f"Make your ruling."
        )
        coord_content, coord_tokens = _llm_call(COORDINATOR_PROMPT, coord_input, max_tokens=400)
        total_tokens += coord_tokens

        # Parse verdict
        jm = re.search(r"\{[\s\S]*?\}", coord_content)
        if jm:
            try:
                parsed = json.loads(jm.group())
                verdict = parsed.get("final_verdict", "SAFE").upper()
            except json.JSONDecodeError:
                verdict = "SAFE"
        else:
            verdict = "SAFE" if "safe" in coord_content.lower() else "VULNERABLE"

        final_vuln = verdict == "VULNERABLE"
        flip_map[cid] = final_vuln

        # Was this case flipped by critique? If debate overturns critique → restore
        s3_vuln = case["stage3_vulnerable"]
        changed = final_vuln != s3_vuln
        print(f" → Debate: {verdict}" + (" (overturns critique)" if changed else ""))

        debate_details.append({
            "contract_id": cid,
            "stage2_vulnerable": case["stage2_vulnerable"],
            "stage3_vulnerable": case["stage3_vulnerable"],
            "debate_verdict": verdict,
            "overturned_critique": changed,
        })

        time.sleep(0.15)

    # Apply debate verdicts to stage3 results
    debated = []
    flips = {"restored_to_vuln": 0, "confirmed_safe": 0, "no_debate": 0}
    for r in stage3_results:
        new_r = dict(r)
        cid = r.get("contract_id", "")
        if cid in flip_map:
            new_r["predicted_vulnerable"] = flip_map[cid]
            new_r["debate_resolved"] = True
            if flip_map[cid] and not r.get("predicted_vulnerable"):
                flips["restored_to_vuln"] += 1
            else:
                flips["confirmed_safe"] += 1
        else:
            new_r["debate_resolved"] = False
            flips["no_debate"] += 1
        debated.append(new_r)

    print(f"    Debate results: {flips}")
    print(f"    Tokens: {total_tokens:,}")

    summary = {
        "total_debates": len(debate_details),
        "flips": flips,
        "details": debate_details,
    }
    return debated, total_tokens, summary


# ============================================================
# Dataset & Metrics
# ============================================================

def load_dataset():
    with open(DATASET_FILE) as f:
        data = json.load(f)
    contracts = data["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]
    random.shuffle(sample)
    return sample


def load_contract_code(filepath):
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def compute_metrics(results):
    tp = fp = tn = fn = 0
    for r in results:
        gt = r.get("ground_truth_vulnerable", False)
        pred = r.get("predicted_vulnerable", False)
        if gt and pred: tp += 1
        elif not gt and pred: fp += 1
        elif gt and not pred: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "total": len(results),
    }


# ============================================================
# Main
# ============================================================
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("DmAVID ABLATION STUDY v4 — Redesigned Multi-Agent Pipeline")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print("Pipeline: Baseline → Self-Verify → Critique → Debate")
    print("=" * 70)

    contracts = load_dataset()
    print(f"Dataset: {len(contracts)} contracts")

    id_to_filepath = {}
    for c in contracts:
        cid = c.get("id", "")
        fp = c.get("filepath", "")
        if cid and fp:
            id_to_filepath[cid] = fp

    def code_loader(contract_id):
        fp = id_to_filepath.get(contract_id, "")
        return load_contract_code(fp)

    start_time = time.time()
    all_configs = []

    # =============================================
    # Stage 1: Baseline (LLM+RAG)
    # =============================================
    print("\n" + "=" * 60)
    print("STAGE 1: Baseline (LLM+RAG)")
    print("=" * 60)

    baseline_results = []
    baseline_tokens = 0
    for i, contract in enumerate(contracts):
        code = load_contract_code(contract.get("filepath", ""))
        if not code.strip():
            continue
        analysis = analyze_with_rag(code)
        gt_vuln = contract.get("label") == "vulnerable"
        result = {
            "contract_id": contract.get("id", f"c_{i}"),
            "ground_truth_vulnerable": gt_vuln,
            "category": contract.get("category", contract.get("vulnerability_type", "unknown")),
            "predicted_vulnerable": analysis.get("predicted_vulnerable", False),
            "confidence": analysis.get("confidence", 0.5),
            "vulnerability_types": analysis.get("vulnerability_types", []),
            "reasoning": analysis.get("reasoning", ""),
            "tokens_used": analysis.get("tokens_used", 0),
        }
        baseline_tokens += result["tokens_used"]
        baseline_results.append(result)
        if (i + 1) % 50 == 0:
            print(f"    Progress: {i+1}/{len(contracts)} ({baseline_tokens:,} tokens)")
        time.sleep(0.1)

    baseline_metrics = compute_metrics(baseline_results)
    print(f"  F1={baseline_metrics['f1']:.4f}  P={baseline_metrics['precision']:.4f}  R={baseline_metrics['recall']:.4f}")
    print(f"  TP={baseline_metrics['tp']} FP={baseline_metrics['fp']} FN={baseline_metrics['fn']} TN={baseline_metrics['tn']}")

    all_configs.append({
        "config": "baseline",
        "description": "LLM+RAG (identical to 05_run_llm_rag.py)",
        "metrics": baseline_metrics,
        "tokens": baseline_tokens,
    })

    # =============================================
    # Stage 2: +Self-Verify (structured)
    # =============================================
    print("\n" + "=" * 60)
    print("STAGE 2: +Self-Verify (structured exploit path extraction)")
    print("=" * 60)

    sv_results, sv_tokens = run_self_verify(baseline_results, code_loader)
    sv_metrics = compute_metrics(sv_results)
    print(f"  F1={sv_metrics['f1']:.4f}  P={sv_metrics['precision']:.4f}  R={sv_metrics['recall']:.4f}")
    print(f"  TP={sv_metrics['tp']} FP={sv_metrics['fp']} FN={sv_metrics['fn']} TN={sv_metrics['tn']}")

    all_configs.append({
        "config": "+self-verify",
        "description": "Baseline + structured exploit path verification (null fields → SAFE)",
        "metrics": sv_metrics,
        "tokens": baseline_tokens + sv_tokens,
    })

    # =============================================
    # Stage 3: +Critique (FP-focused)
    # =============================================
    print("\n" + "=" * 60)
    print("STAGE 3: +Critique (FP-focused auditor with few-shot)")
    print("=" * 60)

    critique_results, critique_tokens = run_critique(sv_results, code_loader)
    critique_metrics = compute_metrics(critique_results)
    print(f"  F1={critique_metrics['f1']:.4f}  P={critique_metrics['precision']:.4f}  R={critique_metrics['recall']:.4f}")
    print(f"  TP={critique_metrics['tp']} FP={critique_metrics['fp']} FN={critique_metrics['fn']} TN={critique_metrics['tn']}")

    all_configs.append({
        "config": "+critique",
        "description": "Baseline + Self-Verify + FP-focused Critique (auditor persona, few-shot)",
        "metrics": critique_metrics,
        "tokens": baseline_tokens + sv_tokens + critique_tokens,
    })

    # =============================================
    # Stage 4: +Debate (disagreement-triggered)
    # =============================================
    print("\n" + "=" * 60)
    print("STAGE 4: +Debate (triggered by S2 vs S3 disagreement)")
    print("=" * 60)

    debate_results, debate_tokens, debate_summary = run_debate(
        sv_results, critique_results, code_loader, max_cases=20)
    debate_metrics = compute_metrics(debate_results)
    print(f"  F1={debate_metrics['f1']:.4f}  P={debate_metrics['precision']:.4f}  R={debate_metrics['recall']:.4f}")
    print(f"  TP={debate_metrics['tp']} FP={debate_metrics['fp']} FN={debate_metrics['fn']} TN={debate_metrics['tn']}")

    all_configs.append({
        "config": "+debate",
        "description": "Full pipeline: Baseline + Self-Verify + Critique + Disagreement Debate",
        "metrics": debate_metrics,
        "tokens": baseline_tokens + sv_tokens + critique_tokens + debate_tokens,
        "debate_summary": {
            "total_debates": debate_summary["total_debates"],
            "flips": debate_summary["flips"],
        },
    })

    # =============================================
    # Summary
    # =============================================
    total_time = time.time() - start_time

    print("\n" + "=" * 70)
    print("ABLATION RESULTS v4 — Redesigned Pipeline")
    print("=" * 70)
    print(f"\n{'Config':<22} {'F1':>8} {'P':>8} {'R':>8} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}")
    print("-" * 75)
    for cfg in all_configs:
        m = cfg["metrics"]
        print(f"{cfg['config']:<22} {m['f1']:>8.4f} {m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['tp']:>5} {m['fp']:>5} {m['fn']:>5} {m['tn']:>5}")

    base_f1 = all_configs[0]["metrics"]["f1"]
    print(f"\nBaseline F1: {base_f1:.4f}")
    for cfg in all_configs[1:]:
        delta = cfg["metrics"]["f1"] - base_f1
        pct = delta / base_f1 * 100 if base_f1 > 0 else 0
        print(f"  {cfg['config']:<20} F1={cfg['metrics']['f1']:.4f} (delta: {delta:+.4f}, {pct:+.1f}%)")

    print(f"\nTotal time: {total_time/60:.1f} minutes")

    # Save
    output = {
        "experiment": "ablation_study_v4",
        "description": "Redesigned multi-agent pipeline: structured Self-Verify, FP-focused Critique, disagreement-triggered Debate",
        "model": MODEL,
        "dataset_size": len(contracts),
        "timestamp": datetime.now().isoformat(),
        "total_time_seconds": round(total_time, 1),
        "configs": all_configs,
    }

    outfile = os.path.join(OUTPUT_DIR, "ablation_v4_results.json")
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {outfile}")

    # Save per-stage details
    stage_data = {
        "baseline": baseline_results,
        "self-verify": sv_results,
        "critique": critique_results,
        "debate": debate_results,
    }
    for name, res in stage_data.items():
        detail_file = os.path.join(OUTPUT_DIR, f"ablation_v4_{name}_details.json")
        with open(detail_file, "w") as f:
            json.dump({"config": name, "metrics": compute_metrics(res), "results": res},
                      f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
