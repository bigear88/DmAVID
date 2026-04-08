#!/usr/bin/env python3
"""
Post-processing for Strategy 1: Self-Verification via Exploit Path Generation.

- Input : experiments/llm_rag/llm_rag_results.json (gpt-4.1-mini + RAG)
- Output: prints baseline vs hybrid metrics, and optionally writes a new JSON.

Only re-examines cases where Stage-1 predicted_vulnerable == True.
Reference: PoCo (arXiv:2511.02780), Heimdallr (arXiv:2601.17833)
"""

import os
import sys
import json
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

from openai import OpenAI

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_FILE = os.path.join(BASE_DIR, "experiments", "llm_rag", "llm_rag_results.json")
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "hybrid", "self_verify_results.json")

client = OpenAI()
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")


@dataclass
class SampleResult:
    contract_id: str
    ground_truth: str
    category: str
    stage1_pred_vuln: bool
    stage1_conf: float
    stage1_reason: str
    hybrid_pred_vuln: bool
    verify_reason: str
    time_verify: float
    tokens_verify: int
    error: str = ""


def build_exploit_prompt(sample: Dict[str, Any]) -> str:
    vuln_types = sample.get("vulnerability_types") or []
    vuln_str = ", ".join(vuln_types) if vuln_types else "a potential vulnerability"
    stage1_reason = sample.get("reasoning", "")[:1500]

    prompt = f"""
You previously analyzed the following Ethereum smart contract and classified it as VULNERABLE due to {vuln_str}.

Now act as a red-team security researcher and provide a CONCRETE exploit path that demonstrates how the vulnerability can be triggered in practice.

Your answer MUST follow this structure:

1. Required Preconditions:
   - Describe the initial on-chain state, balances, roles, and any necessary setup.

2. Transaction Sequence:
   - A step-by-step sequence of function calls or transactions.
   - For each step, specify: caller, target function, key parameters, and relevant state changes.

3. Expected Outcome:
   - Describe the final on-chain state that proves the exploit succeeded
     (e.g., stolen funds, broken invariant, locked funds, privilege escalation).

Constraints:
- The exploit path MUST be logically consistent with the provided reasoning and typical EVM execution.
- If you CANNOT construct a valid and logically consistent exploit path, explicitly state:
  "Upon review, a concrete exploit path cannot be constructed, and the initial assessment may be a false positive."

Previous reasoning from your earlier audit:
\"\"\"{stage1_reason}\"\"\"
"""
    return prompt.strip()


def call_exploit_verifier(code: str, sample: Dict[str, Any], max_retries: int = 2) -> dict:
    prompt = build_exploit_prompt(sample)
    user_content = f"Here is the Solidity contract you previously audited:\n```solidity\n{code}\n```"

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            start = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.2,
                **token_param(1024),
                seed=42,
            )
            elapsed = time.time() - start
            content = resp.choices[0].message.content.strip()
            usage = resp.usage.total_tokens if resp.usage else 0
            return {
                "success": True,
                "text": content,
                "time": elapsed,
                "tokens": usage,
                "error": None,
            }
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False,
                "text": "",
                "time": 0.0,
                "tokens": 0,
                "error": last_error,
            }


def decide_from_exploit_text(text: str) -> bool:
    """
    Heuristic: if LLM explicitly says it cannot construct exploit → flip to SAFE.
    Otherwise keep VULNERABLE.
    """
    low = text.lower()
    if "cannot be constructed" in low and "false positive" in low:
        return False
    if "may be a false positive" in low:
        return False
    if "cannot construct" in low and "exploit" in low:
        return False
    if "no concrete exploit" in low:
        return False
    if "initial assessment may be" in low and "false" in low:
        return False
    return True


def recompute_metrics(samples: List[SampleResult]) -> Dict[str, Any]:
    tp = sum(1 for s in samples if s.ground_truth == "vulnerable" and s.hybrid_pred_vuln)
    fn = sum(1 for s in samples if s.ground_truth == "vulnerable" and not s.hybrid_pred_vuln)
    fp = sum(1 for s in samples if s.ground_truth == "safe" and s.hybrid_pred_vuln)
    tn = sum(1 for s in samples if s.ground_truth == "safe" and not s.hybrid_pred_vuln)

    total = tp + fn + fp + tn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    spec = tn / (tn + fp) if (tn + fp) else 0.0

    return {
        "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4), "specificity": round(spec, 4),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Self-Verification Post-Processing")
    parser.add_argument("--conf-threshold", type=float, default=None,
                        help="Only verify samples with confidence below this threshold (default: verify all)")
    args = parser.parse_args()

    print("=" * 60)
    print("DmAVID Self-Verification Post-Processing")
    print(f"Model: {MODEL}")
    print(f"Confidence threshold: {args.conf_threshold or 'ALL (verify every vulnerable prediction)'}")
    print("=" * 60)

    data = load_llm_rag_results(RESULTS_FILE)
    results = data["results"]
    print(f"Loaded {len(results)} samples from {RESULTS_FILE}")

    # Load dataset for file paths
    with open(DATASET_FILE, "r") as f:
        dataset = json.load(f)
    filepath_map = {c["id"]: c["filepath"] for c in dataset["contracts"] if "filepath" in c}
    filename_map = {c["filename"]: c["filepath"] for c in dataset["contracts"] if "filepath" in c}

    base_m = data["metrics"]
    print(f"\nBaseline LLM+RAG:")
    print(f"  TP={base_m['tp']} FN={base_m['fn']} FP={base_m['fp']} TN={base_m['tn']} F1={base_m['f1_score']:.4f}")

    samples: List[SampleResult] = []
    total_verify_tokens = 0
    flipped_count = 0
    verified_count = 0

    for i, r in enumerate(results):
        gt = r.get("ground_truth")
        if gt not in ("vulnerable", "safe"):
            continue

        stage1_pred_vuln = bool(r.get("predicted_vulnerable", False))
        stage1_conf = float(r.get("confidence", 0.5))
        stage1_reason = r.get("reasoning", "")

        hybrid_pred_vuln = stage1_pred_vuln
        verify_reason = ""
        t_verify = 0.0
        tok_verify = 0

        # Only verify vulnerable predictions (optionally filtered by confidence)
        should_verify = stage1_pred_vuln
        if args.conf_threshold and stage1_conf >= args.conf_threshold:
            should_verify = False  # High confidence → skip verification

        if should_verify:
            verified_count += 1
            # Load contract source code
            contract_id = r.get("contract_id", "")
            filepath = filepath_map.get(contract_id) or filename_map.get(r.get("filename", ""), "")
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
            except Exception as e:
                code = f"// ERROR loading source: {e}"

            vres = call_exploit_verifier(code, r)
            if vres["success"]:
                hybrid_pred_vuln = decide_from_exploit_text(vres["text"])
                verify_reason = vres["text"][:800]
                t_verify = vres["time"]
                tok_verify = vres["tokens"]
                total_verify_tokens += tok_verify
                if not hybrid_pred_vuln and stage1_pred_vuln:
                    flipped_count += 1
                    print(f"  [FLIP] #{i+1} {r.get('filename','?')} (conf={stage1_conf:.2f}, gt={gt}) → SAFE")
            else:
                verify_reason = f"[error] {vres['error']}"

        samples.append(SampleResult(
            contract_id=r.get("contract_id", ""),
            ground_truth=gt,
            category=r.get("category", ""),
            stage1_pred_vuln=stage1_pred_vuln,
            stage1_conf=stage1_conf,
            stage1_reason=stage1_reason[:200],
            hybrid_pred_vuln=hybrid_pred_vuln,
            verify_reason=verify_reason[:200],
            time_verify=round(t_verify, 3),
            tokens_verify=tok_verify,
        ))

        if (i + 1) % 25 == 0:
            m = recompute_metrics(samples)
            print(f"  [{i+1}/{len(results)}] TP={m['tp']} FN={m['fn']} FP={m['fp']} TN={m['tn']} "
                  f"F1={m['f1']:.4f} | verified={verified_count} flipped={flipped_count}")

    hybrid_m = recompute_metrics(samples)

    print("\n" + "=" * 60)
    print("SELF-VERIFICATION RESULTS")
    print("=" * 60)
    print(f"  Verified: {verified_count} contracts")
    print(f"  Flipped to SAFE: {flipped_count}")
    print(f"  Verify tokens: {total_verify_tokens:,}")
    print()
    print(f"  {'Metric':<15} {'Baseline':>10} {'Hybrid':>10} {'Delta':>10}")
    print(f"  {'-'*45}")
    for key, bkey in [("tp","tp"),("fn","fn"),("fp","fp"),("tn","tn")]:
        bv = base_m[bkey]
        hv = hybrid_m[key]
        print(f"  {key.upper():<15} {bv:>10} {hv:>10} {hv-bv:>+10}")
    print(f"  {'Precision':<15} {base_m.get('precision',0):>10.4f} {hybrid_m['precision']:>10.4f} {hybrid_m['precision']-base_m.get('precision',0):>+10.4f}")
    print(f"  {'Recall':<15} {base_m.get('recall',0):>10.4f} {hybrid_m['recall']:>10.4f} {hybrid_m['recall']-base_m.get('recall',0):>+10.4f}")
    print(f"  {'F1':<15} {base_m['f1_score']:>10.4f} {hybrid_m['f1']:>10.4f} {hybrid_m['f1']-base_m['f1_score']:>+10.4f}")
    print(f"  {'FPR':<15} {base_m.get('fpr',0):>10.4f} {hybrid_m['fpr']:>10.4f} {hybrid_m['fpr']-base_m.get('fpr',0):>+10.4f}")

    beat = hybrid_m['f1'] > base_m['f1_score']
    print(f"\n  {'✅ F1 IMPROVED!' if beat else '❌ F1 not improved'}: {base_m['f1_score']:.4f} → {hybrid_m['f1']:.4f}")

    # Save results
    output = {
        "experiment": "self_verification_postprocess",
        "model": MODEL,
        "conf_threshold": args.conf_threshold,
        "baseline_metrics": base_m,
        "hybrid_metrics": hybrid_m,
        "verified_count": verified_count,
        "flipped_count": flipped_count,
        "total_verify_tokens": total_verify_tokens,
        "samples": [asdict(s) for s in samples],
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {OUTPUT_FILE}")


def load_llm_rag_results(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    main()
