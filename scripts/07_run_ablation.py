#!/usr/bin/env python3
"""
Experiment 7: DmAVID Unified Ablation Study

Unified baseline: Script 05's LLM+RAG cache (keyword RAG, no ChromaDB).
Progressively add detection components to measure independent contribution:

  baseline  — Stage 1 only (llm_rag_results.json)
  +sv       — + JSON exploit verifier on vulnerable predictions
  +slither  — + Slither Stage 2 on safe predictions (≥2 H/M findings)
  +both     — + both SV and Slither Stage 2

Design follows Karpathy's ablation prescription:
  same Stage 1 for all conditions → fair component-level comparison.
"""

import os, json, time, re, sys, subprocess, argparse
from datetime import datetime
from openai import OpenAI
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from _model_compat import token_param

# Import shared utilities from 06_run_hybrid (safe: has if __name__=='__main__' guard)
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "hybrid", os.path.join(SCRIPT_DIR, "06_run_hybrid.py")
)
_hybrid = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hybrid)

strip_answer_comments   = _hybrid.strip_answer_comments
detect_solc_version     = _hybrid.detect_solc_version
run_slither_quick       = _hybrid.run_slither_quick
prefilter_slither_findings = _hybrid.prefilter_slither_findings
run_exploit_verification = _hybrid.run_exploit_verification
run_stage2              = _hybrid.run_stage2

# ── Config ──────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(SCRIPT_DIR)
DATASET_FILE    = os.path.join(BASE_DIR, "data", "dataset_1000.json")
LLM_RAG_FILE    = os.path.join(BASE_DIR, "experiments", "llm_rag", "llm_rag_results.json")
OUTPUT_DIR      = os.path.join(BASE_DIR, "experiments", "ablation")
LLM_MODEL       = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
MAX_CODE_LENGTH = 12_000
SLITHER_HM_MIN  = 2   # Minimum H/M findings to trigger Stage 2

os.makedirs(OUTPUT_DIR, exist_ok=True)
client = OpenAI()

# ── Metrics ─────────────────────────────────────────────────────────────────
def compute_metrics(preds: List[Dict]) -> Dict:
    tp = sum(1 for p in preds if p["gt"] == "vulnerable" and p["pred"])
    fn = sum(1 for p in preds if p["gt"] == "vulnerable" and not p["pred"])
    fp = sum(1 for p in preds if p["gt"] == "safe"       and p["pred"])
    tn = sum(1 for p in preds if p["gt"] == "safe"       and not p["pred"])
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec  = tp / (tp + fn) if tp + fn else 0.0
    f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr  = fp / (fp + tn) if fp + tn else 0.0
    return dict(tp=tp, fn=fn, fp=fp, tn=tn,
                precision=round(prec, 4), recall=round(rec, 4),
                f1=round(f1, 4), fpr=round(fpr, 4))


def print_metrics_table(all_results: Dict[str, Dict]):
    """Print aligned comparison table."""
    conditions = list(all_results.keys())
    metrics_order = ["tp", "fn", "fp", "tn", "precision", "recall", "f1", "fpr"]
    labels = dict(tp="TP", fn="FN", fp="FP", tn="TN",
                  precision="Precision", recall="Recall", f1="F1", fpr="FPR")

    header = f"  {'Metric':<12}" + "".join(f"  {c:>12}" for c in conditions)
    print("\n" + "=" * (14 + 14 * len(conditions)))
    print("ABLATION STUDY RESULTS")
    print("=" * (14 + 14 * len(conditions)))
    print(header)
    print("  " + "-" * (12 + 14 * len(conditions)))

    for m in metrics_order:
        row = f"  {labels[m]:<12}"
        for c in conditions:
            v = all_results[c][m]
            if m in ("precision", "recall", "f1", "fpr"):
                row += f"  {v:>11.4f}"
            else:
                row += f"  {v:>12d}"
        print(row)

    print("  " + "-" * (12 + 14 * len(conditions)))
    print(f"\n  {'SV flips':<12}" + "".join(
        f"  {all_results[c].get('sv_flips', 0):>12d}" for c in conditions))
    print(f"  {'S2 flips':<12}" + "".join(
        f"  {all_results[c].get('slither_flips', 0):>12d}" for c in conditions))
    print(f"  {'API calls':<12}" + "".join(
        f"  {all_results[c].get('api_calls', 0):>12d}" for c in conditions))
    print(f"  {'Tokens':<12}" + "".join(
        f"  {all_results[c].get('tokens', 0):>12,}" for c in conditions))


# ── Main Ablation Logic ──────────────────────────────────────────────────────
def run_ablation(sv_threshold: float = 1.0):
    """
    sv_threshold: max confidence for SV to run (1.0 = run on all vulnerable predictions)
    """
    print("=" * 60)
    print("Experiment 7: DmAVID Unified Ablation Study")
    print(f"  Stage 1 source: llm_rag_results.json (keyword RAG)")
    print(f"  LLM Model: {LLM_MODEL}")
    print(f"  SV threshold: conf ≤ {sv_threshold}")
    print(f"  Slither H/M min: {SLITHER_HM_MIN}")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)

    # ── Load Stage 1 cache ────────────────────────────────────────
    with open(LLM_RAG_FILE) as f:
        llm_data = json.load(f)
    stage1_results = llm_data["results"]
    print(f"\nLoaded {len(stage1_results)} Stage 1 predictions from llm_rag_results.json")

    # ── Resolve file paths ────────────────────────────────────────
    with open(DATASET_FILE) as f:
        dataset = json.load(f)
    filepath_map = {c["id"]: c["filepath"]       for c in dataset["contracts"] if "filepath" in c}
    filename_map = {c["filename"]: c["filepath"] for c in dataset["contracts"] if "filepath" in c}

    # ── Pre-compute Slither (shared across all conditions) ────────
    print("\n[Slither] Pre-computing findings for all contracts...")
    t_slither_start = time.time()
    slither_cache: Dict[str, Dict] = {}

    for i, r in enumerate(stage1_results):
        cid      = r.get("contract_id", "")
        fname    = r.get("filename", "")
        filepath = filepath_map.get(cid) or filename_map.get(fname, "")

        code = ""
        findings_raw = []
        if filepath and os.path.exists(filepath):
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                code = strip_answer_comments(f.read())
            findings_raw = run_slither_quick(filepath)

        ver = detect_solc_version(code) if code else "0.8.0"
        filtered = prefilter_slither_findings(findings_raw, code, ver)
        hm = [f for f in filtered if f["impact"] in ("High", "Medium")]

        slither_cache[cid] = {
            "filepath": filepath,
            "code": code[:MAX_CODE_LENGTH],
            "filtered_findings": filtered,
            "hm_count": len(hm),
        }

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(stage1_results)}] Slither pre-compute done")

    t_slither = time.time() - t_slither_start
    hm_contracts = sum(1 for v in slither_cache.values() if v["hm_count"] >= SLITHER_HM_MIN)
    print(f"  Done in {t_slither:.1f}s | contracts with ≥{SLITHER_HM_MIN} H/M: {hm_contracts}")

    # ── Run ablation conditions ───────────────────────────────────
    conditions = ["baseline", "+sv", "+slither", "+both"]
    all_results: Dict[str, Dict] = {}

    for condition in conditions:
        use_sv      = condition in ("+sv",      "+both")
        use_slither = condition in ("+slither", "+both")

        print(f"\n{'─'*60}")
        print(f"[{condition}]  use_sv={use_sv}  use_slither={use_slither}")
        print(f"{'─'*60}")

        preds:         List[Dict] = []
        tokens_used:   int = 0
        api_calls:     int = 0
        sv_flips:      int = 0
        slither_flips: int = 0

        for i, r in enumerate(stage1_results):
            cid        = r.get("contract_id", "")
            gt         = r["ground_truth"]
            s1_vuln    = bool(r["predicted_vulnerable"])
            conf       = float(r.get("confidence", 0.9))
            vuln_types = r.get("vulnerability_types", [])

            sc               = slither_cache.get(cid, {})
            code             = sc.get("code", "")
            filtered         = sc.get("filtered_findings", [])
            hm_count         = sc.get("hm_count", 0)

            pred = s1_vuln
            path = "stage1"

            # ── +SV: exploit verifier on vulnerable predictions ──
            if s1_vuln and use_sv and conf <= sv_threshold:
                verify = run_exploit_verification(code, vuln_types, client)
                tokens_used += verify.get("tokens_used", 0)
                api_calls   += 1
                if not verify["exploit_constructable"]:
                    pred = False
                    path = "sv_flipped"
                    sv_flips += 1
                    if (i + 1) % 25 == 0 or True:
                        pass  # report handled by progress line
                else:
                    path = "sv_confirmed"

            # ── +Slither: Stage 2 on safe predictions ────────────
            if not s1_vuln and use_slither and hm_count >= SLITHER_HM_MIN:
                s2 = run_stage2(code, filtered, conf, client)
                tokens_used += s2.get("tokens_used", 0)
                api_calls   += 1
                if s2.get("success") and s2.get("predicted_vulnerable"):
                    pred = True
                    path = "slither_override"
                    slither_flips += 1

            preds.append({"gt": gt, "pred": pred, "path": path})

            if (i + 1) % 25 == 0:
                m = compute_metrics(preds)
                print(f"  [{i+1}/{len(stage1_results)}] "
                      f"TP={m['tp']} FN={m['fn']} FP={m['fp']} TN={m['tn']} "
                      f"F1={m['f1']:.4f} FPR={m['fpr']:.4f} | "
                      f"sv_flips={sv_flips} s2_flips={slither_flips} tokens={tokens_used:,}")

        final_metrics = compute_metrics(preds)
        all_results[condition] = {
            **final_metrics,
            "sv_flips": sv_flips,
            "slither_flips": slither_flips,
            "api_calls": api_calls,
            "tokens": tokens_used,
        }

        print(f"\n  [{condition}] Final: "
              f"TP={final_metrics['tp']} FN={final_metrics['fn']} "
              f"FP={final_metrics['fp']} TN={final_metrics['tn']} "
              f"F1={final_metrics['f1']:.4f} FPR={final_metrics['fpr']:.4f}")

    # ── Print and save results ────────────────────────────────────
    print_metrics_table(all_results)

    # Per-category recall for best condition
    best_cond = max((c for c in conditions if c != "baseline"),
                    key=lambda c: all_results[c]["f1"])
    print(f"\n  Best condition: {best_cond} (F1={all_results[best_cond]['f1']:.4f})")

    # Save
    output = {
        "experiment": "ablation",
        "timestamp": datetime.now().isoformat(),
        "model": LLM_MODEL,
        "stage1_source": "llm_rag_results.json",
        "sv_threshold": sv_threshold,
        "slither_hm_min": SLITHER_HM_MIN,
        "results": all_results,
    }
    out_path = os.path.join(OUTPUT_DIR, "ablation_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {out_path}")

    return all_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DmAVID Unified Ablation Study")
    parser.add_argument("--sv-threshold", type=float, default=1.0,
                        help="Max confidence for SV exploit verifier (default: 1.0 = all)")
    parser.add_argument("--conditions", nargs="+",
                        default=["baseline", "+sv", "+slither", "+both"],
                        help="Ablation conditions to run")
    args = parser.parse_args()
    run_ablation(sv_threshold=args.sv_threshold)
