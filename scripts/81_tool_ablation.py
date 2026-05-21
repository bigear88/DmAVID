#!/usr/bin/env python3
"""
81_tool_ablation.py
DmAVID 6-arm Tool Ablation Study

Arms:
  A: LLM-only (no RAG, re-run or load from llm_base_results.json)
  B: LLM+RAG baseline (llm_rag_results.json, no LLM call)
  C: B + hardcoded rules (direct flip, no LLM)
  D: B + LLM re-eval with tools (same as script 80)
  E: D + source code (re-eval prompt includes contract source, first 200 lines)
"""

import os
import sys
import json
import re
import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, BASE_DIR)

from openai import OpenAI
from _model_compat import token_param
from tools.grep_guard import grep_guard
from tools.solc_check import solc_check

MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
TEMPERATURE = 0.1
SEED = 42

RAG_RESULTS_PATH  = os.path.join(BASE_DIR, "experiments", "llm_rag", "llm_rag_results.json")
BASE_RESULTS_PATH = os.path.join(BASE_DIR, "experiments", "llm_base", "llm_base_results.json")
DATASET_PATH      = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_DIR        = os.path.join(BASE_DIR, "experiments", "tool_augmented")
OUTPUT_PATH       = os.path.join(OUTPUT_DIR, "ablation_results.json")


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def strip_annotations(code):
    code = re.sub(r"[^\n]*<(?:yes|no)>[^\n]*", "", code)
    code = re.sub(r"[^\n]*@vulnerable_at_lines:[^\n]*\n?", "", code)
    return code


def format_grep_guard(result):
    lines = [
        f"找到的防護機制: {', '.join(result['mitigations']) if result['mitigations'] else '無'}",
        f"僅使用 .transfer(): {'是' if result['transfer_only'] else '否'}",
        f"ReentrancyGuard: {'有' if result['has_reentrancy_guard'] else '無'}",
        f"SafeMath: {'有' if result['has_safemath'] else '無'}",
        f"onlyOwner: {'有' if result['has_only_owner'] else '無'}",
        f".send() 返回值有檢查: {'是' if result['has_send_checked'] else '否'}",
        f".call.value() 存在: {'是' if result['call_value_present'] else '否'}",
        f"防護機制數量: {result['mitigation_count']}",
    ]
    return "\n".join(lines)


def format_solc_check(result):
    lines = [
        f"Pragma: {result['pragma_raw']}",
        f"版本: {result['version']}",
        f"內建 overflow 保護 (>=0.8): {'是' if result['overflow_safe_builtin'] else '否'}",
        f"SafeMath: {'有' if result['has_safemath'] else '無'}",
        f"unchecked 區塊: {'有' if result['has_unchecked_block'] else '無'}",
        f"算術運算: {'有' if result['has_arithmetic_ops'] else '無'}",
        f"Overflow 風險: {result['overflow_risk']}",
    ]
    return "\n".join(lines)


def compute_metrics_raw(tp, fn, fp, tn):
    total     = tp + fn + fp + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1_score":  round(f1, 4),
        "fpr":       round(fpr, 4),
    }


def compute_metrics_from_preds(ground_truths, preds):
    tp = fn = fp = tn = 0
    for gt_str, pred in zip(ground_truths, preds):
        gt = gt_str == "vulnerable"
        if   gt and pred:       tp += 1
        elif gt and not pred:   fn += 1
        elif not gt and pred:   fp += 1
        else:                   tn += 1
    return compute_metrics_raw(tp, fn, fp, tn)


# ──────────────────────────────────────────────
# Prompts (same as script 80)
# ──────────────────────────────────────────────
REEVAL_PROMPT = """\
你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 VULNERABLE，原因是 {vulnerability_types}。
原始分析的信心度: {confidence}

我用靜態分析工具對合約原始碼做了獨立檢查，結果如下：

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

【Solidity 版本分析 (solc_check)】
{solc_check_formatted}

請根據你的專業知識，結合以上工具證據，獨立判斷這個合約是否真的有漏洞。

注意事項：
- .transfer() 有 2300 gas limit，不足以執行 reentrancy attack
- SafeMath 全域宣告不代表所有函數都使用（如 BECToken 的 batchTransfer）
- onlyOwner 只保護有修飾符的函數，不保護其他函數
- 工具證據是事實，但需要你來判斷這些事實對漏洞判定的影響

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "reasoning": "detailed explanation of your assessment considering tool evidence"}}"""

REEVAL_PROMPT_WITH_CODE = """\
你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 VULNERABLE，原因是 {vulnerability_types}。
原始分析的信心度: {confidence}

【合約原始碼（前 200 行）】
```solidity
{contract_code}
```

我用靜態分析工具對合約原始碼做了獨立檢查，結果如下：

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

【Solidity 版本分析 (solc_check)】
{solc_check_formatted}

請根據你的專業知識，結合原始碼和工具證據，獨立判斷這個合約是否真的有漏洞。

注意事項：
- .transfer() 有 2300 gas limit，不足以執行 reentrancy attack
- SafeMath 全域宣告不代表所有函數都使用（如 BECToken 的 batchTransfer）
- onlyOwner 只保護有修飾符的函數，不保護其他函數
- 工具證據是事實，但需要你來判斷這些事實對漏洞判定的影響

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "reasoning": "detailed explanation of your assessment considering tool evidence and source code"}}"""

RESCAN_PROMPT = """\
你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 SAFE。

但我用工具檢查發現以下風險因子：

【Solidity 版本分析 (solc_check)】
- Solidity 版本: {version}（低於 0.8，沒有內建 overflow 保護）
- SafeMath: 未使用
- 合約中有算術運算
- Overflow 風險評級: HIGH

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

請根據你的專業知識，結合以上工具證據，重新檢查這個合約是否有 integer overflow/underflow 漏洞。

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "vulnerability_types": ["INTEGER_OVERFLOW"] or [], "reasoning": "detailed explanation"}}"""

RESCAN_PROMPT_WITH_CODE = """\
你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 SAFE。

【合約原始碼（前 200 行）】
```solidity
{contract_code}
```

但我用工具檢查發現以下風險因子：

【Solidity 版本分析 (solc_check)】
- Solidity 版本: {version}（低於 0.8，沒有內建 overflow 保護）
- SafeMath: 未使用
- 合約中有算術運算
- Overflow 風險評級: HIGH

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

請根據你的專業知識，結合原始碼和工具證據，重新檢查這個合約是否有 integer overflow/underflow 漏洞。

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "vulnerability_types": ["INTEGER_OVERFLOW"] or [], "reasoning": "detailed explanation"}}"""

LLM_ONLY_PROMPT = """\
你是一個 Solidity 智能合約安全審計專家。請分析以下合約是否有安全漏洞。

【合約原始碼】
```solidity
{contract_code}
```

請仔細分析合約的安全性，包括但不限於：reentrancy、integer overflow/underflow、access control、unchecked calls 等常見漏洞。

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "vulnerability_types": [], "confidence": 0.0-1.0, "reasoning": "detailed explanation"}}"""


# ──────────────────────────────────────────────
# LLM call helper
# ──────────────────────────────────────────────
def call_llm(client, prompt):
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=TEMPERATURE,
        seed=SEED,
        **token_param(1024),
    )
    raw = resp.choices[0].message.content.strip()
    tokens = resp.usage.total_tokens
    json_match = re.search(r"\{.*\}", raw, re.DOTALL)
    result = json.loads(json_match.group()) if json_match else {}
    return result, tokens


# ──────────────────────────────────────────────
# Arm runners
# ──────────────────────────────────────────────

def run_arm_a(rag_results, filepath_map, client):
    """Arm A: LLM-only (no RAG). Load from llm_base if available, else re-run."""
    print("\n[Arm A] LLM-only...")
    if os.path.exists(BASE_RESULTS_PATH):
        print(f"  Loading from {BASE_RESULTS_PATH}")
        with open(BASE_RESULTS_PATH) as f:
            base_data = json.load(f)
        base_results = {r["filename"]: r for r in base_data["results"]}
        preds = []
        gts   = []
        per_contract = []
        for r in rag_results:
            fn = r["filename"]
            gt = r["ground_truth"]
            if fn in base_results:
                pred = base_results[fn]["predicted_vulnerable"]
            else:
                pred = r["predicted_vulnerable"]  # fallback
            preds.append(pred)
            gts.append(gt)
            per_contract.append({"filename": fn, "ground_truth": gt, "predicted_vulnerable": pred})
        return compute_metrics_from_preds(gts, preds), per_contract, 0
    else:
        print("  llm_base_results.json not found. Re-running LLM without RAG context...")
        preds = []
        gts   = []
        per_contract = []
        total_tokens = 0
        for i, r in enumerate(rag_results):
            fn  = r["filename"]
            gt  = r["ground_truth"]
            filepath = filepath_map.get(fn)
            code_raw = ""
            if filepath and os.path.exists(filepath):
                with open(filepath, encoding="utf-8", errors="replace") as f:
                    code_raw = f.read()
            code = strip_annotations(code_raw)
            try:
                prompt = LLM_ONLY_PROMPT.format(contract_code=code[:8000])
                result, tokens = call_llm(client, prompt)
                total_tokens += tokens
                pred = result.get("verdict", "VULNERABLE").upper() == "VULNERABLE"
            except Exception as e:
                print(f"  [ERROR] arm_a {fn}: {e}")
                pred = r["predicted_vulnerable"]
            preds.append(pred)
            gts.append(gt)
            per_contract.append({"filename": fn, "ground_truth": gt, "predicted_vulnerable": pred})
            if (i + 1) % 25 == 0 or (i + 1) == len(rag_results):
                m = compute_metrics_from_preds(gts, preds)
                print(f"  [{i+1}/{len(rag_results)}] F1={m['f1_score']:.4f}", flush=True)
        return compute_metrics_from_preds(gts, preds), per_contract, total_tokens


def run_arm_b(rag_results):
    """Arm B: LLM+RAG baseline (no LLM call)."""
    print("\n[Arm B] LLM+RAG baseline (direct from llm_rag_results.json)...")
    preds = [r["predicted_vulnerable"] for r in rag_results]
    gts   = [r["ground_truth"] for r in rag_results]
    per_contract = [
        {"filename": r["filename"], "ground_truth": r["ground_truth"], "predicted_vulnerable": r["predicted_vulnerable"]}
        for r in rag_results
    ]
    return compute_metrics_from_preds(gts, preds), per_contract


def run_arm_c(rag_results, filepath_map):
    """Arm C: B + hardcoded rules (no LLM). Direct flip based on tool signals."""
    print("\n[Arm C] B + hardcoded rules (no LLM)...")
    preds = []
    gts   = []
    per_contract = []
    for r in rag_results:
        fn   = r["filename"]
        gt   = r["ground_truth"]
        base_pred = r["predicted_vulnerable"]
        filepath = filepath_map.get(fn)
        code_raw = ""
        if filepath and os.path.exists(filepath):
            with open(filepath, encoding="utf-8", errors="replace") as f:
                code_raw = f.read()
        code = strip_annotations(code_raw)
        gg = grep_guard(code)
        sc = solc_check(code)

        pred = base_pred
        flip_reason = None

        if base_pred:
            # pred=VULN: if strong mitigations, flip to SAFE
            if gg["mitigation_count"] >= 2 or gg["transfer_only"]:
                pred = False
                flip_reason = "hardcoded: mitigation_count>=2 or transfer_only"
        else:
            # pred=SAFE: if overflow_risk==high, flip to VULN
            if sc["overflow_risk"] == "high":
                pred = True
                flip_reason = "hardcoded: overflow_risk==high"

        preds.append(pred)
        gts.append(gt)
        per_contract.append({
            "filename": fn,
            "ground_truth": gt,
            "base_predicted_vulnerable": base_pred,
            "predicted_vulnerable": pred,
            "flip_reason": flip_reason,
            "grep_guard": gg,
            "solc_check": sc,
        })
    return compute_metrics_from_preds(gts, preds), per_contract


def run_arm_d(rag_results, filepath_map, client):
    """Arm D: B + LLM re-eval with tools (same logic as script 80)."""
    print("\n[Arm D] B + LLM re-eval with tools...")
    preds = []
    gts   = []
    per_contract = []
    total_tokens = 0
    llm_calls    = 0
    flipped      = 0

    for i, r in enumerate(rag_results):
        fn   = r["filename"]
        gt   = r["ground_truth"]
        base_pred = r["predicted_vulnerable"]
        filepath = filepath_map.get(fn)
        code_raw = ""
        if filepath and os.path.exists(filepath):
            with open(filepath, encoding="utf-8", errors="replace") as f:
                code_raw = f.read()
        code = strip_annotations(code_raw)
        gg = grep_guard(code)
        sc = solc_check(code)

        pred        = base_pred
        reeval_res  = None
        reeval_done = False

        vuln_types_str = ", ".join(r.get("vulnerability_types", [])) or "unknown"
        confidence     = r.get("confidence", 0.9)

        if base_pred:
            try:
                prompt = REEVAL_PROMPT.format(
                    vulnerability_types=vuln_types_str,
                    confidence=confidence,
                    grep_guard_formatted=format_grep_guard(gg),
                    solc_check_formatted=format_solc_check(sc),
                )
                reeval_res, tokens = call_llm(client, prompt)
                total_tokens += tokens
                llm_calls    += 1
                verdict = reeval_res.get("verdict", "VULNERABLE").upper()
                if verdict == "SAFE":
                    pred = False
                    flipped += 1
                reeval_done = True
            except Exception as e:
                print(f"  [ERROR] arm_d reeval {fn}: {e}", flush=True)

        elif not base_pred and sc["overflow_risk"] == "high":
            try:
                prompt = RESCAN_PROMPT.format(
                    version=sc["version"],
                    grep_guard_formatted=format_grep_guard(gg),
                )
                reeval_res, tokens = call_llm(client, prompt)
                total_tokens += tokens
                llm_calls    += 1
                verdict = reeval_res.get("verdict", "SAFE").upper()
                if verdict == "VULNERABLE":
                    pred = True
                    flipped += 1
                reeval_done = True
            except Exception as e:
                print(f"  [ERROR] arm_d rescan {fn}: {e}", flush=True)

        preds.append(pred)
        gts.append(gt)
        per_contract.append({
            "filename": fn,
            "ground_truth": gt,
            "base_predicted_vulnerable": base_pred,
            "predicted_vulnerable": pred,
            "reeval_done": reeval_done,
            "reeval_result": reeval_res,
            "grep_guard": gg,
            "solc_check": sc,
        })

        if (i + 1) % 25 == 0 or (i + 1) == len(rag_results):
            m = compute_metrics_from_preds(gts, preds)
            print(f"  [{i+1}/{len(rag_results)}] F1={m['f1_score']:.4f} llm_calls={llm_calls} flipped={flipped}", flush=True)

    return compute_metrics_from_preds(gts, preds), per_contract, total_tokens


def run_arm_e(rag_results, filepath_map, client):
    """Arm E: D + source code attached to re-eval prompt."""
    print("\n[Arm E] B + LLM re-eval with tools + source code...")
    preds = []
    gts   = []
    per_contract = []
    total_tokens = 0
    llm_calls    = 0
    flipped      = 0

    for i, r in enumerate(rag_results):
        fn   = r["filename"]
        gt   = r["ground_truth"]
        base_pred = r["predicted_vulnerable"]
        filepath = filepath_map.get(fn)
        code_raw = ""
        if filepath and os.path.exists(filepath):
            with open(filepath, encoding="utf-8", errors="replace") as f:
                code_raw = f.read()
        code = strip_annotations(code_raw)
        # First 200 lines
        code_200 = "\n".join(code.split("\n")[:200])
        gg = grep_guard(code)
        sc = solc_check(code)

        pred        = base_pred
        reeval_res  = None
        reeval_done = False

        vuln_types_str = ", ".join(r.get("vulnerability_types", [])) or "unknown"
        confidence     = r.get("confidence", 0.9)

        if base_pred:
            try:
                prompt = REEVAL_PROMPT_WITH_CODE.format(
                    vulnerability_types=vuln_types_str,
                    confidence=confidence,
                    contract_code=code_200,
                    grep_guard_formatted=format_grep_guard(gg),
                    solc_check_formatted=format_solc_check(sc),
                )
                reeval_res, tokens = call_llm(client, prompt)
                total_tokens += tokens
                llm_calls    += 1
                verdict = reeval_res.get("verdict", "VULNERABLE").upper()
                if verdict == "SAFE":
                    pred = False
                    flipped += 1
                reeval_done = True
            except Exception as e:
                print(f"  [ERROR] arm_e reeval {fn}: {e}", flush=True)

        elif not base_pred and sc["overflow_risk"] == "high":
            try:
                prompt = RESCAN_PROMPT_WITH_CODE.format(
                    version=sc["version"],
                    contract_code=code_200,
                    grep_guard_formatted=format_grep_guard(gg),
                )
                reeval_res, tokens = call_llm(client, prompt)
                total_tokens += tokens
                llm_calls    += 1
                verdict = reeval_res.get("verdict", "SAFE").upper()
                if verdict == "VULNERABLE":
                    pred = True
                    flipped += 1
                reeval_done = True
            except Exception as e:
                print(f"  [ERROR] arm_e rescan {fn}: {e}", flush=True)

        preds.append(pred)
        gts.append(gt)
        per_contract.append({
            "filename": fn,
            "ground_truth": gt,
            "base_predicted_vulnerable": base_pred,
            "predicted_vulnerable": pred,
            "reeval_done": reeval_done,
            "reeval_result": reeval_res,
            "grep_guard": gg,
            "solc_check": sc,
        })

        if (i + 1) % 25 == 0 or (i + 1) == len(rag_results):
            m = compute_metrics_from_preds(gts, preds)
            print(f"  [{i+1}/{len(rag_results)}] F1={m['f1_score']:.4f} llm_calls={llm_calls} flipped={flipped}", flush=True)

    return compute_metrics_from_preds(gts, preds), per_contract, total_tokens


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    client = OpenAI()

    print(f"Model: {MODEL}")
    with open(RAG_RESULTS_PATH) as f:
        rag_data = json.load(f)
    rag_results = rag_data["results"]

    with open(DATASET_PATH) as f:
        ds = json.load(f)
    filepath_map = {c["filename"]: c["filepath"] for c in ds["contracts"]}

    b_metric = rag_data["metrics"]
    b_f1 = b_metric["f1_score"]
    total = len(rag_results)
    print(f"Total contracts: {total}")

    # ── Arm A ──
    m_a, pc_a, tok_a = run_arm_a(rag_results, filepath_map, client)

    # ── Arm B ──
    m_b, pc_b = run_arm_b(rag_results)

    # ── Arm C ──
    m_c, pc_c = run_arm_c(rag_results, filepath_map)

    # ── Arm D ──
    m_d, pc_d, tok_d = run_arm_d(rag_results, filepath_map, client)

    # ── Arm E ──
    m_e, pc_e, tok_e = run_arm_e(rag_results, filepath_map, client)

    # ── Comparison table ──
    arms = [
        ("A", "LLM-only",          m_a, tok_a),
        ("B", "+RAG (baseline)",    m_b, 0),
        ("C", "+hardcoded rules",   m_c, 0),
        ("D", "+LLM w/ tools",      m_d, tok_d),
        ("E", "+LLM w/ tools+code", m_e, tok_e),
    ]

    print("\n" + "=" * 90)
    print(f"{'Arm':<5} {'Config':<22} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4} {'Prec':>7} {'Rec':>7} {'F1':>7} {'FPR':>7} {'ΔF1':>8}")
    print("-" * 90)
    for arm_id, cfg, m, _ in arms:
        delta = m["f1_score"] - b_f1
        delta_str = f"{delta:+.1%}"
        print(
            f"{arm_id:<5} {cfg:<22} {m['tp']:>4} {m['fn']:>4} {m['fp']:>4} {m['tn']:>4}"
            f" {m['precision']:>7.3f} {m['recall']:>7.3f} {m['f1_score']:>7.3f}"
            f" {m['fpr']:>7.3f} {delta_str:>8}"
        )
    print("=" * 90)

    # ── C vs D diff ──
    c_by_file = {r["filename"]: r for r in pc_c}
    d_by_file = {r["filename"]: r for r in pc_d}
    c_vs_d_diff = []
    for fn, rc in c_by_file.items():
        rd = d_by_file.get(fn)
        if rd and rc["predicted_vulnerable"] != rd["predicted_vulnerable"]:
            c_vs_d_diff.append({
                "filename": fn,
                "ground_truth": rc["ground_truth"],
                "arm_c_pred": rc["predicted_vulnerable"],
                "arm_d_pred": rd["predicted_vulnerable"],
                "flip_reason_c": rc.get("flip_reason"),
                "arm_d_reeval": rd.get("reeval_result"),
            })

    print(f"\nC vs D differences: {len(c_vs_d_diff)} contracts")
    for diff in c_vs_d_diff[:10]:
        print(f"  {diff['filename']}: GT={diff['ground_truth']} C={diff['arm_c_pred']} D={diff['arm_d_pred']}")

    # ── Save output ──
    output = {
        "experiment": "tool_ablation_6arm",
        "model": MODEL,
        "timestamp": datetime.datetime.now().isoformat(),
        "arms": {
            "A": {"config": "LLM-only",          "metrics": m_a, "tokens": tok_a},
            "B": {"config": "+RAG (baseline)",    "metrics": m_b, "tokens": 0},
            "C": {"config": "+hardcoded rules",   "metrics": m_c, "tokens": 0},
            "D": {"config": "+LLM w/ tools",      "metrics": m_d, "tokens": tok_d},
            "E": {"config": "+LLM w/ tools+code", "metrics": m_e, "tokens": tok_e},
        },
        "baseline_f1": b_f1,
        "c_vs_d_diff": c_vs_d_diff,
        "per_contract": {
            "A": pc_a,
            "B": pc_b,
            "C": pc_c,
            "D": pc_d,
            "E": pc_e,
        },
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"\nAblation results saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
