#!/usr/bin/env python3
"""
80_tool_augmented_pipeline.py
DmAVID Tool-Augmented Pipeline (Level 3: LLM reasons WITH tool outputs)

Reads llm_rag_results.json (Script 05 baseline), runs static analysis tools
on each contract, then uses LLM to re-evaluate with tool evidence.
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

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
TEMPERATURE = 0.1
SEED = 42

RAG_RESULTS_PATH = os.path.join(BASE_DIR, "experiments", "llm_rag", "llm_rag_results.json")
DATASET_PATH     = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_DIR       = os.path.join(BASE_DIR, "experiments", "tool_augmented")
OUTPUT_PATH      = os.path.join(OUTPUT_DIR, "tool_augmented_results.json")


# ──────────────────────────────────────────────
# Strip SmartBugs annotations
# ──────────────────────────────────────────────
def strip_annotations(code):
    code = re.sub(r"[^\n]*<(?:yes|no)>[^\n]*", "", code)
    code = re.sub(r"[^\n]*@vulnerable_at_lines:[^\n]*\n?", "", code)
    return code


# ──────────────────────────────────────────────
# Formatters
# ──────────────────────────────────────────────
def format_grep_guard(result):
    lines = []
    lines.append(f"找到的防護機制: {', '.join(result['mitigations']) if result['mitigations'] else '無'}")
    lines.append(f"僅使用 .transfer(): {'是' if result['transfer_only'] else '否'}")
    lines.append(f"ReentrancyGuard: {'有' if result['has_reentrancy_guard'] else '無'}")
    lines.append(f"SafeMath: {'有' if result['has_safemath'] else '無'}")
    lines.append(f"onlyOwner: {'有' if result['has_only_owner'] else '無'}")
    lines.append(f".send() 返回值有檢查: {'是' if result['has_send_checked'] else '否'}")
    lines.append(f".call.value() 存在: {'是' if result['call_value_present'] else '否'}")
    lines.append(f"防護機制數量: {result['mitigation_count']}")
    return "\n".join(lines)


def format_solc_check(result):
    lines = []
    lines.append(f"Pragma: {result['pragma_raw']}")
    lines.append(f"版本: {result['version']}")
    lines.append(f"內建 overflow 保護 (>=0.8): {'是' if result['overflow_safe_builtin'] else '否'}")
    lines.append(f"SafeMath: {'有' if result['has_safemath'] else '無'}")
    lines.append(f"unchecked 區塊: {'有' if result['has_unchecked_block'] else '無'}")
    lines.append(f"算術運算: {'有' if result['has_arithmetic_ops'] else '無'}")
    lines.append(f"Overflow 風險: {result['overflow_risk']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Prompts
# ──────────────────────────────────────────────
REEVAL_PROMPT_TEMPLATE = """\n你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 VULNERABLE，原因是 {vulnerability_types}。
原始分析的信心度: {confidence}

我用靜態分析工具對合約原始碼做了獨立檢查，結果如下：

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

【Solidity 版本分析 (solc_check)】
{solc_check_formatted}

請根據你的專業知識，結合以上工具證據，判斷這個合約是否真的有漏洞。

重要注意事項：
- .transfer() 的 2300 gas limit 可防止 REENTRANCY 重入，但無法防止 DENIAL_OF_SERVICE 或 UNCHECKED_CALL 漏洞
- SafeMath 全域宣告不代表所有函數都使用（如 BECToken batchTransfer 用直接相乘而非 .mul()）
- onlyOwner 只保護有此修飾符的函數
- send-checked 只表示 .send() 返回值被檢查，不能防止 DoS 或 reentrancy 攻擊
- 請針對「指定的漏洞類型」評估防護機制是否有效

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "reasoning": "detail on whether protective mechanisms effectively prevent the specific vulnerability types"}}"""

RESCAN_PROMPT_TEMPLATE = """\n你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 SAFE。
靜態工具偵測到此合約有潛在 overflow 風險：Solidity {version}（無內建保護）、未使用 SafeMath。

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

【合約原始碼片段（前 3000 字元）】
{code_snippet}

仔細檢查算術運算是否存在可利用的 integer overflow/underflow。
只有能指出「具體函數名稱」和「具體算術操作」確實會溢出，才改判 VULNERABLE。

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "vulnerable_function": "function name or null", "overflow_operation": "specific op or null", "reasoning": "analysis"}}"""


# ──────────────────────────────────────────────
# Metrics
# ──────────────────────────────────────────────
def compute_metrics(results):
    tp = fn = fp = tn = 0
    for r in results:
        gt   = r["ground_truth"] == "vulnerable"
        pred = r["tool_augmented_vulnerable"]
        if   gt and pred:       tp += 1
        elif gt and not pred:   fn += 1
        elif not gt and pred:   fp += 1
        else:                   tn += 1
    total     = tp + fn + fp + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    spec      = tn / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision":    round(precision, 4),
        "recall":       round(recall, 4),
        "f1_score":     round(f1, 4),
        "fpr":          round(fpr, 4),
        "specificity":  round(spec, 4),
    }


def print_progress(done, total, results_so_far, label=""):
    m = compute_metrics(results_so_far)
    print(
        f"[{done}/{total}]{label} "
        f"TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} F1={m['f1_score']:.4f}",
        flush=True,
    )


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    client = OpenAI()

    print(f"Model: {MODEL}")
    print(f"Loading RAG results from {RAG_RESULTS_PATH}")
    with open(RAG_RESULTS_PATH) as f:
        rag_data = json.load(f)
    rag_results = rag_data["results"]

    print(f"Loading dataset from {DATASET_PATH}")
    with open(DATASET_PATH) as f:
        ds = json.load(f)
    contracts = ds["contracts"]
    filepath_map = {c["filename"]: c["filepath"] for c in contracts}

    b = rag_data["metrics"]
    baseline_metrics = {
        "tp": b["tp"], "fn": b["fn"], "fp": b["fp"], "tn": b["tn"], "f1": b["f1_score"]
    }

    # Stats counters
    vuln_reeval_count    = 0
    vuln_flipped_to_safe = 0
    safe_rescan_count    = 0
    safe_flipped_to_vuln = 0
    total_llm_calls      = 0
    total_reeval_tokens  = 0

    final_results = []
    total = len(rag_results)
    print(f"Processing {total} contracts...")
    print(f"Baseline: TP={b['tp']} FN={b['fn']} FP={b['fp']} TN={b['tn']} F1={b['f1_score']:.4f}")

    for i, r in enumerate(rag_results):
        filename = r["filename"]
        filepath = filepath_map.get(filename)

        code_raw = ""
        if filepath and os.path.exists(filepath):
            with open(filepath, encoding="utf-8", errors="replace") as f:
                code_raw = f.read()
        code = strip_annotations(code_raw)

        gg = grep_guard(code)
        sc = solc_check(code)

        is_pred_vuln  = r["predicted_vulnerable"]
        tool_aug_vuln = is_pred_vuln
        reeval_done   = False
        reeval_result = None
        tokens_used_here = 0

        vuln_types_str = ", ".join(r.get("vulnerability_types", [])) or "unknown"
        confidence     = r.get("confidence", 0.9)

        if is_pred_vuln and gg["mitigation_count"] >= 2:
            # Re-evaluate ALL VULNERABLE predictions with tool evidence
            vuln_reeval_count += 1
            prompt = REEVAL_PROMPT_TEMPLATE.format(
                vulnerability_types=vuln_types_str,
                confidence=confidence,
                grep_guard_formatted=format_grep_guard(gg),
                solc_check_formatted=format_solc_check(sc),
            )
            try:
                resp = client.chat.completions.create(
                    model=MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=TEMPERATURE,
                    seed=SEED,
                    **token_param(1024),
                )
                raw_resp = resp.choices[0].message.content.strip()
                tokens_used_here     = resp.usage.total_tokens
                total_reeval_tokens += tokens_used_here
                total_llm_calls     += 1

                json_match = re.search(r"\{.*\}", raw_resp, re.DOTALL)
                if json_match:
                    reeval_result = json.loads(json_match.group())
                    verdict = reeval_result.get("verdict", "VULNERABLE").upper()
                    if verdict == "SAFE":
                        tool_aug_vuln = False
                        vuln_flipped_to_safe += 1
                reeval_done = True
            except Exception as e:
                print(f"  [ERROR] reeval {filename}: {e}", flush=True)

        elif False:  # overflow rescan disabled (too many FPs)
            # Re-scan SAFE predictions with high overflow risk
            safe_rescan_count += 1
            prompt = RESCAN_PROMPT_TEMPLATE.format(
                version=sc["version"],
                grep_guard_formatted=format_grep_guard(gg),
                code_snippet=code[:3000] if code else "(no code)",
            )
            try:
                resp = client.chat.completions.create(
                    model=MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=TEMPERATURE,
                    seed=SEED,
                    **token_param(1024),
                )
                raw_resp = resp.choices[0].message.content.strip()
                tokens_used_here     = resp.usage.total_tokens
                total_reeval_tokens += tokens_used_here
                total_llm_calls     += 1

                json_match = re.search(r"\{.*\}", raw_resp, re.DOTALL)
                if json_match:
                    reeval_result = json.loads(json_match.group())
                    verdict = reeval_result.get("verdict", "SAFE").upper()
                    has_specific_fn = bool(reeval_result.get("vulnerable_function"))
                    if verdict == "VULNERABLE" and has_specific_fn:
                        tool_aug_vuln = True
                        safe_flipped_to_vuln += 1
                reeval_done = True
            except Exception as e:
                print(f"  [ERROR] rescan {filename}: {e}", flush=True)

        entry = {
            **r,
            "tool_augmented_vulnerable": tool_aug_vuln,
            "grep_guard":   gg,
            "solc_check":   sc,
            "reeval_done":  reeval_done,
            "reeval_result": reeval_result,
            "reeval_tokens": tokens_used_here,
        }
        final_results.append(entry)

        if (i + 1) % 25 == 0 or (i + 1) == total:
            print_progress(
                i + 1, total, final_results,
                f" [reeval={vuln_reeval_count} rescan={safe_rescan_count}]",
            )

    tool_aug_metrics = compute_metrics(final_results)

    output = {
        "experiment":   "tool_augmented_pipeline_v3",
        "design_level": "Level 3: LLM reasons WITH tool outputs",
        "model":        MODEL,
        "timestamp":    datetime.datetime.now().isoformat(),
        "baseline_metrics":      baseline_metrics,
        "tool_augmented_metrics": tool_aug_metrics,
        "tool_stats": {
            "vuln_reeval_count":    vuln_reeval_count,
            "vuln_flipped_to_safe": vuln_flipped_to_safe,
            "safe_rescan_count":    safe_rescan_count,
            "safe_flipped_to_vuln": safe_flipped_to_vuln,
            "total_llm_calls":      total_llm_calls,
            "total_reeval_tokens":  total_reeval_tokens,
        },
        "results": final_results,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print(f"Done! Results saved to {OUTPUT_PATH}")
    print(f"Baseline    : TP={b['tp']} FN={b['fn']} FP={b['fp']} TN={b['tn']} F1={b['f1_score']:.4f}")
    m = tool_aug_metrics
    print(f"Tool-Aug    : TP={m['tp']} FN={m['fn']} FP={m['fp']} TN={m['tn']} F1={m['f1_score']:.4f}")
    print(f"Prec={m['precision']:.4f} Rec={m['recall']:.4f} FPR={m['fpr']:.4f}")
    print(f"LLM calls: {total_llm_calls}, Tokens: {total_reeval_tokens}")
    print(f"Vuln flipped->SAFE: {vuln_flipped_to_safe}/{vuln_reeval_count}")
    print(f"Safe flipped->VULN: {safe_flipped_to_vuln}/{safe_rescan_count}")


if __name__ == "__main__":
    main()
