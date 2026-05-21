#!/usr/bin/env python3
"""
82_threshold_sensitivity.py
Gate threshold sensitivity analysis for mitigation_count.

Tests thresholds T in {1, 2, 3}:
  - T=3 : uses subset of v4 cached re-evals (count>=3, 10 contracts)
  - T=2 : current v4 results, fully cached (17 contracts)
  - T=1 : v4 cache + new LLM calls for count==1 pred=VULN (58 new calls)

Purpose: verify F1 improvement is robust to threshold choice,
addressing the concern that T=2 was selected via test-set error analysis.
"""

import os, sys, json, re, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from openai import OpenAI
from _model_compat import token_param
from tools.grep_guard import grep_guard
from tools.solc_check import solc_check

MODEL       = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
TEMPERATURE = 0.1
SEED        = 42

CACHE_PATH   = ROOT / "experiments/tool_augmented/tool_augmented_results.json"
RAG_PATH     = ROOT / "experiments/llm_rag/llm_rag_results.json"
DATASET_PATH = ROOT / "data/dataset_1000.json"
OUT_PATH     = ROOT / "experiments/tool_augmented/threshold_sensitivity.json"

REEVAL_PROMPT_TEMPLATE = """\
你是一個 Solidity 智能合約安全審計專家。

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


def format_grep_guard(r):
    return "\n".join([
        f"找到的防護機制: {', '.join(r['mitigations']) if r['mitigations'] else '無'}",
        f"僅使用 .transfer(): {'是' if r['transfer_only'] else '否'}",
        f"ReentrancyGuard: {'有' if r['has_reentrancy_guard'] else '無'}",
        f"SafeMath: {'有' if r['has_safemath'] else '無'}",
        f"onlyOwner: {'有' if r['has_only_owner'] else '無'}",
        f".send() 返回值有檢查: {'是' if r['has_send_checked'] else '否'}",
        f".call.value() 存在: {'是' if r['call_value_present'] else '否'}",
        f"防護機制數量: {r['mitigation_count']}",
    ])


def format_solc_check(r):
    return "\n".join([
        f"Pragma: {r['pragma_raw']}",
        f"版本: {r['version']}",
        f"內建 overflow 保護 (>=0.8): {'是' if r['overflow_safe_builtin'] else '否'}",
        f"SafeMath: {'有' if r['has_safemath'] else '無'}",
        f"unchecked 區塊: {'有' if r['has_unchecked_block'] else '否'}",
        f"算術運算: {'有' if r['has_arithmetic_ops'] else '有'}",
        f"Overflow 風險: {r['overflow_risk']}",
    ])


def metrics(entries):
    tp = fn = fp = tn = 0
    for e in entries:
        gt   = e["ground_truth"] == "vulnerable"
        pred = e["final_vulnerable"]
        if   gt and pred:     tp += 1
        elif gt and not pred: fn += 1
        elif not gt and pred: fp += 1
        else:                 tn += 1
    prec = tp / (tp + fp) if tp + fp else 0
    rec  = tp / (tp + fn) if tp + fn else 0
    f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr  = fp / (fp + tn) if fp + tn else 0
    return dict(TP=tp, FN=fn, FP=fp, TN=tn,
                precision=round(prec, 4), recall=round(rec, 4),
                F1=round(f1, 4), FPR=round(fpr, 4))


def call_llm(client, vuln_types, confidence, gg, sc):
    prompt = REEVAL_PROMPT_TEMPLATE.format(
        vulnerability_types   = ", ".join(vuln_types) if vuln_types else "UNKNOWN",
        confidence            = confidence,
        grep_guard_formatted  = format_grep_guard(gg),
        solc_check_formatted  = format_solc_check(sc),
    )
    resp = client.chat.completions.create(
        model       = MODEL,
        messages    = [{"role": "user", "content": prompt}],
        temperature = TEMPERATURE,
        seed        = SEED,
        **token_param(1024),
    )
    content = resp.choices[0].message.content.strip()
    tokens  = resp.usage.total_tokens
    try:
        data    = json.loads(re.search(r'\{.*\}', content, re.DOTALL).group())
        verdict = data.get("verdict", "").upper()
        return verdict, data.get("reasoning", ""), tokens
    except Exception:
        return "VULNERABLE", content, tokens


def main():
    client = OpenAI()

    print("Loading cached v4 results ...")
    with open(CACHE_PATH) as f:
        cache = json.load(f)
    cache_results = cache["results"]

    with open(RAG_PATH) as f:
        rag_data = json.load(f)

    # ── For T=1: identify count==1 pred=VULN contracts ───────────────────────
    need_new = [r for r in cache_results
                if r["predicted_vulnerable"] and r["grep_guard"]["mitigation_count"] == 1]
    print(f"Contracts needing new LLM calls for T=1: {len(need_new)}")

    t1_extra     = {}
    new_tokens   = 0
    print(f"Running {len(need_new)} new LLM calls ...")
    for i, r in enumerate(need_new, 1):
        fname      = r["filename"]
        gg         = r["grep_guard"]
        sc         = r["solc_check"]
        vuln_types = r.get("vulnerability_types", [])
        confidence = r.get("confidence", 0.5)
        verdict, reasoning, tokens = call_llm(client, vuln_types, confidence, gg, sc)
        t1_extra[fname] = {"verdict": verdict, "reasoning": reasoning, "tokens": tokens}
        new_tokens += tokens
        status = "→SAFE" if verdict == "SAFE" else "→VULN"
        gt     = "GT=" + r["ground_truth"][:4].upper()
        print(f"  [{i:2d}/{len(need_new)}] {fname[:50]:<50} cnt=1 {status} {gt}")

    print(f"New LLM calls done. Tokens: {new_tokens:,}")

    # ── Apply each threshold ──────────────────────────────────────────────────
    thresholds        = [1, 2, 3]
    threshold_results = {}

    for T in thresholds:
        entries        = []
        flipped        = 0
        reeval_count   = 0

        for r in cache_results:
            mc    = r["grep_guard"]["mitigation_count"]
            pred  = r["predicted_vulnerable"]
            fname = r["filename"]
            final = pred

            if pred and mc >= T:
                reeval_count += 1

                if mc >= 2 and r.get("reeval_done"):
                    # Cached v4 result covers count>=2
                    rr      = r.get("reeval_result") or {}
                    verdict = rr.get("verdict", "VULNERABLE").upper()
                    if verdict == "SAFE":
                        final  = False
                        flipped += 1

                elif mc == 1 and T == 1 and fname in t1_extra:
                    # Newly computed result for count==1 (only used when T=1)
                    verdict = t1_extra[fname]["verdict"].upper()
                    if verdict == "SAFE":
                        final   = False
                        flipped += 1

            entries.append({
                "filename":         fname,
                "ground_truth":     r["ground_truth"],
                "final_vulnerable": final,
                "mitigation_count": mc,
            })

        m = metrics(entries)
        m["reeval_count"]    = reeval_count
        m["flipped_to_safe"] = flipped
        threshold_results[f"T={T}"] = m

    # ── Baseline ──────────────────────────────────────────────────────────────
    base_entries = [
        {"filename": r["filename"], "ground_truth": r["ground_truth"],
         "final_vulnerable": r["predicted_vulnerable"],
         "mitigation_count": r["grep_guard"]["mitigation_count"]}
        for r in cache_results
    ]
    baseline = metrics(base_entries)

    # ── Print table ───────────────────────────────────────────────────────────
    print("\n" + "="*76)
    print(f"{'Condition':<12} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4} "
          f"{'F1':>7} {'FPR':>6} {'Flipped':>8} {'Re-eval':>8} {'ΔF1':>8}")
    print("-"*76)
    print(f"{'Baseline':<12} {baseline['TP']:>4} {baseline['FN']:>4} "
          f"{baseline['FP']:>4} {baseline['TN']:>4} "
          f"{baseline['F1']:>7.4f} {baseline['FPR']:>6.4f} {'—':>8} {'—':>8} {'—':>8}")
    for T in thresholds:
        key = f"T={T}"
        m   = threshold_results[key]
        d   = m["F1"] - baseline["F1"]
        print(f"{'gate>='+str(T):<12} {m['TP']:>4} {m['FN']:>4} {m['FP']:>4} {m['TN']:>4} "
              f"{m['F1']:>7.4f} {m['FPR']:>6.4f} "
              f"{m['flipped_to_safe']:>7}↓ {m['reeval_count']:>8} {d:>+8.4f}")
    print("="*76)

    # ── Save ──────────────────────────────────────────────────────────────────
    out = {
        "experiment":           "threshold_sensitivity",
        "timestamp":            datetime.datetime.now().isoformat(),
        "model":                MODEL,
        "note":                 "T=2 is current v4. T=1 adds 58 new LLM calls for count==1 contracts.",
        "new_llm_calls_for_T1": len(need_new),
        "new_tokens_for_T1":    new_tokens,
        "baseline":             baseline,
        "results":              threshold_results,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved -> {OUT_PATH}")


if __name__ == "__main__":
    main()
