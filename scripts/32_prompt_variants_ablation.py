#!/usr/bin/env python3
"""
Sprint 1: Prompt 變體消融實驗 (Prompt Variants Ablation Study)

目的：對照 Tsai (2023) 高科大碩論的 prompt engineering 研究，量化 4 種
      prompt 變體在 SmartBugs 子集上的偵測表現差異。

設計：四個變體共用同一資料集、同一模型、同一 seed=42、同一 temperature=0.1，
      只變動 system prompt suffix 與 user prompt prefix。如此可將效果差異
      歸因於 prompt 設計，而非取樣或解碼隨機性。

變體：
  V1_baseline           : 原 04_run_llm_base.py 的 prompt（無 CoT 提示）
  V2_cot                : V1 + "Let's think step by step"
  V3_plan_solve         : V1 + Plan-and-Solve 結構提示
  V4_plan_solve_user    : V3 + 使用者具體弱點提示（對應 Tsai 2023 第 31 頁）

對照論文：
  Tsai, Y.-H. (2023)。基於大型語言模型之以太坊智能合約漏洞偵測研究
  (碩士論文)，國立高雄科技大學資訊工程系，pp. 24-31.

執行：
  cd /home/curtis/DmAVID
  python scripts/32_prompt_variants_ablation.py

  # 想只跑單一變體做煙霧測試：
  python scripts/32_prompt_variants_ablation.py --variants V1_baseline --limit 5

Author: Curtis Chang (張宏睿), 2026
"""

import os
import sys
import json
import time
import random
import argparse
from datetime import datetime
from typing import Dict, List, Any

# ---- 路徑設定 ----
BASE_DIR = os.environ.get(
    "DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

from openai import OpenAI
from _model_compat import token_param  # 沿用既有相容層

random.seed(42)

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/prompt_ablation")
os.makedirs(OUTPUT_DIR, exist_ok=True)

MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

# ---- gpt-4.1-mini 計價（2026/04 OpenAI 公開價，每 1M tokens）----
PRICE_PER_1M_INPUT_USD = 0.40
PRICE_PER_1M_OUTPUT_USD = 1.60


# ============================================================
# Prompt 變體定義
# ============================================================

# 共用：原 04_run_llm_base.py 的 SYSTEM_PROMPT 主體
SYSTEM_PROMPT_BASE = """You are an expert smart contract security auditor specializing in Ethereum Solidity contracts.
Your task is to analyze the given Solidity source code and determine if it contains security vulnerabilities.

You must respond in the following JSON format ONLY (no other text):
{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1", "type2"],
  "severity": "High/Medium/Low/None",
  "reasoning": "brief explanation"
}

Common vulnerability types to check:
- Reentrancy
- Integer Overflow/Underflow
- Access Control issues
- Unchecked External Calls
- Denial of Service
- Front Running
- Bad Randomness
- Time Manipulation
- Short Address Attack
- Flash Loan Attack
- Price Oracle Manipulation"""

USER_BASE = "Analyze this Solidity contract for vulnerabilities:\n\n```solidity\n{code}\n```"

USER_WITH_HINTS = (
    "Analyze this Solidity contract for vulnerabilities. Pay special attention to: "
    "(a) external calls before state updates, "
    "(b) tx.origin usage for authentication, "
    "(c) unchecked low-level calls (.call, .send), "
    "(d) reliance on block.timestamp or blockhash for randomness, "
    "(e) missing access control modifiers on state-changing functions.\n\n"
    "```solidity\n{code}\n```"
)

PROMPT_VARIANTS: Dict[str, Dict[str, str]] = {
    "V1_baseline": {
        "description": "原 04_run_llm_base.py prompt，無 CoT 提示，純 JSON 輸出指令",
        "system": SYSTEM_PROMPT_BASE,
        "user_template": USER_BASE,
    },
    "V2_cot": {
        "description": "Zero-shot CoT (Kojima et al., 2022)：追加 magic prompt",
        "system": (
            SYSTEM_PROMPT_BASE
            + "\n\nLet's think step by step before producing the JSON answer. "
              "You may include your reasoning inside the \"reasoning\" field, "
              "but the top-level structure must remain valid JSON."
        ),
        "user_template": USER_BASE,
    },
    "V3_plan_solve": {
        "description": "Plan-and-Solve (Wang et al., 2023)：先規劃再執行",
        "system": (
            SYSTEM_PROMPT_BASE
            + "\n\nFirst, devise a plan to systematically check each vulnerability "
              "category listed above against the contract. Then carry out the plan "
              "step by step. Finally, output the JSON answer. The reasoning field "
              "should summarize the plan execution."
        ),
        "user_template": USER_BASE,
    },
    "V4_plan_solve_user": {
        "description": "Plan-and-Solve + 使用者具體弱點提示（對應 Tsai 2023 第 31 頁）",
        "system": (
            SYSTEM_PROMPT_BASE
            + "\n\nFirst, devise a plan to systematically check each vulnerability "
              "category listed above against the contract. Then carry out the plan "
              "step by step. Finally, output the JSON answer. The reasoning field "
              "should summarize the plan execution."
        ),
        "user_template": USER_WITH_HINTS,
    },
}


# ============================================================
# 推論與解析
# ============================================================

def analyze_contract(code: str, variant_key: str, max_retries: int = 2) -> Dict[str, Any]:
    """以指定 prompt 變體分析單一合約。
    回傳結構與 04_run_llm_base.py 相同，便於下游分析腳本重用。
    """
    if len(code) > 15000:
        code = code[:15000] + "\n// ... (truncated)"

    variant = PROMPT_VARIANTS[variant_key]
    system_prompt = variant["system"]
    user_prompt = variant["user_template"].format(code=code)

    last_error = None
    start_time = time.time()
    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                **token_param(1024),
                seed=42,
            )
            elapsed = time.time() - start_time
            content = response.choices[0].message.content.strip()

            # JSON 解析（容錯：抓最外層大括號）
            import re
            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                parsed = json.loads(content)

            usage = response.usage
            return {
                "success": True,
                "predicted_vulnerable": bool(parsed.get("has_vulnerability", False)),
                "confidence": float(parsed.get("confidence", 0.5)),
                "vulnerability_types": parsed.get("vulnerability_types", []) or [],
                "severity": parsed.get("severity", "None"),
                "reasoning": parsed.get("reasoning", "")[:500],
                "time_seconds": round(elapsed, 3),
                "input_tokens": usage.prompt_tokens if usage else 0,
                "output_tokens": usage.completion_tokens if usage else 0,
                "total_tokens": usage.total_tokens if usage else 0,
                "raw_content_head": content[:200],
                "error": None,
            }
        except json.JSONDecodeError as e:
            # JSON 解析失敗：以關鍵字 fallback（與 04 一致）
            has_vuln = any(w in content.lower() for w in ["true", "vulnerable", "yes", "found"])
            return {
                "success": True,
                "predicted_vulnerable": has_vuln,
                "confidence": 0.5,
                "vulnerability_types": [],
                "severity": "Unknown",
                "reasoning": content[:500],
                "time_seconds": round(time.time() - start_time, 3),
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "raw_content_head": content[:200],
                "error": f"json_parse_error: {e}",
            }
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False,
                "predicted_vulnerable": False,
                "confidence": 0.0,
                "vulnerability_types": [],
                "severity": "None",
                "reasoning": "",
                "time_seconds": round(time.time() - start_time, 3),
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "raw_content_head": "",
                "error": str(last_error),
            }


# ============================================================
# 樣本選擇（與 04_run_llm_base.py 完全一致以確保可比性）
# ============================================================

def load_sample() -> List[Dict[str, Any]]:
    with open(DATASET_FILE, "r") as f:
        dataset = json.load(f)
    contracts = dataset["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]

    # 與 04_run_llm_base.py 相同的取樣邏輯：random.seed(42) 已在頂端設定
    random.shuffle(safe)
    sample_safe = safe[:100]
    sample = vuln + sample_safe
    random.shuffle(sample)
    return sample


# ============================================================
# 指標計算
# ============================================================

def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_time = 0.0
    error_count = 0

    for r in results:
        gt = r["ground_truth"] == "vulnerable"
        pred = r["prediction"]["predicted_vulnerable"]
        if gt and pred: tp += 1
        elif (not gt) and pred: fp += 1
        elif (not gt) and (not pred): tn += 1
        elif gt and (not pred): fn += 1

        total_input_tokens += r["prediction"].get("input_tokens", 0)
        total_output_tokens += r["prediction"].get("output_tokens", 0)
        total_time += r["prediction"].get("time_seconds", 0.0)
        if not r["prediction"].get("success", True):
            error_count += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    cost_usd = (
        total_input_tokens / 1_000_000 * PRICE_PER_1M_INPUT_USD
        + total_output_tokens / 1_000_000 * PRICE_PER_1M_OUTPUT_USD
    )

    return {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "total_tokens": total_input_tokens + total_output_tokens,
        "estimated_cost_usd": round(cost_usd, 4),
        "total_time_seconds": round(total_time, 2),
        "avg_time_per_call_seconds": round(total_time / total, 3) if total > 0 else 0.0,
        "error_count": error_count,
    }


def bootstrap_f1_ci(results: List[Dict[str, Any]], n_iter: int = 1000, seed: int = 42) -> Dict[str, float]:
    """以 bootstrap 估計 F1 之 95% 信賴區間。"""
    import numpy as np
    rng = np.random.default_rng(seed)
    n = len(results)
    if n == 0:
        return {"f1_ci_low": 0.0, "f1_ci_high": 0.0}

    f1_samples = []
    indices = np.arange(n)
    for _ in range(n_iter):
        idx = rng.choice(indices, size=n, replace=True)
        boot = [results[i] for i in idx]
        m = compute_metrics(boot)
        f1_samples.append(m["f1"])
    return {
        "f1_ci_low": round(float(np.percentile(f1_samples, 2.5)), 4),
        "f1_ci_high": round(float(np.percentile(f1_samples, 97.5)), 4),
    }


# ============================================================
# 主流程
# ============================================================

def run_variant(variant_key: str, sample: List[Dict[str, Any]], limit: int = 0) -> Dict[str, Any]:
    print(f"\n{'='*70}")
    print(f"Running variant: {variant_key}")
    print(f"Description    : {PROMPT_VARIANTS[variant_key]['description']}")
    print(f"Sample size    : {len(sample) if limit == 0 else min(limit, len(sample))}")
    print(f"Model          : {MODEL}")
    print(f"{'='*70}")

    target = sample if limit == 0 else sample[:limit]
    results = []

    for i, contract in enumerate(target, 1):
        name = contract.get("name") or contract.get("id") or contract.get("filename", "unknown")
        code = contract.get("code")
        if code is None:
            try:
                with open(contract["filepath"], "r", encoding="utf-8", errors="replace") as fh:
                    code = fh.read()
            except (FileNotFoundError, KeyError) as exc:
                print(f"  [{i:>3}/{len(target)}] {name[:50]:<50} SKIP (missing file: {exc})")
                continue
        print(f"  [{i:>3}/{len(target)}] {name[:50]:<50} ", end="", flush=True)
        prediction = analyze_contract(code, variant_key)
        results.append({
            "name": name,
            "ground_truth": contract["label"],
            "vulnerability_category": contract.get("category", "unknown"),
            "prediction": prediction,
        })
        gt = contract["label"]
        pred = "vulnerable" if prediction["predicted_vulnerable"] else "safe"
        ok = "✓" if gt == pred else "✗"
        print(f"GT={gt[:4]:<4} Pred={pred[:4]:<4} {ok}")

    metrics = compute_metrics(results)
    metrics.update(bootstrap_f1_ci(results))

    output = {
        "variant": variant_key,
        "description": PROMPT_VARIANTS[variant_key]["description"],
        "model": MODEL,
        "timestamp": datetime.now().isoformat(),
        "system_prompt": PROMPT_VARIANTS[variant_key]["system"],
        "user_template": PROMPT_VARIANTS[variant_key]["user_template"],
        "metrics": metrics,
        "results": results,
    }

    out_path = os.path.join(OUTPUT_DIR, f"{variant_key}_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n  → Saved: {out_path}")
    print(f"  → Metrics: P={metrics['precision']} R={metrics['recall']} "
          f"F1={metrics['f1']} (95% CI [{metrics['f1_ci_low']}, {metrics['f1_ci_high']}]) "
          f"Acc={metrics['accuracy']}")
    print(f"  → Cost: ${metrics['estimated_cost_usd']} ({metrics['total_tokens']} tokens)")
    return output


def write_summary_csv(all_outputs: List[Dict[str, Any]]):
    import csv
    csv_path = os.path.join(OUTPUT_DIR, "metrics_summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "variant", "description", "n", "tp", "fp", "tn", "fn",
            "precision", "recall", "f1", "f1_ci_low", "f1_ci_high",
            "accuracy", "input_tokens", "output_tokens", "total_tokens",
            "cost_usd", "avg_time_sec", "error_count",
        ])
        for o in all_outputs:
            m = o["metrics"]
            writer.writerow([
                o["variant"], o["description"], m["total"],
                m["tp"], m["fp"], m["tn"], m["fn"],
                m["precision"], m["recall"], m["f1"],
                m["f1_ci_low"], m["f1_ci_high"], m["accuracy"],
                m["total_input_tokens"], m["total_output_tokens"], m["total_tokens"],
                m["estimated_cost_usd"], m["avg_time_per_call_seconds"], m["error_count"],
            ])
    print(f"\n→ Summary CSV: {csv_path}")


def main():
    parser = argparse.ArgumentParser(description="Prompt 變體消融實驗")
    parser.add_argument(
        "--variants", nargs="+",
        default=list(PROMPT_VARIANTS.keys()),
        help="要跑的變體（預設全部）。例：--variants V1_baseline V2_cot",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="每個變體限制樣本數（用於煙霧測試）。0 = 全跑",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("Sprint 1 — Prompt Variants Ablation Study")
    print(f"Timestamp : {datetime.now().isoformat()}")
    print(f"Model     : {MODEL}")
    print(f"Dataset   : {DATASET_FILE}")
    print(f"Variants  : {args.variants}")
    print(f"Limit     : {args.limit if args.limit > 0 else 'no limit (full sample)'}")
    print("=" * 70)

    sample = load_sample()
    print(f"\nLoaded {len(sample)} contracts "
          f"({sum(1 for c in sample if c['label']=='vulnerable')} vuln + "
          f"{sum(1 for c in sample if c['label']=='safe')} safe)")

    if args.limit == 0:
        n_calls = len(sample) * len(args.variants)
        est_cost = n_calls * 0.003  # 粗估每 call 約 $0.003
        print(f"\n預估 API 呼叫數：{n_calls}，預估成本：~${est_cost:.2f} USD")
        confirm = input("\n按 Enter 開始，或 Ctrl-C 取消...")

    all_outputs = []
    for variant_key in args.variants:
        if variant_key not in PROMPT_VARIANTS:
            print(f"⚠ 未知變體：{variant_key}，跳過")
            continue
        out = run_variant(variant_key, sample, limit=args.limit)
        all_outputs.append(out)

    write_summary_csv(all_outputs)

    print("\n" + "=" * 70)
    print("變體對照（sorted by F1）")
    print("=" * 70)
    print(f"{'Variant':<22} {'P':>6} {'R':>6} {'F1':>6} {'CI':>20} {'Cost':>8}")
    for o in sorted(all_outputs, key=lambda x: -x["metrics"]["f1"]):
        m = o["metrics"]
        ci = f"[{m['f1_ci_low']:.3f},{m['f1_ci_high']:.3f}]"
        print(f"{o['variant']:<22} {m['precision']:>6.3f} {m['recall']:>6.3f} "
              f"{m['f1']:>6.3f} {ci:>20} ${m['estimated_cost_usd']:>7.3f}")
    print("=" * 70)


if __name__ == "__main__":
    main()
