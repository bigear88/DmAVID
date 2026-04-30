#!/usr/bin/env python3
"""
Sprint 6: LLM-as-Judge for Repair Quality

對 DmAVID llm_rag_results.json 中含 repair 建議的 TP 樣本（n=88），
用 GPT-4.1-mini 評分（1-5）三個維度：Specificity / Correctness / Compileability。

Idempotent：已 judge 過的 contract_id 從 cache 跳過。
Cost guard：執行前 print 預估，超過 $0.20 上限自動終止。

Usage:
  cd /home/curtis/DmAVID
  python3 scripts/42_explainability_judge.py [--dry-run] [--max-cost 0.20]

Output:
  experiments/explainability/repair_quality_judge.json

Model pricing reference (GPT-4.1-mini, 2025-2026):
  input  $0.40 / 1M tokens
  output $1.60 / 1M tokens

Author: Curtis Chang (張宏睿), 2026
"""
import os
import sys
import json
import argparse
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LLM_RAG = ROOT / "experiments/llm_rag/llm_rag_results.json"
SOL_ROOT = ROOT / "data/smartbugs_curated_repo/dataset"
OUT = ROOT / "experiments/explainability/repair_quality_judge.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

# Pricing (USD per 1M tokens)
PRICE_IN = 0.40
PRICE_OUT = 1.60

JUDGE_MODEL = "gpt-4.1-mini"

JUDGE_PROMPT_TEMPLATE = """You are a Solidity security auditor evaluating a vulnerability repair suggestion.

VULNERABLE CODE (excerpt, ground truth category: {category}):
```solidity
{code}
```

REPAIR SUGGESTION (extracted from analyzer reasoning):
{repair_text}

Rate the suggestion on a 1-5 scale considering THREE dimensions equally weighted:
1. Specificity — does it identify which line/function to change?
2. Correctness — does the fix actually eliminate the vulnerability?
3. Compileability — would the modified code compile under Solidity 0.4–0.8?

Output ONLY a single JSON object, no markdown, no extra text:
{{"score": <integer 1-5>, "reasoning": "<one sentence justification>"}}
"""


def extract_repair_text(reasoning):
    """從 LLM reasoning 抽出修復建議段（包含 'recommend', 'should', 'fix', 'use', 'add' 等動作詞的句子）"""
    if not reasoning:
        return ""
    # 切句 (粗略)
    sentences = re.split(r"(?<=[.!?。！？])\s+", reasoning)
    keywords = [
        "recommend", "should", "must", "fix", "use ", "apply", "add ",
        "replace", "follow", "implement", "ensure", "checks-effects",
        "reentrancyguard", "safemath", "require\\(", "modifier",
    ]
    repair_sents = [s for s in sentences if any(re.search(kw, s, re.I) for kw in keywords)]
    if not repair_sents:
        return reasoning[-400:]  # fallback：取末段
    return " ".join(repair_sents)[:1000]


def get_code_excerpt(contract_id, max_chars=1500):
    """從 SmartBugs 找對應 .sol 檔，回傳前 max_chars 字元

    contract_id 格式: curated_<category>_<filename>.sol
    其中 <category> 可能含底線（如 unchecked_low_level_calls），<filename> 也可能含底線
    （如 wallet_04_confused_sign.sol、modifier_reentrancy.sol）。
    用「枚舉現有 category 目錄前綴」精準切分，比 regex 穩健。"""
    if not contract_id.startswith("curated_"):
        return ""
    if not SOL_ROOT.exists():
        return ""
    for cat_dir in sorted(SOL_ROOT.iterdir(), key=lambda p: -len(p.name)):
        if not cat_dir.is_dir():
            continue
        prefix = f"curated_{cat_dir.name}_"
        if contract_id.startswith(prefix):
            filename = contract_id[len(prefix):]
            candidate = cat_dir / filename
            if candidate.exists():
                try:
                    return candidate.read_text(encoding="utf-8", errors="ignore")[:max_chars]
                except Exception:
                    return ""
            break
    # fallback：全 dataset rglob
    fallback_name = contract_id[len("curated_"):]
    for f in SOL_ROOT.rglob("*.sol"):
        if f.name == fallback_name or contract_id.endswith(f.name):
            try:
                return f.read_text(encoding="utf-8", errors="ignore")[:max_chars]
            except Exception:
                pass
    return ""


def estimate_cost(n_to_judge, avg_in=900, avg_out=80):
    """預估 cost (USD)"""
    in_tokens = n_to_judge * avg_in
    out_tokens = n_to_judge * avg_out
    cost = in_tokens / 1_000_000 * PRICE_IN + out_tokens / 1_000_000 * PRICE_OUT
    return cost, in_tokens, out_tokens


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="只印估算不送 API")
    p.add_argument("--max-cost", type=float, default=0.20, help="cost ceiling USD")
    p.add_argument("--limit", type=int, default=0, help="只 judge 前 N 筆（0=全部）")
    return p.parse_args()


def load_existing_results():
    if OUT.exists():
        try:
            return json.loads(OUT.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"results": []}


def main():
    args = parse_args()
    print("=" * 70)
    print(f"Sprint 6 — LLM-as-Judge Repair Quality  (model={JUDGE_MODEL})")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    # ---------- 載入 DmAVID 結果，篩選含 repair 的 TP ----------
    d = json.loads(LLM_RAG.read_text(encoding="utf-8"))
    results = d["results"]
    tps = [r for r in results if r.get("ground_truth") == "vulnerable"
           and r.get("predicted_vulnerable") is True]

    # 篩選 reasoning 含 repair-action 關鍵字的（與既有 26 metric_3 計算一致）
    repair_keywords = ["recommend", "should", "fix", "use ", "apply", "follow",
                       "implement", "ensure", "ReentrancyGuard", "SafeMath",
                       "checks-effects", "modifier", "require"]
    have_repair = []
    for r in tps:
        rs = r.get("reasoning", "") or ""
        if any(kw.lower() in rs.lower() for kw in repair_keywords):
            have_repair.append(r)
    print(f"\nDmAVID TP n={len(tps)},  含 repair 建議者 n={len(have_repair)}")

    # ---------- Idempotent: 已 judged（score 為有效 int）的跳過 ----------
    # 之前 score=None 的 SKIP（如檔名找不到 → 修復程式後可重 retry）不算 judged
    existing = load_existing_results()
    judged_ids = {r["contract_id"] for r in existing.get("results", [])
                  if isinstance(r.get("score"), int)}
    # 從 existing.results 移除 None-score 條目，待會兒重 judge 後一併寫入
    existing["results"] = [r for r in existing.get("results", [])
                           if isinstance(r.get("score"), int)]
    todo = [r for r in have_repair if r["contract_id"] not in judged_ids]
    if args.limit > 0:
        todo = todo[: args.limit]
    print(f"已 judged: {len(judged_ids)},  本次待 judge: {len(todo)}")

    if not todo:
        print("\n所有樣本已 judge 完，無需再呼叫 API。直接寫出彙整。")
        save_results(existing, len(have_repair))
        return

    # ---------- Cost 估算 + 守門 ----------
    est_cost, est_in, est_out = estimate_cost(len(todo))
    print(f"\n[Cost Estimate]")
    print(f"  待 judge:        {len(todo)} samples")
    print(f"  預估 input:      ~{est_in:,} tokens")
    print(f"  預估 output:     ~{est_out:,} tokens")
    print(f"  預估費用:        ~${est_cost:.4f}")
    print(f"  Max cost ceiling: ${args.max_cost:.2f}")
    if est_cost > args.max_cost:
        print(f"\n✗ 預估超過 ceiling，終止。")
        sys.exit(1)
    if args.dry_run:
        print("\n--dry-run 模式，不送 API。結束。")
        return

    # ---------- 送 API ----------
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("\n✗ OPENAI_API_KEY 未設定")
        sys.exit(1)

    from openai import OpenAI
    client = OpenAI(api_key=api_key)

    new_results = list(existing.get("results", []))
    actual_in, actual_out = 0, 0
    print(f"\n[Judging]  total={len(todo)}")
    for i, r in enumerate(todo, 1):
        cid = r["contract_id"]
        category = r.get("category", "unknown")
        code = get_code_excerpt(cid, max_chars=1500)
        repair_text = extract_repair_text(r.get("reasoning", ""))
        if not code:
            new_results.append({
                "contract_id": cid, "category": category,
                "score": None, "reasoning": "[skipped] code excerpt unavailable",
                "input_tokens": 0, "output_tokens": 0,
            })
            print(f"  [{i:>3}/{len(todo)}] {cid:<60} SKIP (no code)")
            continue

        prompt = JUDGE_PROMPT_TEMPLATE.format(category=category, code=code, repair_text=repair_text)
        try:
            resp = client.chat.completions.create(
                model=JUDGE_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                response_format={"type": "json_object"},
                max_tokens=200,
            )
            content = resp.choices[0].message.content
            usage = resp.usage
            actual_in += usage.prompt_tokens
            actual_out += usage.completion_tokens
            try:
                judged = json.loads(content)
                score = int(judged.get("score", 0))
                reason = judged.get("reasoning", "")
            except (json.JSONDecodeError, ValueError, TypeError):
                score = None
                reason = f"[parse-error] {content[:200]}"
            new_results.append({
                "contract_id": cid, "category": category,
                "score": score, "reasoning": reason,
                "input_tokens": usage.prompt_tokens,
                "output_tokens": usage.completion_tokens,
            })
            print(f"  [{i:>3}/{len(todo)}] {cid:<60} score={score}")
        except Exception as e:
            new_results.append({
                "contract_id": cid, "category": category,
                "score": None, "reasoning": f"[api-error] {type(e).__name__}: {e}",
                "input_tokens": 0, "output_tokens": 0,
            })
            print(f"  [{i:>3}/{len(todo)}] {cid:<60} ERROR: {e}")

        # 增量寫出 (每 10 筆 flush，避免中斷掉資料)
        if i % 10 == 0:
            interim = {
                "experiment": "explainability_repair_quality_judge",
                "model": JUDGE_MODEL,
                "timestamp": datetime.now().isoformat(),
                "n_total_with_repair": len(have_repair),
                "results": new_results,
                "interim": True,
            }
            OUT.write_text(json.dumps(interim, ensure_ascii=False, indent=2), encoding="utf-8")

    # 實際 cost
    actual_cost = actual_in / 1_000_000 * PRICE_IN + actual_out / 1_000_000 * PRICE_OUT
    print(f"\n[Actual Cost]")
    print(f"  Input tokens:  {actual_in:,}")
    print(f"  Output tokens: {actual_out:,}")
    print(f"  Actual cost:   ${actual_cost:.4f}")

    # ---------- 彙整 + 寫出 ----------
    final = {
        "experiment": "explainability_repair_quality_judge",
        "model": JUDGE_MODEL,
        "timestamp": datetime.now().isoformat(),
        "n_total_with_repair": len(have_repair),
        "n_judged": sum(1 for r in new_results if isinstance(r.get("score"), int)),
        "actual_cost_usd": round(actual_cost, 4),
        "actual_input_tokens": actual_in,
        "actual_output_tokens": actual_out,
        "results": new_results,
    }
    save_results(final, len(have_repair))


def save_results(payload, n_total_with_repair):
    """彙整 score 統計 + 累計 cost + 寫出"""
    if "n_total_with_repair" not in payload:
        payload["n_total_with_repair"] = n_total_with_repair
    results = payload.get("results", [])
    scores = [r["score"] for r in results if isinstance(r.get("score"), int)]
    if scores:
        payload["score_stats"] = {
            "n": len(scores),
            "avg": round(sum(scores) / len(scores), 4),
            "min": min(scores),
            "max": max(scores),
            "distribution": {str(s): scores.count(s) for s in sorted(set(scores))},
        }
    # 累計 token 與 cost（跨多次 run 之 cumulative）
    total_in = sum(r.get("input_tokens", 0) for r in results)
    total_out = sum(r.get("output_tokens", 0) for r in results)
    total_cost = total_in / 1_000_000 * PRICE_IN + total_out / 1_000_000 * PRICE_OUT
    payload["cumulative_input_tokens"] = total_in
    payload["cumulative_output_tokens"] = total_out
    payload["cumulative_cost_usd"] = round(total_cost, 4)
    payload.pop("interim", None)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n→ Saved: {OUT}")
    if scores:
        print(f"  avg score: {payload['score_stats']['avg']:.2f} / 5  (n={len(scores)})")
        print(f"  distribution: {payload['score_stats']['distribution']}")


if __name__ == "__main__":
    main()
