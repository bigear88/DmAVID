#!/usr/bin/env python3
"""
Sprint 4: False-Positive 類型歸因分析 (FP Hallucination Type Attribution)

目的：當方法把 safe 合約誤判為 vulnerable 時，它「自稱」看到了哪種漏洞？
      四種方法（LLM Baseline / V4 Prompt / DmAVID Hybrid，CodeBERT 無 type 輸出）
      在 100 個 safe 合約上的 FP 幻覺類型分布。

由此可回答：
  - 哪些漏洞類型最容易被誤報（共通幻覺模式）？
  - 多代理架構（DmAVID Hybrid）相對 LLM Baseline 在哪些類型上 FP 抑制最有效？
  - V4 Prompt（強化提示）相較 baseline 抑制了哪些類型？

注意：原 Sprint 4 設計（per-category Recall）在 SmartBugs 上失敗——
      因為所有方法整體 FN 僅 1 個，Recall 全部飽和於 ~1.0，無辨別力。
      改採 FP 類型歸因，才是四種方法真正能對照的維度。

執行：
  cd /home/curtis/DmAVID
  python3 scripts/35_per_category_breakdown.py

Author: Curtis Chang (張宏睿), 2026
"""

import os
import sys
import json
import csv
import re
from collections import Counter, defaultdict, OrderedDict
from datetime import datetime
from typing import List, Dict, Any, Tuple, Callable

BASE_DIR = os.environ.get(
    "DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments", "per_category")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# 類型字串正規化
# ============================================================

def normalize_type(s: str) -> str:
    """將「Reentrancy / reentrancy / Re-entrancy / re-entrancy attack」收斂。"""
    if not isinstance(s, str):
        return "unknown"
    s = s.lower().strip()
    # 移除常見尾綴
    s = re.sub(r"\s+(attack|vulnerability|vulnerab\w*|issue|risk|exploit)$", "", s)
    s = re.sub(r"^(potential|possible)\s+", "", s)
    # 空白與連字號統一為底線
    s = re.sub(r"[\s\-/]+", "_", s)
    # 同義詞收斂（保守的常見映射）
    SYNONYMS = {
        "reentrancy": "reentrancy",
        "re_entrancy": "reentrancy",
        "integer_overflow": "arithmetic",
        "integer_underflow": "arithmetic",
        "integer_overflow_underflow": "arithmetic",
        "overflow": "arithmetic",
        "underflow": "arithmetic",
        "arithmetic_overflow": "arithmetic",
        "arithmetic_underflow": "arithmetic",
        "access_control": "access_control",
        "access_control_issues": "access_control",
        "missing_access_control": "access_control",
        "tx_origin": "access_control",
        "unchecked_external_calls": "unchecked_low_level_calls",
        "unchecked_external_call": "unchecked_low_level_calls",
        "unchecked_low_level_calls": "unchecked_low_level_calls",
        "unchecked_low_level_call": "unchecked_low_level_calls",
        "unchecked_call": "unchecked_low_level_calls",
        "unchecked_send": "unchecked_low_level_calls",
        "denial_of_service": "denial_of_service",
        "dos": "denial_of_service",
        "front_running": "front_running",
        "frontrunning": "front_running",
        "bad_randomness": "bad_randomness",
        "weak_randomness": "bad_randomness",
        "block.timestamp": "time_manipulation",
        "block_timestamp": "time_manipulation",
        "timestamp_dependence": "time_manipulation",
        "time_manipulation": "time_manipulation",
        "short_address_attack": "short_addresses",
        "short_addresses": "short_addresses",
        "flash_loan": "flash_loan",
        "price_oracle_manipulation": "price_oracle",
        "oracle_manipulation": "price_oracle",
    }
    return SYNONYMS.get(s, s)


# ============================================================
# 各 method 的 (gt, pred, types) extractor
# ============================================================

def ex_llm_base(records):
    return [
        (r["ground_truth"],
         bool(r["predicted_vulnerable"]),
         [normalize_type(t) for t in (r.get("vulnerability_types") or [])])
        for r in records
    ]


def ex_v4_prompt(records):
    return [
        (r["ground_truth"],
         bool(r["prediction"]["predicted_vulnerable"]),
         [normalize_type(t) for t in (r["prediction"].get("vulnerability_types") or [])])
        for r in records
    ]


def ex_hybrid(records):
    return [
        (r["ground_truth"],
         bool(r["predicted_vulnerable"]),
         [normalize_type(t) for t in (r.get("vulnerability_types") or [])])
        for r in records
    ]


def ex_hybrid_canonical(records):
    """canonical v5_clean (LLM+RAG+Self-Verify 三類) 的 extractor。
    ground_truth_vulnerable 是 bool，需轉成 'safe'/'vulnerable' 字串以對齊其它 method。"""
    return [
        ("vulnerable" if r["ground_truth_vulnerable"] else "safe",
         bool(r["predicted_vulnerable"]),
         [normalize_type(t) for t in (r.get("vulnerability_types") or [])])
        for r in records
    ]


# ============================================================
# 載入器
# ============================================================

def load_method(label, rel_path, extractor):
    path = os.path.join(BASE_DIR, rel_path)
    if not os.path.exists(path):
        print(f"⚠ {label}: {rel_path} 不存在，跳過")
        return None
    with open(path) as f:
        data = json.load(f)
    records = data if isinstance(data, list) else data.get("results", data)
    triples = extractor(records)
    print(f"  {label:<22} {rel_path:<70} ({len(triples)} samples)")
    return triples


# ============================================================
# FP 分析
# ============================================================

def analyze_fp_types(triples):
    """回傳 (fp_count, fp_with_types_count, type_mentions Counter, types_per_fp 平均)。"""
    fp_count = 0
    fp_with_types = 0
    type_mentions = Counter()  # 每次提及加 1（一個 FP 報多種型，每種都記）
    fp_unique_types = []  # 每個 FP 至少貢獻一次的 unique type
    for gt, pred, types in triples:
        if gt == "safe" and pred:
            fp_count += 1
            unique_types = list({t for t in types if t})
            if unique_types:
                fp_with_types += 1
                for t in unique_types:
                    type_mentions[t] += 1
                fp_unique_types.append(len(unique_types))
            else:
                fp_unique_types.append(0)
    avg_types_per_fp = (sum(fp_unique_types) / len(fp_unique_types)) if fp_unique_types else 0.0
    return {
        "fp_count": fp_count,
        "fp_with_types": fp_with_types,
        "type_mentions": type_mentions,
        "avg_types_per_fp": round(avg_types_per_fp, 2),
    }


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 70)
    print("Sprint 4 — FP 類型歸因分析")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    sources = [
        ("LLM_Baseline",   "experiments/llm_base/llm_base_results.json",        ex_llm_base),
        ("V4_Prompt",      "experiments/prompt_ablation/V4_plan_solve_user_results.json", ex_v4_prompt),
        ("DmAVID_Hybrid",  "experiments/ablation/ablation_v5_clean_self-verify_details.json", ex_hybrid_canonical),
    ]

    print("\n[1/3] 載入...")
    method_data = OrderedDict()
    for label, rel_path, extractor in sources:
        triples = load_method(label, rel_path, extractor)
        if triples is None:
            continue
        method_data[label] = triples

    print("\n[2/3] FP 類型統計...")
    method_fp = OrderedDict()
    all_types = set()
    for label, triples in method_data.items():
        res = analyze_fp_types(triples)
        method_fp[label] = res
        all_types.update(res["type_mentions"].keys())
        # 整體驗證
        tp = sum(1 for gt, p, _ in triples if gt == "vulnerable" and p)
        fp = sum(1 for gt, p, _ in triples if gt == "safe" and p)
        tn = sum(1 for gt, p, _ in triples if gt == "safe" and not p)
        fn = sum(1 for gt, p, _ in triples if gt == "vulnerable" and not p)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        method_fp[label]["overall"] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        }
        print(f"  {label:<22} FP={res['fp_count']:>3}/100  "
              f"FP_with_types={res['fp_with_types']:>3}  "
              f"avg_types/FP={res['avg_types_per_fp']:.2f}  "
              f"unique_types={len(res['type_mentions'])}")

    # 頻率排序：以「所有方法 FP 總提及」決定主軸 type 順序
    all_total = Counter()
    for label, res in method_fp.items():
        for t, c in res["type_mentions"].items():
            all_total[t] += c
    type_order = [t for t, _ in all_total.most_common()]

    print("\n[3/3] 寫出檔案...")
    methods = list(method_fp.keys())

    # CSV pivot
    pivot_path = os.path.join(OUTPUT_DIR, "fp_type_pivot.csv")
    with open(pivot_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["hallucinated_type"] + methods + ["combined"])
        for t in type_order:
            row = [t]
            combined = 0
            for m in methods:
                c = method_fp[m]["type_mentions"].get(t, 0)
                row.append(c)
                combined += c
            row.append(combined)
            w.writerow(row)
        # 摘要列
        w.writerow([])
        w.writerow(["__total_FP_count__"] + [method_fp[m]["fp_count"] for m in methods] + ["—"])
        w.writerow(["__FP_with_any_type__"] + [method_fp[m]["fp_with_types"] for m in methods] + ["—"])
        w.writerow(["__avg_types_per_FP__"] + [method_fp[m]["avg_types_per_fp"] for m in methods] + ["—"])
    print(f"  → {pivot_path}")

    # CSV long
    long_path = os.path.join(OUTPUT_DIR, "fp_type_long.csv")
    with open(long_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "hallucinated_type", "fp_contracts_with_this_type",
                    "share_of_method_fp"])
        for m in methods:
            total_fp = method_fp[m]["fp_count"] or 1
            for t in type_order:
                c = method_fp[m]["type_mentions"].get(t, 0)
                share = c / total_fp
                w.writerow([m, t, c, round(share, 4)])
    print(f"  → {long_path}")

    # Markdown
    md_path = os.path.join(OUTPUT_DIR, "fp_type_table.md")
    with open(md_path, "w") as f:
        f.write("# Sprint 4 — False-Positive 類型歸因分析\n\n")
        f.write(f"_Generated: {datetime.now().isoformat()}_\n\n")
        f.write("**研究問題**：當方法將 safe 合約誤判為 vulnerable，它「自稱」發現的是哪種漏洞？\n\n")
        f.write("**樣本範圍**：243 樣本中的 100 個 safe 合約。\n\n")

        f.write("## 整體驗證\n\n")
        f.write("| 方法 | TP | FP | TN | FN | Precision | Recall | F1 |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|---:|\n")
        for m in methods:
            ov = method_fp[m]["overall"]
            f.write(f"| {m} | {ov['tp']} | {ov['fp']} | {ov['tn']} | {ov['fn']} | "
                    f"{ov['precision']:.4f} | {ov['recall']:.4f} | {ov['f1']:.4f} |\n")

        f.write("\n## FP 數量與多重歸因\n\n")
        f.write("| 方法 | FP 數 / 100 safe | 至少標一種類型的 FP | 平均每 FP 類型數 |\n")
        f.write("|---|---:|---:|---:|\n")
        for m in methods:
            r = method_fp[m]
            f.write(f"| {m} | {r['fp_count']} | {r['fp_with_types']} | {r['avg_types_per_fp']:.2f} |\n")

        f.write("\n## FP 類型歸因（每格為含此類型的 FP 合約數）\n\n")
        f.write("| 幻覺類型 | " + " | ".join(methods) + " | 總計 |\n")
        f.write("|---|" + "|".join(["---:"] * (len(methods) + 1)) + "|\n")
        for t in type_order:
            row = [t]
            combined = 0
            for m in methods:
                c = method_fp[m]["type_mentions"].get(t, 0)
                row.append(str(c))
                combined += c
            row.append(str(combined))
            f.write("| " + " | ".join(row) + " |\n")

        # FP 抑制效果（Hybrid 相對 Baseline 各類型減少了多少）
        if "DmAVID_Hybrid" in method_fp and "LLM_Baseline" in method_fp:
            f.write("\n## DmAVID Hybrid vs LLM Baseline：各類型 FP 抑制\n\n")
            f.write("| 幻覺類型 | LLM Baseline | DmAVID Hybrid | 減少數 | 減少率 |\n")
            f.write("|---|---:|---:|---:|---:|\n")
            base = method_fp["LLM_Baseline"]["type_mentions"]
            hyb = method_fp["DmAVID_Hybrid"]["type_mentions"]
            for t in type_order:
                b = base.get(t, 0)
                h = hyb.get(t, 0)
                diff = b - h
                rate = diff / b if b > 0 else 0.0
                arrow = "↓" if diff > 0 else ("↑" if diff < 0 else "—")
                f.write(f"| {t} | {b} | {h} | {arrow}{abs(diff)} | "
                        f"{rate*100:+.1f}% |\n")

        f.write("\n_注：本表類型字串經正規化收斂（例如 \"Integer Overflow\"→arithmetic、"
                "\"Re-entrancy\"→reentrancy）。一個 FP 合約可能同時被標多種類型，故總計可能"
                "大於該方法的 FP 數。_\n")
    print(f"  → {md_path}")

    # JSON
    json_path = os.path.join(OUTPUT_DIR, "fp_type_full.json")
    out = {
        "timestamp": datetime.now().isoformat(),
        "methods": methods,
        "by_method": {
            m: {
                "overall": method_fp[m]["overall"],
                "fp_count": method_fp[m]["fp_count"],
                "fp_with_types": method_fp[m]["fp_with_types"],
                "avg_types_per_fp": method_fp[m]["avg_types_per_fp"],
                "type_mentions": dict(method_fp[m]["type_mentions"].most_common()),
            } for m in methods
        },
    }
    with open(json_path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")

    # Stdout summary
    print("\n" + "=" * 70)
    print("FP 類型歸因摘要（按 combined 出現頻率）")
    print("=" * 70)
    print(f"{'type':<32} " + " ".join(f"{m:>15}" for m in methods))
    for t in type_order[:15]:
        cells = " ".join(f"{method_fp[m]['type_mentions'].get(t, 0):>15}" for m in methods)
        print(f"{t:<32} {cells}")


if __name__ == "__main__":
    main()
