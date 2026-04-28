#!/usr/bin/env python3
"""
Sprint 5C: ML 公平性消融 — 揭露 SmartBugs 之四項 confounder

研究問題：當 ML 在 SmartBugs (143 vuln + 100 safe) 上達到 F1=1.0 時，
         模型究竟學到「合約語意」還是「合約長度 / metadata 標頭 / 詞彙分佈」
         等 spurious correlation？

設計：四階段累積消融，每階段排除一項 confounder，量化 ML 退化程度：
  Stage 1 Naive            : 全集，不控制任何 confounder
  Stage 2 + Length-matched : 從 wild safe 抽出 length 分佈匹配 vuln 之子集
  Stage 3 + Strip-comments : 移除所有 // 與 /* */ 註解（含 SmartBugs metadata）
  Stage 4 + Keyword-only   : TF-IDF vocabulary 限定 Solidity 關鍵字白名單

每階段以 4 個分類器 (RF / GB / LR / SVM) × 5-fold CV 評估。

輸出：
  experiments/fairness_ablation/
    metrics_per_stage.csv       — 4 stages × 4 classifiers 的 P/R/F1/Acc
    length_distribution.png     — vuln vs safe 合約長度直方圖
    degradation_curve.png       — F1 從 Stage 1 到 Stage 4 的退化曲線
    fairness_ablation_report.json — 完整詳細結果
    run.log                     — 執行日誌

執行：
  cd /home/curtis/DmAVID
  python3 scripts/40_fairness_ablation_full.py

Author: Curtis Chang (張宏睿), 2026
"""

import os
import re
import sys
import json
import csv
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import Counter

import numpy as np

# ============================================================
# 路徑與隨機種子
# ============================================================
BASE_DIR = os.environ.get(
    "DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/fairness_ablation")
os.makedirs(OUTPUT_DIR, exist_ok=True)

SEED = 42
random.seed(SEED)
np.random.seed(SEED)


# ============================================================
# Solidity 關鍵字白名單 (Stage 4 用)
# ============================================================
# 來源：Solidity 0.8 keywords + 高風險函式名 + 結構詞彙
SOLIDITY_KEYWORD_WHITELIST = {
    # 控制流
    "if", "else", "while", "for", "do", "break", "continue", "return",
    "throw", "try", "catch",
    # 型別
    "bool", "int", "uint", "uint8", "uint16", "uint32", "uint64", "uint128",
    "uint256", "address", "bytes", "string", "bytes32", "mapping",
    "struct", "enum", "fixed", "ufixed",
    # 修飾符
    "public", "private", "internal", "external", "view", "pure", "payable",
    "constant", "immutable", "virtual", "override", "abstract",
    # 函式相關
    "function", "constructor", "modifier", "fallback", "receive",
    "returns", "memory", "storage", "calldata",
    # 合約結構
    "contract", "interface", "library", "using", "import", "pragma",
    "is", "this", "super", "new", "delete",
    # 安全相關函式 / 屬性
    "require", "assert", "revert", "emit", "event",
    "msg", "tx", "block", "now",
    "sender", "value", "data", "origin", "timestamp", "number", "coinbase",
    "balance", "transfer", "send", "call", "delegatecall", "staticcall",
    "selfdestruct", "suicide",
    # DeFi 相關
    "owner", "admin", "deposit", "withdraw", "approve", "allowance",
    "balanceOf", "totalSupply", "transferFrom", "mint", "burn",
    "swap", "liquidity", "oracle", "price", "fee",
    # 控制
    "onlyOwner", "nonReentrant", "ReentrancyGuard", "SafeMath",
    "SafeERC20", "Ownable", "AccessControl", "Pausable",
    # 數值
    "true", "false", "null", "wei", "gwei", "ether",
    "seconds", "minutes", "hours", "days", "weeks", "years",
    # 異常 / 邏輯
    "assembly", "unchecked", "checked", "type", "abi",
    "keccak256", "sha256", "ecrecover", "ripemd160",
    # solc / pragma
    "solidity",
}


# ============================================================
# 註解清洗 (Stage 3+)
# ============================================================

def strip_comments(code: str) -> str:
    """移除所有 Solidity 註解（block + line）"""
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"\n[ \t]*\n+", "\n\n", code)
    return code.strip()


# ============================================================
# 樣本載入
# ============================================================

def load_all_contracts() -> List[Dict[str, Any]]:
    """載入 dataset_1000.json，補上 code 欄位"""
    with open(DATASET_FILE, "r") as f:
        dataset = json.load(f)
    contracts = dataset["contracts"]
    enriched = []
    skipped = 0
    for c in contracts:
        code = c.get("code")
        if not code:
            fp = c.get("filepath")
            if fp:
                if not os.path.isabs(fp):
                    fp = os.path.join(BASE_DIR, fp)
                if os.path.exists(fp):
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        code = fh.read()
                else:
                    skipped += 1
                    continue
            else:
                skipped += 1
                continue
        c_copy = dict(c)
        c_copy["code"] = code
        c_copy["code_len"] = len(code)
        enriched.append(c_copy)
    if skipped > 0:
        print(f"  ⚠ Skipped {skipped} contracts (missing code)")
    return enriched


# ============================================================
# 取樣策略
# ============================================================

def sample_naive(all_contracts) -> List[Dict[str, Any]]:
    """Stage 1 Naive：與 04_run_llm_base.py 一致 = 143 vuln + 100 wild safe"""
    vuln = [c for c in all_contracts if c["label"] == "vulnerable"]
    safe = [c for c in all_contracts if c["label"] == "safe"]
    rng = random.Random(SEED)
    rng.shuffle(safe)
    sample_safe = safe[:100]
    sample = vuln + sample_safe
    rng.shuffle(sample)
    return sample


def sample_length_matched(all_contracts) -> List[Dict[str, Any]]:
    """Stage 2 Length-matched：對每個 vuln，從 safe 中找最接近長度的對手 (1:1 配對)"""
    vuln = [c for c in all_contracts if c["label"] == "vulnerable"]
    safe = [c for c in all_contracts if c["label"] == "safe"]

    # 為每個 vuln，找一個尚未被選的、長度差最小的 safe
    safe_by_len = sorted(safe, key=lambda c: c["code_len"])
    used = set()
    matched_safe = []
    for v in vuln:
        target = v["code_len"]
        # 簡單 linear scan 找最近且未用
        best_idx, best_diff = -1, float("inf")
        for i, s in enumerate(safe_by_len):
            if i in used:
                continue
            diff = abs(s["code_len"] - target)
            if diff < best_diff:
                best_diff = diff
                best_idx = i
                # 若 diff=0，立刻接受
                if diff == 0:
                    break
        if best_idx >= 0:
            used.add(best_idx)
            matched_safe.append(safe_by_len[best_idx])

    sample = vuln + matched_safe
    rng = random.Random(SEED)
    rng.shuffle(sample)

    # 統計配對效果
    vuln_lens = [c["code_len"] for c in vuln]
    safe_lens = [c["code_len"] for c in matched_safe]
    print(f"    vuln length:  median={int(np.median(vuln_lens))}, "
          f"mean={int(np.mean(vuln_lens))}, "
          f"min={min(vuln_lens)}, max={max(vuln_lens)}")
    print(f"    safe length:  median={int(np.median(safe_lens))}, "
          f"mean={int(np.mean(safe_lens))}, "
          f"min={min(safe_lens)}, max={max(safe_lens)}")
    return sample


# ============================================================
# 特徵抽取
# ============================================================

def extract_structural_features(code: str) -> Dict[str, float]:
    """簡單 19 維結構特徵 (與 23_traditional_ml_baseline.py 大致對齊)"""
    return {
        "num_functions": len(re.findall(r"\bfunction\s+\w+", code)),
        "num_modifiers": len(re.findall(r"\bmodifier\s+\w+", code)),
        "num_events": len(re.findall(r"\bevent\s+\w+", code)),
        "num_require": code.count("require("),
        "num_assert": code.count("assert("),
        "num_revert": code.count("revert("),
        "has_call_value": int(".call{value:" in code or ".call.value(" in code),
        "has_send": int(".send(" in code),
        "has_transfer": int(".transfer(" in code),
        "has_delegatecall": int(".delegatecall" in code),
        "has_selfdestruct": int("selfdestruct(" in code or "suicide(" in code),
        "has_tx_origin": int("tx.origin" in code),
        "has_block_timestamp": int("block.timestamp" in code or "now" in code),
        "has_blockhash": int("blockhash(" in code or "block.blockhash" in code),
        "has_unchecked": int("unchecked {" in code or "unchecked{" in code),
        "has_assembly": int("assembly {" in code or "assembly{" in code),
        "num_mappings": len(re.findall(r"\bmapping\s*\(", code)),
        "num_payable": code.count("payable"),
        "code_length_log": float(np.log1p(len(code))),
    }


# ============================================================
# 評估流程 (sklearn)
# ============================================================

def evaluate_stage(stage_name: str, sample, use_strip_comments: bool,
                   use_keyword_only: bool) -> Dict[str, Any]:
    """單一 stage：跑 4 個分類器 5-fold CV"""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import SVC
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
    from sklearn.preprocessing import StandardScaler
    from scipy.sparse import hstack, csr_matrix

    print(f"\n[{stage_name}] N={len(sample)} "
          f"({sum(1 for c in sample if c['label']=='vulnerable')} vuln + "
          f"{sum(1 for c in sample if c['label']=='safe')} safe)")
    print(f"    strip_comments={use_strip_comments}, "
          f"keyword_only={use_keyword_only}")

    # 取出 code 與 label
    codes = [c["code"] for c in sample]
    labels = np.array([1 if c["label"] == "vulnerable" else 0 for c in sample])

    # Stage 3+: strip comments
    if use_strip_comments:
        codes = [strip_comments(c) for c in codes]

    # TF-IDF features
    if use_keyword_only:
        # 限定 vocabulary
        tfidf = TfidfVectorizer(
            vocabulary=sorted(SOLIDITY_KEYWORD_WHITELIST),
            token_pattern=r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        )
    else:
        tfidf = TfidfVectorizer(
            max_features=500,
            token_pattern=r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        )
    X_tfidf = tfidf.fit_transform(codes)

    # Structural features
    struct_feats = [extract_structural_features(c) for c in codes]
    feat_names = list(struct_feats[0].keys())
    X_struct = np.array([[f[k] for k in feat_names] for f in struct_feats])
    scaler = StandardScaler()
    X_struct = scaler.fit_transform(X_struct)

    # 合併
    X = hstack([X_tfidf, csr_matrix(X_struct)])

    classifiers = {
        "RF": RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=-1),
        "GB": GradientBoostingClassifier(n_estimators=100, random_state=SEED),
        "LR": LogisticRegression(max_iter=2000, random_state=SEED),
        "SVM": SVC(kernel="rbf", random_state=SEED, probability=False),
    }

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    results = {}
    for clf_name, clf in classifiers.items():
        p_list, r_list, f1_list, acc_list = [], [], [], []
        for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X, labels)):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = labels[train_idx], labels[test_idx]
            clf.fit(X_train, y_train)
            y_pred = clf.predict(X_test)
            p_list.append(precision_score(y_test, y_pred, zero_division=0))
            r_list.append(recall_score(y_test, y_pred, zero_division=0))
            f1_list.append(f1_score(y_test, y_pred, zero_division=0))
            acc_list.append(accuracy_score(y_test, y_pred))
        results[clf_name] = {
            "precision": round(float(np.mean(p_list)), 4),
            "precision_std": round(float(np.std(p_list)), 4),
            "recall": round(float(np.mean(r_list)), 4),
            "recall_std": round(float(np.std(r_list)), 4),
            "f1": round(float(np.mean(f1_list)), 4),
            "f1_std": round(float(np.std(f1_list)), 4),
            "accuracy": round(float(np.mean(acc_list)), 4),
            "accuracy_std": round(float(np.std(acc_list)), 4),
        }
        print(f"    {clf_name:<3}: F1={results[clf_name]['f1']:.4f} "
              f"(±{results[clf_name]['f1_std']:.4f})  "
              f"Acc={results[clf_name]['accuracy']:.4f}  "
              f"P={results[clf_name]['precision']:.4f}  "
              f"R={results[clf_name]['recall']:.4f}")

    return {
        "stage": stage_name,
        "n_samples": len(sample),
        "n_vuln": int(np.sum(labels)),
        "n_safe": int(len(labels) - np.sum(labels)),
        "n_features_tfidf": X_tfidf.shape[1],
        "n_features_struct": len(feat_names),
        "use_strip_comments": use_strip_comments,
        "use_keyword_only": use_keyword_only,
        "classifiers": results,
    }


# ============================================================
# 視覺化
# ============================================================

def plot_length_distribution(all_contracts):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    vuln_lens = [c["code_len"] for c in all_contracts
                 if c["label"] == "vulnerable"]
    safe_lens = [c["code_len"] for c in all_contracts
                 if c["label"] == "safe"]

    fig, ax = plt.subplots(figsize=(10, 6))
    bins = np.logspace(np.log10(100), np.log10(100000), 40)
    ax.hist(vuln_lens, bins=bins, alpha=0.6, label=f"Vulnerable (N={len(vuln_lens)})",
            color="#C0392B", edgecolor="#7B1F12")
    ax.hist(safe_lens, bins=bins, alpha=0.6, label=f"Safe (N={len(safe_lens)})",
            color="#27AE60", edgecolor="#1E8449")
    ax.set_xscale("log")
    ax.set_xlabel("Contract length (chars, log scale)", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("SmartBugs Contract Length Distribution\n"
                 f"vuln median={int(np.median(vuln_lens))}, "
                 f"safe median={int(np.median(safe_lens))} "
                 f"({np.median(safe_lens)/np.median(vuln_lens):.1f}x larger)",
                 fontsize=12)
    ax.legend(fontsize=11)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    out = os.path.join(OUTPUT_DIR, "length_distribution.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"\n→ Saved: {out}")


def plot_degradation_curve(stage_results):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    stages = [r["stage"] for r in stage_results]
    classifiers = ["RF", "GB", "LR", "SVM"]
    colors = {"RF": "#C0392B", "GB": "#D4942C", "LR": "#5B7FA8", "SVM": "#27AE60"}

    fig, ax = plt.subplots(figsize=(11, 6))
    x = np.arange(len(stages))
    for clf in classifiers:
        f1s = [r["classifiers"][clf]["f1"] for r in stage_results]
        f1_stds = [r["classifiers"][clf]["f1_std"] for r in stage_results]
        ax.errorbar(x, f1s, yerr=f1_stds, marker="o", markersize=10,
                    linewidth=2, capsize=6, label=clf, color=colors[clf])
        for xi, f in zip(x, f1s):
            ax.text(xi, f + 0.025, f"{f:.3f}", ha="center", fontsize=9.5,
                    color=colors[clf], fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels([s.replace(" ", "\n", 1) for s in stages], fontsize=10)
    ax.set_ylabel("F1 Score (5-fold CV mean ± std)", fontsize=12)
    ax.set_title("ML Fairness Ablation: F1 Degradation as Confounders Are Removed\n"
                 "(Showing how SmartBugs structural unfairness inflates ML scores)",
                 fontsize=12, pad=12)
    ax.set_ylim(0.3, 1.05)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.legend(loc="upper right", fontsize=11)
    out = os.path.join(OUTPUT_DIR, "degradation_curve.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ Saved: {out}")


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 70)
    print("Sprint 5C — ML 公平性消融分析")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Output:    {OUTPUT_DIR}")
    print("=" * 70)

    # 載入全資料
    print("\n[Setup] 載入 dataset...")
    all_contracts = load_all_contracts()
    print(f"  Total: {len(all_contracts)} contracts")
    print(f"    vuln: {sum(1 for c in all_contracts if c['label']=='vulnerable')}")
    print(f"    safe: {sum(1 for c in all_contracts if c['label']=='safe')}")

    # 視覺化長度分佈 (用全集)
    print("\n[Setup] 繪製合約長度直方圖...")
    plot_length_distribution(all_contracts)

    # ===== 4-stage ablation =====
    stage_results = []

    # Stage 1: Naive
    sample_s1 = sample_naive(all_contracts)
    r1 = evaluate_stage("S1 Naive", sample_s1,
                        use_strip_comments=False, use_keyword_only=False)
    stage_results.append(r1)

    # Stage 2: + Length-matched
    sample_s2 = sample_length_matched(all_contracts)
    r2 = evaluate_stage("S2 + Length-matched", sample_s2,
                        use_strip_comments=False, use_keyword_only=False)
    stage_results.append(r2)

    # Stage 3: + Strip-comments (用 Stage 2 的 sample)
    r3 = evaluate_stage("S3 + Strip-comments", sample_s2,
                        use_strip_comments=True, use_keyword_only=False)
    stage_results.append(r3)

    # Stage 4: + Keyword-only (用 Stage 2 的 sample)
    r4 = evaluate_stage("S4 + Keyword-only", sample_s2,
                        use_strip_comments=True, use_keyword_only=True)
    stage_results.append(r4)

    # 視覺化退化曲線
    print("\n[Plot] 繪製 F1 退化曲線...")
    plot_degradation_curve(stage_results)

    # CSV 輸出
    csv_path = os.path.join(OUTPUT_DIR, "metrics_per_stage.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["stage", "n_samples", "n_vuln", "n_safe",
                    "classifier", "precision", "precision_std",
                    "recall", "recall_std", "f1", "f1_std",
                    "accuracy", "accuracy_std"])
        for r in stage_results:
            for clf, m in r["classifiers"].items():
                w.writerow([r["stage"], r["n_samples"], r["n_vuln"], r["n_safe"],
                            clf, m["precision"], m["precision_std"],
                            m["recall"], m["recall_std"],
                            m["f1"], m["f1_std"],
                            m["accuracy"], m["accuracy_std"]])
    print(f"\n→ Saved: {csv_path}")

    # JSON 完整報告
    json_path = os.path.join(OUTPUT_DIR, "fairness_ablation_report.json")
    with open(json_path, "w") as f:
        json.dump({
            "experiment": "Sprint 5C — ML Fairness Ablation",
            "timestamp": datetime.now().isoformat(),
            "seed": SEED,
            "stages": stage_results,
        }, f, indent=2)
    print(f"→ Saved: {json_path}")

    # 簡要摘要
    print("\n" + "=" * 70)
    print("SUMMARY: F1 Degradation Across Stages")
    print("=" * 70)
    print(f"{'Classifier':<12} {'S1 Naive':<12} {'S2 +LenMatch':<14} "
          f"{'S3 +StripCmt':<14} {'S4 +KwOnly':<12}")
    for clf in ["RF", "GB", "LR", "SVM"]:
        f1s = [r["classifiers"][clf]["f1"] for r in stage_results]
        print(f"{clf:<12} {f1s[0]:<12.4f} {f1s[1]:<14.4f} "
              f"{f1s[2]:<14.4f} {f1s[3]:<12.4f}")
    print("=" * 70)
    print("\n論文敘事建議：把 S1 → S4 的退化幅度當成「SmartBugs structural")
    print("unfairness 之量化證據」，而非單純報告 ML F1=1.0。")


if __name__ == "__main__":
    main()
