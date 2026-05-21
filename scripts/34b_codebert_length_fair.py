#!/usr/bin/env python3
"""
34b_codebert_length_fair.py
CodeBERT 長度公平性消融實驗 (Length-Fair Ablation)

動機：原版 CodeBERT (34_codebert_baseline.py) F1=0.918，但：
  - curated (vuln) 合約 median=1,140 chars / 42 lines
  - wild (safe) 合約 median=7,429 chars / 221 lines → 6.5x 差距
  - 純 length threshold (< 2000 chars) 就能拿 F1=0.909
  - GBM 用 length+lines 兩個特徵能拿 F1=0.949
  → CodeBERT 0.918 幾乎完全被長度混淆因子解釋

設計：5 組對照 (Arms)
  Arm A — 原版複製 (strip_comments, max_seq_len=512)
  Arm B — 長度匹配子集 (只用 500-10000 chars 的合約, 移除極端長度差異)
  Arm C — 固定窗口截取 (所有合約截取中間 1024 chars, 移除長度信號)
  Arm D — 純長度分類器 (LogReg + GBM, 無 GPU)
  Arm E — 隨機標籤基線 (確認 ceiling for random)

用法：
  # 只跑不需 GPU 的 Arms (D+E)
  python scripts/34b_codebert_length_fair.py --arms D E

  # 跑全部 (需 GPU)
  python scripts/34b_codebert_length_fair.py --arms A B C D E

  # 煙霧測試
  python scripts/34b_codebert_length_fair.py --arms A B C --smoke-test

Author: Curtis Chang (張宏睿), 2026
"""

import os
import re
import sys
import json
import time
import random
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple

# ---- 路徑 ----
BASE_DIR = os.environ.get(
    "DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/codebert_length_fair")
os.makedirs(OUTPUT_DIR, exist_ok=True)

SEED = 42


# ============================================================
# 前處理函數
# ============================================================
def strip_comments(code: str) -> str:
    """移除所有 Solidity 註解 (block + line)。"""
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"\n[ \t]*\n+", "\n\n", code)
    return code.strip()


def strip_annotations(code: str) -> str:
    """移除 SmartBugs 行內標註 (<yes>/<no>, @vulnerable_at_lines, SWC URLs)。"""
    code = re.sub(r"[^\n]*<(?:yes|no)>[^\n]*", "", code)
    code = re.sub(r"[^\n]*@vulnerable_at_lines:[^\n]*\n?", "", code)
    code = re.sub(r"https?://swcregistry\.io/docs/SWC-\d+", "", code)
    return code


def extract_middle_window(code: str, window_size: int = 1024) -> str:
    """從合約中間截取固定長度窗口，移除長度信號。"""
    if len(code) <= window_size:
        return code
    start = (len(code) - window_size) // 2
    return code[start:start + window_size]


# ============================================================
# 資料載入
# ============================================================
def load_dataset(require_code: bool = True) -> List[Dict[str, Any]]:
    """載入 SmartBugs 243 子集 (與 34_codebert_baseline.py 一致)。

    Args:
        require_code: True = 必須讀到原始碼 (Arms A/B/C)。
                      False = 只需 metadata (Arms D/E，用 dataset JSON 的 code_length)。
    """
    with open(DATASET_FILE, "r") as f:
        dataset = json.load(f)
    contracts = dataset["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]

    random.seed(SEED)
    random.shuffle(safe)
    sample_safe = safe[:100]
    sample = vuln + sample_safe
    random.shuffle(sample)

    enriched = []
    skipped = 0
    for c in sample:
        code = c.get("code")
        if not code:
            fp = c.get("filepath")
            if fp:
                # 支援不同環境的路徑映射
                if not os.path.isabs(fp):
                    fp = os.path.join(BASE_DIR, fp)
                # 嘗試相對於 BASE_DIR 的 data/ 路徑
                if not os.path.exists(fp):
                    rel = fp.replace("/home/curtis/DmAVID/", "")
                    fp_alt = os.path.join(BASE_DIR, rel)
                    if os.path.exists(fp_alt):
                        fp = fp_alt
                if os.path.exists(fp):
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        code = fh.read()

        if require_code and not code:
            skipped += 1
            continue

        enriched.append({
            "name": c.get("name") or c.get("id") or c.get("filename") or "unknown",
            "code_raw": code or "",
            "code_length_raw": len(code) if code else c.get("code_length", 0),
            "code_length_meta": c.get("code_length", 0),  # 從 JSON metadata
            "label": 1 if c["label"] == "vulnerable" else 0,
            "label_str": c["label"],
            "category": c.get("category", "unknown"),
        })
    if skipped > 0:
        print(f"  ⚠ Skipped {skipped} contracts (missing code)")
    return enriched


def prepare_arm_data(
    sample: List[Dict],
    arm: str,
    window_size: int = 1024,
) -> Tuple[List[Dict], str]:
    """依 arm 設定前處理資料，回傳 (processed_data, description)。"""

    if arm == "A":
        # 原版：strip_comments, 完整長度
        processed = []
        for c in sample:
            code = strip_comments(c["code_raw"])
            processed.append({**c, "code": code, "code_length": len(code)})
        desc = "原版 strip_comments (reproduce 0.918)"
        return processed, desc

    elif arm == "B":
        # 長度匹配子集：500-10000 chars (strip_comments 後)
        processed = []
        for c in sample:
            code = strip_comments(c["code_raw"])
            clen = len(code)
            if 500 <= clen <= 10000:
                processed.append({**c, "code": code, "code_length": clen})
        desc = f"長度匹配 [500-10000] 子集 (n={len(processed)})"
        return processed, desc

    elif arm == "C":
        # 固定窗口：所有合約截取中間 window_size chars
        processed = []
        for c in sample:
            code = strip_comments(c["code_raw"])
            code = strip_annotations(code)
            code = extract_middle_window(code, window_size)
            processed.append({**c, "code": code, "code_length": len(code)})
        desc = f"固定窗口 {window_size} chars (中間截取)"
        return processed, desc

    else:
        raise ValueError(f"Unknown arm: {arm}")


# ============================================================
# CodeBERT 訓練 + 評估 (Arms A/B/C)
# ============================================================
def run_codebert_arm(
    data: List[Dict],
    arm_name: str,
    arm_desc: str,
    args,
) -> Dict:
    """訓練 CodeBERT 並回傳 metrics dict。"""
    import numpy as np
    import torch
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        Trainer, TrainingArguments, DataCollatorWithPadding,
    )
    from datasets import Dataset
    from sklearn.model_selection import train_test_split

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)
    np.random.seed(SEED)

    labels = [c["label"] for c in data]
    n_vuln = sum(labels)
    n_safe = len(labels) - n_vuln
    print(f"\n{'='*60}")
    print(f"Arm {arm_name}: {arm_desc}")
    print(f"  Total: {len(data)} ({n_vuln} vuln + {n_safe} safe)")
    print(f"  Device: {device}")

    # Length stats
    vuln_lens = [c["code_length"] for c in data if c["label"] == 1]
    safe_lens = [c["code_length"] for c in data if c["label"] == 0]
    print(f"  Vuln length: mean={np.mean(vuln_lens):.0f}, median={np.median(vuln_lens):.0f}")
    print(f"  Safe length: mean={np.mean(safe_lens):.0f}, median={np.median(safe_lens):.0f}")
    ratio = np.median(safe_lens) / max(np.median(vuln_lens), 1)
    print(f"  Length ratio (safe/vuln median): {ratio:.2f}x")

    # Stratified split
    train_data, test_data = train_test_split(
        data, test_size=0.2, random_state=SEED, stratify=labels
    )
    print(f"  Train: {len(train_data)}, Test: {len(test_data)}")

    # Tokenize
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, num_labels=2
    ).to(device)

    def tokenize_fn(batch):
        return tokenizer(
            batch["code"], truncation=True, padding=False,
            max_length=args.max_seq_len,
        )

    train_ds = Dataset.from_list([
        {"code": c["code"], "label": c["label"]} for c in train_data
    ]).map(tokenize_fn, batched=True, remove_columns=["code"])
    test_ds = Dataset.from_list([
        {"code": c["code"], "label": c["label"]} for c in test_data
    ]).map(tokenize_fn, batched=True, remove_columns=["code"])

    # Train
    train_args = TrainingArguments(
        output_dir=os.path.join(OUTPUT_DIR, f"checkpoints_arm{arm_name}"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_ratio=0.1,
        logging_steps=10,
        save_strategy="no",
        eval_strategy="epoch",
        seed=SEED,
        report_to=[],
        fp16=device.type == "cuda",
    )
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    import transformers as _tf
    _trainer_kwargs = {
        "model": model,
        "args": train_args,
        "train_dataset": train_ds,
        "eval_dataset": test_ds,
        "data_collator": data_collator,
    }
    if int(_tf.__version__.split(".")[0]) >= 5:
        _trainer_kwargs["processing_class"] = tokenizer
    else:
        _trainer_kwargs["tokenizer"] = tokenizer
    trainer = Trainer(**_trainer_kwargs)

    t0 = time.time()
    trainer.train()
    train_time = time.time() - t0

    # Predict
    predictions = trainer.predict(test_ds)
    pred_labels = np.argmax(predictions.predictions, axis=1)
    true_labels = np.array([c["label"] for c in test_data])

    tp = int(np.sum((pred_labels == 1) & (true_labels == 1)))
    fp = int(np.sum((pred_labels == 1) & (true_labels == 0)))
    tn = int(np.sum((pred_labels == 0) & (true_labels == 0)))
    fn = int(np.sum((pred_labels == 0) & (true_labels == 1)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Bootstrap CI
    rng = np.random.default_rng(SEED)
    n = len(true_labels)
    f1_samples = []
    for _ in range(1000):
        idx = rng.choice(n, size=n, replace=True)
        bp, bt = pred_labels[idx], true_labels[idx]
        btp = int(np.sum((bp == 1) & (bt == 1)))
        bfp = int(np.sum((bp == 1) & (bt == 0)))
        bfn = int(np.sum((bp == 0) & (bt == 1)))
        bp_v = btp / (btp + bfp) if (btp + bfp) > 0 else 0.0
        br = btp / (btp + bfn) if (btp + bfn) > 0 else 0.0
        bf1 = 2 * bp_v * br / (bp_v + br) if (bp_v + br) > 0 else 0.0
        f1_samples.append(bf1)
    ci_low = float(np.percentile(f1_samples, 2.5))
    ci_high = float(np.percentile(f1_samples, 97.5))

    result = {
        "arm": arm_name,
        "description": arm_desc,
        "n_total": len(data),
        "n_train": len(train_data),
        "n_test": len(test_data),
        "n_vuln": n_vuln,
        "n_safe": n_safe,
        "length_ratio": round(ratio, 2),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "f1_ci_low": round(ci_low, 4),
        "f1_ci_high": round(ci_high, 4),
        "train_time_seconds": round(train_time, 2),
    }

    print(f"  Results: TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  F1={f1:.4f} [{ci_low:.4f}, {ci_high:.4f}]")
    print(f"  Train time: {train_time/60:.1f} min")

    # Per-sample predictions
    per_sample = []
    for i, c in enumerate(test_data):
        per_sample.append({
            "name": c["name"],
            "ground_truth": c["label_str"],
            "predicted": "vulnerable" if pred_labels[i] == 1 else "safe",
            "code_length": c["code_length"],
            "correct": bool(pred_labels[i] == c["label"]),
        })
    result["per_sample"] = per_sample
    return result


# ============================================================
# Arm D: 純長度分類器 (無 GPU)
# ============================================================
def run_length_only(sample: List[Dict]) -> Dict:
    """用純長度特徵跑分類器。"""
    import numpy as np
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import f1_score

    np.random.seed(SEED)

    # 用 metadata 長度（不依賴原始碼讀取，適用所有環境）
    X = np.array([[c["code_length_meta"]] for c in sample])
    y = np.array([c["label"] for c in sample])

    labels = y.tolist()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=labels
    )

    results = {"arm": "D", "description": "純長度分類器 (無 GPU)", "sub_results": []}

    # D1: Length threshold
    best_f1, best_t = 0, 0
    for t in range(200, 20000, 50):
        pred = (X_train[:, 0] < t).astype(int)
        f = f1_score(y_train, pred)
        if f > best_f1:
            best_f1, best_t = f, t

    pred_test = (X_test[:, 0] < best_t).astype(int)
    f1_t = f1_score(y_test, pred_test)

    tp = int(np.sum((pred_test == 1) & (y_test == 1)))
    fp = int(np.sum((pred_test == 1) & (y_test == 0)))
    tn = int(np.sum((pred_test == 0) & (y_test == 0)))
    fn = int(np.sum((pred_test == 0) & (y_test == 1)))

    results["sub_results"].append({
        "method": f"Length < {best_t}",
        "f1": round(f1_t, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    })
    print(f"\n  D1: Length threshold (<{best_t}): F1={f1_t:.4f}")

    # D2: Logistic Regression
    lr = LogisticRegression(random_state=SEED)
    lr.fit(X_train, y_train)
    pred_lr = lr.predict(X_test)
    f1_lr = f1_score(y_test, pred_lr)
    results["sub_results"].append({
        "method": "LogReg (length)",
        "f1": round(f1_lr, 4),
    })
    print(f"  D2: LogReg (length): F1={f1_lr:.4f}")

    # D3: GBM on length
    gb = GradientBoostingClassifier(random_state=SEED, n_estimators=100)
    gb.fit(X_train, y_train)
    pred_gb = gb.predict(X_test)
    f1_gb = f1_score(y_test, pred_gb)
    results["sub_results"].append({
        "method": "GBM (length)",
        "f1": round(f1_gb, 4),
    })
    print(f"  D3: GBM (length): F1={f1_gb:.4f}")

    # Summary
    results["best_length_only_f1"] = max(f1_t, f1_lr, f1_gb)
    results["n_train"] = len(X_train)
    results["n_test"] = len(X_test)
    return results


# ============================================================
# Arm E: 隨機標籤基線
# ============================================================
def run_random_baseline(sample: List[Dict]) -> Dict:
    """隨機分類基線。"""
    import numpy as np
    from sklearn.metrics import f1_score

    np.random.seed(SEED)
    y = np.array([c["label"] for c in sample])

    # Majority class baseline
    majority = 1 if np.mean(y) > 0.5 else 0
    f1_majority = f1_score(y, np.full_like(y, majority))

    # Random with class prior
    rng = np.random.default_rng(SEED)
    prior = np.mean(y)
    f1_randoms = []
    for _ in range(100):
        pred = (rng.random(len(y)) < prior).astype(int)
        f1_randoms.append(f1_score(y, pred))
    f1_random_mean = np.mean(f1_randoms)

    result = {
        "arm": "E",
        "description": "隨機基線",
        "majority_class_f1": round(float(f1_majority), 4),
        "random_prior_f1_mean": round(float(f1_random_mean), 4),
        "class_prior": round(float(prior), 4),
    }
    print(f"\n  E1: Majority class: F1={f1_majority:.4f}")
    print(f"  E2: Random (class prior): F1={f1_random_mean:.4f}")
    print(f"  Class prior (vuln): {prior:.3f}")
    return result


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="CodeBERT 長度公平性消融")
    parser.add_argument("--arms", nargs="+", default=["D", "E"],
                        choices=["A", "B", "C", "D", "E"],
                        help="要執行的 arms (預設 D E，不需 GPU)")
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-seq-len", type=int, default=512)
    parser.add_argument("--window-size", type=int, default=1024,
                        help="Arm C 固定窗口大小 (chars)")
    parser.add_argument("--model-name", default="microsoft/codebert-base")
    args = parser.parse_args()

    random.seed(SEED)

    print("=" * 60)
    print("CodeBERT 長度公平性消融實驗")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Arms: {', '.join(args.arms)}")
    print("=" * 60)

    # Load data — 只有 A/B/C 需要讀原始碼；D/E 只需 metadata
    needs_code = any(a in args.arms for a in ["A", "B", "C"])
    print(f"\n[Loading dataset... (require_code={needs_code})]")
    sample = load_dataset(require_code=needs_code)
    print(f"  Total: {len(sample)} contracts")

    all_results = {
        "experiment": "CodeBERT Length-Fair Ablation",
        "timestamp": datetime.now().isoformat(),
        "arms": {},
    }

    # Arm D (no GPU)
    if "D" in args.arms:
        print(f"\n{'='*60}")
        print("Arm D: 純長度分類器")
        result_d = run_length_only(sample)
        all_results["arms"]["D"] = result_d

    # Arm E (no GPU)
    if "E" in args.arms:
        print(f"\n{'='*60}")
        print("Arm E: 隨機基線")
        result_e = run_random_baseline(sample)
        all_results["arms"]["E"] = result_e

    # CodeBERT arms (need GPU)
    for arm in ["A", "B", "C"]:
        if arm not in args.arms:
            continue

        data, desc = prepare_arm_data(sample, arm, args.window_size)

        if args.smoke_test:
            random.shuffle(data)
            data = data[:50]
            args.epochs = 1
            desc += " [SMOKE TEST]"

        # Check minimum samples
        n_vuln = sum(1 for c in data if c["label"] == 1)
        n_safe = sum(1 for c in data if c["label"] == 0)
        if n_vuln < 5 or n_safe < 5:
            print(f"\n  Arm {arm} skipped: too few samples ({n_vuln} vuln, {n_safe} safe)")
            continue

        result = run_codebert_arm(data, arm, desc, args)
        # Remove per_sample from summary (save separately)
        per_sample = result.pop("per_sample", [])
        all_results["arms"][arm] = result

        # Save per-sample
        ps_path = os.path.join(OUTPUT_DIR, f"per_sample_arm{arm}.json")
        with open(ps_path, "w", encoding="utf-8") as f:
            json.dump(per_sample, f, indent=2, ensure_ascii=False)

    # ── Summary table ──
    print("\n" + "=" * 60)
    print("SUMMARY: CodeBERT 長度公平性消融")
    print("=" * 60)
    print(f"{'Arm':<6} {'Description':<45} {'F1':>8} {'95% CI':>20} {'n':>5}")
    print("-" * 90)

    if "E" in all_results["arms"]:
        e = all_results["arms"]["E"]
        print(f"{'E':<6} {'隨機基線 (majority class)':<45} {e['majority_class_f1']:>8.4f} {'—':>20} {'243':>5}")

    if "D" in all_results["arms"]:
        d = all_results["arms"]["D"]
        for sub in d["sub_results"]:
            print(f"{'D':<6} {sub['method']:<45} {sub['f1']:>8.4f} {'—':>20} {d['n_test']:>5}")

    for arm in ["A", "B", "C"]:
        if arm in all_results["arms"]:
            r = all_results["arms"][arm]
            ci = f"[{r['f1_ci_low']:.4f}, {r['f1_ci_high']:.4f}]"
            print(f"{arm:<6} {r['description']:<45} {r['f1']:>8.4f} {ci:>20} {r['n_test']:>5}")

    print("-" * 90)
    print("CodeBERT 原版 (Sprint 3 參考值):  F1=0.9180 [0.840, 0.983]  n=49")
    print("DmAVID Hybrid (論文主結果):        F1=0.9121")

    if "D" in all_results["arms"]:
        best_d = all_results["arms"]["D"]["best_length_only_f1"]
        print(f"\n⚠ 純長度分類器最佳 F1 = {best_d:.4f}")
        print(f"  → CodeBERT 0.918 的長度混淆因子佔比: "
              f"{best_d/0.918*100:.1f}%")

    # Save
    out_path = os.path.join(OUTPUT_DIR, "length_fair_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
