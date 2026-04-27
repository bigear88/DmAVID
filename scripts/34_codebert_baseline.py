#!/usr/bin/env python3
"""
Sprint 3: CodeBERT 深度學習基線 (CodeBERT Deep-Learning Baseline)

目的：建立 microsoft/codebert-base 微調後之二元分類基線 (vulnerable / safe)，
      作為 DmAVID Hybrid (F1=0.9121) 與 V4 Prompt 工程最佳結果 (F1=0.7889)
      的深度學習對照基線，補齊論文第肆章&#x300C;為何不跟深度學習方法比較&#x300D;的
      口試委員提問空白。

設計：
- 與 04_run_llm_base.py 共用同一 SmartBugs 子集 (143 vuln + 100 safe = 243 contracts)
- 80/20 stratified split (seed=42)，固定 train/test 切分以利 reproducibility
- HuggingFace Trainer：3 epochs, lr=2e-5, batch_size=8, max_seq_len=512
- 報告 Precision / Recall / F1 / Accuracy + 1000-iter bootstrap 95% CI
- 輸出獨立至 experiments/codebert_baseline/

執行：
  cd /home/curtis/DmAVID
  python scripts/34_codebert_baseline.py

  # 煙霧測試：1 epoch + 取樣 50 個合約
  python scripts/34_codebert_baseline.py --smoke-test

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
from typing import Dict, List, Any


# ============================================================
# 註解前處理（SmartBugs Curated 標準前處理步驟）
# ============================================================
# SmartBugs Curated 資料集規範定義 vulnerable 合約檔頭含 @vulnerable_at_lines、
# @source、@author 等 metadata 註解（見 github.com/smartbugs/smartbugs-curated）。
# 為使 CodeBERT 學自程式碼語意而非 metadata 標頭，fine-tune 前移除所有 // 與
# /* */ 註解（同 PLM-based DL 智能合約偵測之常規做法）。

def strip_comments(code: str) -> str:
    """移除所有 Solidity 註解（block + line），SmartBugs 微調前之標準前處理。"""
    # 1. 先拔除所有 block comment /* ... */（含跨行）
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    # 2. 再拔除單行註解 // ...
    code = re.sub(r"//[^\n]*", "", code)
    # 3. 收斂多餘空白行
    code = re.sub(r"\n[ \t]*\n+", "\n\n", code)
    return code.strip()

# ---- 路徑設定 ----
BASE_DIR = os.environ.get(
    "DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/codebert_baseline")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---- 隨機種子 ----
SEED = 42
random.seed(SEED)


# ============================================================
# 樣本載入 (與 04_run_llm_base.py 一致)
# ============================================================

def load_sample(strip_leaky_comments: bool = True) -> List[Dict[str, Any]]:
    """載入 SmartBugs 243 子集，並嘗試從 filepath 補上 code。

    Args:
        strip_leaky_comments: True（預設）時呼叫 strip_comments() 移除所有 //
            與 /* */ 註解，依 SmartBugs Curated 規範前處理 metadata 標頭。
            False 為原始模式（保留所有註解；僅供 debug/ablation，不應用於正式結果）。
    """
    with open(DATASET_FILE, "r") as f:
        dataset = json.load(f)
    contracts = dataset["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]

    # 與 04 / 32 一致的取樣邏輯
    random.seed(SEED)
    random.shuffle(safe)
    sample_safe = safe[:100]
    sample = vuln + sample_safe
    random.shuffle(sample)

    # 補上 code 內容（dataset_1000.json 內 keys 為 id/filename/filepath/label/category）
    enriched = []
    skipped = 0
    raw_chars_total = 0
    stripped_chars_total = 0
    for c in sample:
        code = c.get("code")
        if not code:
            fp = c.get("filepath")
            if fp:
                # filepath 可能是相對路徑或絕對路徑
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
        raw_chars_total += len(code)
        if strip_leaky_comments:
            code = strip_comments(code)
        stripped_chars_total += len(code)
        name = c.get("name") or c.get("id") or c.get("filename") or "unknown"
        label_int = 1 if c["label"] == "vulnerable" else 0
        enriched.append({
            "name": name,
            "code": code,
            "label": label_int,
            "label_str": c["label"],
            "category": c.get("category", "unknown"),
        })
    if skipped > 0:
        print(f"⚠ Skipped {skipped} contracts (missing code)")
    if strip_leaky_comments and raw_chars_total > 0:
        reduction = 1 - stripped_chars_total / raw_chars_total
        print(f"  Comment stripping: {raw_chars_total:,} → {stripped_chars_total:,} chars "
              f"({reduction*100:.1f}% removed)")
    return enriched


# ============================================================
# 訓練與評估
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="CodeBERT 基線微調實驗")
    parser.add_argument("--smoke-test", action="store_true",
                        help="煙霧測試：1 epoch + 取樣 50 個合約 (~3-5 分鐘 GPU)")
    parser.add_argument("--epochs", type=int, default=3, help="訓練 epoch 數 (預設 3)")
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-seq-len", type=int, default=512)
    parser.add_argument("--model-name", default="microsoft/codebert-base",
                        help="HuggingFace model id")
    parser.add_argument("--keep-leaky-comments", action="store_true",
                        help="保留所有註解（不執行 SmartBugs metadata 前處理）。"
                             "僅供 debug/ablation；正式結果請使用預設值。")
    parser.add_argument("--output-suffix", default="",
                        help="輸出檔名後綴，例如 '_ablation'")
    args = parser.parse_args()

    # 延遲載入 transformers / torch (避免 import 開銷影響 -h)
    import numpy as np
    import torch
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        Trainer, TrainingArguments, DataCollatorWithPadding,
    )
    from datasets import Dataset
    from sklearn.model_selection import train_test_split

    # GPU 偵測
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("=" * 70)
    print(f"Sprint 3 — CodeBERT 深度學習基線")
    print(f"Timestamp   : {datetime.now().isoformat()}")
    print(f"Model       : {args.model_name}")
    print(f"Device      : {device}", end="")
    if device.type == "cuda":
        print(f" ({torch.cuda.get_device_name(0)})")
    else:
        print(" — ⚠ CPU 模式預估 4-8 小時，建議改用 GPU")
    print(f"Epochs      : {args.epochs}")
    print(f"Batch size  : {args.batch_size}")
    print(f"Learning rate: {args.lr}")
    print(f"Max seq len : {args.max_seq_len}")
    print(f"Smoke test  : {args.smoke_test}")
    print(f"Strip comments (SmartBugs metadata preprocessing): {not args.keep_leaky_comments}")
    print("=" * 70)

    # 設定全部隨機種子
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)
    np.random.seed(SEED)

    # 1. 載入資料
    print("\n[1/5] 載入資料集...")
    sample = load_sample(strip_leaky_comments=not args.keep_leaky_comments)
    print(f"  載入 {len(sample)} 筆 ({sum(1 for c in sample if c['label']==1)} vuln + "
          f"{sum(1 for c in sample if c['label']==0)} safe)")

    if args.smoke_test:
        random.shuffle(sample)
        sample = sample[:50]
        args.epochs = 1
        print(f"  煙霧測試：取樣前 50 筆，epochs=1")

    # 2. 80/20 stratified split
    print("\n[2/5] Train/Test split (80/20 stratified, seed=42)...")
    labels = [c["label"] for c in sample]
    train_data, test_data = train_test_split(
        sample, test_size=0.2, random_state=SEED, stratify=labels
    )
    print(f"  Train: {len(train_data)} ({sum(1 for c in train_data if c['label']==1)} vuln + "
          f"{sum(1 for c in train_data if c['label']==0)} safe)")
    print(f"  Test : {len(test_data)} ({sum(1 for c in test_data if c['label']==1)} vuln + "
          f"{sum(1 for c in test_data if c['label']==0)} safe)")

    # 3. Tokenize
    print(f"\n[3/5] 載入 tokenizer 與模型 ({args.model_name})...")
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, num_labels=2
    )

    def tokenize_fn(batch):
        return tokenizer(
            batch["code"],
            truncation=True,
            padding=False,  # dynamic padding via collator
            max_length=args.max_seq_len,
        )

    train_ds = Dataset.from_list([
        {"code": c["code"], "label": c["label"]} for c in train_data
    ]).map(tokenize_fn, batched=True, remove_columns=["code"])
    test_ds = Dataset.from_list([
        {"code": c["code"], "label": c["label"]} for c in test_data
    ]).map(tokenize_fn, batched=True, remove_columns=["code"])

    # 4. 訓練
    print(f"\n[4/5] 訓練 {args.epochs} epochs...")
    train_args = TrainingArguments(
        output_dir=os.path.join(OUTPUT_DIR, "model_checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_ratio=0.1,
        logging_steps=10,
        save_strategy="no",  # 不存中繼 checkpoint，只取最終結果
        eval_strategy="epoch",
        seed=SEED,
        report_to=[],  # 不送 wandb / tensorboard
        fp16=device.type == "cuda",
    )
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    # transformers 5.x: `tokenizer` arg renamed to `processing_class`
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

    train_start = time.time()
    train_result = trainer.train()
    train_time = time.time() - train_start
    print(f"  訓練耗時: {train_time/60:.1f} 分鐘")

    # 5. 預測 + 評估
    print("\n[5/5] 預測測試集 + 計算指標...")
    predictions = trainer.predict(test_ds)
    pred_labels = np.argmax(predictions.predictions, axis=1)
    true_labels = np.array([c["label"] for c in test_data])

    # 混淆矩陣
    tp = int(np.sum((pred_labels == 1) & (true_labels == 1)))
    fp = int(np.sum((pred_labels == 1) & (true_labels == 0)))
    tn = int(np.sum((pred_labels == 0) & (true_labels == 0)))
    fn = int(np.sum((pred_labels == 0) & (true_labels == 1)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(true_labels) if len(true_labels) > 0 else 0.0

    # Bootstrap 95% CI on F1
    rng = np.random.default_rng(SEED)
    n = len(true_labels)
    f1_samples = []
    for _ in range(1000):
        idx = rng.choice(n, size=n, replace=True)
        bp = pred_labels[idx]
        bt = true_labels[idx]
        btp = int(np.sum((bp == 1) & (bt == 1)))
        bfp = int(np.sum((bp == 1) & (bt == 0)))
        bfn = int(np.sum((bp == 0) & (bt == 1)))
        bp_v = btp / (btp + bfp) if (btp + bfp) > 0 else 0.0
        br = btp / (btp + bfn) if (btp + bfn) > 0 else 0.0
        bf1 = 2 * bp_v * br / (bp_v + br) if (bp_v + br) > 0 else 0.0
        f1_samples.append(bf1)
    ci_low = float(np.percentile(f1_samples, 2.5))
    ci_high = float(np.percentile(f1_samples, 97.5))

    # 結果輸出
    metrics = {
        "experiment": "Sprint 3 — CodeBERT Baseline",
        "model": args.model_name,
        "timestamp": datetime.now().isoformat(),
        "device": str(device),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.lr,
        "max_seq_len": args.max_seq_len,
        "train_size": len(train_data),
        "test_size": len(test_data),
        "train_time_seconds": round(train_time, 2),
        "leaky_comments_kept": bool(args.keep_leaky_comments),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "f1_ci_low": round(ci_low, 4),
        "f1_ci_high": round(ci_high, 4),
        "accuracy": round(accuracy, 4),
    }

    # 逐筆預測明細
    per_sample = []
    for i, c in enumerate(test_data):
        per_sample.append({
            "name": c["name"],
            "ground_truth": c["label_str"],
            "predicted": "vulnerable" if pred_labels[i] == 1 else "safe",
            "category": c.get("category", "unknown"),
            "correct": bool(pred_labels[i] == c["label"]),
        })

    suffix = args.output_suffix or ("_ablation" if args.keep_leaky_comments else "")
    out_metrics = os.path.join(OUTPUT_DIR, f"metrics{suffix}.json")
    out_per_sample = os.path.join(OUTPUT_DIR, f"per_sample_predictions{suffix}.json")
    out_csv = os.path.join(OUTPUT_DIR, "metrics_summary.csv")

    with open(out_metrics, "w") as f:
        json.dump({"metrics": metrics, "results": per_sample}, f, indent=2, ensure_ascii=False)
    with open(out_per_sample, "w") as f:
        json.dump(per_sample, f, indent=2, ensure_ascii=False)

    # CSV：累加模式（讀回現有列、加新列、重寫）
    import csv
    method_label = (
        "CodeBERT (ablation: 保留註解)"
        if args.keep_leaky_comments
        else "CodeBERT (微調)"
    )
    new_row = [method_label, metrics["test_size"], tp, fp, tn, fn,
               metrics["precision"], metrics["recall"], metrics["f1"],
               metrics["f1_ci_low"], metrics["f1_ci_high"], metrics["accuracy"]]

    header = ["method", "n_test", "tp", "fp", "tn", "fn",
              "precision", "recall", "f1", "f1_ci_low", "f1_ci_high", "accuracy"]
    existing_methods = []
    existing_rows = []
    if os.path.exists(out_csv):
        with open(out_csv, "r") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i == 0 or not row or row[0].startswith("#") or row[0].startswith("DmAVID Hybrid") or row[0].startswith("V4 Prompt"):
                    continue
                if row[0].startswith("CodeBERT"):
                    existing_methods.append(row[0])
                    existing_rows.append(row)
    # 替換相同 method label 或追加
    rows_to_write = [r for r in existing_rows if r[0] != method_label]
    rows_to_write.append(new_row)

    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows_to_write:
            w.writerow(r)
        w.writerow([])
        w.writerow(["# 對照組 (來自其他實驗)"])
        w.writerow(["DmAVID Hybrid (本研究主要結果)", "243", "—", "—", "—", "—",
                    "0.84", "0.98", "0.9121", "—", "—", "0.85"])
        w.writerow(["V4 Prompt (Sprint 1 最佳)", "243", "142", "75", "25", "1",
                    "0.6544", "0.9930", "0.7889", "0.7384", "0.8316", "0.6872"])

    print("\n" + "=" * 70)
    print(f"CodeBERT Baseline Results (test set N={len(test_data)})")
    print("=" * 70)
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  Precision = {precision:.4f}")
    print(f"  Recall    = {recall:.4f}")
    print(f"  F1        = {f1:.4f}  (95% CI [{ci_low:.4f}, {ci_high:.4f}])")
    print(f"  Accuracy  = {accuracy:.4f}")
    print(f"  Training time: {train_time/60:.1f} min on {device}")
    print("=" * 70)
    print(f"\n=== 對照組 (Reference) ===")
    print(f"  DmAVID Hybrid (主要結果): F1=0.9121")
    print(f"  V4 Prompt (Sprint 1):    F1=0.7889 [0.7384, 0.8316]")
    print(f"  CodeBERT (本實驗):        F1={f1:.4f} [{ci_low:.4f}, {ci_high:.4f}]")
    if f1 >= 0.85:
        print(f"  → CodeBERT 表現接近 Hybrid，DmAVID 主要優勢在 FP 控制與多代理迭代")
    elif f1 >= 0.75:
        print(f"  → CodeBERT 介於 V4 Prompt 與 Hybrid 之間，DmAVID Hybrid 相對 DL 仍具明顯優勢")
    else:
        print(f"  → CodeBERT 弱於 V4 Prompt 與 Hybrid，DmAVID 全面領先")
    print(f"\nResults saved to:")
    print(f"  {out_metrics}")
    print(f"  {out_per_sample}")
    print(f"  {out_csv}")


if __name__ == "__main__":
    main()
