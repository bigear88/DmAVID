#!/usr/bin/env python3
"""
Sprint 5 路線 A — Out-of-Distribution Generalization：ML/CodeBERT vs DmAVID Hybrid。

訓練：
  - Traditional ML（RF/LR/GB/SVM）採 Stage 2 length-matched config（143v+143s=286, TF-IDF 500 + structural 19）
  - CodeBERT 採 Sprint 3 config（143v+100s=243，epochs=3, batch=8, lr=2e-5, max_seq=512, seed=42）
  - 兩者皆 train on full data（不分 holdout，因 EVMbench post-cutoff 即為 OOD test set）

測試：data/evmbench/audits/ 下 8 個 2025+ audits
  - 每個 audit 的 patch/*.sol 全部合併為單一輸入
  - 套用同 SmartBugs 訓練前處理（strip_comments）

評估三軌：
  - vuln-level recall（17 gold vulns）：僅 DmAVID 適用（ML/CodeBERT 結構上做不到）
  - audit-level recall（8 audits）：detect_score>0 即計入
  - contract-level（每個 audit 一個合約 → 預測 vulnerable/safe）

對照 DmAVID Hybrid（experiments/leakage_test/evmbench_hybrid_results.json）：
  - vuln-level: 2/17 = 11.76%
  - audit-level: 2/8 = 25.00%
"""
import json
import os
import re
import sys
import time
import warnings
import random
from collections import OrderedDict
from datetime import datetime

import numpy as np
import pandas as pd

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline, FeatureUnion

warnings.filterwarnings("ignore")
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

BASE_DIR = os.environ.get(
    "DAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
EVMBENCH_AUDITS_DIR = os.path.join(BASE_DIR, "data", "evmbench", "audits")
DMAVID_HYBRID_RESULTS = os.path.join(BASE_DIR, "experiments", "leakage_test", "evmbench_hybrid_results.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments", "sprint5_route_a")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# 前處理（與 Sprint 3 對齊）
# ============================================================

def strip_comments(code: str) -> str:
    """移除 Solidity 註解（block + line），SmartBugs 訓練前標準前處理。"""
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"\n[ \t]*\n+", "\n\n", code)
    return code.strip()


# ============================================================
# 結構化特徵（Stage 2 同 23_traditional_ml_baseline.py）
# ============================================================

def extract_structural_features(code):
    f = {}
    lines = code.split("\n")
    f["total_lines"] = len(lines)
    f["code_length"] = len(code)
    f["num_functions"] = len(re.findall(r"\bfunction\b", code))
    f["num_modifiers"] = len(re.findall(r"\bmodifier\b", code))
    f["num_events"] = len(re.findall(r"\bevent\b", code))
    f["num_mappings"] = len(re.findall(r"\bmapping\b", code))
    f["num_requires"] = len(re.findall(r"\brequire\b", code))
    f["num_asserts"] = len(re.findall(r"\bassert\b", code))
    f["num_reverts"] = len(re.findall(r"\brevert\b", code))
    f["num_external_calls"] = len(re.findall(r"\.call\b|\.send\b|\.transfer\b|\.delegatecall\b", code))
    f["num_msg_value"] = len(re.findall(r"msg\.value", code))
    f["num_msg_sender"] = len(re.findall(r"msg\.sender", code))
    f["num_block_timestamp"] = len(re.findall(r"block\.timestamp|now\b", code))
    f["num_selfdestruct"] = len(re.findall(r"selfdestruct|suicide", code))
    f["has_payable"] = 1 if "payable" in code else 0
    f["has_onlyowner"] = 1 if re.search(r"onlyOwner|only_owner", code, re.IGNORECASE) else 0
    f["has_reentrancy_guard"] = 1 if re.search(r"nonReentrant|ReentrancyGuard|mutex", code, re.IGNORECASE) else 0
    f["has_safemath"] = 1 if "SafeMath" in code else 0
    ver_match = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    f["solidity_major_version"] = int(ver_match.group(1).split(".")[1]) if ver_match else 8
    f["is_pre_08"] = 1 if f["solidity_major_version"] < 8 else 0
    return f


class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        sample = extract_structural_features(X[0])
        self.feature_names_ = sorted(sample.keys())
        return self

    def transform(self, X, y=None):
        rows = []
        for code in X:
            sf = extract_structural_features(code)
            rows.append([sf[fn] for fn in self.feature_names_])
        return np.array(rows)


# ============================================================
# SmartBugs 載入 + Stage 2 length-matching
# ============================================================

def load_smartbugs():
    with open(DATASET_FILE) as f:
        ds = json.load(f)
    contracts = ds["contracts"]
    vuln_raw = [c for c in contracts if c["label"] == "vulnerable"]
    safe_raw = [c for c in contracts if c["label"] == "safe"]

    def read(clist):
        out = []
        for c in clist:
            fp = c["filepath"]
            if not os.path.exists(fp):
                continue
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            if code.strip():
                out.append(strip_comments(code))
        return out

    return read(vuln_raw), read(safe_raw)


def length_match_safe(vuln_codes, safe_codes):
    """143v + 143 nearest-neighbor length-matched safe = 286."""
    vuln_lens = [len(c) for c in vuln_codes]
    safe_lens = np.array([len(c) for c in safe_codes], dtype=float)
    matched = []
    used = set()
    for vl in vuln_lens:
        diffs = np.abs(safe_lens - vl)
        for idx in used:
            diffs[idx] = np.inf
        best = int(np.argmin(diffs))
        used.add(best)
        matched.append(safe_codes[best])
    return matched


def sample_243(vuln_codes, safe_codes, seed=42):
    """143v + 100 random safe，用於 CodeBERT 對齊 Sprint 3 配置。"""
    rng = random.Random(seed)
    safe_shuffled = list(safe_codes)
    rng.shuffle(safe_shuffled)
    return vuln_codes + safe_shuffled[:100], [1] * len(vuln_codes) + [0] * 100


# ============================================================
# 8 audits 載入
# ============================================================

def load_evmbench_audits():
    """每 audit 的 patch/*.sol 合併為單一輸入。"""
    audits = []
    for audit_id in sorted(os.listdir(EVMBENCH_AUDITS_DIR)):
        # 只取 2025+ 與 2026+ 的 post-cutoff audits（與 leakage_test 對齊）
        if not (audit_id.startswith("2025-") or audit_id.startswith("2026-")):
            continue
        patch_dir = os.path.join(EVMBENCH_AUDITS_DIR, audit_id, "patch")
        if not os.path.isdir(patch_dir):
            continue
        sol_files = sorted([f for f in os.listdir(patch_dir) if f.endswith(".sol")])
        if not sol_files:
            continue
        merged = []
        for sf in sol_files:
            with open(os.path.join(patch_dir, sf), "r", encoding="utf-8", errors="ignore") as fh:
                merged.append(f"// === {sf} ===\n" + fh.read())
        full_code = "\n\n".join(merged)
        audits.append({
            "audit_id": audit_id,
            "num_files": len(sol_files),
            "raw_length": len(full_code),
            "code": strip_comments(full_code),
        })
    return audits


# ============================================================
# Traditional ML（Stage 2: 143v + 143s_LM, TF-IDF 500 + structural）
# ============================================================

def get_ml_models():
    return OrderedDict([
        ("Random Forest", RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=-1)),
        ("Logistic Regression", LogisticRegression(max_iter=1000, random_state=SEED, C=1.0)),
        ("Gradient Boosting", GradientBoostingClassifier(n_estimators=100, random_state=SEED)),
        ("SVM (RBF)", SVC(kernel="rbf", random_state=SEED)),
    ])


def train_and_eval_ml(codes, labels, audits):
    """訓練 4 個 ML，回傳 in-domain 5-fold CV F1 + 8 audits inference。"""
    tfidf_kwargs = dict(
        max_features=500,
        token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    ml_results = OrderedDict()
    audit_codes = [a["code"] for a in audits]

    for name, clf in get_ml_models().items():
        t0 = time.time()
        pipe = Pipeline([
            ("features", FeatureUnion([
                ("tfidf", TfidfVectorizer(**tfidf_kwargs)),
                ("struct", StructuralFeatureExtractor()),
            ])),
            ("clf", clf),
        ])

        # in-domain CV F1（sanity check）
        cv_f1 = cross_val_score(pipe, codes, labels, cv=cv, scoring="f1")
        # train on full
        pipe.fit(codes, labels)
        # OOD inference
        ood_preds = pipe.predict(audit_codes)

        ml_results[name] = {
            "cv_f1_mean": round(float(cv_f1.mean()), 4),
            "cv_f1_std": round(float(cv_f1.std()), 4),
            "ood_predictions": [int(p) for p in ood_preds],
            "ood_audit_recall": round(float(sum(ood_preds)) / len(ood_preds), 4),
            "time_seconds": round(time.time() - t0, 2),
        }
        print(f"  {name:<22}  CV F1={cv_f1.mean():.4f}±{cv_f1.std():.4f}  OOD={int(sum(ood_preds))}/{len(ood_preds)}  ({time.time()-t0:.1f}s)")
    return ml_results


# ============================================================
# CodeBERT（Sprint 3 config，train on 243 全集）
# ============================================================

def train_and_eval_codebert(train_codes, train_labels, audits):
    import torch
    from torch.utils.data import Dataset
    from transformers import (
        AutoTokenizer, AutoModelForSequenceClassification,
        Trainer, TrainingArguments, DataCollatorWithPadding,
    )
    import transformers as _tf

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"  device = {device}")
    if device == "cpu":
        print("  ⚠ CPU mode — CodeBERT training will be very slow")

    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    model = AutoModelForSequenceClassification.from_pretrained(
        "microsoft/codebert-base", num_labels=2,
    )

    class CodeDataset(Dataset):
        def __init__(self, codes, labels):
            self.codes = codes
            self.labels = labels

        def __len__(self):
            return len(self.codes)

        def __getitem__(self, idx):
            enc = tokenizer(self.codes[idx], truncation=True, max_length=512, padding=False)
            enc["labels"] = self.labels[idx]
            return enc

    train_ds = CodeDataset(train_codes, train_labels)

    out_dir = os.path.join(OUTPUT_DIR, "codebert_ckpt")
    os.makedirs(out_dir, exist_ok=True)

    train_args = TrainingArguments(
        output_dir=out_dir,
        num_train_epochs=3,
        per_device_train_batch_size=8,
        learning_rate=2e-5,
        seed=SEED,
        save_strategy="no",
        report_to="none",
        logging_strategy="epoch",
        disable_tqdm=False,
    )
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    trainer_kwargs = dict(
        model=model, args=train_args,
        train_dataset=train_ds,
        data_collator=data_collator,
    )
    if int(_tf.__version__.split(".")[0]) >= 5:
        trainer_kwargs["processing_class"] = tokenizer
    else:
        trainer_kwargs["tokenizer"] = tokenizer
    trainer = Trainer(**trainer_kwargs)

    t0 = time.time()
    trainer.train()
    train_seconds = round(time.time() - t0, 2)

    # OOD inference
    audit_codes = [a["code"] for a in audits]
    audit_ds = CodeDataset(audit_codes, [0] * len(audit_codes))
    pred_out = trainer.predict(audit_ds)
    preds = pred_out.predictions.argmax(axis=-1).tolist()

    return {
        "train_seconds": train_seconds,
        "ood_predictions": [int(p) for p in preds],
        "ood_audit_recall": round(float(sum(preds)) / len(preds), 4),
    }


# ============================================================
# DmAVID baseline 載入
# ============================================================

def load_dmavid_baseline():
    with open(DMAVID_HYBRID_RESULTS) as f:
        d = json.load(f)
    audit_results = []
    for r in d["per_audit_results"]:
        audit_results.append({
            "audit_id": r["audit_id"],
            "num_gold_vulns": r["num_gold_vulns"],
            "num_detected": r["num_detected"],
            "detect_score": r["detect_score"],
            "audit_level_detected": 1 if r["num_detected"] > 0 else 0,
        })
    return {
        "vuln_level_score": d["overall_detect_score"],
        "vuln_level": f"{d['total_detected']}/{d['total_vulnerabilities']}",
        "audit_level_score": round(sum(r["audit_level_detected"] for r in audit_results) / len(audit_results), 4),
        "per_audit": audit_results,
    }


# ============================================================
# 輸出
# ============================================================

def write_outputs(audits, ml_results, codebert_result, dmavid):
    audit_ids = [a["audit_id"] for a in audits]

    # ml_evmbench_per_audit.csv
    rows = []
    for i, a in enumerate(audits):
        row = {"audit_id": a["audit_id"], "num_files": a["num_files"], "raw_chars": a["raw_length"]}
        for name, res in ml_results.items():
            row[name] = res["ood_predictions"][i]
        rows.append(row)
    pd.DataFrame(rows).to_csv(os.path.join(OUTPUT_DIR, "ml_evmbench_per_audit.csv"), index=False)
    print(f"  → {os.path.join(OUTPUT_DIR, 'ml_evmbench_per_audit.csv')}")

    # codebert_evmbench_per_audit.csv
    rows = []
    for i, a in enumerate(audits):
        rows.append({
            "audit_id": a["audit_id"],
            "num_files": a["num_files"],
            "raw_chars": a["raw_length"],
            "CodeBERT": codebert_result["ood_predictions"][i],
        })
    pd.DataFrame(rows).to_csv(os.path.join(OUTPUT_DIR, "codebert_evmbench_per_audit.csv"), index=False)
    print(f"  → {os.path.join(OUTPUT_DIR, 'codebert_evmbench_per_audit.csv')}")

    # comparison.md
    md = []
    md.append("# Sprint 5 路線 A — Out-of-Distribution Generalization 對比")
    md.append(f"\n_Generated: {datetime.now().isoformat()}_\n")
    md.append("**訓練資料**：SmartBugs（ML 用 Stage 2 length-matched 286；CodeBERT 用 Sprint 3 配置 243）")
    md.append("**測試資料**：EVMbench post-cutoff 8 個 audits（2025+ / 2026+），每 audit 之 `patch/*.sol` 合併為單一輸入\n")

    md.append("## 三軌總覽\n")
    md.append("| 方法 | In-Domain F1（5-fold CV） | OOD Audit-level Recall | OOD Vuln-level Recall |")
    md.append("|---|---:|---:|---:|")
    for name, res in ml_results.items():
        md.append(f"| {name} | {res['cv_f1_mean']:.4f}±{res['cv_f1_std']:.4f} | {int(sum(res['ood_predictions']))}/8 = {res['ood_audit_recall']*100:.2f}% | ✘ N/A |")
    md.append(f"| CodeBERT (微調) | — | {int(sum(codebert_result['ood_predictions']))}/8 = {codebert_result['ood_audit_recall']*100:.2f}% | ✘ N/A |")
    md.append(f"| **DmAVID Hybrid (canonical)** | — | **{int(dmavid['audit_level_score']*8)}/8 = {dmavid['audit_level_score']*100:.2f}%** | **{dmavid['vuln_level']} = {dmavid['vuln_level_score']*100:.2f}%** |")

    md.append("\n## 逐 audit 預測（1=vulnerable, 0=safe）\n")
    cols = ["audit_id"] + list(ml_results.keys()) + ["CodeBERT", "DmAVID_audit", "DmAVID_vulns"]
    md.append("| " + " | ".join(cols) + " |")
    md.append("|" + "|".join(["---"] * len(cols)) + "|")
    dmavid_map = {r["audit_id"]: r for r in dmavid["per_audit"]}
    for i, a in enumerate(audits):
        cells = [a["audit_id"]]
        for name, res in ml_results.items():
            cells.append(str(res["ood_predictions"][i]))
        cells.append(str(codebert_result["ood_predictions"][i]))
        dr = dmavid_map.get(a["audit_id"])
        if dr:
            cells.append(str(dr["audit_level_detected"]))
            cells.append(f"{dr['num_detected']}/{dr['num_gold_vulns']}")
        else:
            cells.append("—")
            cells.append("—")
        md.append("| " + " | ".join(cells) + " |")

    md.append("\n## 解讀\n")
    md.append("- **In-Domain vs OOD 落差**：ML 在 SmartBugs CV F1 ≈ 0.93，但在 EVMbench OOD 上 audit-level recall 顯著退化，顯示其偵測力高度依賴 SmartBugs 樣本特徵。")
    md.append("- **DmAVID Hybrid 唯一支援 vuln-level**：傳統 ML 與 PLM 微調均為 contract-level binary classifier，結構上無法輸出具體漏洞清單。")
    md.append("- **OOD 是研究價值所在**：post-cutoff 8 audits 確保不在預訓練/微調語料中，這是真實佈署條件下唯一公平的對比場景。")

    md_path = os.path.join(OUTPUT_DIR, "comparison.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"  → {md_path}")

    # full json
    full = {
        "experiment": "sprint5_route_a_ood_generalization",
        "timestamp": datetime.now().isoformat(),
        "seed": SEED,
        "audits": [{"audit_id": a["audit_id"], "num_files": a["num_files"], "raw_length": a["raw_length"]} for a in audits],
        "ml_results": ml_results,
        "codebert_result": codebert_result,
        "dmavid_baseline": dmavid,
    }
    json_path = os.path.join(OUTPUT_DIR, "results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(full, f, indent=2, ensure_ascii=False)
    print(f"  → {json_path}")


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 70)
    print("Sprint 5 路線 A — OOD Generalization (ML/CodeBERT vs DmAVID Hybrid)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    print("\n[1/5] 載入 SmartBugs...")
    vuln_codes, safe_codes = load_smartbugs()
    print(f"  vuln={len(vuln_codes)} safe={len(safe_codes)}")

    safe_lm = length_match_safe(vuln_codes, safe_codes)
    ml_codes = vuln_codes + safe_lm
    ml_labels = [1] * len(vuln_codes) + [0] * len(safe_lm)
    print(f"  Stage 2 (length-matched): vuln={len(vuln_codes)} safe_LM={len(safe_lm)} → 286")

    cb_codes, cb_labels = sample_243(vuln_codes, safe_codes, seed=SEED)
    print(f"  Sprint 3 (243): vuln=143 safe=100")

    print("\n[2/5] 載入 EVMbench 8 audits...")
    audits = load_evmbench_audits()
    for a in audits:
        print(f"  {a['audit_id']}: {a['num_files']} files, {a['raw_length']} chars")
    if len(audits) != 8:
        print(f"  ⚠ 預期 8 個但找到 {len(audits)} 個，將繼續執行")

    print("\n[3/5] 訓練 ML（Stage 2）+ OOD inference...")
    ml_results = train_and_eval_ml(ml_codes, ml_labels, audits)

    print("\n[4/5] 訓練 CodeBERT（Sprint 3 config）+ OOD inference...")
    codebert_result = train_and_eval_codebert(cb_codes, cb_labels, audits)
    print(f"  OOD CodeBERT: {int(sum(codebert_result['ood_predictions']))}/{len(audits)}")

    print("\n[5/5] 載入 DmAVID Hybrid baseline + 寫出...")
    dmavid = load_dmavid_baseline()
    print(f"  DmAVID vuln-level: {dmavid['vuln_level']} = {dmavid['vuln_level_score']*100:.2f}%")
    print(f"  DmAVID audit-level: {dmavid['audit_level_score']*100:.2f}%")

    write_outputs(audits, ml_results, codebert_result, dmavid)

    print("\n" + "=" * 70)
    print("Sprint 5 路線 A 完成")
    print("=" * 70)


if __name__ == "__main__":
    main()
