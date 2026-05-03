#!/usr/bin/env python3
"""
Fine-tune CodeBERT on SmartBugs (matching 34_codebert_baseline.py setup)
then run inference on EVMbench 10 audit contracts to populate
exi_deep_results.json codebert.attack_path_coverage with a real measurement.

Reuses 34_codebert_baseline.py functions (strip_comments, load_sample)
to guarantee the fine-tune is identical to the canonical CodeBERT baseline.
"""
import os
import re
import sys
import json
import time
import random
import yaml
from datetime import datetime
from pathlib import Path

import numpy as np
import torch
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    Trainer, TrainingArguments, DataCollatorWithPadding,
)
from datasets import Dataset
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from importlib import import_module
cb = import_module("34_codebert_baseline")

OUT_DIR = ROOT / "experiments/codebert_baseline"
OUT_FILE = OUT_DIR / "codebert_evmbench_results.json"
EXI_FILE = ROOT / "experiments/explainability/exi_deep_results.json"

SEED = 42
MAX_LEN = 512
EPOCHS = 3
BATCH = 8
LR = 2e-5
MODEL_NAME = "microsoft/codebert-base"

# 與 enhanced_results.json 一致的 10 個 audit
AUDITS = [
    "2024-01-curves", "2024-03-taiko", "2024-05-olas", "2024-07-basin",
    "2024-01-renft", "2024-06-size", "2024-08-phi", "2024-12-secondswap",
    "2025-04-forte", "2026-01-tempo-stablecoin-dex",
]

EXCLUDE_PATH_PARTS = {"node_modules", "lib", "test", "Test", "tests",
                      "mocks", "mock", "discord-export", ".git"}


def find_sol_files(audit_id):
    """搜尋 audit 之 contract .sol files，過濾 lib/test/node_modules"""
    repo_root = ROOT / "data/evmbench_repos" / audit_id
    if not repo_root.is_dir():
        return []
    found = []
    for p in repo_root.rglob("*.sol"):
        parts = set(p.relative_to(repo_root).parts)
        if parts & EXCLUDE_PATH_PARTS:
            continue
        # require under "contracts" or "src" or top-level repo subdir
        rel = p.relative_to(repo_root)
        first = rel.parts[0] if rel.parts else ""
        if first in ("contracts", "src") or "contracts" in rel.parts or "src" in rel.parts:
            found.append(p)
    return sorted(set(found))


def parse_gold_findings(audit_id):
    """從 config.yaml 解析每個 vulnerability 之 patch_path_mapping → contract path mapping"""
    cfg_path = ROOT / "data/evmbench/audits" / audit_id / "config.yaml"
    if not cfg_path.is_file():
        return []
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    out = []
    for v in cfg.get("vulnerabilities", []):
        ppm = v.get("patch_path_mapping") or {}
        target_paths = list(ppm.values())  # e.g. ["contracts/Curves.sol"]
        out.append({"id": v.get("id"), "title": v.get("title"),
                    "target_paths": target_paths})
    return out


def main():
    print("=" * 70)
    print("CodeBERT × EVMbench inference  (Sprint patch v50)")
    print(f"Model: {MODEL_NAME}, max_len={MAX_LEN}, epochs={EPOCHS}, seed={SEED}")
    print("=" * 70)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device} ({torch.cuda.get_device_name(0) if device.type=='cuda' else 'CPU'})")

    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    if device.type == "cuda": torch.cuda.manual_seed_all(SEED)

    # 1. Load SmartBugs (與 34 baseline 完全相同)
    print("\n[1/4] Load SmartBugs sample (strip_leaky_comments=True)...")
    sample = cb.load_sample(strip_leaky_comments=True)
    train_data, test_data = train_test_split(
        sample, test_size=0.2, random_state=SEED,
        stratify=[c["label"] for c in sample],
    )
    print(f"  train={len(train_data)}, test={len(test_data)}")

    # 2. Fine-tune
    print(f"\n[2/4] Fine-tune {MODEL_NAME} on {len(train_data)} contracts...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    def tok_fn(b):
        return tokenizer(b["code"], truncation=True, padding=False, max_length=MAX_LEN)

    train_ds = Dataset.from_list([{"code": c["code"], "label": c["label"]} for c in train_data]).map(tok_fn, batched=True, remove_columns=["code"])
    test_ds = Dataset.from_list([{"code": c["code"], "label": c["label"]} for c in test_data]).map(tok_fn, batched=True, remove_columns=["code"])

    args = TrainingArguments(
        output_dir=str(OUT_DIR / "model_checkpoints_evmbench_run"),
        num_train_epochs=EPOCHS, per_device_train_batch_size=BATCH,
        per_device_eval_batch_size=BATCH, learning_rate=LR,
        weight_decay=0.01, warmup_ratio=0.1, logging_steps=20,
        save_strategy="no", eval_strategy="no",
        seed=SEED, report_to=[], fp16=device.type == "cuda",
    )
    import transformers as _tf
    kwargs = {"model": model, "args": args, "train_dataset": train_ds,
              "data_collator": DataCollatorWithPadding(tokenizer=tokenizer)}
    if int(_tf.__version__.split(".")[0]) >= 5:
        kwargs["processing_class"] = tokenizer
    else:
        kwargs["tokenizer"] = tokenizer
    trainer = Trainer(**kwargs)
    t0 = time.time()
    trainer.train()
    print(f"  fine-tune done in {time.time()-t0:.1f}s")

    # Sanity-check on SmartBugs test
    pred = trainer.predict(test_ds)
    pl = np.argmax(pred.predictions, axis=1)
    tl = np.array([c["label"] for c in test_data])
    tp = int(((pl == 1) & (tl == 1)).sum())
    fp = int(((pl == 1) & (tl == 0)).sum())
    tn = int(((pl == 0) & (tl == 0)).sum())
    fn = int(((pl == 0) & (tl == 1)).sum())
    smartbugs_test_f1 = round(2*tp / (2*tp + fp + fn), 4) if (2*tp + fp + fn) else 0
    print(f"  SmartBugs test sanity: TP={tp} FP={fp} TN={tn} FN={fn} F1={smartbugs_test_f1}")

    # 3. EVMbench inference
    print("\n[3/4] EVMbench inference per audit...")
    per_audit = []
    raw_predictions = []
    total_findings = 0
    detected_findings = 0

    for aid in AUDITS:
        sols = find_sol_files(aid)
        gold = parse_gold_findings(aid)
        gold_count = len(gold)
        total_findings += gold_count

        if not sols:
            print(f"  [{aid}] no .sol found ({gold_count} gold)")
            per_audit.append({
                "audit_id": aid, "contracts_scanned": 0,
                "gold_findings": gold_count,
                "predicted_vulnerable_contracts": 0,
                "detected_findings": 0,
                "note": "no_sol_files_in_repos",
            })
            continue

        # Tokenize and predict for all contracts
        contract_codes = []
        contract_paths = []
        for p in sols:
            try:
                code = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            stripped = cb.strip_comments(code)
            contract_codes.append(stripped)
            contract_paths.append(p)

        ds = Dataset.from_list([{"code": c} for c in contract_codes]).map(tok_fn, batched=True, remove_columns=["code"])
        pred = trainer.predict(ds)
        labels_pred = np.argmax(pred.predictions, axis=1)
        # softmax prob
        probs = np.exp(pred.predictions) / np.exp(pred.predictions).sum(axis=1, keepdims=True)

        n_vuln_contracts = int(labels_pred.sum())
        # 對齊 gold findings：對每個 finding，檢查其 target_paths 對應之 contract 是否被預測 vulnerable
        finding_detected = 0
        for f in gold:
            for tp_path in f["target_paths"]:
                # tp_path 是相對於 repo 的路徑（如 "contracts/Curves.sol"）
                # 比對 contract_paths 是否有結尾匹配
                tp_norm = tp_path.replace("\\", "/").lstrip("/")
                hit = False
                for i, cp in enumerate(contract_paths):
                    rel = str(cp.relative_to(ROOT / "data/evmbench_repos" / aid)).replace("\\", "/")
                    if rel == tp_norm or rel.endswith("/" + tp_norm) or rel.endswith(tp_norm):
                        if labels_pred[i] == 1:
                            hit = True
                            break
                if hit:
                    finding_detected += 1
                    break
        detected_findings += finding_detected

        per_audit.append({
            "audit_id": aid,
            "contracts_scanned": len(contract_paths),
            "gold_findings": gold_count,
            "predicted_vulnerable_contracts": n_vuln_contracts,
            "detected_findings": finding_detected,
        })
        for i, p in enumerate(contract_paths):
            raw_predictions.append({
                "audit_id": aid,
                "contract_path": str(p.relative_to(ROOT)),
                "pred": int(labels_pred[i]),
                "prob_vulnerable": round(float(probs[i, 1]), 4),
            })
        print(f"  [{aid}] scanned={len(contract_paths)}  vuln_pred={n_vuln_contracts}  detected={finding_detected}/{gold_count}")

    detect_rate = round(detected_findings / total_findings, 4) if total_findings else 0.0

    # 4. Output JSON + update EXI
    print(f"\n[4/4] Total: {detected_findings}/{total_findings} = {detect_rate*100:.2f}%")

    out = {
        "experiment": "codebert_evmbench_inference_v50_lock",
        "model_checkpoint": MODEL_NAME + " (fine-tuned in-memory, not persisted)",
        "fine_tune_config": {
            "epochs": EPOCHS, "batch_size": BATCH, "learning_rate": LR,
            "max_seq_len": MAX_LEN, "seed": SEED,
            "strip_leaky_comments": True, "train_size": len(train_data),
            "smartbugs_test_f1_sanity": smartbugs_test_f1,
        },
        "evmbench_audits_total": len(AUDITS),
        "gold_findings_total": total_findings,
        "detect_definition": "lenient: contract-level binary prediction maps to all gold findings whose patch_path_mapping target matches that contract path",
        "detected_findings": detected_findings,
        "detect_rate": detect_rate,
        "per_audit": per_audit,
        "raw_predictions": raw_predictions,
        "computed_at": datetime.now().isoformat(),
        "data_source_commit": "DmAVID repo @ 4ea52dd (master)",
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n→ {OUT_FILE}")

    # Update EXI: codebert.attack_path 改為實測值
    exi = json.loads(EXI_FILE.read_text(encoding="utf-8"))
    if "codebert" in exi:
        cb_node = exi["codebert"]
        old_apc = cb_node.get("attack_path")
        old_exi = cb_node.get("exi")
        cb_node["attack_path"] = detect_rate
        cb_node["attack_path_note"] = (
            f"Lenient contract-level mapping on EVMbench 10 audits ({detected_findings}/{total_findings}); "
            "see experiments/codebert_baseline/codebert_evmbench_results.json"
        )
        cb_node["attack_path_source"] = "experiments/codebert_baseline/codebert_evmbench_results.json"
        cb_node["attack_path_definition"] = "lenient_contract_level"
        # 重算 EXI: 25*pc + 30*rca + 25*apc + 20*(rq/5)
        pc = cb_node.get("pattern_coverage", 0.0)
        rca = cb_node.get("root_cause", 0.0)
        rq = cb_node.get("repair_quality_avg_1to5", 0.0)
        apc = detect_rate
        new_exi = round(25*pc + 30*rca + 25*apc + 20*(rq/5), 2)
        cb_node["exi_old"] = old_exi
        cb_node["exi"] = new_exi
        print(f"\nEXI update: codebert.attack_path {old_apc} → {detect_rate}")
        print(f"            codebert.exi {old_exi} → {new_exi}")
        EXI_FILE.write_text(json.dumps(exi, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"→ {EXI_FILE}")
    else:
        print(f"  WARN: 'codebert' key not found in EXI file; raw json keys = {list(exi.keys())[:8]}")

    print("\nDone.")


if __name__ == "__main__":
    main()
