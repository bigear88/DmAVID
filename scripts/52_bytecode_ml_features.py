#!/usr/bin/env python3
"""
Sprint 8 Step 3：opcode → 3 種特徵設定

F1 baseline   : 1-gram opcode + TF-IDF
F2 SoliAudit  : 1-gram + 2-gram + 3-gram + TF-IDF
F3 enhanced   : F2 + opcode 序列長度 + control flow stats（JUMP/JUMPI/JUMPDEST 比例）

Output:
  experiments/bytecode_ml/features_F1.npz
  experiments/bytecode_ml/features_F2.npz
  experiments/bytecode_ml/features_F3.npz
  experiments/bytecode_ml/features_meta.json (每個 setting 的 shape, vocab size)
"""
import json
import numpy as np
from pathlib import Path
from datetime import datetime

from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import save_npz, hstack, csr_matrix

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "experiments/bytecode_ml"
OP_DIR = OUT_DIR / "opcodes"
COMPILE = OUT_DIR / "compile_results.json"
META = OUT_DIR / "features_meta.json"


def load_opcode_corpus():
    """回傳 (corpus_strings, labels, contract_ids)，順序對齊 compile_results"""
    d = json.loads(COMPILE.read_text(encoding="utf-8"))
    success = [c for c in d["contracts"] if c.get("compile_status") == "success"]
    rows = []
    for c in success:
        op_path = OP_DIR / f"{c['contract_id']}.txt"
        if not op_path.exists():
            continue
        ops = op_path.read_text(encoding="utf-8").strip().split("\n")
        if not ops or ops == [""]:
            continue
        rows.append({
            "contract_id": c["contract_id"],
            "label": 1 if c["label"] == "vulnerable" else 0,
            "ops": ops,
        })
    return rows


def extract_control_flow_stats(ops):
    """JUMP/JUMPI/JUMPDEST/LOG/CALL 比例 + 序列長度"""
    n = len(ops)
    c = {
        "len": n,
        "len_log1p": float(np.log1p(n)),
        "jump_ratio": ops.count("JUMP") / n if n else 0,
        "jumpi_ratio": ops.count("JUMPI") / n if n else 0,
        "jumpdest_ratio": ops.count("JUMPDEST") / n if n else 0,
        "log_ratio": ops.count("LOG") / n if n else 0,
        "call_ratio": (ops.count("CALL") + ops.count("STATICCALL") + ops.count("DELEGATECALL")) / n if n else 0,
    }
    return [c["len"], c["len_log1p"], c["jump_ratio"], c["jumpi_ratio"],
            c["jumpdest_ratio"], c["log_ratio"], c["call_ratio"]]


def main():
    print("=" * 70)
    print(f"Sprint 8 Step 3 — Build Features  ({datetime.now().isoformat()})")
    print("=" * 70)

    rows = load_opcode_corpus()
    n = len(rows)
    print(f"  contracts: {n}")
    labels = np.array([r["label"] for r in rows])
    cids = [r["contract_id"] for r in rows]
    docs = [" ".join(r["ops"]) for r in rows]

    meta = {"experiment": "sprint8_features", "timestamp": datetime.now().isoformat(),
            "n_contracts": n, "label_dist": {"vuln": int(labels.sum()), "safe": int((labels == 0).sum())},
            "settings": {}}

    # --- F1: 1-gram TF-IDF ---
    v1 = TfidfVectorizer(ngram_range=(1, 1), token_pattern=r"\S+", lowercase=False, sublinear_tf=True, min_df=2)
    X1 = v1.fit_transform(docs)
    print(f"  F1 (1-gram): {X1.shape}, vocab={len(v1.vocabulary_)}")
    meta["settings"]["F1"] = {"description": "1-gram opcode + TF-IDF",
                               "shape": list(X1.shape), "vocab_size": len(v1.vocabulary_)}
    save_npz(OUT_DIR / "features_F1.npz", X1)

    # --- F2: 1+2+3-gram ---
    v2 = TfidfVectorizer(ngram_range=(1, 3), token_pattern=r"\S+", lowercase=False,
                          sublinear_tf=True, min_df=2, max_features=10000)
    X2 = v2.fit_transform(docs)
    print(f"  F2 (1+2+3-gram): {X2.shape}, vocab={len(v2.vocabulary_)}")
    meta["settings"]["F2"] = {"description": "1+2+3-gram opcode + TF-IDF (max_features=10000)",
                               "shape": list(X2.shape), "vocab_size": len(v2.vocabulary_)}
    save_npz(OUT_DIR / "features_F2.npz", X2)

    # --- F3: F2 + control flow stats ---
    cf = np.array([extract_control_flow_stats(r["ops"]) for r in rows])
    # 簡單 z-score 正規化（避免長度 dominate）
    cf = (cf - cf.mean(axis=0)) / (cf.std(axis=0) + 1e-9)
    X3 = hstack([X2, csr_matrix(cf)])
    print(f"  F3 (F2 + control flow): {X3.shape}")
    meta["settings"]["F3"] = {"description": "F2 + opcode length + JUMP/JUMPI/JUMPDEST/LOG/CALL ratios",
                               "shape": list(X3.shape), "extra_features": 7}
    save_npz(OUT_DIR / "features_F3.npz", X3)

    # 寫 labels + ids（供 53 用）
    np.savez(OUT_DIR / "labels_and_ids.npz",
             labels=labels, contract_ids=np.array(cids, dtype=object))

    META.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n→ features_F1/F2/F3.npz + labels_and_ids.npz + features_meta.json")


if __name__ == "__main__":
    main()
