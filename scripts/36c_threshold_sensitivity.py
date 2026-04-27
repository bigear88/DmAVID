#!/usr/bin/env python3
"""Sprint 5 路線 A 補：threshold 敏感性實驗。

預設 RF/GB 在 0/8，但 RF P_vuln 最高 0.39 距 0.5 僅 0.11。
若降閾值，是否能把 distribution-shift 的「機率被推向 safe」效應分離出 audit-level recall？
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("s5", os.path.join(os.path.dirname(__file__), "36_sprint5_route_a_evmbench_generalization.py"))
s5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(s5)

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline, FeatureUnion
from datetime import datetime

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "sprint5_route_a")

print("[1] 載入 + 訓練...")
vuln_codes, safe_codes = s5.load_smartbugs()
safe_lm = s5.length_match_safe(vuln_codes, safe_codes)
train_codes = vuln_codes + safe_lm
labels = [1] * len(vuln_codes) + [0] * len(safe_lm)
audits = s5.load_evmbench_audits()
audit_codes = [a["code"] for a in audits]

tfidf_kwargs = dict(max_features=500, token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*", ngram_range=(1, 2), sublinear_tf=True)

def make_pipe(clf):
    return Pipeline([
        ("features", FeatureUnion([
            ("tfidf", TfidfVectorizer(**tfidf_kwargs)),
            ("struct", s5.StructuralFeatureExtractor()),
        ])),
        ("clf", clf),
    ])

models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42, C=1.0),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    "SVM (RBF)": SVC(kernel="rbf", random_state=42, probability=True),
}

probas = {}
for name, clf in models.items():
    pipe = make_pipe(clf)
    pipe.fit(train_codes, labels)
    probas[name] = pipe.predict_proba(audit_codes)[:, 1]

print("\n[2] 各 threshold 下的 audit-level recall:")
thresholds = [0.5, 0.45, 0.4, 0.35, 0.3, 0.25, 0.2]
header = f"  {'Model':<22} " + "  ".join(f"τ={t:.2f}" for t in thresholds)
print(header)
print("  " + "-" * (len(header) - 2))

results = {}
for name, p in probas.items():
    row = []
    results[name] = {"probas": [round(float(x), 4) for x in p.tolist()]}
    for t in thresholds:
        n_pos = int((p >= t).sum())
        results[name][f"recall_at_{t:.2f}"] = f"{n_pos}/8 = {n_pos/8*100:.2f}%"
        row.append(f"{n_pos}/8")
    print(f"  {name:<22} " + "  ".join(f"{x:>6}" for x in row))

print("\n[3] RF/GB OOD predict_proba 排序（找出最接近 0.5 的）:")
for name in ["Random Forest", "Gradient Boosting"]:
    p = probas[name]
    order = np.argsort(-p)
    print(f"\n  {name} (sorted by P_vuln desc):")
    for idx in order:
        print(f"    {audits[idx]['audit_id']:<32} P_vuln={p[idx]:.4f}")

# 寫出 JSON
out = {
    "experiment": "sprint5_route_a_threshold_sensitivity",
    "timestamp": datetime.now().isoformat(),
    "audits": [a["audit_id"] for a in audits],
    "thresholds_tested": thresholds,
    "results": results,
    "interpretation": (
        "若 threshold 從 0.5 降到 0.3 後 RF/GB recall 顯著上升，"
        "表示 distribution shift 主要把 P_vuln 整體往 safe 方向推，"
        "非「模型完全無法區分」。但 threshold 調整需要 OOD validation set，"
        "在僅 8 vulnerable audits 無 safe 對照下，這只能作為診斷而非優化方法。"
    ),
}
out_path = os.path.join(OUTPUT_DIR, "threshold_sensitivity.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
print(f"\n寫出 → {out_path}")
