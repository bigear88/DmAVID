#!/usr/bin/env python3
"""Sprint 5 診斷：為何 RF/GB 在 OOD 給 0/8？查資料分布、特徵尺度、預測機率。"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("s5", os.path.join(os.path.dirname(__file__), "36_sprint5_route_a_evmbench_generalization.py"))
s5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(s5)

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.pipeline import Pipeline, FeatureUnion

print("[1] 載入...")
vuln_codes, safe_codes = s5.load_smartbugs()
safe_lm = s5.length_match_safe(vuln_codes, safe_codes)
train_codes = vuln_codes + safe_lm
labels = [1] * len(vuln_codes) + [0] * len(safe_lm)
audits = s5.load_evmbench_audits()

print("\n[2] 結構化特徵分布（train vs OOD audits）")
def stats(codes, name):
    feats = [s5.extract_structural_features(c) for c in codes]
    print(f"\n  {name} (n={len(codes)}):")
    for k in ["total_lines", "code_length", "num_functions", "solidity_major_version", "is_pre_08", "has_safemath"]:
        vals = [f[k] for f in feats]
        print(f"    {k:<24} median={np.median(vals):>10.1f}  mean={np.mean(vals):>10.1f}  min={min(vals):>6}  max={max(vals):>10}")

stats(vuln_codes, "Train: SmartBugs vuln (143)")
stats(safe_lm, "Train: SmartBugs safe_LM (143)")
stats([a["code"] for a in audits], "OOD: EVMbench audits (8)")

print("\n[3] 訓練 RF/GB 看預測機率（不只 hard label）")
tfidf_kwargs = dict(max_features=500, token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*", ngram_range=(1, 2), sublinear_tf=True)

for name, clf in [
    ("Random Forest", RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)),
    ("Gradient Boosting", GradientBoostingClassifier(n_estimators=100, random_state=42)),
]:
    pipe = Pipeline([
        ("features", FeatureUnion([
            ("tfidf", TfidfVectorizer(**tfidf_kwargs)),
            ("struct", s5.StructuralFeatureExtractor()),
        ])),
        ("clf", clf),
    ])
    pipe.fit(train_codes, labels)
    probs = pipe.predict_proba([a["code"] for a in audits])
    print(f"\n  {name} OOD predict_proba (P_vuln):")
    for a, p in zip(audits, probs):
        bar = "█" * int(p[1] * 30)
        print(f"    {a['audit_id']:<32} P_vuln={p[1]:.4f}  P_safe={p[0]:.4f}  {bar}")

print("\n[4] 結構化特徵的 RF importance（看哪個特徵主導決策）")
pipe_rf = Pipeline([
    ("features", FeatureUnion([
        ("tfidf", TfidfVectorizer(**tfidf_kwargs)),
        ("struct", s5.StructuralFeatureExtractor()),
    ])),
    ("clf", RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)),
])
pipe_rf.fit(train_codes, labels)
union = pipe_rf.named_steps["features"]
rf = pipe_rf.named_steps["clf"]
tfidf = union.transformer_list[0][1]
struct_ex = union.transformer_list[1][1]
n_tfidf = len(tfidf.get_feature_names_out())
struct_names = struct_ex.feature_names_
print(f"\n  TF-IDF features: {n_tfidf}, Structural: {len(struct_names)}, Total: {n_tfidf + len(struct_names)}")
imp = rf.feature_importances_
struct_imp = imp[n_tfidf:]
print(f"  TF-IDF total importance:      {imp[:n_tfidf].sum():.4f}")
print(f"  Structural total importance:  {struct_imp.sum():.4f}")
print(f"\n  Top 10 structural features:")
for fname, fimp in sorted(zip(struct_names, struct_imp), key=lambda x: -x[1])[:10]:
    print(f"    {fname:<28} {fimp:.4f}")

print("\n[5] 8 audits 在這幾個 top 特徵上的位置 vs train vuln 分布")
top_feats = [f for f, _ in sorted(zip(struct_names, struct_imp), key=lambda x: -x[1])[:5]]
train_vuln_feats = [s5.extract_structural_features(c) for c in vuln_codes]
audit_feats = [s5.extract_structural_features(a["code"]) for a in audits]
for fname in top_feats:
    train_vals = [f[fname] for f in train_vuln_feats]
    audit_vals = [f[fname] for f in audit_feats]
    print(f"\n  {fname}:")
    print(f"    Train vuln: median={np.median(train_vals):.1f}, p95={np.percentile(train_vals, 95):.1f}, max={max(train_vals)}")
    print(f"    OOD audits: {audit_vals}")
