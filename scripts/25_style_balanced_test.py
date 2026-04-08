#!/usr/bin/env python3
"""
Phase 3: Style-Balanced Experiment — FIXED version.
Proves ML learned style, not vulnerabilities.

FIXES:
  1. TF-IDF inside Pipeline (no cross-fold leakage)
  2. 70/30 train/test split
  3. Reports held-out test F1
"""
import json, os, sys, re, random, warnings, time
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, confusion_matrix
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "style_balanced", "balanced_results_fixed.json")


def extract_features(code):
    features = {}
    features["total_lines"] = len(code.split("\n"))
    features["code_length"] = len(code)
    features["num_functions"] = len(re.findall(r"\bfunction\b", code))
    features["num_modifiers"] = len(re.findall(r"\bmodifier\b", code))
    features["num_events"] = len(re.findall(r"\bevent\b", code))
    features["num_mappings"] = len(re.findall(r"\bmapping\b", code))
    features["num_requires"] = len(re.findall(r"\brequire\b", code))
    features["num_external_calls"] = len(re.findall(r"\.call\b|\.send\b|\.transfer\b", code))
    features["num_msg_value"] = len(re.findall(r"msg\.value", code))
    features["num_msg_sender"] = len(re.findall(r"msg\.sender", code))
    features["has_payable"] = 1 if "payable" in code else 0
    features["has_onlyowner"] = 1 if re.search(r"onlyOwner", code, re.IGNORECASE) else 0
    features["has_reentrancy_guard"] = 1 if "nonReentrant" in code else 0
    features["has_safemath"] = 1 if "SafeMath" in code else 0
    ver = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    features["solidity_ver"] = int(ver.group(1).split(".")[1]) if ver else 8
    features["is_pre_08"] = 1 if features["solidity_ver"] < 8 else 0
    return features


class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.feature_names_ = None

    def fit(self, X, y=None):
        self.feature_names_ = sorted(extract_features(X[0]).keys())
        return self

    def transform(self, X, y=None):
        return np.array([[extract_features(c)[k] for k in self.feature_names_] for c in X])


def clean_code(code):
    code = re.sub(r"@vulnerable_at_lines?:.*", "", code)
    code = re.sub(r"@source:.*", "", code)
    code = re.sub(r"@author:.*", "", code)
    code = re.sub(r"<yes>.*<report>.*", "", code)
    code = re.sub(r"// SPDX-License.*", "", code)
    return code


def build_pipeline(clf):
    return Pipeline([
        ('features', FeatureUnion([
            ('tfidf', TfidfVectorizer(
                max_features=500,
                token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
                ngram_range=(1, 2),
                sublinear_tf=True,
            )),
            ('struct', StructuralFeatureExtractor()),
        ])),
        ('clf', clf),
    ])


def main():
    print("=" * 60)
    print("Phase 3: Style-Balanced ML Experiment — FIXED")
    print("  - TF-IDF inside Pipeline")
    print("  - 70/30 train/test split")
    print("=" * 60)

    with open(DATASET_FILE) as f:
        ds = json.load(f)

    # ============================================================
    # Experiment 1: Same-source balanced (Curated only + short Wild)
    # ============================================================
    print("\n--- Exp 1: SmartBugs Curated + Short Wild (style-balanced) ---")

    curated = [c for c in ds["contracts"] if c.get("source") == "smartbugs_curated"]
    wild = [c for c in ds["contracts"] if c.get("source") == "smartbugs_wild"]

    codes_1, labels_1 = [], []
    for c in curated:
        fp = c["filepath"]
        if not os.path.exists(fp):
            continue
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            code = clean_code(f.read())
        if not code.strip():
            continue
        codes_1.append(code)
        labels_1.append(1)

    short_wild = [c for c in wild if c["lines"] < 200]
    random.shuffle(short_wild)
    for c in short_wild[:min(len(curated), len(short_wild))]:
        fp = c["filepath"]
        if not os.path.exists(fp):
            continue
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            code = clean_code(f.read())
        if not code.strip():
            continue
        codes_1.append(code)
        labels_1.append(0)

    y1 = np.array(labels_1)
    print(f"Balanced set: {sum(y1)} vuln + {len(y1)-sum(y1)} safe = {len(y1)}")

    # 70/30 split
    codes_1_train, codes_1_test, y1_train, y1_test = train_test_split(
        codes_1, y1, test_size=0.30, random_state=42, stratify=y1)
    print(f"  Train: {len(codes_1_train)}, Test: {len(codes_1_test)}")

    # ============================================================
    # Experiment 2: Original SmartBugs (style-biased)
    # ============================================================
    print("\n--- Exp 2: Original SmartBugs (Curated vuln + Wild safe, biased) ---")
    vuln_all = [c for c in ds["contracts"] if c["label"] == "vulnerable"]
    safe_all = [c for c in ds["contracts"] if c["label"] == "safe"]
    random.shuffle(safe_all)
    sample2 = vuln_all + safe_all[:100]

    codes_2, labels_2 = [], []
    for c in sample2:
        fp = c["filepath"]
        if not os.path.exists(fp):
            continue
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            code = clean_code(f.read())
        if not code.strip():
            continue
        codes_2.append(code)
        labels_2.append(1 if c["label"] == "vulnerable" else 0)

    y2 = np.array(labels_2)

    codes_2_train, codes_2_test, y2_train, y2_test = train_test_split(
        codes_2, y2, test_size=0.30, random_state=42, stratify=y2)
    print(f"Original set: {sum(y2)} vuln + {len(y2)-sum(y2)} safe = {len(y2)}")
    print(f"  Train: {len(codes_2_train)}, Test: {len(codes_2_test)}")

    # Run models
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    }

    results = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    for name, model_cls in models.items():
        # Exp 1: balanced — Pipeline on train, test on held-out
        pipe1 = build_pipeline(type(model_cls)(**model_cls.get_params()))
        cv_f1_bal = cross_val_score(pipe1, codes_1_train, y1_train, cv=cv, scoring="f1")
        pipe1.fit(codes_1_train, y1_train)
        test_f1_bal = f1_score(y1_test, pipe1.predict(codes_1_test))

        # Exp 2: original (biased) — Pipeline on train, test on held-out
        pipe2 = build_pipeline(type(model_cls)(**model_cls.get_params()))
        cv_f1_orig = cross_val_score(pipe2, codes_2_train, y2_train, cv=cv, scoring="f1")
        pipe2.fit(codes_2_train, y2_train)
        test_f1_orig = f1_score(y2_test, pipe2.predict(codes_2_test))

        drop_cv = cv_f1_bal.mean() - cv_f1_orig.mean()
        drop_test = test_f1_bal - test_f1_orig

        results[name] = {
            "balanced_cv_f1": round(float(cv_f1_bal.mean()), 4),
            "balanced_test_f1": round(float(test_f1_bal), 4),
            "original_cv_f1": round(float(cv_f1_orig.mean()), 4),
            "original_test_f1": round(float(test_f1_orig), 4),
            "drop_cv": round(float(drop_cv), 4),
            "drop_test": round(float(drop_test), 4),
        }
        print(f"\n  {name}:")
        print(f"    Original  — CV F1={cv_f1_orig.mean():.4f}, Test F1={test_f1_orig:.4f}")
        print(f"    Balanced  — CV F1={cv_f1_bal.mean():.4f}, Test F1={test_f1_bal:.4f}")
        print(f"    Drop (test): {drop_test:+.4f}")

    # Summary
    print("\n" + "=" * 60)
    print("STYLE LEAKAGE PROOF — FIXED (Pipeline + 70/30 split)")
    print("=" * 60)
    print(f"\n{'Method':<25} {'Orig Test F1':>13} {'Bal Test F1':>13} {'Drop':>8}")
    print("-" * 63)
    for name, r in results.items():
        print(f"{name:<25} {r['original_test_f1']:>13.4f} {r['balanced_test_f1']:>13.4f} {r['drop_test']:>+8.4f}")

    for name, r in results.items():
        if r["drop_test"] < -0.10:
            print(f"\n  ⚠️  {name}: Test F1 dropped {abs(r['drop_test'])*100:.1f}% → CONFIRMS style leakage")
        elif r["drop_test"] < -0.05:
            print(f"\n  ⚠️  {name}: Test F1 dropped {abs(r['drop_test'])*100:.1f}% → Partial style leakage")
        else:
            print(f"\n  ✅ {name}: Test F1 stable → learned real patterns (or residual style)")

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "experiment": "style_balanced_test_FIXED",
            "fix_description": "TF-IDF inside Pipeline + 70/30 split",
            "balanced_set": f"{sum(y1)} vuln + {len(y1)-sum(y1)} safe",
            "original_set": f"{sum(y2)} vuln + {len(y2)-sum(y2)} safe",
            "results": results,
        }, f, indent=2)
    print(f"\nSaved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
