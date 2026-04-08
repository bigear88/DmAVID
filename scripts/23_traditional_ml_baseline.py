#!/usr/bin/env python3
"""
Step 3a: Traditional ML Baselines for Smart Contract Vulnerability Detection.
FIXED VERSION — corrects data leakage issues:
  1. TF-IDF is now inside a Pipeline (fitted only on train folds)
  2. Proper 70/30 train/test split
  3. No more train=test evaluation
  4. Reports both CV (on train) and held-out test F1
"""
import json, os, sys, re, time, warnings
import numpy as np
from collections import Counter
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split, StratifiedKFold
from sklearn.pipeline import Pipeline, FeatureUnion
from scipy.sparse import hstack, csr_matrix
import random

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "traditional_ml", "ml_baseline_results_fixed.json")

# ============================================================
# Feature Extraction
# ============================================================

def extract_structural_features(code):
    """Extract structural features from Solidity source code."""
    features = {}
    lines = code.split("\n")
    features["total_lines"] = len(lines)
    features["code_length"] = len(code)
    features["num_functions"] = len(re.findall(r"\bfunction\b", code))
    features["num_modifiers"] = len(re.findall(r"\bmodifier\b", code))
    features["num_events"] = len(re.findall(r"\bevent\b", code))
    features["num_mappings"] = len(re.findall(r"\bmapping\b", code))
    features["num_requires"] = len(re.findall(r"\brequire\b", code))
    features["num_asserts"] = len(re.findall(r"\bassert\b", code))
    features["num_reverts"] = len(re.findall(r"\brevert\b", code))
    features["num_external_calls"] = len(re.findall(r"\.call\b|\.send\b|\.transfer\b|\.delegatecall\b", code))
    features["num_msg_value"] = len(re.findall(r"msg\.value", code))
    features["num_msg_sender"] = len(re.findall(r"msg\.sender", code))
    features["num_block_timestamp"] = len(re.findall(r"block\.timestamp|now\b", code))
    features["num_selfdestruct"] = len(re.findall(r"selfdestruct|suicide", code))
    features["has_payable"] = 1 if "payable" in code else 0
    features["has_onlyowner"] = 1 if re.search(r"onlyOwner|only_owner", code, re.IGNORECASE) else 0
    features["has_reentrancy_guard"] = 1 if re.search(r"nonReentrant|ReentrancyGuard|mutex", code, re.IGNORECASE) else 0
    features["has_safemath"] = 1 if "SafeMath" in code else 0
    ver_match = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    features["solidity_major_version"] = int(ver_match.group(1).split(".")[1]) if ver_match else 8
    features["is_pre_08"] = 1 if features["solidity_major_version"] < 8 else 0
    return features


class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """Sklearn-compatible transformer for structural features."""
    def __init__(self):
        self.feature_names_ = None

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


def load_dataset():
    """Load dataset and return raw codes + labels."""
    with open(DATASET_FILE) as f:
        ds = json.load(f)

    contracts = ds["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]

    print(f"Dataset: {len(vuln)} vulnerable + {min(100, len(safe))} safe = {len(sample)}")

    codes = []
    labels = []

    for c in sample:
        fp = c["filepath"]
        if not os.path.exists(fp):
            continue
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        if not code.strip():
            continue
        codes.append(code)
        labels.append(1 if c["label"] == "vulnerable" else 0)

    print(f"Loaded: {len(codes)} contracts ({sum(labels)} vuln, {len(labels)-sum(labels)} safe)")
    return codes, labels


# ============================================================
# Main — FIXED version
# ============================================================
def main():
    print("=" * 60)
    print("Traditional ML Baselines — FIXED (no data leakage)")
    print("  - TF-IDF inside Pipeline (fitted only on train folds)")
    print("  - 70/30 stratified train/test split")
    print("  - CV on train set only, final score on held-out test")
    print("=" * 60)

    codes, labels = load_dataset()
    y = np.array(labels)

    # ============================================================
    # PROPER 70/30 SPLIT
    # ============================================================
    codes_train, codes_test, y_train, y_test = train_test_split(
        codes, y, test_size=0.30, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(codes_train)} ({sum(y_train)} vuln, {len(y_train)-sum(y_train)} safe)")
    print(f"Test:  {len(codes_test)} ({sum(y_test)} vuln, {len(y_test)-sum(y_test)} safe)")

    # ============================================================
    # Build Pipeline: TF-IDF + Structural → Classifier
    # TF-IDF is INSIDE the pipeline so it only sees train data
    # ============================================================
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42, C=1.0),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "SVM (RBF)": SVC(kernel="rbf", random_state=42, probability=True),
    }

    results = {}

    for name, clf in models.items():
        print(f"\n--- {name} ---")
        t0 = time.time()

        # Pipeline ensures TF-IDF is fit only on training folds
        pipe = Pipeline([
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

        # 5-fold CV on TRAIN SET ONLY
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_f1 = cross_val_score(pipe, codes_train, y_train, cv=cv, scoring="f1")
        cv_prec = cross_val_score(pipe, codes_train, y_train, cv=cv, scoring="precision")
        cv_rec = cross_val_score(pipe, codes_train, y_train, cv=cv, scoring="recall")

        # Train on full train set, evaluate on held-out TEST set
        pipe.fit(codes_train, y_train)
        y_pred_test = pipe.predict(codes_test)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
        test_f1 = f1_score(y_test, y_pred_test)
        test_prec = precision_score(y_test, y_pred_test)
        test_rec = recall_score(y_test, y_pred_test)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        elapsed = time.time() - t0

        result = {
            "cv_f1_mean": round(float(cv_f1.mean()), 4),
            "cv_f1_std": round(float(cv_f1.std()), 4),
            "cv_precision_mean": round(float(cv_prec.mean()), 4),
            "cv_recall_mean": round(float(cv_rec.mean()), 4),
            "test_f1": round(float(test_f1), 4),
            "test_precision": round(float(test_prec), 4),
            "test_recall": round(float(test_rec), 4),
            "test_fpr": round(float(fpr), 4),
            "test_tp": int(tp), "test_fn": int(fn),
            "test_fp": int(fp), "test_tn": int(tn),
            "time_seconds": round(elapsed, 2),
        }
        results[name] = result

        print(f"  CV F1 (train):  {cv_f1.mean():.4f} (+/- {cv_f1.std():.4f})")
        print(f"  CV Precision:   {cv_prec.mean():.4f}")
        print(f"  CV Recall:      {cv_rec.mean():.4f}")
        print(f"  Test F1:        {test_f1:.4f}")
        print(f"  Test Precision: {test_prec:.4f}")
        print(f"  Test Recall:    {test_rec:.4f}")
        print(f"  Test: TP={tp} FN={fn} FP={fp} TN={tn} FPR={fpr:.4f}")
        print(f"  Time: {elapsed:.2f}s")

        # Feature importance for tree-based models
        if hasattr(pipe.named_steps['clf'], "feature_importances_"):
            importances = pipe.named_steps['clf'].feature_importances_
            feat_union = pipe.named_steps['features']
            tfidf_n = len(feat_union.transformer_list[0][1].vocabulary_)
            struct_names = feat_union.transformer_list[1][1].feature_names_
            struct_imp = [(struct_names[i], importances[tfidf_n + i]) for i in range(len(struct_names))]
            struct_imp.sort(key=lambda x: x[1], reverse=True)
            top5 = struct_imp[:5]
            result["top_structural_features"] = [{"name": n, "importance": round(float(v), 4)} for n, v in top5]
            print(f"  Top structural: {', '.join(f'{n}={v:.3f}' for n, v in top5)}")

    # Summary comparison
    print("\n" + "=" * 60)
    print("SUMMARY: Traditional ML — FIXED (no data leakage)")
    print("=" * 60)
    print(f"\n{'Method':<25} {'CV F1':>8} {'Test F1':>9} {'Test P':>8} {'Test R':>8} {'FPR':>6}")
    print("-" * 70)
    for name, r in results.items():
        print(f"{name:<25} {r['cv_f1_mean']:>8.4f} {r['test_f1']:>9.4f} "
              f"{r['test_precision']:>8.4f} {r['test_recall']:>8.4f} {r['test_fpr']:>6.4f}")

    # DmAVID baselines for comparison (from experiments/*.json)
    print(f"\n{'--- DmAVID Pipeline ---':<25}")
    print(f"{'Slither':<25} {'—':>8} {'0.7459':>9} {'0.6164':>8} {'0.9441':>8}")
    print(f"{'LLM+RAG':<25} {'—':>8} {'0.8917':>9} {'0.8189':>8} {'0.9790':>8}")

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    output = {
        "experiment": "traditional_ml_baselines_FIXED",
        "fix_description": [
            "TF-IDF inside sklearn Pipeline (no leakage across CV folds)",
            "70/30 stratified train/test split (test set never seen during training/CV)",
            "Removed train=test evaluation",
        ],
        "dataset": f"SmartBugs {len(codes)} contracts",
        "train_size": len(codes_train),
        "test_size": len(codes_test),
        "features": "TF-IDF (500) + structural (19) via Pipeline",
        "cross_validation": "5-fold StratifiedKFold on train only",
        "results": results,
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
