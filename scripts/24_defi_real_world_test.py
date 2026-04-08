#!/usr/bin/env python3
"""
Phase 2: Real-World DeFi Test — FIXED version.
Compares Traditional ML vs DmAVID LLM+RAG on REAL DeFi attack contracts.

FIXES:
  1. TF-IDF inside Pipeline (no cross-fold leakage)
  2. 70/30 train/test split
  3. Reports held-out test F1
  4. No LLM API calls (ML-only, to avoid cost)
"""
import json, os, sys, re, time, glob, random, warnings
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFIHACKLABS = os.path.join(BASE_DIR, "data", "DeFiHackLabs", "src", "test")
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "defi_real_world", "defi_results_fixed.json")


def extract_structural_features(code):
    features = {}
    features["total_lines"] = len(code.split("\n"))
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
    def __init__(self):
        self.feature_names_ = None

    def fit(self, X, y=None):
        self.feature_names_ = sorted(extract_structural_features(X[0]).keys())
        return self

    def transform(self, X, y=None):
        return np.array([[extract_structural_features(c)[k] for k in self.feature_names_] for c in X])


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


def load_defihacklabs(max_contracts=100):
    sol_files = sorted(glob.glob(os.path.join(DEFIHACKLABS, "**", "*_exp.sol"), recursive=True))
    print(f"DeFiHackLabs: {len(sol_files)} exploit .sol files found")
    contracts = []
    for fp in sol_files[:max_contracts]:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            if len(code) < 100:
                continue
            contracts.append({"code": code, "filename": os.path.basename(fp), "label": "vulnerable"})
        except Exception:
            pass
    print(f"  Loaded: {len(contracts)} DeFi exploit contracts")
    return contracts


def load_safe_contracts(n=100):
    with open(DATASET_FILE) as f:
        ds = json.load(f)
    safe = [c for c in ds["contracts"] if c["label"] == "safe"]
    random.shuffle(safe)
    contracts = []
    for c in safe[:n]:
        fp = c["filepath"]
        if not os.path.exists(fp):
            continue
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        if not code.strip():
            continue
        contracts.append({"code": code, "filename": c["filename"], "label": "safe"})
    print(f"  Loaded: {len(contracts)} safe contracts (SmartBugs Wild)")
    return contracts


def main():
    print("=" * 60)
    print("Phase 2: Real-World DeFi Test — FIXED (Pipeline + 70/30)")
    print("=" * 60)

    vuln_contracts = load_defihacklabs(max_contracts=100)
    safe_contracts = load_safe_contracts(n=100)

    if len(vuln_contracts) == 0:
        print("\n⚠️  DeFiHackLabs data not found. Skipping this experiment.")
        print(f"  Expected path: {DEFIHACKLABS}")
        # Save empty result
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, "w") as f:
            json.dump({"experiment": "defi_real_world_FIXED", "error": "DeFiHackLabs data not found"}, f, indent=2)
        return

    all_contracts = vuln_contracts + safe_contracts
    random.shuffle(all_contracts)

    codes = [c["code"] for c in all_contracts]
    labels = [1 if c["label"] == "vulnerable" else 0 for c in all_contracts]
    y = np.array(labels)

    print(f"\nDeFi test set: {sum(y)} vuln + {len(y)-sum(y)} safe = {len(y)}")

    # 70/30 split
    codes_train, codes_test, y_train, y_test = train_test_split(
        codes, y, test_size=0.30, random_state=42, stratify=y)
    print(f"Train: {len(codes_train)}, Test: {len(codes_test)}")

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "SVM (RBF)": SVC(kernel="rbf", random_state=42),
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    ml_results = {}

    for name, clf in models.items():
        pipe = build_pipeline(clf)
        cv_f1 = cross_val_score(pipe, codes_train, y_train, cv=cv, scoring="f1")
        pipe.fit(codes_train, y_train)
        y_pred = pipe.predict(codes_test)
        test_f1 = f1_score(y_test, y_pred)
        test_prec = precision_score(y_test, y_pred, zero_division=0)
        test_rec = recall_score(y_test, y_pred, zero_division=0)

        ml_results[name] = {
            "cv_f1": round(float(cv_f1.mean()), 4),
            "test_f1": round(float(test_f1), 4),
            "test_precision": round(float(test_prec), 4),
            "test_recall": round(float(test_rec), 4),
        }
        print(f"  {name}: CV F1={cv_f1.mean():.4f}, Test F1={test_f1:.4f}, P={test_prec:.4f}, R={test_rec:.4f}")

    # Summary
    print("\n" + "=" * 60)
    print("CROSS-DATASET COMPARISON — FIXED")
    print("=" * 60)
    print(f"\n{'Method':<25} {'DeFi Test F1':>13}")
    print("-" * 40)
    for name, r in ml_results.items():
        print(f"{name:<25} {r['test_f1']:>13.4f}")

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "experiment": "defi_real_world_FIXED",
            "fix_description": "TF-IDF inside Pipeline + 70/30 split",
            "dataset": f"DeFiHackLabs ({len(vuln_contracts)} vuln) + SmartBugs Wild ({len(safe_contracts)} safe)",
            "train_size": len(codes_train),
            "test_size": len(codes_test),
            "traditional_ml": ml_results,
        }, f, indent=2)
    print(f"\nSaved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
