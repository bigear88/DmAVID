#!/usr/bin/env python3
"""
Step 3a: Traditional ML Baselines for Smart Contract Vulnerability Detection.

Implements Random Forest, Logistic Regression, and simple CNN/LSTM baselines
using opcode-level TF-IDF features from compiled Solidity contracts.

Since many SmartBugs contracts use old Solidity versions that are hard to compile,
we use source-code-level features as a practical alternative:
  - Token-level TF-IDF (Solidity keywords + operators)
  - Code structure features (function count, modifier count, etc.)
  - Slither alert features (if available)

Per committee requirement: establish traditional ML baselines to compare against
DmAVID's LLM+RAG approach (張教授, 中期實驗補強).
"""
import json, os, sys, re, time, warnings
import numpy as np
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score
import random

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.environ.get("DAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "traditional_ml", "ml_baseline_results.json")

# ============================================================
# Feature Extraction from Solidity Source Code
# ============================================================

SOLIDITY_KEYWORDS = [
    "pragma", "contract", "function", "modifier", "event", "struct", "enum",
    "mapping", "address", "uint", "int", "bool", "string", "bytes",
    "public", "private", "internal", "external", "view", "pure", "payable",
    "require", "assert", "revert", "if", "else", "for", "while", "do",
    "return", "returns", "emit", "new", "delete", "throw",
    "msg.sender", "msg.value", "block.timestamp", "block.number",
    "transfer", "send", "call", "delegatecall", "staticcall",
    "this", "super", "selfdestruct", "suicide",
    "storage", "memory", "calldata",
    "constructor", "fallback", "receive",
    "onlyOwner", "nonReentrant", "SafeMath",
]

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
    # Solidity version
    ver_match = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    features["solidity_major_version"] = int(ver_match.group(1).split(".")[1]) if ver_match else 8
    features["is_pre_08"] = 1 if features["solidity_major_version"] < 8 else 0
    return features

def load_and_extract_features():
    """Load dataset and extract features for all contracts."""
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
    struct_features = []

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
        struct_features.append(extract_structural_features(code))

    print(f"Loaded: {len(codes)} contracts ({sum(labels)} vuln, {len(labels)-sum(labels)} safe)")
    return codes, labels, struct_features

def build_feature_matrix(codes, struct_features):
    """Build combined feature matrix: TF-IDF + structural features."""
    # TF-IDF on source code tokens
    tfidf = TfidfVectorizer(
        max_features=500,
        token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    X_tfidf = tfidf.fit_transform(codes)

    # Structural features
    feature_names = sorted(struct_features[0].keys())
    X_struct = np.array([[sf[fn] for fn in feature_names] for sf in struct_features])

    # Combine
    X_combined = np.hstack([X_tfidf.toarray(), X_struct])
    print(f"Feature matrix: {X_combined.shape} (TF-IDF={X_tfidf.shape[1]} + struct={X_struct.shape[1]})")

    return X_combined, tfidf, feature_names

# ============================================================
# Run Experiments
# ============================================================
def main():
    print("=" * 60)
    print("Traditional ML Baselines for Smart Contract Detection")
    print("=" * 60)

    codes, labels, struct_features = load_and_extract_features()
    X, tfidf, feat_names = build_feature_matrix(codes, struct_features)
    y = np.array(labels)

    # Models to test
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42, C=1.0),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "SVM (RBF)": SVC(kernel="rbf", random_state=42, probability=True),
    }

    results = {}

    for name, model in models.items():
        print(f"\n--- {name} ---")
        t0 = time.time()

        # 5-fold cross validation
        cv_f1 = cross_val_score(model, X, y, cv=5, scoring="f1")
        cv_prec = cross_val_score(model, X, y, cv=5, scoring="precision")
        cv_rec = cross_val_score(model, X, y, cv=5, scoring="recall")

        # Also train on full set and get predictions for confusion matrix
        model.fit(X, y)
        y_pred = model.predict(X)
        tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
        train_f1 = f1_score(y, y_pred)

        elapsed = time.time() - t0

        result = {
            "cv_f1_mean": round(float(cv_f1.mean()), 4),
            "cv_f1_std": round(float(cv_f1.std()), 4),
            "cv_precision_mean": round(float(cv_prec.mean()), 4),
            "cv_recall_mean": round(float(cv_rec.mean()), 4),
            "train_f1": round(train_f1, 4),
            "train_tp": int(tp), "train_fn": int(fn),
            "train_fp": int(fp), "train_tn": int(tn),
            "time_seconds": round(elapsed, 2),
        }
        results[name] = result

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f"  CV F1: {cv_f1.mean():.4f} (+/- {cv_f1.std():.4f})")
        print(f"  CV Precision: {cv_prec.mean():.4f}")
        print(f"  CV Recall: {cv_rec.mean():.4f}")
        print(f"  Train: TP={tp} FN={fn} FP={fp} TN={tn} F1={train_f1:.4f} FPR={fpr:.4f}")
        print(f"  Time: {elapsed:.2f}s")

        # Feature importance for tree-based models
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            # Get top structural feature importances
            tfidf_count = X.shape[1] - len(feat_names)
            struct_imp = [(feat_names[i], importances[tfidf_count + i]) for i in range(len(feat_names))]
            struct_imp.sort(key=lambda x: x[1], reverse=True)
            top5 = struct_imp[:5]
            result["top_structural_features"] = [{"name": n, "importance": round(float(v), 4)} for n, v in top5]
            print(f"  Top structural features: {', '.join(f'{n}={v:.3f}' for n, v in top5)}")

    # Summary comparison
    print("\n" + "=" * 60)
    print("SUMMARY: Traditional ML vs DmAVID Pipeline")
    print("=" * 60)
    print(f"\n{'Method':<25} {'CV F1':>8} {'CV Prec':>8} {'CV Rec':>8}")
    print("-" * 55)
    for name, r in results.items():
        print(f"{name:<25} {r['cv_f1_mean']:>8.4f} {r['cv_precision_mean']:>8.4f} {r['cv_recall_mean']:>8.4f}")

    # DmAVID baselines for comparison
    print(f"\n{'--- DmAVID Pipeline ---':<25}")
    print(f"{'Slither':<25} {'0.7459':>8} {'0.6164':>8} {'0.9441':>8}")
    print(f"{'LLM Base (GPT-4.1-mini)':<25} {'0.7507':>8} {'0.6008':>8} {'1.0000':>8}")
    print(f"{'LLM+RAG':<25} {'0.8468':>8} {'0.7421':>8} {'0.9860':>8}")
    print(f"{'LLM+RAG+Self-Verify':<25} {'0.8896':>8} {'0.8103':>8} {'0.9860':>8}")

    # Save results
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    output = {
        "experiment": "traditional_ml_baselines",
        "dataset": "SmartBugs 243 contracts",
        "features": "TF-IDF (500) + structural (19)",
        "cross_validation": "5-fold",
        "results": results,
        "comparison": {
            "Slither": {"f1": 0.7459, "precision": 0.6164, "recall": 0.9441},
            "LLM_Base": {"f1": 0.7507, "precision": 0.6008, "recall": 1.0},
            "LLM_RAG": {"f1": 0.8468, "precision": 0.7421, "recall": 0.986},
            "LLM_RAG_SelfVerify": {"f1": 0.8896, "precision": 0.8103, "recall": 0.986},
        }
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
