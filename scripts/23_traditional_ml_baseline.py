#!/usr/bin/env python3
"""
Step 3a: Traditional ML Fairness Ablation — Three-Stage Experiment.

Stage 1 (Naive):       random.shuffle(safe) + safe[:100], TF-IDF max_features=500 full vocab
Stage 2 (Length-Matched): nearest-neighbor length matching, 143v+143s=286, TF-IDF same as Stage 1
Stage 3 (LM+Keyword-Only): sampling same as Stage 2, TF-IDF with Solidity keyword whitelist only,
                            structural features exclude total_lines and code_length

All stages: 5-fold Stratified CV, 4 models (RF, LR, GB, SVM-RBF)
"""
import json, os, sys, re, time, warnings
import numpy as np
from collections import Counter
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import f1_score
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.pipeline import Pipeline, FeatureUnion
import random

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.environ.get("DAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_FILE = os.path.join(BASE_DIR, "data", "dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "traditional_ml", "ml_fairness_ablation.json")

# ============================================================
# Solidity vulnerability keyword whitelist (Stage 3)
# ============================================================
SOLIDITY_VULN_KEYWORDS = [
    'function', 'public', 'external', 'internal', 'private',
    'require', 'assert', 'revert', 'if', 'else', 'for', 'while',
    'call', 'delegatecall', 'send', 'transfer', 'value',
    'msg', 'sender', 'tx', 'origin', 'block', 'timestamp',
    'mapping', 'address', 'uint', 'uint256', 'int', 'payable',
    'fallback', 'receive', 'selfdestruct', 'suicide',
    'storage', 'memory', 'modifier', 'onlyOwner', 'nonReentrant',
]

# Structural features to EXCLUDE in Stage 3
STAGE3_EXCLUDED_STRUCTURAL = {"total_lines", "code_length"}

# ============================================================
# Feature Extraction
# ============================================================

def extract_structural_features(code):
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
    def __init__(self, exclude_features=None):
        self.exclude_features = exclude_features
        self.feature_names_ = None

    def fit(self, X, y=None):
        sample = extract_structural_features(X[0])
        excl = self.exclude_features or set()
        self.feature_names_ = sorted(k for k in sample.keys() if k not in excl)
        return self

    def transform(self, X, y=None):
        rows = []
        for code in X:
            sf = extract_structural_features(code)
            rows.append([sf[fn] for fn in self.feature_names_])
        return np.array(rows)


# ============================================================
# Dataset loading helpers
# ============================================================

def load_all_contracts():
    """Load all contracts from dataset, return (vuln_list, safe_list) each as (code, filepath)."""
    with open(DATASET_FILE) as f:
        ds = json.load(f)

    contracts = ds["contracts"]
    vuln_raw = [c for c in contracts if c["label"] == "vulnerable"]
    safe_raw = [c for c in contracts if c["label"] == "safe"]

    def read_contracts(clist):
        out = []
        for c in clist:
            fp = c["filepath"]
            if not os.path.exists(fp):
                continue
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            if code.strip():
                out.append(code)
        return out

    return read_contracts(vuln_raw), read_contracts(safe_raw)


def sample_stage1(vuln_codes, safe_codes):
    """Stage 1: random shuffle + take first 100 safe."""
    safe_shuffled = list(safe_codes)
    random.seed(42)
    random.shuffle(safe_shuffled)
    codes = vuln_codes + safe_shuffled[:100]
    labels = [1] * len(vuln_codes) + [0] * min(100, len(safe_shuffled))
    return codes, np.array(labels)


def sample_stage2(vuln_codes, safe_codes):
    """Stage 2: length-matched nearest-neighbor pairing. 143v + 143s = 286."""
    vuln_lens = [len(c) for c in vuln_codes]
    safe_lens = np.array([len(c) for c in safe_codes], dtype=float)

    matched_safe = []
    used_indices = set()
    length_diffs = []

    for vl in vuln_lens:
        diffs = np.abs(safe_lens - vl)
        # mask already-used indices
        for idx in used_indices:
            diffs[idx] = np.inf
        best_idx = int(np.argmin(diffs))
        used_indices.add(best_idx)
        matched_safe.append(safe_codes[best_idx])
        length_diffs.append(abs(int(safe_lens[best_idx]) - vl))

    codes = vuln_codes + matched_safe
    labels = [1] * len(vuln_codes) + [0] * len(matched_safe)

    # pairing quality stats
    pairing_stats = {
        "median_diff": int(np.median(length_diffs)),
        "mean_diff": round(float(np.mean(length_diffs)), 1),
        "max_diff": int(np.max(length_diffs)),
        "min_diff": int(np.min(length_diffs)),
        "num_pairs": len(length_diffs),
    }
    return codes, np.array(labels), pairing_stats


# ============================================================
# Run one stage
# ============================================================

def get_models():
    return {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42, C=1.0),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "SVM (RBF)": SVC(kernel="rbf", random_state=42),
    }


def run_stage(codes, labels, stage_name, tfidf_kwargs, struct_exclude=None):
    """Run 5-fold CV for all 4 models. Returns dict of results."""
    print(f"\n{'='*60}")
    print(f"  {stage_name}")
    print(f"  Dataset: {sum(labels)} vuln + {len(labels)-sum(labels)} safe = {len(labels)}")
    print(f"{'='*60}")

    models = get_models()
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    stage_results = {}

    for name, clf in models.items():
        t0 = time.time()

        pipe = Pipeline([
            ('features', FeatureUnion([
                ('tfidf', TfidfVectorizer(**tfidf_kwargs)),
                ('struct', StructuralFeatureExtractor(exclude_features=struct_exclude)),
            ])),
            ('clf', clf),
        ])

        cv_f1 = cross_val_score(pipe, codes, labels, cv=cv, scoring="f1")
        elapsed = time.time() - t0

        stage_results[name] = {
            "cv_f1_mean": round(float(cv_f1.mean()), 4),
            "cv_f1_std": round(float(cv_f1.std()), 4),
            "cv_f1_folds": [round(float(x), 4) for x in cv_f1],
            "time_seconds": round(elapsed, 2),
        }
        print(f"  {name:<25} F1 = {cv_f1.mean():.4f} ± {cv_f1.std():.4f}  ({elapsed:.1f}s)")

    return stage_results


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 60)
    print("ML Fairness Ablation — Three-Stage Experiment")
    print("=" * 60)

    vuln_codes, safe_codes = load_all_contracts()
    print(f"Loaded: {len(vuln_codes)} vulnerable, {len(safe_codes)} safe contracts")

    # --- Common TF-IDF settings for Stage 1 & 2 ---
    tfidf_full = dict(
        max_features=500,
        token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
        ngram_range=(1, 2),
        sublinear_tf=True,
    )

    # --- Stage 3 TF-IDF: keyword whitelist only ---
    tfidf_keywords = dict(
        vocabulary=SOLIDITY_VULN_KEYWORDS,
        token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
        sublinear_tf=True,
    )

    # ========================
    # Stage 1: Naive sampling
    # ========================
    codes_s1, labels_s1 = sample_stage1(vuln_codes, safe_codes)
    results_s1 = run_stage(codes_s1, labels_s1,
                           "Stage 1: Naive (random 100 safe, full TF-IDF)",
                           tfidf_full)

    # ========================
    # Stage 2: Length-matched
    # ========================
    codes_s2, labels_s2, pairing_stats = sample_stage2(vuln_codes, safe_codes)
    results_s2 = run_stage(codes_s2, labels_s2,
                           "Stage 2: Length-Matched (143v + 143s, full TF-IDF)",
                           tfidf_full)

    # ========================
    # Stage 3: LM + Keyword-Only
    # ========================
    # Uses same length-matched data as Stage 2
    results_s3 = run_stage(codes_s2, labels_s2,
                           "Stage 3: LM + Keyword-Only (143v + 143s, keyword TF-IDF, no length features)",
                           tfidf_keywords,
                           struct_exclude=STAGE3_EXCLUDED_STRUCTURAL)

    # ============================================================
    # Print comparison table
    # ============================================================
    print("\n" + "=" * 70)
    print("  THREE-STAGE COMPARISON TABLE")
    print("=" * 70)
    print(f"\n{'Model':<25} {'Stage 1 (Naive)':>16} {'Stage 2 (LM)':>16} {'Stage 3 (KW)':>16}")
    print("-" * 73)
    for name in get_models().keys():
        s1 = results_s1[name]
        s2 = results_s2[name]
        s3 = results_s3[name]
        print(f"{name:<25} "
              f"{s1['cv_f1_mean']:.4f}±{s1['cv_f1_std']:.4f}  "
              f"{s2['cv_f1_mean']:.4f}±{s2['cv_f1_std']:.4f}  "
              f"{s3['cv_f1_mean']:.4f}±{s3['cv_f1_std']:.4f}")

    # ============================================================
    # Print pairing quality (Stage 2)
    # ============================================================
    print(f"\n--- Stage 2 Length-Matching Quality ---")
    print(f"  Pairs:       {pairing_stats['num_pairs']}")
    print(f"  Median diff: {pairing_stats['median_diff']} chars")
    print(f"  Mean diff:   {pairing_stats['mean_diff']} chars")
    print(f"  Max diff:    {pairing_stats['max_diff']} chars")
    print(f"  Min diff:    {pairing_stats['min_diff']} chars")

    # ============================================================
    # Save JSON
    # ============================================================
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    output = {
        "experiment": "ml_fairness_ablation",
        "description": "Three-stage fairness ablation: Naive → Length-Matched → Keyword-Only",
        "stages": {
            "stage1_naive": {
                "description": "Random 100 safe, full TF-IDF (500 features), all structural features",
                "dataset_size": len(labels_s1),
                "vuln_count": int(sum(labels_s1)),
                "safe_count": int(len(labels_s1) - sum(labels_s1)),
                "results": results_s1,
            },
            "stage2_length_matched": {
                "description": "Nearest-neighbor length matching, 143v+143s, full TF-IDF, all structural",
                "dataset_size": len(labels_s2),
                "vuln_count": int(sum(labels_s2)),
                "safe_count": int(len(labels_s2) - sum(labels_s2)),
                "pairing_quality": pairing_stats,
                "results": results_s2,
            },
            "stage3_keyword_only": {
                "description": "Length-matched + keyword-only TF-IDF + structural without total_lines/code_length",
                "dataset_size": len(labels_s2),
                "vuln_count": int(sum(labels_s2)),
                "safe_count": int(len(labels_s2) - sum(labels_s2)),
                "keyword_vocabulary": SOLIDITY_VULN_KEYWORDS,
                "excluded_structural": list(STAGE3_EXCLUDED_STRUCTURAL),
                "results": results_s3,
            },
        },
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
