#!/usr/bin/env python3
"""
Phase 3: Style-Balanced Experiment — Three-Stage Fairness Ablation.

Stage 1 (Naive):          random.shuffle(safe) + safe[:100], full TF-IDF, all structural
Stage 2 (Length-Matched):  nearest-neighbor length matching 143v+143s=286, full TF-IDF
Stage 3 (Keyword-Only):   same as Stage 2, keyword-only TF-IDF, no total_lines/code_length

All stages: 5-fold Stratified CV + 70/30 held-out test, 4 models (RF, LR, GB, SVM-RBF)
"""
import json, os, re, random, warnings, time
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import f1_score, confusion_matrix
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
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

STAGE3_EXCLUDED_STRUCTURAL = {"total_lines", "code_length"}

# ============================================================
# Feature Extraction
# ============================================================

def extract_features(code):
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
    ver = re.search(r"pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)", code)
    features["solidity_ver"] = int(ver.group(1).split(".")[1]) if ver else 8
    features["is_pre_08"] = 1 if features["solidity_ver"] < 8 else 0
    return features


class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, exclude_features=None):
        self.exclude_features = exclude_features
        self.feature_names_ = None

    def fit(self, X, y=None):
        excl = self.exclude_features or set()
        self.feature_names_ = sorted(k for k in extract_features(X[0]).keys() if k not in excl)
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


# ============================================================
# Dataset loading
# ============================================================

def load_all_contracts():
    """Load all contracts, return (vuln_codes, safe_codes)."""
    with open(DATASET_FILE) as f:
        ds = json.load(f)

    def read_list(clist):
        out = []
        for c in clist:
            fp = c["filepath"]
            if not os.path.exists(fp):
                continue
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                code = clean_code(f.read())
            if code.strip():
                out.append(code)
        return out

    vuln_raw = [c for c in ds["contracts"] if c["label"] == "vulnerable"]
    safe_raw = [c for c in ds["contracts"] if c["label"] == "safe"]
    return read_list(vuln_raw), read_list(safe_raw)


# ============================================================
# Sampling strategies
# ============================================================

def sample_naive(vuln_codes, safe_codes):
    """Stage 1: random shuffle + take first 100 safe."""
    safe_shuffled = list(safe_codes)
    random.seed(42)
    random.shuffle(safe_shuffled)
    n_safe = min(100, len(safe_shuffled))
    codes = vuln_codes + safe_shuffled[:n_safe]
    labels = [1] * len(vuln_codes) + [0] * n_safe
    return codes, np.array(labels)


def sample_length_matched(vuln_codes, safe_codes):
    """Stage 2 & 3: nearest-neighbor length matching, 143v + 143s = 286."""
    vuln_lens = [len(c) for c in vuln_codes]
    safe_lens = np.array([len(c) for c in safe_codes], dtype=float)

    matched_safe = []
    used = set()
    length_diffs = []

    for vl in vuln_lens:
        diffs = np.abs(safe_lens - vl)
        for idx in used:
            diffs[idx] = np.inf
        best = int(np.argmin(diffs))
        used.add(best)
        matched_safe.append(safe_codes[best])
        length_diffs.append(abs(int(safe_lens[best]) - vl))

    codes = vuln_codes + matched_safe
    labels = [1] * len(vuln_codes) + [0] * len(matched_safe)

    stats = {
        "num_pairs": len(length_diffs),
        "median_diff": int(np.median(length_diffs)),
        "mean_diff": round(float(np.mean(length_diffs)), 1),
        "max_diff": int(np.max(length_diffs)),
        "min_diff": int(np.min(length_diffs)),
    }
    return codes, np.array(labels), stats


# ============================================================
# Model definitions
# ============================================================

def get_models():
    return {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42, C=1.0),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "SVM (RBF)": SVC(kernel="rbf", random_state=42),
    }


def build_pipeline(clf, tfidf_kwargs, struct_exclude=None):
    return Pipeline([
        ('features', FeatureUnion([
            ('tfidf', TfidfVectorizer(**tfidf_kwargs)),
            ('struct', StructuralFeatureExtractor(exclude_features=struct_exclude)),
        ])),
        ('clf', clf),
    ])


# ============================================================
# Run one stage
# ============================================================

def run_stage(codes, labels, stage_name, tfidf_kwargs, struct_exclude=None):
    """Run 5-fold CV + 70/30 held-out test for all 4 models."""
    print(f"\n{'='*60}")
    print(f"  {stage_name}")
    print(f"  Dataset: {sum(labels)} vuln + {len(labels)-sum(labels)} safe = {len(labels)}")
    print(f"{'='*60}")

    codes_train, codes_test, y_train, y_test = train_test_split(
        codes, labels, test_size=0.30, random_state=42, stratify=labels)
    print(f"  Train: {len(codes_train)}, Test: {len(codes_test)}")

    models = get_models()
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    stage_results = {}

    for name, clf in models.items():
        t0 = time.time()
        pipe = build_pipeline(
            type(clf)(**clf.get_params()), tfidf_kwargs, struct_exclude)

        # 5-fold CV on train
        cv_f1 = cross_val_score(pipe, codes_train, y_train, cv=cv, scoring="f1")

        # Held-out test
        pipe.fit(codes_train, y_train)
        y_pred = pipe.predict(codes_test)
        test_f1 = f1_score(y_test, y_pred)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        elapsed = time.time() - t0

        stage_results[name] = {
            "cv_f1_mean": round(float(cv_f1.mean()), 4),
            "cv_f1_std": round(float(cv_f1.std()), 4),
            "cv_f1_folds": [round(float(x), 4) for x in cv_f1],
            "test_f1": round(float(test_f1), 4),
            "test_tp": int(tp), "test_fn": int(fn),
            "test_fp": int(fp), "test_tn": int(tn),
            "test_fpr": round(float(fpr), 4),
            "time_seconds": round(elapsed, 2),
        }
        print(f"  {name:<25} CV F1={cv_f1.mean():.4f}+/-{cv_f1.std():.4f}  "
              f"Test F1={test_f1:.4f}  ({elapsed:.1f}s)")

    return stage_results


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 60)
    print("ML Fairness Ablation — Three-Stage Experiment")
    print("  - TF-IDF inside Pipeline (no leakage)")
    print("  - 70/30 stratified train/test split")
    print("=" * 60)

    vuln_codes, safe_codes = load_all_contracts()
    print(f"Loaded: {len(vuln_codes)} vulnerable, {len(safe_codes)} safe contracts")

    # TF-IDF configs
    tfidf_full = dict(
        max_features=500,
        token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    tfidf_keywords = dict(
        vocabulary=SOLIDITY_VULN_KEYWORDS,
        token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
        sublinear_tf=True,
    )

    # ========================
    # Stage 1: Naive
    # ========================
    codes_s1, labels_s1 = sample_naive(vuln_codes, safe_codes)
    results_s1 = run_stage(codes_s1, labels_s1,
        "Stage 1: Naive (random 100 safe, full TF-IDF)", tfidf_full)

    # ========================
    # Stage 2: Length-Matched
    # ========================
    codes_s2, labels_s2, pairing_stats = sample_length_matched(vuln_codes, safe_codes)
    results_s2 = run_stage(codes_s2, labels_s2,
        "Stage 2: Length-Matched (143v+143s, full TF-IDF)", tfidf_full)

    # ========================
    # Stage 3: LM + Keyword-Only
    # ========================
    results_s3 = run_stage(codes_s2, labels_s2,
        "Stage 3: LM + Keyword-Only (143v+143s, keyword TF-IDF, no length feats)",
        tfidf_keywords, struct_exclude=STAGE3_EXCLUDED_STRUCTURAL)

    # ============================================================
    # Three-Stage Comparison Table
    # ============================================================
    print("\n" + "=" * 80)
    print("  THREE-STAGE COMPARISON TABLE (CV F1)")
    print("=" * 80)
    print(f"\n{'Model':<25} {'S1 Naive':>16} {'S2 LenMatch':>16} {'S3 Keyword':>16}  {'S1->S3':>8}")
    print("-" * 85)
    for name in get_models().keys():
        s1 = results_s1[name]
        s2 = results_s2[name]
        s3 = results_s3[name]
        drop = s3["cv_f1_mean"] - s1["cv_f1_mean"]
        print(f"{name:<25} "
              f"{s1['cv_f1_mean']:.4f}+/-{s1['cv_f1_std']:.4f}  "
              f"{s2['cv_f1_mean']:.4f}+/-{s2['cv_f1_std']:.4f}  "
              f"{s3['cv_f1_mean']:.4f}+/-{s3['cv_f1_std']:.4f}  "
              f"{drop:>+7.4f}")

    print(f"\n{'Model':<25} {'S1 Test F1':>11} {'S2 Test F1':>11} {'S3 Test F1':>11}  {'S1->S3':>8}")
    print("-" * 70)
    for name in get_models().keys():
        s1_t = results_s1[name]["test_f1"]
        s2_t = results_s2[name]["test_f1"]
        s3_t = results_s3[name]["test_f1"]
        drop = s3_t - s1_t
        print(f"{name:<25} {s1_t:>11.4f} {s2_t:>11.4f} {s3_t:>11.4f}  {drop:>+7.4f}")

    # ============================================================
    # Pairing Quality (Stage 2)
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
        "description": "Three-stage fairness ablation: Naive -> Length-Matched -> Keyword-Only",
        "pipeline": "TF-IDF inside sklearn Pipeline (no cross-fold leakage), 70/30 stratified split",
        "stages": {
            "stage1_naive": {
                "description": "Random 100 safe, full TF-IDF (500 features), all structural features",
                "dataset_size": int(len(labels_s1)),
                "vuln_count": int(sum(labels_s1)),
                "safe_count": int(len(labels_s1) - sum(labels_s1)),
                "results": results_s1,
            },
            "stage2_length_matched": {
                "description": "Nearest-neighbor length matching, 143v+143s, full TF-IDF, all structural",
                "dataset_size": int(len(labels_s2)),
                "vuln_count": int(sum(labels_s2)),
                "safe_count": int(len(labels_s2) - sum(labels_s2)),
                "pairing_quality": pairing_stats,
                "results": results_s2,
            },
            "stage3_keyword_only": {
                "description": "Length-matched + keyword-only TF-IDF + structural without total_lines/code_length",
                "dataset_size": int(len(labels_s2)),
                "vuln_count": int(sum(labels_s2)),
                "safe_count": int(len(labels_s2) - sum(labels_s2)),
                "keyword_vocabulary": SOLIDITY_VULN_KEYWORDS,
                "excluded_structural": sorted(STAGE3_EXCLUDED_STRUCTURAL),
                "results": results_s3,
            },
        },
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
