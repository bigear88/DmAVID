#!/usr/bin/env python3
"""
Sprint 8 Step 4：9 組 ML 訓練 + paired bootstrap CI

3 features × 3 models = 9 settings
- 80/20 stratified split, seed=42（對齊 Sprint 3 CodeBERT）
- 5-fold CV grid search 簡化版
- best hyperparameter retrain on full train, eval on test
- paired bootstrap on test set (1000 iterations) → F1 95% CI

對 DmAVID 比較：
- 取 ablation_v5_clean_self-verify_details.json 之 per-contract pred 對應到 test set 子集
- 1000 paired bootstrap：DmAVID F1 - bytecode_ml F1 分布 + 95% CI
- McNemar p-value

Output:
  experiments/bytecode_ml/results.json
  experiments/bytecode_ml/paired_bootstrap.json
"""
import json
import time
import numpy as np
from pathlib import Path
from datetime import datetime

from sklearn.model_selection import StratifiedKFold, train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from scipy.sparse import load_npz
from scipy import stats as scipy_stats

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "experiments/bytecode_ml"
SV_FILE = ROOT / "experiments/ablation/ablation_v5_clean_self-verify_details.json"
LLM_RAG = ROOT / "experiments/llm_rag/llm_rag_results.json"
RESULTS = OUT_DIR / "results.json"
BOOT = OUT_DIR / "paired_bootstrap.json"

SEED = 42
N_BOOT = 1000


def load_features(name):
    return load_npz(OUT_DIR / f"features_{name}.npz")


def load_labels_ids():
    d = np.load(OUT_DIR / "labels_and_ids.npz", allow_pickle=True)
    return d["labels"], list(d["contract_ids"])


def get_dmavid_predictions():
    """從 v5_clean self-verify 取 per-contract 預測，回傳 dict[cid] -> 0/1"""
    d = json.loads(SV_FILE.read_text(encoding="utf-8"))
    return {r["contract_id"]: int(r.get("predicted_vulnerable", False)) for r in d["results"]}


def metrics_dict(y_true, y_pred):
    return {
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "tp": int(((y_true == 1) & (y_pred == 1)).sum()),
        "fp": int(((y_true == 0) & (y_pred == 1)).sum()),
        "tn": int(((y_true == 0) & (y_pred == 0)).sum()),
        "fn": int(((y_true == 1) & (y_pred == 0)).sum()),
    }


def fpr_of(m):
    return round(m["fp"] / max(m["fp"] + m["tn"], 1), 4)


def bootstrap_f1_ci(y_true, y_pred, n_boot=N_BOOT, seed=SEED):
    """單方法 F1 95% CI"""
    rng = np.random.default_rng(seed)
    n = len(y_true)
    f1s = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        try:
            f1s.append(f1_score(y_true[idx], y_pred[idx], zero_division=0))
        except Exception:
            f1s.append(0)
    f1s = np.array(f1s)
    return round(float(np.percentile(f1s, 2.5)), 4), round(float(np.percentile(f1s, 97.5)), 4)


def paired_bootstrap_diff(y_true, pred_a, pred_b, n_boot=N_BOOT, seed=SEED):
    """同一份 test set 上 paired bootstrap：F1(A) - F1(B) 分布"""
    rng = np.random.default_rng(seed)
    n = len(y_true)
    diffs = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        f1a = f1_score(y_true[idx], pred_a[idx], zero_division=0)
        f1b = f1_score(y_true[idx], pred_b[idx], zero_division=0)
        diffs.append(f1a - f1b)
    diffs = np.array(diffs)
    return {
        "mean_diff_f1_dmavid_minus_bytecode": round(float(diffs.mean()), 4),
        "ci_low": round(float(np.percentile(diffs, 2.5)), 4),
        "ci_high": round(float(np.percentile(diffs, 97.5)), 4),
        "p_diff_gt_0": round(float((diffs > 0).mean()), 4),
        "diffs_sample": [round(float(x), 4) for x in diffs[:50].tolist()],
    }


def mcnemar_test(y_true, pred_a, pred_b):
    """McNemar p-value：A 對 B 錯 vs B 對 A 錯"""
    # 1 = correct, 0 = wrong
    correct_a = (pred_a == y_true)
    correct_b = (pred_b == y_true)
    b = int((correct_a & ~correct_b).sum())  # A right, B wrong
    c = int((~correct_a & correct_b).sum())  # A wrong, B right
    if b + c == 0:
        return {"b": b, "c": c, "p_value": 1.0}
    # Use binomial test (exact)
    p = scipy_stats.binomtest(min(b, c), b + c, p=0.5).pvalue
    return {"b_a_only_correct": b, "c_b_only_correct": c, "p_value": round(float(p), 4)}


GRIDS = {
    "RF": (RandomForestClassifier(random_state=SEED, n_jobs=-1),
           {"n_estimators": [100, 300], "max_depth": [None, 20]}),
    "GBoost": (GradientBoostingClassifier(random_state=SEED),
               {"n_estimators": [100, 300], "learning_rate": [0.05, 0.1]}),
    "SVM": (SVC(kernel="rbf", random_state=SEED),
            {"C": [1, 10]}),
}


def train_one(X, y, feat_name, model_name):
    """80/20 + GridSearchCV(5-fold) + final test eval + bootstrap CI"""
    X_tr, X_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X, y, np.arange(len(y)), test_size=0.2, stratify=y, random_state=SEED)
    model, grid = GRIDS[model_name]
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    gs = GridSearchCV(model, grid, scoring="f1", cv=skf, n_jobs=-1, verbose=0)
    t_train = time.time()
    gs.fit(X_tr, y_tr)
    train_time = time.time() - t_train

    best = gs.best_estimator_
    t_inf = time.time()
    y_pred = best.predict(X_te)
    infer_time_per = (time.time() - t_inf) / max(len(y_te), 1)

    m = metrics_dict(y_te, y_pred)
    m["fpr"] = fpr_of(m)
    ci_lo, ci_hi = bootstrap_f1_ci(y_te, y_pred)
    m["ci_low"] = ci_lo
    m["ci_high"] = ci_hi
    m["train_time_s"] = round(train_time, 2)
    m["infer_time_s_per_contract"] = round(infer_time_per, 6)
    m["best_hyperparameter"] = gs.best_params_
    m["test_indices"] = idx_te.tolist()
    m["test_predictions"] = [int(x) for x in y_pred]
    return m


def main():
    print("=" * 70)
    print(f"Sprint 8 Step 4 — Train 9 ML Settings  ({datetime.now().isoformat()})")
    print("=" * 70)

    labels, cids = load_labels_ids()
    print(f"  contracts: {len(labels)},  vuln={int(labels.sum())},  safe={int((labels==0).sum())}")

    settings = {}
    for feat in ["F1", "F2", "F3"]:
        X = load_features(feat)
        print(f"\n[{feat}] shape={X.shape}")
        for model in ["RF", "GBoost", "SVM"]:
            key = f"{feat}_{model}"
            t0 = time.time()
            m = train_one(X, labels, feat, model)
            print(f"  {key:<10} F1={m['f1']:.4f}  CI=[{m['ci_low']},{m['ci_high']}]  "
                  f"P={m['precision']:.4f} R={m['recall']:.4f}  "
                  f"train={m['train_time_s']}s  total={time.time()-t0:.1f}s")
            settings[key] = m

    # best
    best_key = max(settings.keys(), key=lambda k: settings[k]["f1"])
    best_m = settings[best_key]
    print(f"\n[Best] {best_key}: F1={best_m['f1']:.4f} CI=[{best_m['ci_low']},{best_m['ci_high']}]")

    # DmAVID 對 best 之 paired bootstrap（同 test set 子集）
    dm_pred = get_dmavid_predictions()
    test_idx = np.array(best_m["test_indices"])
    test_cids = [cids[i] for i in test_idx]
    test_y = labels[test_idx]
    test_yhat_byte = np.array(best_m["test_predictions"])

    # 對齊 DmAVID 預測（test_cids 中 DmAVID 有的）
    test_yhat_dm = np.array([dm_pred.get(cid, 0) for cid in test_cids])
    overlap_n = sum(1 for cid in test_cids if cid in dm_pred)
    print(f"\n[Paired bootstrap] test n={len(test_cids)},  DmAVID 覆蓋 {overlap_n}")

    dm_metrics = metrics_dict(test_y, test_yhat_dm)
    dm_metrics["fpr"] = fpr_of(dm_metrics)
    dm_ci_lo, dm_ci_hi = bootstrap_f1_ci(test_y, test_yhat_dm)
    dm_metrics["ci_low"] = dm_ci_lo
    dm_metrics["ci_high"] = dm_ci_hi
    print(f"  DmAVID on test: F1={dm_metrics['f1']:.4f} CI=[{dm_ci_lo},{dm_ci_hi}]")
    print(f"  bytecode best:  F1={best_m['f1']:.4f} CI=[{best_m['ci_low']},{best_m['ci_high']}]")

    bs = paired_bootstrap_diff(test_y, test_yhat_dm, test_yhat_byte)
    mc = mcnemar_test(test_y, test_yhat_dm, test_yhat_byte)
    bs["mcnemar"] = mc
    print(f"  diff (DmAVID - bytecode) mean={bs['mean_diff_f1_dmavid_minus_bytecode']} "
          f"CI=[{bs['ci_low']},{bs['ci_high']}]  P(diff>0)={bs['p_diff_gt_0']}  McNemar p={mc['p_value']}")

    # CI overlap?
    ci_overlap = not (best_m["ci_low"] > dm_ci_hi or dm_ci_lo > best_m["ci_high"])
    if dm_metrics["f1"] > best_m["f1"]:
        interp = "DmAVID > bytecode_ML"
    elif dm_metrics["f1"] < best_m["f1"]:
        interp = "bytecode_ML > DmAVID"
    else:
        interp = "DmAVID == bytecode_ML"

    out = {
        "experiment": "sprint8_train_9_settings",
        "timestamp": datetime.now().isoformat(),
        "n_train": int(len(labels) * 0.8),
        "n_test": len(test_y),
        "settings": {k: {kk: vv for kk, vv in v.items()
                         if kk not in ("test_indices", "test_predictions")}
                     for k, v in settings.items()},
        "best_setting": {"name": best_key, "f1": best_m["f1"]},
        "comparison_with_dmavid_on_test_subset": {
            "dmavid_metrics_on_test": dm_metrics,
            "best_bytecode_ml_metrics": {kk: vv for kk, vv in best_m.items()
                                          if kk not in ("test_indices", "test_predictions")},
            "ci_overlap": ci_overlap,
            "interpretation": interp,
        },
    }
    RESULTS.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n→ Saved: {RESULTS}")

    # paired bootstrap（包含 raw test arrays 供 chart 用）
    BOOT.write_text(json.dumps({
        "experiment": "sprint8_paired_bootstrap",
        "timestamp": datetime.now().isoformat(),
        "n_test": len(test_y),
        "best_bytecode_setting": best_key,
        "test_y_true": [int(x) for x in test_y.tolist()],
        "test_yhat_dmavid": [int(x) for x in test_yhat_dm.tolist()],
        "test_yhat_bytecode": [int(x) for x in test_yhat_byte.tolist()],
        "test_contract_ids": test_cids,
        "paired_bootstrap_diff": bs,
        "n_boot": N_BOOT,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"→ Saved: {BOOT}")


if __name__ == "__main__":
    main()
