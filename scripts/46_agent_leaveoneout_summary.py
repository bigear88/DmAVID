#!/usr/bin/env python3
"""
Sprint 7: 整合 5-Agent leave-one-out 結果 + 邊際貢獻 + removable flag

5 個 Agent 對照組：
  Teacher    leave-out → LLM Base (no RAG) F1
  Student    leave-out → 框架不存在 F1=0
  Red Team   leave-out → V1_baseline (no adversarial iteration) F1
  Blue Team  leave-out → LLM+RAG only (no critique / self-verify) F1
  Coordinator leave-out → 4 agents simple majority F1（45 寫出之 json）

完整 DmAVID F1 = 0.9121（canonical：ablation_v5_clean_self-verify_details.json）

removable 判定：marginal_contribution < 0.005 視為「可移除」

Output:
  experiments/coordinator_ablation/leaveoneout_summary.json
"""
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "experiments/coordinator_ablation"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT = OUT_DIR / "leaveoneout_summary.json"

REMOVABLE_THRESHOLD = 0.005

# 對照組來源檔
SOURCES = {
    "teacher":    "experiments/llm_base/llm_base_results.json",
    "student":    None,  # 框架不存在
    "red_team":   "experiments/prompt_ablation/V1_baseline_results.json",
    "blue_team":  "experiments/llm_rag/llm_rag_results.json",
    "coordinator": "experiments/coordinator_ablation/no_coordinator_results.json",
}

# 完整 DmAVID canonical
FULL_F1_SOURCE = "experiments/ablation/ablation_v5_clean_self-verify_details.json"


def load_metrics(rel_path):
    """從 results json 讀 metrics block，回傳完整 metrics dict 或 None"""
    if not rel_path:
        return None
    p = ROOT / rel_path
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    return d.get("metrics", d)


def f1_of(metrics):
    """兼容 f1 與 f1_score 兩種命名（llm_base/llm_rag 用 f1_score, V1/ablation/coordinator 用 f1）"""
    if not metrics:
        return None
    v = metrics.get("f1")
    if v is None:
        v = metrics.get("f1_score")
    return v


def main():
    print("=" * 70)
    print("Sprint 7 — Agent Leave-One-Out Summary")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    # 完整 DmAVID
    full_metrics = load_metrics(FULL_F1_SOURCE)
    full_f1 = f1_of(full_metrics)
    if full_f1 is None:
        print(f"✗ 無法讀取 full DmAVID F1，from {FULL_F1_SOURCE}")
        return
    print(f"\nFull DmAVID F1 (canonical) = {full_f1}  source={FULL_F1_SOURCE}")

    # 5 leave-out
    print("\n[Leave-One-Out F1]")
    leave_out = {}

    # Teacher
    m = load_metrics(SOURCES["teacher"])
    leave_out["teacher"] = {
        "f1": f1_of(m), "metrics": m,
        "source": SOURCES["teacher"],
        "interpretation": "等同 LLM Base（無 RAG）",
    }
    # Student
    leave_out["student"] = {
        "f1": 0.0, "metrics": None,
        "source": "n/a (框架不存在)",
        "interpretation": "Student 為核心 LLM 引擎，移除後框架無法運行",
    }
    # Red Team
    m = load_metrics(SOURCES["red_team"])
    leave_out["red_team"] = {
        "f1": f1_of(m), "metrics": m,
        "source": SOURCES["red_team"],
        "interpretation": "等同 V1_baseline（無 adversarial iteration）",
    }
    # Blue Team
    m = load_metrics(SOURCES["blue_team"])
    leave_out["blue_team"] = {
        "f1": f1_of(m), "metrics": m,
        "source": SOURCES["blue_team"],
        "interpretation": "等同 LLM+RAG only（無 critique / self-verify）",
    }
    # Coordinator
    m = load_metrics(SOURCES["coordinator"])
    leave_out["coordinator"] = {
        "f1": f1_of(m), "metrics": m,
        "source": SOURCES["coordinator"],
        "interpretation": "4 agent 並行 + simple majority voting（NEW 實驗）",
    }

    # 邊際貢獻
    for name, info in leave_out.items():
        f1 = info["f1"]
        if f1 is None:
            info["marginal_contribution"] = None
            info["removable"] = None
            continue
        contrib = round(full_f1 - f1, 4)
        info["marginal_contribution"] = contrib
        info["removable"] = bool(contrib < REMOVABLE_THRESHOLD)
        print(f"  {name:<12} F1={f1:.4f}  contribution=+{contrib:+.4f}  removable={info['removable']}")

    # 排序
    rankable = [(n, info["marginal_contribution"]) for n, info in leave_out.items()
                if info["marginal_contribution"] is not None]
    rankable.sort(key=lambda x: -x[1])
    ranking = [{"agent": n, "marginal_contribution": c} for n, c in rankable]

    out = {
        "experiment": "agent_leaveoneout_ablation",
        "timestamp": datetime.now().isoformat(),
        "full_dmavid_f1": full_f1,
        "full_dmavid_source": FULL_F1_SOURCE,
        "removable_threshold_pp": REMOVABLE_THRESHOLD,
        "leave_one_out": leave_out,
        "ranking_by_contribution": ranking,
        "removable_agents": [n for n, info in leave_out.items() if info.get("removable")],
        "essential_agents": [n for n, info in leave_out.items()
                             if info.get("removable") is False],
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n→ Saved: {OUT}")
    print(f"\nRanking (by marginal contribution, high → low):")
    for r in ranking:
        print(f"  {r['agent']:<12} +{r['marginal_contribution']:+.4f}")
    print(f"\nEssential agents: {out['essential_agents']}")
    print(f"Removable agents: {out['removable_agents']}")


if __name__ == "__main__":
    main()
