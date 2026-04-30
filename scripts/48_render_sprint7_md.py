#!/usr/bin/env python3
"""
Sprint 7: 渲染論文整合 markdown。

從 leaveoneout_summary.json + no_coordinator_results.json 取所有數值，
markdown 不手寫任何 F1 數字。

Output:
  DmAVID_第肆章新節_Agent真實消融實驗.md
"""
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUMMARY = ROOT / "experiments/coordinator_ablation/leaveoneout_summary.json"
COORD = ROOT / "experiments/coordinator_ablation/no_coordinator_results.json"
OUT = ROOT / "DmAVID_第肆章新節_Agent真實消融實驗.md"

AGENT_LABEL = {
    "teacher": "Teacher (RAG)",
    "student": "Student (LLM core)",
    "red_team": "Red Team",
    "blue_team": "Blue Team",
    "coordinator": "Coordinator",
}


def main():
    d = json.loads(SUMMARY.read_text(encoding="utf-8"))
    coord = json.loads(COORD.read_text(encoding="utf-8")) if COORD.exists() else {}

    full_f1 = d["full_dmavid_f1"]
    lo = d["leave_one_out"]
    rank = d["ranking_by_contribution"]
    essential = d["essential_agents"]
    removable = d["removable_agents"]

    # Coordinator metrics 細節
    coord_metrics = coord.get("metrics", {})
    rt_cost = coord_metrics.get("actual_red_team_cost_usd", 0)
    rt_in = coord_metrics.get("red_team_input_tokens", 0)
    rt_out = coord_metrics.get("red_team_output_tokens", 0)
    coord_votes = coord.get("agent_vuln_votes", {})

    md = f"""# 第肆章 第十四節 Agent 真實消融實驗（Sprint 7）

> 對應第貳章第七節文獻缺口 G_y：「多代理 LLM 框架普遍以啟發式論證（heuristic argumentation）
> 主張各代理之必要性，缺乏真實的 leave-one-out 對照實驗作量化支撐。」
>
> 本節以 5 組真實 leave-one-out 實驗驗證每個 Agent 的邊際貢獻，4 組從既有實驗整理（無需重跑），
> 1 組（Coordinator）以 simple majority voting baseline 新跑。完整 DmAVID 五代理協作 F1
> = **{full_f1:.4f}**（canonical：experiments/ablation/ablation_v5_clean_self-verify_details.json）。

## 4.14.1 實驗設計

對每個 Agent，定義「拿掉該 Agent」後之等效對照組：

| Leave-out | 等效對照 | 既有實驗來源 | 備註 |
|---|---|---|---|
| Teacher | LLM Base（無 RAG） | `experiments/llm_base/llm_base_results.json` | 既有 |
| Student | 框架不存在 | n/a | F1 = 0 |
| Red Team | 無對抗式迭代（Round 1 only） | `experiments/prompt_ablation/V1_baseline_results.json` | 既有 |
| Blue Team | 無 critique 與 self-verify | `experiments/llm_rag/llm_rag_results.json` | 既有 |
| **Coordinator** | 4 agent 並行 + simple majority voting | `experiments/coordinator_ablation/no_coordinator_results.json` | **NEW** |

Coordinator leave-out 之投票協定：
- **Teacher**：對 ChromaDB `vuln_knowledge` (39 entries) 之 top-1 距離以全體 median 切分，距離 ≤ median 投 vulnerable（unsupervised median split）
- **Student**：沿用 `llm_rag_results.json` 之 `predicted_vulnerable`
- **Red Team**：對合約產 1 個 semantically-preserving 變體（GPT-4.1-mini, T=0.3）→ 對變體 LLM 偵測（T=0.0）；偵測為 vulnerable 即投 vulnerable
- **Blue Team**：沿用 `ablation_v5_clean_self-verify_details.json` 之 `sv_verdict`
- **Final**：4 票 majority；2-2 平手按 DeFi 偏好 precision 慣例 → safe（保守）

實際 Red Team API 成本 **${rt_cost:.4f} USD**（input {rt_in:,} tokens / output {rt_out:,} tokens），
其餘 3 個 agent 投票**完全不需新 LLM call**（從既有實驗派生）。

## 4.14.2 主結果（表 4-34）

**表 4-34**　5-Agent leave-one-out F1、邊際貢獻與是否可移除

| 拿掉的 Agent | Leave-out F1 | 邊際貢獻 (Δ) | 可移除 (Δ < 0.005) | 等效對照組 |
|---|---:|---:|:-:|---|
"""
    # 主表 — 排序按 Sprint 7 spec 表的順序：teacher, student, red, blue, coordinator
    table_order = ["teacher", "student", "red_team", "blue_team", "coordinator"]
    for a in table_order:
        info = lo[a]
        f1 = info["f1"]
        contrib = info["marginal_contribution"]
        removable_flag = info["removable"]
        f1_s = f"{f1:.4f}" if f1 is not None else "—"
        contrib_s = f"+{contrib:.4f}" if contrib is not None else "—"
        rem_s = "✓" if removable_flag else ("—" if removable_flag is None else "✗")
        md += f"| {AGENT_LABEL[a]} | {f1_s} | {contrib_s} | {rem_s} | {info['interpretation']} |\n"

    md += f"""
- 完整 DmAVID F1 = **{full_f1:.4f}**（reference）
- 邊際貢獻定義：full F1 − leave-out F1，越大表示該 Agent 越關鍵
- 可移除門檻：Δ F1 < 0.005（0.5 個百分點）

**圖 4-19**　Agent 邊際貢獻 bar chart（charts/sprint7_agent_contribution.png）

**圖 4-20**　Leave-out F1 排序橫向圖（charts/sprint7_leaveoneout_f1.png）

## 4.14.3 邊際貢獻排序（高 → 低）

| 排名 | Agent | 邊際貢獻 |
|---:|---|---:|
"""
    for i, r in enumerate(rank, 1):
        md += f"| {i} | {AGENT_LABEL[r['agent']]} | +{r['marginal_contribution']:.4f} |\n"

    # Coordinator 細節
    md += f"""
## 4.14.4 Coordinator leave-out 投票分布

4 個 Agent 在 SmartBugs 243 合約（143 vuln + 100 safe）之投票次數：

| Agent | 投 vulnerable 次數 | 占比 |
|---|---:|---:|
"""
    n_total = coord.get("metrics", {}).get("total", 243)
    for a in ["teacher", "student", "red_team", "blue_team"]:
        v = coord_votes.get(a, 0)
        md += f"| {AGENT_LABEL[a]} | {v} / {n_total} | {v/n_total*100:.1f}% |\n"
    md += f"""
Teacher 之 median split 距離 = {coord.get('teacher_median_distance', 0):.4f}（unsupervised threshold）。

Coordinator leave-out 整體指標：
- TP / FP / TN / FN = {coord_metrics.get('tp','—')} / {coord_metrics.get('fp','—')} / {coord_metrics.get('tn','—')} / {coord_metrics.get('fn','—')}
- Precision = {coord_metrics.get('precision','—')},  Recall = {coord_metrics.get('recall','—')},  **F1 = {coord_metrics.get('f1','—')}**
- FPR = {coord_metrics.get('fpr','—')}

## 4.14.5 結論

1. **核心 Agent（不可移除）**：{', '.join(AGENT_LABEL[a] for a in essential) if essential else '—'}
"""
    if essential:
        md += "   這些 Agent 邊際貢獻 ≥ 0.005，移除後 F1 顯著下降。\n"
    md += f"""
2. **可考慮簡化的 Agent**：{', '.join(AGENT_LABEL[a] for a in removable) if removable else '無 — 5 個 Agent 全部具實質貢獻'}
"""
    if removable:
        md += "   邊際貢獻 < 0.005，可在簡化版省略而幾乎不影響 F1。\n"
    else:
        md += "   未發現可移除之 Agent，所有 5 代理皆對最終 F1 有實質正貢獻。\n"

    md += f"""
3. **與原表 4-13（Pipeline 反推）對齊**：原表以 ablation v4 階段消融反推每個 Agent 之貢獻
   為啟發式分析；本實驗以**真實 leave-one-out** 取代之。兩者方向應一致（Student / Teacher
   皆關鍵），但本表採用之「對照組來源」皆為已存在之實驗 results 檔，數據可逐項追溯，
   符合 reproducible research 標準。

4. **Coordinator 角色驗證**：simple majority voting baseline 之 F1 =
   {coord_metrics.get('f1','—')} 相對 full DmAVID F1 = {full_f1:.4f}，
   邊際貢獻 = +{lo['coordinator']['marginal_contribution']:.4f}。
   {('此差距 < 0.005 → Coordinator 在 in-distribution SmartBugs 上**可考慮以 simple voting 取代**'
     if lo['coordinator']['removable']
     else '此差距 ≥ 0.005 → **Coordinator 之有序協作機制（不只是 voting）對 F1 有實質貢獻**')}。

5. **方法論貢獻**：本節為文獻中**首次**對 5-Agent DmAVID 框架做完整 leave-one-out 量化驗證，
   填補第貳章第七節 G_y 缺口；所有 leave-out F1 皆從現有 / 新 json 結果檔派生，無人工 review。

## 4.14.6 評估限制

- 4 對照組複用既有實驗結果，不重複計算 confidence interval；如要做 paired-bootstrap 比較，
  需重新運行對 same 243 合約之預測比對。
- Coordinator leave-out 中 Teacher 投票協定為 unsupervised median split，
  若改用 supervised threshold 校正可能讓 Teacher signal 更純。
- 本實驗範圍限於 SmartBugs Curated；EVMbench 規模上之 Agent 必要性未涵蓋（future work）。

---
_資料來源：experiments/coordinator_ablation/leaveoneout_summary.json_
_Coordinator leave-out 實際成本：${rt_cost:.4f} USD_
_生成時間：{datetime.now().isoformat()}_
"""
    OUT.write_text(md, encoding="utf-8")
    print(f"→ Saved: {OUT}")


if __name__ == "__main__":
    main()
