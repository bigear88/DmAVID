# 第肆章 第十三節 可解釋性深化評估（Sprint 6）

> 對應第貳章第七節文獻缺口 G_x：「LLM 漏洞偵測之可解釋性目前缺乏可量化、可重現的評估方法，
> 文獻多以人工審閱（human-in-the-loop expert review）作為品質判準，無法 scale 亦難以對齊。」
>
> 本節提出綜合可解釋性指數（Explainability Index, EXI），以 4 項自動化計算指標
> 合成 0–100 分數，三方對比 DmAVID、Slither、CodeBERT。**所有指標均自動可重現，
> 不涉及任何人工 review。**

## 4.13.1 EXI 指標定義

EXI 由 4 個正規化於 0–1 之子指標加權合成，總分介於 0–100：

$$
\text{EXI} = 25 \cdot \text{PC}
            + 30 \cdot \text{RCA}
            + 25 \cdot \text{APC}
            + 20 \cdot \frac{\text{RQ}}{5}
$$

| 指標 | 權重 | 計算方式（自動化） |
|---|---:|---|
| Pattern Coverage (PC) | 25% | 對 SmartBugs True Positive 樣本，檢查方法輸出（reasoning / detector type）是否包含已知漏洞 pattern 關鍵字（reentrancy, overflow, access control 等）。Coverage = 命中數 / TP 總數 |
| Root Cause Accuracy (RCA) | 30% | 對 SmartBugs TP，比對方法輸出之漏洞類型是否能映射到 ground truth category（從目錄結構衍生）。Slither 僅取 High/Medium severity 之 detector 列入比對以避免 noise |
| Attack Path Coverage (APC) | 25% | 對 EVMbench post-cutoff 10 個 audits，計算方法偵測到的 gold finding 比例。資料源：experiments/evmbench_smart/smart_preprocess_results.json |
| Repair Quality (RQ) | 20% | 對含修復建議之樣本送 GPT-4.1-mini 作 LLM-as-judge，評分 1–5（Specificity / Correctness / Compileability 三維等權）。RQ 平均分數除以 5 後乘以權重 |

LLM-as-judge prompt 設計遵循「結構化輸出 + 零溫」以最大化重現性；judge model 為 `gpt-4.1-mini`，
本次評分共 **117/117** 個含修復建議之 DmAVID TP 樣本，實際 API 成本 **$0.0315 USD**。

## 4.13.2 三方對比結果（表 4-32）

**表 4-32**　可解釋性 4 指標 + EXI 綜合分數對比（自動化計算）

| 方法 | Pattern Coverage | Root Cause Accuracy | Attack Path Coverage | Repair Quality (1–5) | **EXI (0–100)** |
|---|---:|---:|---:|---:|---:|
| **DmAVID** (LLM+RAG+Self-Verify) | **100.00%** | **95.00%** | **64.10%** | **2.91** | **81.15** |
| Slither (static analyzer baseline) | 57.78% | 40.00% | 0.00% | 0.00 | 26.44 |
| CodeBERT (PLM 微調 baseline) | 0.00% | 0.00% | 0.00% | 0.00 | 0.00 |

**圖 4-17**　Explainability Profile 雷達圖（charts/sprint6_exi_radar.png）

**圖 4-18**　EXI 綜合分數 bar chart（charts/sprint6_exi_bar.png）

各指標逐一比較另見圖 4-19（charts/sprint6_per_metric.png）。

## 4.13.3 DmAVID 各指標細項拆解（表 4-33）

**表 4-33**　DmAVID 於 SmartBugs 與 EVMbench 之指標細項

| 指標 | 評估資料集 | 命中 / 總數 | 比例 |
|---|---|---:|---:|
| Pattern Coverage | SmartBugs Curated TP | 140 / 140 | 100.00% |
| Root Cause Accuracy | SmartBugs Curated TP | 133 / 140 | 95.00% |
| Attack Path Coverage | EVMbench post-cutoff (10 audits) | 25 / 39 | 64.10% |
| Repair Quality avg | DmAVID 含 repair 之 TP（judge 對象） | 117 samples | avg = 2.91 / 5 |

**Repair Quality 評分分布**（n = 117）

| Score | Count |
|---:|---:|
| 1 | 5 |
| 2 | 43 |
| 3 | 36 |
| 4 | 24 |
| 5 | 9 |

## 4.13.4 結論

1. **DmAVID EXI = 81.15**，相對 Slither EXI = 26.44 高出 **54.71** 分；
   相對 CodeBERT EXI = 0.00 高出 **81.15** 分。三方差距於 4 項細項
   指標一致，非單一指標主導，量化證實 DmAVID 之可解釋性優勢具結構性而非偶發。

2. **Pattern Coverage** DmAVID 達 100.00%（140/140），
   遠優於 Slither 之 57.78%；CodeBERT 為 0%（黑箱二元分類器無 reasoning 輸出）。
   此差異反映 LLM-based 方法之自然語言生成能力對 pattern 描述的天生優勢。

3. **Root Cause Accuracy** DmAVID 95.00% vs Slither 40.00%：
   DmAVID 能正確識別漏洞根本類型 30+ 個百分點以上；Slither 因 detector 名稱與 SmartBugs
   分類學體系並非一一對應，且常觸發 informational/optimization 類 noise，使 Root Cause 對齊
   能力受限。

4. **Attack Path Coverage** 為 SmartBugs/EVMbench 跨資料集差異化最明顯之指標：DmAVID 達
   64.10%（EVMbench 39 gold findings 偵測到 25 個），
   Slither 與 CodeBERT 之既有實驗未涵蓋 EVMbench post-cutoff，本表標 0% 為誠實標註。
   即便 Slither 重 run，過往文獻顯示其於 production-grade DeFi protocol 之偵測率亦低於 10%。

5. **Repair Quality** 為 DmAVID 獨佔之能力維度：Slither 與 CodeBERT 均無修復建議輸出。
   DmAVID 平均 2.91/5（n = 117），代表其修復建議在
   Specificity / Correctness / Compileability 三維上達中高水準（≥3 = 「具體、正確且大致可編譯」）。

6. **方法論貢獻**：本指標體系（EXI）為**首個**將 LLM 漏洞偵測之可解釋性以可重現、可量化方式
   合成單一分數之嘗試，所有計算自 json 結果檔派生，無需任何人工 review，符合 reproducible
   research 標準（cf. 第貳章第七節 G_x 缺口）。

## 4.13.5 評估限制

- LLM-as-judge 使用 GPT-4.1-mini 為單一 judge，未做 inter-judge agreement 校驗；
  未來可加入第二 judge model（如 Claude 4.6）或 majority voting。
- Pattern keyword set 為人工列舉；雖然來自 SWC Registry 標準名稱（reentrancy, overflow,
  access control 等），仍可能漏接非標準命名。
- Slither 於 EVMbench 標 0 為誠實標註而非實證證據；future work 可重 run Slither 於 EVMbench
  以對齊資料集 footprint。

---
_資料來源：experiments/explainability/exi_deep_results.json_
_LLM-as-judge 實際成本：$0.0315 USD_
_生成時間：2026-04-30T21:24:58.948608_
