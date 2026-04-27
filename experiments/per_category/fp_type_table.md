# Sprint 4 — False-Positive 類型歸因分析

_Generated: 2026-04-27T19:00:10.306400_

**研究問題**：當方法將 safe 合約誤判為 vulnerable，它「自稱」發現的是哪種漏洞？

**樣本範圍**：243 樣本中的 100 個 safe 合約。

## 整體驗證

| 方法 | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| LLM_Baseline | 142 | 95 | 5 | 1 | 0.5992 | 0.9930 | 0.7474 |
| V4_Prompt | 142 | 75 | 25 | 1 | 0.6544 | 0.9930 | 0.7889 |
| DmAVID_Hybrid | 140 | 24 | 76 | 3 | 0.8537 | 0.9790 | 0.9121 |

## FP 數量與多重歸因

| 方法 | FP 數 / 100 safe | 至少標一種類型的 FP | 平均每 FP 類型數 |
|---|---:|---:|---:|
| LLM_Baseline | 95 | 95 | 2.42 |
| V4_Prompt | 75 | 75 | 2.76 |
| DmAVID_Hybrid | 24 | 24 | 1.96 |

## FP 類型歸因（每格為含此類型的 FP 合約數）

| 幻覺類型 | LLM_Baseline | V4_Prompt | DmAVID_Hybrid | 總計 |
|---|---:|---:|---:|---:|
| access_control | 92 | 75 | 4 | 171 |
| unchecked_low_level_calls | 57 | 62 | 21 | 140 |
| reentrancy | 21 | 39 | 17 | 77 |
| arithmetic | 29 | 16 | 2 | 47 |
| denial_of_service | 20 | 2 | 2 | 24 |
| time_manipulation | 1 | 10 | 0 | 11 |
| race_condition_in_approve | 4 | 0 | 0 | 4 |
| approval_race_condition | 3 | 0 | 0 | 3 |
| bad_randomness | 1 | 2 | 0 | 3 |
| missing_approval_mechanism | 1 | 0 | 0 | 1 |
| use_of_throw_(deprecated) | 1 | 0 | 0 | 1 |
| tx.origin_authentication | 0 | 1 | 0 | 1 |
| unchecked_call_return | 0 | 0 | 1 | 1 |

## DmAVID Hybrid vs LLM Baseline：各類型 FP 抑制

| 幻覺類型 | LLM Baseline | DmAVID Hybrid | 減少數 | 減少率 |
|---|---:|---:|---:|---:|
| access_control | 92 | 4 | ↓88 | +95.7% |
| unchecked_low_level_calls | 57 | 21 | ↓36 | +63.2% |
| reentrancy | 21 | 17 | ↓4 | +19.0% |
| arithmetic | 29 | 2 | ↓27 | +93.1% |
| denial_of_service | 20 | 2 | ↓18 | +90.0% |
| time_manipulation | 1 | 0 | ↓1 | +100.0% |
| race_condition_in_approve | 4 | 0 | ↓4 | +100.0% |
| approval_race_condition | 3 | 0 | ↓3 | +100.0% |
| bad_randomness | 1 | 0 | ↓1 | +100.0% |
| missing_approval_mechanism | 1 | 0 | ↓1 | +100.0% |
| use_of_throw_(deprecated) | 1 | 0 | ↓1 | +100.0% |
| tx.origin_authentication | 0 | 0 | —0 | +0.0% |
| unchecked_call_return | 0 | 1 | ↑1 | +0.0% |

_注：本表類型字串經正規化收斂（例如 "Integer Overflow"→arithmetic、"Re-entrancy"→reentrancy）。一個 FP 合約可能同時被標多種類型，故總計可能大於該方法的 FP 數。_
