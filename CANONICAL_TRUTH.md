# DmAVID Canonical Truth (Single Source of Truth)

Generated: 2026-04-13
Purpose: lock the authoritative experimental results that the thesis MUST match.
Any future paper revision MUST cite these numbers — not memory, not hand calculation, not older runs.

If a thesis number disagrees with this file, **the thesis is wrong**, not this file.

---

## A. SmartBugs Curated (243 contracts: 143 vuln + 100 safe)

Source of truth: `experiments/ablation/ablation_v5_clean_results.json`
Cross-checked against: `experiments/llm_rag/llm_rag_results.json`,
`experiments/slither/slither_results.json`, `experiments/hybrid/hybrid_results.json`

| Pipeline Stage | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| Slither (static analysis) | 135 | 84 | 8 | 16 | 0.6164 | 0.9441 | **0.7459** |
| LLM Base (no RAG) | 142 | 95 | 1 | 5 | 0.5992 | 0.9930 | **0.7474** |
| **LLM+RAG (official baseline)** | **140** | **26** | **3** | **74** | **0.8434** | **0.9790** | **0.9061** |
| Hybrid (Slither+LLM+RAG fusion) | 127 | 30 | 16 | 70 | 0.8089 | 0.8881 | **0.8467** |
| **+Self-Verify (three-class, FINAL)** | **140** | **24** | **3** | **76** | **0.8537** | **0.9790** | **0.9121** |
| +Critique (Reflexion) | 143 | 88 | 0 | 12 | 0.6190 | 1.0000 | 0.7647 |
| +Critique+Debate | 143 | 88 | 0 | 12 | 0.6190 | 1.0000 | 0.7647 |

### Notes on multiple LLM+RAG runs

Two LLM+RAG runs exist in the repo. **Only the first is canonical.**

| Run | TP/FP/FN/TN | F1 | File | Status |
|---|---|---|---|---|
| Official (canonical) | 140/26/3/74 | 0.9061 | `llm_rag/llm_rag_results.json`, `ablation_v5_clean_results.json` | **USE THIS** |
| Self-Verify run baseline | 140/31/3/69 | 0.8917 | `hybrid/self_verify_results.json` (`baseline_metrics`) | DEPRECATED — older snapshot, do not cite |

The thesis must use **F1=0.9061** as the LLM+RAG baseline everywhere. Any reference to 0.8917 in Ch3/Ch5 should be updated.

### Self-Verify version comparison (informational)

| Version | F1 | Notes |
|---|---|---|
| v3 (confidence threshold) | 0.9032 | superseded |
| v4 (structured exploit) | 0.5473 | failed — recall collapse |
| v5 (type-aware) | 0.8873 | superseded |
| v6 (type-aware + conservative) | 0.9065 | superseded |
| **v5_clean (three-class, FINAL)** | **0.9121** | canonical |

---

## B. EVMbench (10 audits / 39 ground-truth vulnerabilities)

| Stage | Detected | Rate | Source |
|---|---|---|---|
| LLM+RAG (detect-only) | **3 / 39** | **7.69%** | `experiments/evmbench/evmbench_detect_results.json` |
| Hybrid (Slither+LLM+RAG) | **3 / 39** | **7.69%** | `experiments/evmbench/evmbench_hybrid_results.json` |
| Enhanced (intermediate, hint-injected) | **12 / 39** | **30.77%** | `experiments/evmbench_enhanced/enhanced_results.json` (TP=12, FP=0, FN=27, P=1.0, R=0.3077, F1=0.4706) |
| **Smart preprocess (FINAL)** | **25 / 39** | **64.10%** | `experiments/evmbench_smart/smart_preprocess_results.json` |

### Smart preprocess per-audit breakdown

| audit_id | gold | detected | score |
|---|---|---|---|
| 2024-01-curves | 4 | 3 | 0.75 |
| 2024-03-taiko | 5 | 0 | 0.00 |
| 2024-05-olas | 2 | 2 | 1.00 |
| 2024-07-basin | 2 | 1 | 0.50 |
| 2024-01-renft | 6 | 6 | 1.00 |
| 2024-06-size | 4 | 4 | 1.00 |
| 2024-08-phi | 6 | 4 | 0.67 |
| 2024-12-secondswap | 3 | 3 | 1.00 |
| 2025-04-forte | 5 | 0 | 0.00 |
| 2026-01-tempo-stablecoin-dex | 2 | 2 | 1.00 |
| **TOTAL** | **39** | **25** | **0.641** |

### Improvement deltas (correct math)

Stage-to-stage absolute (percentage points):
- LLM+RAG → Enhanced: 7.69% → 30.77% = **+23.08 pp**
- Enhanced → Smart: 30.77% → 64.10% = **+33.33 pp**
- LLM+RAG → Smart (overall): 7.69% → 64.10% = **+56.41 pp**

Stage-to-stage relative:
- LLM+RAG → Enhanced: (30.77 − 7.69) / 7.69 = **+300.0%**
- Enhanced → Smart: (64.10 − 30.77) / 30.77 = **+108.3%**
- LLM+RAG → Smart (overall): (64.10 − 7.69) / 7.69 = **+733.4%**

---

## C. DeFi Real-World Generalization

Source of truth: `experiments/defi_real_world/defi_results.json` (LLM+RAG cross-domain test)
Plus: `experiments/defi_real_world/defi_results_fixed.json` (Traditional ML fixed pipeline)

### LLM+RAG on real DeFi data (30 contracts)

| Metric | Value |
|---|---|
| TP | 4 |
| FN | 11 |
| FP | 4 |
| TN | 11 |
| Precision | 0.5000 |
| Recall | 0.2667 |
| F1 | **0.3478** |
| FPR | 0.2667 |

### Traditional ML cross-domain (DeFiHackLabs vs SmartBugs)

| Model | SmartBugs F1 | Real DeFi F1 (FIXED pipeline) |
|---|---|---|
| Random Forest | 0.993 | 1.000 |
| Logistic Regression | 0.9083 | 0.9836 |
| Gradient Boosting | 1.000 | 0.9836 |
| SVM (RBF) | 0.8115 | 0.7647 |

### EVMbench per-audit category mapping (for thesis Table 4-14)

| audit_id | category | detected? |
|---|---|---|
| 2024-01-curves | DeFi lending/AMM | YES (3/4) |
| 2024-12-secondswap | DEX/secondary market | YES (3/3) |
| 2026-01-tempo-stablecoin-dex | Stablecoin DEX | YES (2/2) |
| 2024-01-renft | NFT rental | YES (6/6) |
| 2024-05-olas | Autonomy/agents | YES (2/2) |
| 2024-06-size | Lending | YES (4/4) |
| 2024-07-basin | DeFi infra | partial (1/2) |
| 2024-08-phi | Identity | partial (4/6) |
| 2024-03-taiko | L2 rollup | NO (0/5) |
| 2025-04-forte | DeFi infra | NO (0/5) |

DeFi lending/trading audits successfully detected: **curves + secondswap + tempo + size = 4** (not 2, not 3 — depends on exact categorization).

---

## D. Token & Cost (informational)

| Stage | Total Tokens |
|---|---|
| LLM+RAG SmartBugs (243) | 427,535 |
| LLM+RAG SmartBugs (ablation v5_clean) | 427,617 |
| Self-Verify (v5_clean) | 673,490 (cumulative) |
| Critique stage | 662,486 |
| EVMbench Enhanced | 95,377 |
| Slither SmartBugs avg time | 0.506 s/contract |
| LLM+RAG SmartBugs avg time | 3.084 s/contract |

---

## E. Deprecated runs (DO NOT cite in thesis)

The following exist in the repo but must NOT be referenced in the thesis. They are older intermediate experiments superseded by the canonical files above.

- `experiments/ablation/ablation_results.json` (v1, no version tag)
- `experiments/ablation/ablation_v2_results.json`
- `experiments/ablation/ablation_v3_results.json`
- `experiments/ablation/ablation_v4_results.json`
- `experiments/ablation/ablation_v5_results.json` (uncleaned)
- `experiments/ablation/ablation_v6_results.json`
- `experiments/hybrid/self_verify_results.json` `baseline_metrics` field (older LLM+RAG snapshot, F1=0.8917)

The canonical Self-Verify result is the v5_clean three-class run (F1=0.9121).

---

## F. How to use this file

1. Whenever the thesis quotes a number, find the row above it came from.
2. If the thesis disagrees, the thesis is wrong.
3. Run `tools/validate_thesis_tables.py` to auto-check all chapter docx files against this canonical set.
4. After fixing the thesis, re-run the validator to confirm 0 mismatches.
