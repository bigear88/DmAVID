# DmAVID Canonical Truth (Single Source of Truth)

Generated: 2026-04-13 | Last updated: 2026-05-25
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

## H. Iterative Multi-Agent Pipeline — DmAVID Coordinator (CANONICAL, 2026-06-22, ChromaDB)

Source of truth: `experiments/dmavid_autonomous/` (autonomous Coordinator, scripts/20_coordinator_autonomous.py)
Script: `scripts/20_coordinator_autonomous.py` (knowledge-feedback closed loop, ChromaDB-enabled)
KB write: Blue Team -> `write_blue_team_to_chroma()` (ChromaDB, embedding `text-embedding-3-small`, `data/chroma_kb/`)
         + structured JSON `scripts/knowledge/vulnerability_knowledge.json`; next round via `reload_dynamic_kb()`.
Dataset: SmartBugs Curated 243 contracts (143 vuln + 100 safe), seed=42
Model: gpt-4.1-mini, temperature=0.1, rounds=3 (clean-KB start)

**CANONICAL ITERATIVE RESULT = real PoC-verified gate (experiments/dmavid_autonomous/): non-monotonic 0.9164(R1 peak) -> 0.9060 -> 0.9128(final), ≈ single-pass 0.9121. Table (B) below (monotonic 0.9103->0.9153->0.9158) is the compile-only ABLATION — an upper bound whose patches are NOT exploit-verified.**

> **Gating note (updated 2026-06-28):** the **canonical/main** iterative result uses the **strict real `forge test` PoC** gate (a variant feeds knowledge only if its exploit actually replays) → ~1 patch/round, sparse signal, **non-monotonic 0.9164 -> 0.9060 -> 0.9128** (peak R1, final ≈ single-pass 0.9121; `experiments/dmavid_autonomous/`). The **compile-only ABLATION** relaxes the gate to `solc`-compile-only (variant feeds knowledge once it compiles → 11/8/7 = 26 patches) producing **monotonic 0.9103 -> 0.9153 -> 0.9158** (`experiments/dmavid_autonomous_BAK_precompile_20260626/`, now committed) — patches NOT exploit-verified, treated as an upper bound. A 3-seed (42/7/123) treatment-vs-placebo test shows the monotonic gain is seed-sensitive (placebo R3 0.9201 ≥ treatment 0.9149). The loop's process-level value (FN curriculum, KB growth, explainability) is robust.

Baseline (LLM+RAG Stage 2, no iteration): F1=0.9061, FPR=0.26.

**(A) CANONICAL — real PoC-verified gate (experiments/dmavid_autonomous/):**

| Round | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| Round 1 (PEAK) | 137 | 19 | 6 | 81 | 0.8782 | 0.9580 | **0.9164** | 0.19 |
| Round 2 | 135 | 20 | 8 | 80 | 0.8710 | 0.9441 | **0.9060** | 0.20 |
| **Round 3 (FINAL)** | **136** | **19** | **7** | **81** | **0.8774** | **0.9510** | **0.9128** | **0.19** |

**(B) ABLATION — compile-only gate (experiments/dmavid_autonomous_BAK_precompile_20260626/, monotonic upper bound):**

| Round | TP | FP | FN | TN | Precision | Recall | F1 | FPR | patches |
|---|---|---|---|---|---|---|---|---|---|
| Round 1 | 132 | 15 | 11 | 85 | 0.8980 | 0.9231 | **0.9103** | 0.15 | 11 |
| Round 2 | 135 | 17 | 8 | 83 | 0.8882 | 0.9441 | **0.9153** | 0.17 | 8 |
| **Round 3** | **136** | **18** | **7** | **82** | **0.8831** | **0.9510** | **0.9158** | **0.18** | 7 |

**Improvement summary:**
- CANONICAL (real PoC): F1 non-monotonic 0.9164(R1 peak) -> 0.9060 -> 0.9128(final); final ≈ single-pass Self-Verify 0.9121.
- ABLATION (compile-only): F1 monotonic 0.9103 -> 0.9153 -> 0.9158 (26 patches); upper bound, patches not exploit-verified.

**Per-category — compile-only ablation (R1 -> R3, from BAK round_1/round_3); under the strict PoC gate per-category is mixed (access_control 1.0->0.9412, arithmetic 0.9286->0.8889):**
- arithmetic (15):                0.8889 -> 0.9286 (+0.040)
- bad_randomness (8):             0.9333 -> 0.9333 (+0.000)
- access_control (18):            0.9412 -> 0.9714 (+0.030)
- unchecked_low_level_calls (52): 0.9600 -> 0.9903 (+0.030)
- time_manipulation (5):          0.8889 -> 1.0000 (+0.111)
- none/safe FPR (100):            0.1500 -> 0.1800 (+0.030)

**Mechanism:** ChromaDB knowledge-feedback closed loop + FN Curriculum Learning.
Blue Team synthesizes defense patterns per round (11/8/7), capped per-category (<=5/type),
retaining **16 patches** in `vulnerability_knowledge.json` AND vectorized into ChromaDB;
patches are read back each round via `reload_dynamic_kb()` into Student's RAG context.

**Cost:** ~2,388K tokens (Student 1,674K + Self-Verify 662K dominant), ~$23.88 (budget $50).
**Red Team:** 26 adversarial variants total (11/8/7), all Foundry-compiled (solc).

### Thesis claim (CORRECT):
> Under a strict forge-test PoC gate (canonical), the ChromaDB closed-loop iterative DmAVID
> pipeline yields a non-monotonic F1 (0.9164 -> 0.9060 -> 0.9128), on par with single-pass
> Self-Verify (0.9121); a compile-only-gate ablation shows a monotonic rise to 0.9158 (upper
> bound, patches not exploit-verified). The loop's value lies in FN correction + process quality.

### DEPRECATED (superseded 2026-06-22): exp15 JSON-only iterative run
`experiments/exp15/` (scripts/19_coordinator_round2.py) F1=0.9132 (2 rounds, JSON KB, no ChromaDB
in the feedback path) is SUPERSEDED by the autonomous ChromaDB run above. Do NOT cite 0.9132,
0.8961, 0.9650, 0.9930 (iterative), or "39->51 entries" as the iterative result anymore.
Note: Recall=0.9930 remains valid ONLY for LLM Base (section A) and prompt-ablation V1-V4.

## F. How to use this file

1. Whenever the thesis quotes a number, find the row above it came from.
2. If the thesis disagrees, the thesis is wrong.
3. Run `tools/validate_thesis_tables.py` to auto-check all chapter docx files against this canonical set.
4. After fixing the thesis, re-run the validator to confirm 0 mismatches.

---

## G. EVMbench Post-Cutoff Validation (8 audits, 2025-01 to 2026-01)

Source of truth: `experiments/evmbench_postcutoff/postcutoff_results.json`
Generated: 2026-05-09
Script: `scripts/31_postcutoff_validation.py`

This section validates generalization to audits published **after the model knowledge cutoff**.
8 audits used (3 excluded due to missing source repos: next-generation, thorwallet, sequence).

| audit_id | gold | detected | score | source |
|---|---|---|---|---|
| 2025-04-forte | 5 | 0 | 0.00 | existing (evmbench_smart) |
| 2026-01-tempo-stablecoin-dex | 2 | 2 | 1.00 | existing (evmbench_smart) |
| 2025-01-liquid-ron | 1 | 1 | 1.00 | new (postcutoff run) |
| 2025-04-virtuals | 4 | 3 | 0.75 | new (postcutoff run) |
| 2025-05-blackhole | 1 | 1 | 1.00 | new (postcutoff run) |
| 2025-06-panoptic | 2 | 2 | 1.00 | new (postcutoff run) |
| 2026-01-tempo-feeamm | 1 | 1 | 1.00 | new (postcutoff run) |
| 2026-01-tempo-mpp-streams | 1 | 0 | 0.00 | new (postcutoff run) |
| **TOTAL** | **17** | **10** | **58.82%** | |

### Summary
- 8 post-cutoff audits validated (2025-01 to 2026-01)
- 10/17 gold vulnerabilities detected = **58.82% post-cutoff detect rate**
- Tokens (new runs only): 33,552
- Model: gpt-4.1-mini, same smart_preprocess strategy as section B FINAL

### Notes
- forte (0/5) and tempo-mpp-streams (0/1) are the two failures
- liquid-ron, blackhole, panoptic, tempo-feeamm: 100% detection
- virtuals: 3/4 (75%) — H-04 not detected
