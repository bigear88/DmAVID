# DmAVID Official Ablation Results (v5_clean)

Generated: 2026-04-09
Model: gpt-4.1-mini (OpenAI)
Dataset: SmartBugs Curated (143 vulnerable + 100 safe = 243 contracts)
Seed: 42 (deterministic sampling)

## Complete Pipeline Comparison Table

| Pipeline Stage | F1 | Precision | Recall | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| Slither (static analysis) | 0.7459 | 0.6164 | 0.9441 | 135 | 84 | 8 | 16 |
| LLM Base (no RAG) | 0.7474 | 0.5992 | 0.9930 | 142 | 95 | 1 | 5 |
| **LLM+RAG (official baseline)** | **0.9061** | **0.8434** | **0.9790** | **140** | **26** | **3** | **74** |
| +Self-Verify (three-class) | **0.9121** | **0.8537** | **0.9790** | **140** | **24** | **3** | **76** |
| +Critique (Reflexion) | 0.7647 | 0.6190 | 1.0000 | 143 | 88 | 0 | 12 |
| +Critique+Debate | 0.7647 | 0.6190 | 1.0000 | 143 | 88 | 0 | 12 |

## Self-Verify Version Comparison

| Version | Approach | F1 | P | R | Flips | TP Loss |
|---------|----------|-----|------|------|-------|---------|
| v3 | Confidence threshold (≥0.90 skip) | 0.9032 | 0.8383 | 0.9790 | 0 | 0 |
| v4 | Structured exploit path (null→SAFE) | 0.5473 | 0.9483 | 0.3846 | 109 | 85 |
| v5 | Type-aware per-vuln validation | 0.8873 | 0.9242 | 0.8531 | 34 | 18 |
| v6 | Type-aware + conservative critique | 0.9065 | 0.9333 | 0.8811 | 32 | 14 |
| **v5_clean** | **Three-class (UNCERTAIN preserves)** | **0.9121** | **0.8537** | **0.9790** | **2** | **0** |

## Key Findings

### 1. LLM+RAG as Baseline
- RAG knowledge base improves F1 from 0.7474 (LLM Base) to 0.9061 (+21.2%)
- RAG reduces FP from 95 to 26 (-72.6%) while maintaining near-perfect recall (0.9790)
- Outperforms Slither static analysis: F1 0.9061 vs 0.7459 (+21.5%)

### 2. Self-Verify (Three-Class) — Best Result
- F1 improves from 0.9061 to 0.9121 (+0.7%) with ZERO recall loss
- Only 2 FP flipped to SAFE, both correctly identified (0 TP loss)
- Three-class design (VULNERABLE/SAFE/UNCERTAIN) prevents recall collapse
- UNCERTAIN class preserves baseline prediction, avoiding false negatives

### 3. Critique Agent — Structural Limitation
- Critic feedback causes FP explosion: 26→88 (+238.5%)
- Recall reaches 1.0000 but Precision drops to 0.6190
- Root cause: Critic hints make detector over-sensitive, alerting on every pattern
- This is consistent across v3 (FP 28→92) and v5_clean (FP 26→88)

### 4. Debate — No Effect
- Zero disputed cases (all predictions high confidence after Critique)
- Debate requires low-confidence disagreements to trigger, which Critique eliminates
- Architecture mismatch: Critique + Debate operate on different signals

## Per-Category Recall (Baseline LLM+RAG)

| Category | Recall | Count |
|----------|--------|-------|
| access_control | 100.0% | 18/18 |
| reentrancy | 100.0% | 31/31 |
| bad_randomness | 100.0% | 8/8 |
| denial_of_service | 100.0% | 6/6 |
| front_running | 100.0% | 4/4 |
| time_manipulation | 100.0% | 5/5 |
| other | 100.0% | 3/3 |
| short_addresses | 100.0% | 1/1 |
| unchecked_low_level_calls | 98.1% | 51/52 |
| arithmetic | 86.7% | 13/15 |

## Discussion: Why Structured Exploit Path Extraction Hurts Recall

The v4 experiment revealed a fundamental tension: requiring LLMs to decompose
vulnerabilities into structured components (target_state_variable, external_call_line,
state_update_after_call) dramatically improves precision (0.9483) but collapses
recall (0.3846). This occurs because:

1. The structured template was designed for reentrancy but applied to all types
2. Non-reentrancy vulnerabilities (bad_randomness, front_running, access_control)
   cannot fill reentrancy-specific fields → forced SAFE classification
3. Even with per-type templates (v5), the LLM struggles to extract structured
   components from complex, multi-function contracts

The v5_clean three-class approach resolves this by treating ambiguous cases as
UNCERTAIN (preserving baseline) rather than forcing a binary decision. This
achieves the best F1 (0.9121) with zero recall loss.

## Files

- Official baseline: `experiments/llm_rag/llm_rag_results.json`
- Ablation v3 (leakage-free): `experiments/ablation/ablation_v3_results.json`
- Ablation v5_clean: `experiments/ablation/ablation_v5_clean_results.json`
- Self-Verify v5/v6: `experiments/ablation/ablation_v5_results.json`, `ablation_v6_results.json`
- Script: `scripts/31_ablation_study_v5_clean.py`
