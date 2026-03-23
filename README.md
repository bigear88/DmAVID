# DeFi Smart Contract Vulnerability Detection using LLM

基於大型語言模型的乙太坊 DeFi 智能合約漏洞偵測機制研究

A Study on the Vulnerability Detection Mechanism of Ethereum DeFi Smart Contracts Based on Large Language Models

## Overview

This research project implements a **hybrid vulnerability detection framework** for Ethereum DeFi smart contracts, combining traditional static analysis tools (Slither, Mythril) with Large Language Models (GPT-4.1-mini) and Retrieval-Augmented Generation (RAG).

### Key Features

- **LLM-based Detection**: Leverages GPT-4.1-mini for semantic understanding of smart contract code
- **RAG Enhancement**: Retrieval-Augmented Generation with DeFi-specific vulnerability knowledge base
- **Hybrid Approach**: Combines static analysis (Slither) with LLM + RAG semantic analysis
- **DeFi-Specific**: Focuses on DeFi protocol vulnerabilities including flash loan attacks, price oracle manipulation, and reentrancy
- **DavidAgent Multi-Agent Framework**: Adversarial self-strengthening via Teacher-Student-Red Team iteration
- **Real Experiments**: All results are from actual tool execution on SmartBugs dataset
- **Statistical Validation**: McNemar tests and cost-sensitive analysis included
- **Full Reproducibility**: One-click reproduction script and raw prediction CSV provided

## Project Structure

```
defi-llm-vulnerability-detection/
├── README.md
├── LICENSE
├── requirements.txt
├── configs/
│   └── config.yaml
├── scripts/                              # Experiment scripts
│   ├── run_all.sh                        # ★ One-click reproduction script
│   ├── 01_prepare_dataset.py             # Dataset preparation (SmartBugs)
│   ├── 02_run_slither.py                 # Slither static analysis
│   ├── 03_run_mythril.py                 # Mythril symbolic execution
│   ├── 03_run_mythril_fast.py            # Mythril (fast mode, smaller sample)
│   ├── 04_run_llm_base.py               # LLM baseline detection (GPT-4.1-mini)
│   ├── 05_run_llm_rag.py                # LLM + RAG enhanced detection
│   ├── 06_run_hybrid.py                 # Hybrid framework (Slither + LLM + RAG)
│   ├── 07_generate_charts.py            # Generate result charts
│   ├── 08_supplementary_analysis.py     # Confusion matrices, McNemar, cost analysis
│   ├── 09_gen_supplementary_charts.py   # Generate supplementary charts
│   ├── 09_run_evmbench_detect.py        # EVMbench LLM+RAG detection
│   ├── 10_run_evmbench_hybrid.py        # EVMbench Hybrid detection
│   ├── 11_teacher_challenge.py          # ★ DavidAgent Teacher Agent
│   ├── 12_red_team_generate.py          # ★ DavidAgent Red Team Agent
│   ├── 13_foundry_validate.py           # ★ DavidAgent Foundry Validator
│   ├── 14_adversarial_loop.py           # ★ DavidAgent Dual-layer Iteration Loop
│   ├── 15_evmbench_reeval.py            # ★ EVMbench Post-iteration Re-evaluation
│   ├── 16_vuln_intel_collector.py       # ★ DavidAgent Zero-day Intel Collector
│   ├── 17_auto_research.py             # ★ DavidAgent AutoResearch Coordinator
│   └── run_experiment.py                # Legacy experiment runner
├── src/                                  # Source code modules
│   ├── detection/
│   │   ├── hybrid_detector.py
│   │   ├── llm_detector.py
│   │   └── static_analyzer.py
│   ├── evaluation/
│   │   └── metrics.py
│   ├── preprocessing/
│   └── utils/
├── experiments/                          # Experiment results (JSON)
│   ├── slither/slither_results.json
│   ├── mythril/mythril_results.json
│   ├── llm_base/llm_base_results.json
│   ├── llm_rag/llm_rag_results.json
│   ├── hybrid/hybrid_results.json
│   ├── evmbench/                         # EVMbench baseline results
│   ├── evmbench_reeval/                  # ★ Post-iteration EVMbench results
│   ├── iteration_history/                # ★ Adversarial iteration F1 progression
│   └── red_team/                         # ★ Red Team adversarial variants
├── supplementary_results/                # ★ Supplementary analysis results
│   ├── confusion_matrices.json           # Confusion matrices for all methods
│   ├── mcnemar_tests.json                # McNemar statistical tests
│   ├── cost_sensitive_analysis.json      # Cost-sensitive analysis
│   ├── vulnerability_type_comparison.json # Per-category detection comparison
│   ├── all_predictions.csv               # ★ Raw predictions for all contracts
│   ├── slither_predictions.csv           # Per-method prediction CSV
│   ├── llm_base_predictions.csv
│   ├── llm_rag_predictions.csv
│   ├── mythril_predictions.csv
│   └── hybrid_predictions.csv
├── charts/                               # Generated charts (PNG, 300 DPI)
│   ├── fig4_1_performance_comparison.png
│   ├── fig4_2_empirical_comparison.png
│   ├── fig4_3_fpr_comparison.png
│   ├── fig4_4_time_f1_tradeoff.png
│   ├── fig4_5_ablation_study.png
│   ├── fig4_6_rag_improvement.png
│   ├── fig4_7_category_recall.png
│   ├── fig4_8_radar_chart.png
│   ├── fig4_9_roc_space.png
│   ├── fig4_10_confusion_matrix.png
│   ├── fig4_sup1_confusion_matrices.png  # ★ All confusion matrices
│   ├── fig4_sup2_mcnemar_tests.png       # ★ McNemar test results
│   ├── fig4_sup3_cost_sensitive.png      # ★ Cost-sensitive analysis
│   └── fig4_sup4_vuln_type_recall.png    # ★ Per-type recall comparison
├── data/                                 # Dataset
│   └── dataset_1000.json                 # Full dataset pool; evaluation uses 243 contracts (143 vulnerable + 100 safe)
├── logs/                                 # Experiment execution logs
│   ├── slither_log.txt
│   ├── mythril_log.txt
│   ├── llm_base_log.txt
│   └── llm_base_terminal_log.txt
└── screenshots/                          # Experiment process records
```

## Quick Start

### One-Click Reproduction

```bash
# Clone the repository
git clone https://github.com/bigear88/defi-llm-vulnerability-detection.git
cd defi-llm-vulnerability-detection

# Set your OpenAI API key
export OPENAI_API_KEY='your-api-key'

# Run all experiments with one command
bash scripts/run_all.sh
```

**Estimated time**: 60-90 minutes | **Estimated API cost**: ~$2-5 USD

### Manual Step-by-Step

#### Prerequisites

- Python 3.11+
- OpenAI API Key (for GPT-4.1-mini access)
- Slither (for static analysis)
- Mythril (optional, for symbolic execution)

#### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install analysis tools
pip install slither-analyzer solc-select mythril

# Install Solidity compilers
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.0 0.8.17 0.8.20
```

#### Running Experiments

```bash
# Step 1: Prepare dataset (download SmartBugs)
python scripts/01_prepare_dataset.py

# Step 2: Run Slither static analysis
python scripts/02_run_slither.py

# Step 3: Run Mythril symbolic execution
python scripts/03_run_mythril_fast.py

# Step 4: Run LLM baseline detection
python scripts/04_run_llm_base.py

# Step 5: Run LLM + RAG enhanced detection
python scripts/05_run_llm_rag.py

# Step 6: Run Hybrid framework
python scripts/06_run_hybrid.py

# Step 7: Generate charts
python scripts/07_generate_charts.py

# Step 8: Run supplementary analysis (confusion matrices, McNemar, etc.)
python scripts/08_supplementary_analysis.py
python scripts/09_gen_supplementary_charts.py
```

## Datasets

This project uses the following datasets:

| Dataset | Size | Description |
|---------|------|-------------|
| SmartBugs Curated | 143 contracts | Labeled vulnerability dataset with known vulnerabilities |
| SmartBugs Wild | 100 contracts (sampled) | Safe contracts from 47,398 real-world deployed contracts |
| **Total** | **243 contracts** | **Combined evaluation dataset** |

### Contract Selection Criteria

- Minimum 10 lines of Solidity code (excluding comments)
- Compilable with Solidity 0.4.x–0.8.x
- Random seed = 42 for reproducibility
- Safe contracts verified by Slither initial scan (no high-severity findings)

### Vulnerability Categories (SmartBugs Curated)

| Category | Count |
|----------|-------|
| Reentrancy | 31 |
| Access Control | 17 |
| Arithmetic (Integer Overflow) | 22 |
| Unchecked Return Values | 16 |
| Denial of Service | 6 |
| Front Running | 4 |
| Time Manipulation | 5 |
| Other | 42 |

### Evaluation Level

All evaluations are performed at the **contract level** (binary classification: vulnerable / safe). A contract is classified as "vulnerable" if the detection method identifies at least one vulnerability of any type.

## Research Methodology (DSR)

This research follows the **Design Science Research** methodology (Hevner et al., 2004) in five phases:

1. **Problem Identification**: DeFi security challenges — 410 incidents / $2.013B losses in 2024; traditional tools insufficient for DeFi-specific vulnerabilities
2. **Solution Design**: DavidAgent five-agent adversarial self-strengthening framework with real-time zero-day intelligence
3. **Development**: Three-stage hybrid detection pipeline + AutoResearch parameter optimization
4. **Demonstration**: SmartBugs (243 contracts) + EVMbench (10 projects/39 vulns) + GPT-4.1-mini vs GPT-5.x comparison
5. **Evaluation**: F1/Recall/FPR metrics, McNemar tests, cost-sensitive analysis, ablation studies

### Datasets

| Dataset | Size | Purpose |
|---------|------|---------|
| SmartBugs Curated | 143 vulnerable + 100 safe = 243 contracts | Baseline evaluation (SWC categories) |
| EVMbench | 10 real DeFi/L2/NFT projects, 39 High-severity vulns | Real-world generalization validation |
| Zero-day Intel | 100+ DeFi attack events (2024-2026) from DeFiHackLabs, Rekt News, SlowMist, Code4rena | Dynamic knowledge base update |

### Hybrid Detection Framework

```
Input Contract
      │
      ▼
┌─────────────────┐
│ Static Analysis │ (Slither)
│   Quick Scan    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  RAG Retrieval  │ (ChromaDB + text-embedding-3-small)
│ Vulnerability   │
│ Pattern Matching│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LLM Analysis   │ (GPT-4.1-mini)
│ Semantic Check  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Ensemble      │
│   Decision      │
└────────┬────────┘
         │
         ▼
   Detection Result
```

### Evaluation Metrics

- **Precision**: TP / (TP + FP) — How many flagged contracts are truly vulnerable
- **Recall**: TP / (TP + FN) — How many vulnerable contracts are correctly detected
- **F1-Score**: Harmonic mean of Precision and Recall
- **FPR (False Positive Rate)**: FP / (FP + TN) — Rate of safe contracts incorrectly flagged
- **Specificity**: TN / (TN + FP) — Rate of safe contracts correctly identified
- **Average Detection Time**: Per-contract processing time in seconds
- **Token Usage**: Total LLM API tokens consumed (for cost tracking)

## Experiment Results

All experiments were conducted on 2025-02-20 using the SmartBugs dataset (243 contracts). Results are from **real tool execution**, not simulated.

### Experiment Environment

| Item | Specification |
|------|---------------|
| OS | Ubuntu 22.04 LTS (x86_64) |
| Python | 3.11.0rc1 |
| LLM Model | GPT-4.1-mini (via OpenAI API) |
| LLM Temperature | 0.1 |
| Slither | v0.10.4 |
| Mythril | v0.24.8 |
| Random Seed | 42 |

### Performance Comparison

| Method | Recall | Precision | F1 Score | FPR | Avg Time (s) |
|--------|--------|-----------|----------|-----|---------------|
| **Slither** (Static Analysis) | 94.41% | 61.64% | 74.59% | 84.00% | 2.20 |
| **Mythril** (Symbolic Execution) | 75.00% | 71.43% | 73.17% | 30.00% | 36.24 |
| **LLM Base** (GPT-4.1-mini) | 100.00% | 60.08% | 75.07% | 95.00% | 2.81 |
| **LLM + RAG** | 99.30% | 71.36% | 83.04% | 57.00% | 2.76 |
| **Hybrid** (Slither + LLM + RAG) | 99.30% | 73.20% | **84.27%** | 52.00% | 5.76 |

### Confusion Matrices

| Method | TP | TN | FP | FN | Total |
|--------|----|----|----|----|-------|
| Slither | 135 | 16 | 84 | 8 | 243 |
| Mythril | 15 | 14 | 6 | 5 | 40 |
| LLM Base | 143 | 5 | 95 | 0 | 243 |
| LLM + RAG | 142 | 43 | 57 | 1 | 243 |
| Hybrid | 142 | 48 | 52 | 1 | 243 |

### McNemar Statistical Tests

| Comparison | Shared Contracts | χ² | p-value | Significant |
|------------|-----------------|-----|---------|-------------|
| LLM+RAG vs LLM Base | 243 | 33.23 | <0.001 | *** |
| LLM+RAG vs Hybrid | 243 | 1.23 | 0.267 | n.s. |
| Hybrid vs LLM Base | 243 | 35.02 | <0.001 | *** |
| LLM+RAG vs Slither | 143 | 4.00 | 0.046 | * |
| Hybrid vs Slither | 143 | 4.00 | 0.046 | * |

### Cost-Sensitive Analysis

Hybrid achieves the lowest total misclassification cost across most FN/FP cost ratios (1:1 to 20:1), confirming its superiority in practical deployment scenarios. Only at extreme ratios (50:1+) does LLM Base become optimal due to its perfect recall.

### Key Findings

1. **Hybrid framework achieves the highest F1 score (84.27%)**, demonstrating that combining static analysis with LLM + RAG significantly improves detection accuracy.
2. **RAG dramatically reduces false positive rate**: From 95.00% (LLM Base) to 57.00% (LLM + RAG), a 40.0% reduction.
3. **McNemar test confirms statistical significance**: The improvement of LLM+RAG over LLM Base (p<0.001) and Hybrid over LLM Base (p<0.001) are both statistically significant.
4. **Mythril has very high precision (71.43%) with moderate recall (75.00%)**: Conservative approach with good balance on its smaller sample.
5. **Slither is fast but noisy**: High recall (94.41%) but very high FPR (84.00%).
6. **LLM Base achieves perfect recall (100.00%)** but at the cost of very high FPR (95.00%), making it suitable only when missing vulnerabilities is unacceptable.

## EVMbench Extended Validation (Mar 2026)

> **Note on EVMbench (Feb 2026):**
> This repository provides a lightweight, highly-reproducible baseline for smart contract vulnerability detection (combining Static Analysis, LLM, and RAG). While recent benchmarks like OpenAI's EVMbench focus on end-to-end agentic capabilities (Detect, Patch, Exploit), our pipeline serves as a robust foundation and a cost-efficient benchmark for the **Detection phase**. Future researchers are welcome to fork and integrate our hybrid detection engine into EVMbench's agentic testing environments.

To validate our framework against the latest industry benchmark, we conducted detection experiments on the **EVMbench** dataset (released Feb 2026 by OpenAI & Paradigm), comparing both **LLM+RAG** and **Hybrid** (Slither + LLM + RAG) approaches.

### EVMbench Dataset

- **Source**: 46 real Code4rena audit projects (2023–2026)
- **Total vulnerabilities**: 120 High/Critical severity findings
- **Sample tested**: 10 audits (39 High-severity vulnerabilities)
- **Task**: Detection only (no Patch or Exploit)
- **Judge**: GPT-4.1-mini based semantic matching against gold standard findings

### Detection Results on EVMbench

| Audit Project | Gold Vulns | LLM+RAG Detected | Hybrid Detected |
|---------------|-----------|-------------------|-----------------|
| 2024-01-curves | 4 | 1 | 2 |
| 2024-03-taiko | 5 | 0 | 0 |
| 2024-05-olas | 2 | 0 | 0 |
| 2024-07-basin | 2 | 0 | 0 |
| 2024-01-renft | 6 | 0 | 0 |
| 2024-06-size | 4 | 0 | 0 |
| 2024-08-phi | 6 | 0 | 0 |
| 2024-12-secondswap | 3 | 1 | 0 |
| 2025-04-forte | 5 | 0 | 0 |
| 2026-01-tempo | 2 | 1 | 1 |
| **Total / Average** | **39** | **3 (7.69%)** | **3 (7.69%)** |

### Analysis

- **Detect Score: 7.69%** — comparable to GPT-4o's ~12% on EVMbench (considering we use the lighter GPT-4.1-mini with single API call, not multi-turn Agent)
- **Successfully detected vulnerability types**: Access control flaws (malformed modifiers), fee distribution bugs, integer underflow — classic patterns covered by our RAG knowledge base
- **Key insight**: Our lightweight pipeline excels at detecting **known vulnerability patterns** but struggles with **novel, complex business logic bugs** that require deep protocol understanding and multi-contract analysis
- **Positioning**: This validates our framework as a strong **"Pre-Agent Era" baseline** for the Detection phase

### Tool Context Drift Finding

An interesting phenomenon was observed in the `secondswap` audit: **LLM+RAG detected 1/3 vulnerabilities, but Hybrid detected 0/3** despite the Hybrid model finding more candidate vulnerabilities (4 vs 3). Analysis revealed that Slither's injected static analysis context shifted the LLM's attention toward access control and token transfer issues (flagged by Slither), causing it to miss the core `releaseRate` calculation vulnerability. The Judge could not semantically match the Hybrid output to the gold standard finding. This **"Tool Context Drift"** phenomenon highlights a trade-off in hybrid frameworks: additional static analysis context can expand detection scope but may also divert the LLM's focus from key vulnerability characteristics, affecting final semantic matching accuracy.

### Running EVMbench Experiment

```bash
# Requires EVMbench dataset (git clone with submodules)
git clone --recursive https://github.com/paradigmxyz/evmbench.git

# Run LLM+RAG detection on EVMbench
python scripts/09_run_evmbench_detect.py

# Run Hybrid detection on EVMbench
python scripts/10_run_evmbench_hybrid.py
```

## DavidAgent: Adversarial Self-Strengthening Framework (Mar 2026)

To address the low EVMbench detection rate (7.69%), we developed **DavidAgent**, a multi-agent adversarial iteration framework that continuously improves detection coverage through Teacher-Student-Red Team interactions.

### Framework Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    OUTER LOOP                            │
│  Teacher Agent scans SWC categories for uncovered types  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │                 INNER LOOP                         │  │
│  │  1. Teacher generates Solidity challenges          │  │
│  │  2. Student (LLM+RAG) detects vulnerabilities      │  │
│  │  3. Red Team transforms false negatives            │  │
│  │  4. Foundry validates adversarial variants          │  │
│  │  5. Valid patterns → RAG knowledge base             │  │
│  │  6. Check convergence (ΔF1 < 0.01)                 │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Five-Agent Design

| Agent | Role | Function |
|-------|------|----------|
| **Teacher** | Challenge Generator | Generates vulnerability challenges per SWC category (difficulty 1→5) |
| **Student** | Detector | LLM+RAG detection on challenge contracts |
| **Red Team** | Adversary | Transforms FN cases via variable renaming, code reordering, dead code injection |
| **Foundry Validator** | Verifier | Compiles variants and runs PoC exploitation tests |
| **Knowledge Updater** | Learner | Adds validated patterns to RAG knowledge base |

### Adversarial Iteration Results

**Configuration**: 3 outer rounds, 3 inner rounds, 10 challenges/round, budget $10 USD

| Vulnerability Type | Final F1 | Inner Rounds | FN | Red Team Variants |
|-------------------|----------|-------------|-----|-------------------|
| integer_overflow | 1.0000 | 1 | 0 | 0 |
| access_control | 1.0000 | 2 | 1→0 | 3 |
| delegatecall | 0.9474 | 2 | 1→1 | 6 |
| arithmetic | 1.0000 | 1 | 0 | 0 |

- **Best F1**: 1.0000 | **Average F1**: 0.9868
- **API Cost**: $4.03 (40.3% of budget)
- **Teacher generated**: 40 real Solidity challenge contracts
- **Red Team produced**: 9 adversarial variants

### EVMbench Re-evaluation (Post-Iteration)

After adversarial iteration, we re-evaluated on the same 10 EVMbench audits:

| Metric | Baseline | Enhanced | Improvement |
|--------|----------|----------|-------------|
| **Detect Rate** | 7.69% (3/39) | **28.21% (11/39)** | **+266.67%** |

| Audit | Gold | Baseline | Enhanced |
|-------|------|----------|----------|
| 2024-01-curves | 4 | 2 | 1 |
| 2024-01-renft | 6 | 0 | **4** |
| 2024-08-phi | 6 | 0 | **2** |
| 2024-12-secondswap | 3 | 1 | **3 (100%)** |
| 2026-01-tempo | 2 | 0 | **1** |
| Others (5 audits) | 18 | 0 | 0 |

### Running DavidAgent

```bash
# Install Foundry (required for validation)
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Run adversarial iteration (dry-run first)
python scripts/14_adversarial_loop.py --dry-run

# Run with real API calls (3 rounds, $10 budget)
python scripts/14_adversarial_loop.py --max-rounds 3 --budget 10.0

# Re-evaluate on EVMbench
python scripts/15_evmbench_reeval.py
```

## Limitations

1. **LLM Version Drift**: GPT-4.1-mini behavior may change across API versions. Experiment date: 2025-02-20.
2. **Dataset Representativeness**: SmartBugs Curated primarily contains Solidity 0.4.x–0.5.x contracts, which may not fully represent current DeFi patterns.
3. **Evaluation Scope**: Contract-level binary classification only; function-level or line-level localization not evaluated.
4. **API Cost**: Large-scale auditing with commercial LLM APIs incurs significant costs (~357K tokens for 243 contracts).
5. **External Validity**: Performance on zero-day vulnerabilities or novel attack vectors remains to be validated.

## Raw Data Access

All raw prediction results are available in `supplementary_results/`:

- `all_predictions.csv`: Combined predictions from all methods for every contract
- `{method}_predictions.csv`: Per-method prediction details
- `confusion_matrices.json`: Detailed confusion matrices
- `mcnemar_tests.json`: Statistical test results
- `cost_sensitive_analysis.json`: Cost-sensitive analysis data

## References

1. Sun, D., et al. (2024). GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis. ICSE 2024.
2. Xia, Y., et al. (2024). AuditGPT: Auditing Smart Contracts with ChatGPT. arXiv:2404.04306.
3. Wei, Z., et al. (2025). Advanced Smart Contract Vulnerability Detection via LLM-Powered Multi-Agent Systems. IEEE TSE.
4. Durieux, T., et al. (2020). Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts. ICSE 2020.
5. Feist, J., et al. (2019). Slither: A Static Analysis Framework for Smart Contracts. WETSEB 2019.
6. Mueller, B. (2018). Smashing Ethereum Smart Contracts for Fun and Real Profit. HITB SecConf.

## Author

- **Curtis Chang**
- Advisor: **Dr. David Shou (壽大衛)**
- Institution: Department of Computer Science, University of Taipei (臺北市立大學)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- SmartBugs Team for the curated dataset
- OpenAI for GPT-4.1-mini API access
- Slither Team for the static analysis framework
- Mythril Team for the symbolic execution engine
- OpenAI & Paradigm for the EVMbench benchmark

