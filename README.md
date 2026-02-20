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
- **Real Experiments**: All results are from actual tool execution on SmartBugs dataset

## Project Structure

```
defi-llm-vulnerability-detection/
├── README.md
├── LICENSE
├── requirements.txt
├── configs/
│   └── config.yaml
├── scripts/                          # Experiment scripts
│   ├── 01_prepare_dataset.py         # Dataset preparation (SmartBugs)
│   ├── 02_run_slither.py             # Slither static analysis
│   ├── 03_run_mythril.py             # Mythril symbolic execution
│   ├── 03_run_mythril_fast.py        # Mythril (fast mode, smaller sample)
│   ├── 04_run_llm_base.py            # LLM baseline detection (GPT-4.1-mini)
│   ├── 05_run_llm_rag.py             # LLM + RAG enhanced detection
│   ├── 06_run_hybrid.py              # Hybrid framework (Slither + LLM + RAG)
│   ├── 07_generate_charts.py         # Generate result charts
│   └── run_experiment.py             # Legacy experiment runner
├── src/                              # Source code modules
│   ├── detection/
│   │   ├── hybrid_detector.py
│   │   ├── llm_detector.py
│   │   └── static_analyzer.py
│   ├── evaluation/
│   │   └── metrics.py
│   ├── preprocessing/
│   └── utils/
├── experiments/                      # Experiment results (JSON)
│   ├── slither/
│   │   └── slither_results.json
│   ├── mythril/
│   │   └── mythril_results.json
│   ├── llm_base/
│   │   └── llm_base_results.json
│   ├── llm_rag/
│   │   └── llm_rag_results.json
│   └── hybrid/
│       └── hybrid_results.json
├── charts/                           # Generated charts (PNG, 300 DPI)
│   ├── fig4_1_performance_comparison.png
│   ├── fig4_2_empirical_comparison.png
│   ├── fig4_3_fpr_comparison.png
│   ├── fig4_4_time_f1_tradeoff.png
│   ├── fig4_5_ablation_study.png
│   ├── fig4_6_rag_improvement.png
│   ├── fig4_7_category_recall.png
│   ├── fig4_8_radar_chart.png
│   ├── fig4_9_roc_space.png
│   └── fig4_10_confusion_matrix.png
├── data/                             # Dataset
│   └── dataset_1000.json             # 1000 contracts (143 vulnerable + 857 safe)
├── logs/                             # Experiment execution logs
│   ├── slither_log.txt
│   ├── mythril_log.txt
│   ├── llm_base_log.txt
│   └── llm_base_terminal_log.txt
└── screenshots/                      # Experiment process records
```

## Quick Start

### Prerequisites

- Python 3.11+
- OpenAI API Key (for GPT-4.1-mini access)
- Slither (for static analysis)
- Mythril (for symbolic execution)

### Installation

```bash
# Clone the repository
git clone https://github.com/bigear88/defi-llm-vulnerability-detection.git
cd defi-llm-vulnerability-detection

# Install dependencies
pip install -r requirements.txt

# Install analysis tools
pip install slither-analyzer solc-select mythril

# Install Solidity compilers
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.0 0.8.17 0.8.20
```

### Running Experiments

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
```

## Datasets

This project uses the following datasets:

| Dataset | Size | Description |
|---------|------|-------------|
| SmartBugs Curated | 143 contracts | Labeled vulnerability dataset with known vulnerabilities |
| SmartBugs Wild | 100 contracts (sampled) | Safe contracts from 47,398 real-world deployed contracts |
| **Total** | **243 contracts** | **Combined evaluation dataset** |

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

## Methodology

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
│  RAG Retrieval  │ (TF-IDF Knowledge Base)
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

- Precision, Recall, F1-Score
- False Positive Rate (FPR), Specificity
- Average Detection Time per Contract
- Total Token Usage (LLM cost tracking)

## Experiment Results

All experiments were conducted on the SmartBugs dataset (243 contracts). Results are from **real tool execution**, not simulated.

### Performance Comparison

| Method | Recall | Precision | F1 Score | FPR | Avg Time (s) |
|--------|--------|-----------|----------|-----|---------------|
| **Slither** (Static Analysis) | 95.10% | 60.99% | 74.32% | 87.00% | 2.20 |
| **Mythril** (Symbolic Execution) | 45.00% | 100.00% | 62.07% | 0.00% | 36.24 |
| **LLM Base** (GPT-4.1-mini) | 99.30% | 59.17% | 74.15% | 98.00% | 2.81 |
| **LLM + RAG** | 97.90% | 80.92% | **88.61%** | 33.00% | 2.76 |
| **Hybrid** (Slither + LLM + RAG) | 98.60% | 72.31% | 83.43% | 54.00% | 5.76 |

### Key Findings

1. **LLM + RAG achieves the highest F1 score (88.61%)**, demonstrating that retrieval-augmented generation significantly improves detection accuracy.
2. **RAG dramatically reduces false positive rate**: From 98.00% (LLM Base) to 33.00% (LLM + RAG), a 66.3% reduction.
3. **Mythril has zero false positives but low recall (45.00%)**: Extremely conservative, only flagging confirmed vulnerabilities.
4. **Slither is fast but noisy**: High recall (95.10%) but very high FPR (87.00%).
5. **The Hybrid framework balances speed and accuracy**: Strong recall (98.60%) with reasonable processing time (5.76s).

## References

1. Sun, D., et al. (2024). GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis. ICSE 2024.
2. Xia, Y., et al. (2024). AuditGPT: Auditing Smart Contracts with ChatGPT. arXiv:2404.04306.
3. Wei, Z., et al. (2025). Advanced Smart Contract Vulnerability Detection via LLM-Powered Multi-Agent Systems. IEEE TSE.
4. Durieux, T., et al. (2020). Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts. ICSE 2020.
5. Feist, J., et al. (2019). Slither: A Static Analysis Framework for Smart Contracts. WETSEB 2019.
6. Mueller, B. (2018). Smashing Ethereum Smart Contracts for Fun and Real Profit. HITB SecConf.

## Author

- **Curtis Chang**
- Advisor: **Dr. David Shou**
- Institution: Department of Computer Science, University of Taipei

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- SmartBugs Team for the curated dataset
- OpenAI for GPT-4.1-mini API access
- Slither Team for the static analysis framework
- Mythril Team for the symbolic execution engine
