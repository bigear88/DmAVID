# DeFi Smart Contract Vulnerability Detection using LLM

基於大型語言模型的乙太坊 DeFi 智能合約漏洞偵測機制研究

A Study on the Vulnerability Detection Mechanism of Ethereum DeFi Smart Contracts Based on Large Language Models

## 📋 Overview

This research project implements a hybrid vulnerability detection framework for Ethereum DeFi smart contracts, combining Large Language Models (LLMs) with traditional static analysis tools.

### Key Features

- **LLM-based Detection**: Leverages GPT-4/ChatGPT for semantic understanding of smart contract code
- **RAG Enhancement**: Retrieval-Augmented Generation with DeFi-specific knowledge base
- **Hybrid Approach**: Combines static analysis (Slither) with LLM semantic analysis
- **DeFi-Specific**: Focuses on DeFi protocol vulnerabilities including flash loan attacks, price oracle manipulation, and reentrancy

## 🏗️ Project Structure

```
defi-llm-vulnerability-detection/
├── src/
│   ├── preprocessing/      # Data preprocessing modules
│   │   ├── __init__.py
│   │   ├── contract_parser.py
│   │   └── normalizer.py
│   ├── detection/          # Core detection modules
│   │   ├── __init__.py
│   │   ├── llm_detector.py
│   │   ├── static_analyzer.py
│   │   └── hybrid_detector.py
│   ├── evaluation/         # Evaluation and metrics
│   │   ├── __init__.py
│   │   ├── metrics.py
│   │   └── visualizer.py
│   └── utils/              # Utility functions
│       ├── __init__.py
│       ├── config.py
│       └── logger.py
├── data/
│   ├── raw/                # Raw datasets
│   └── processed/          # Processed datasets
├── configs/                # Configuration files
│   └── config.yaml
├── scripts/                # Execution scripts
│   ├── run_experiment.py
│   └── generate_report.py
├── results/                # Experiment results
├── docs/                   # Documentation
├── requirements.txt
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- OpenAI API Key (for GPT-4 access)
- Slither (for static analysis)

### Installation

```bash
# Clone the repository
git clone https://github.com/curtis/defi-llm-vulnerability-detection.git
cd defi-llm-vulnerability-detection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Slither
pip install slither-analyzer
```

### Configuration

1. Copy the example configuration:
```bash
cp configs/config.example.yaml configs/config.yaml
```

2. Set your API keys:
```yaml
# configs/config.yaml
openai:
  api_key: "your-openai-api-key"
  model: "gpt-4.1-mini"
```

### Running Experiments

```bash
# Preprocess datasets
python scripts/preprocess_data.py

# Run vulnerability detection
python scripts/run_experiment.py --config configs/config.yaml

# Generate evaluation report
python scripts/generate_report.py --results results/experiment_results.json
```

## 📊 Datasets

This project uses the following datasets:

| Dataset | Size | Description |
|---------|------|-------------|
| SmartBugs Curated | 152 contracts | Labeled vulnerability dataset |
| DeFi Attack Incidents | 127+ cases | Real-world DeFi attack cases |
| DeFi Protocols | 3 protocols | Uniswap, Aave, Compound contracts |

## 🔬 Methodology

### 1. Data Preprocessing

- Contract code normalization
- Syntax-aware chunking using tree-sitter
- Feature extraction

### 2. Hybrid Detection Framework

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
│  RAG Retrieval  │
│ Knowledge Base  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LLM Analysis   │ (GPT-4)
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

### 3. Evaluation Metrics

- Precision
- Recall
- F1-Score
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Detection Time

## 📈 Results

### Baseline Comparison

| Method | Precision | Recall | F1-Score |
|--------|-----------|--------|----------|
| Slither | TBD | TBD | TBD |
| GPTScan | TBD | TBD | TBD |
| AuditGPT | TBD | TBD | TBD |
| **Ours** | TBD | TBD | TBD |

## 📚 References

1. Sun, D., et al. (2024). GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis. ICSE 2024.
2. Xia, Y., et al. (2024). AuditGPT: Auditing Smart Contracts with ChatGPT. arXiv:2404.04306.
3. Wei, Z., et al. (2025). Advanced Smart Contract Vulnerability Detection via LLM-Powered Multi-Agent Systems. IEEE TSE.

## 👤 Author

- **張宏睿 (Curtis Chang)**
- Advisor: **壽大衛 博士 (Dr. David Shou)**
- Institution: 臺北市立大學資訊科學系 (Department of Computer Science, University of Taipei)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- SmartBugs Team for the curated dataset
- OpenAI for GPT-4 API access
- Slither Team for the static analysis tool
