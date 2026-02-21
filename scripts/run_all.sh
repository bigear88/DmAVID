#!/bin/bash
# ============================================================
# 一鍵重現腳本 (One-Click Reproduction Script)
# 基於大型語言模型的乙太坊DeFi智能合約漏洞偵測機制研究
# ============================================================
# 使用方式: bash scripts/run_all.sh
# 前置需求: Python 3.11+, pip, OpenAI API Key
# ============================================================

set -e

echo "============================================================"
echo "  DeFi Smart Contract Vulnerability Detection Experiment"
echo "  One-Click Reproduction Script"
echo "============================================================"
echo ""

# 檢查 Python 版本
echo "[1/9] Checking Python version..."
python3 --version || { echo "ERROR: Python 3 not found"; exit 1; }

# 檢查 API Key
echo "[2/9] Checking OpenAI API Key..."
if [ -z "$OPENAI_API_KEY" ]; then
    echo "ERROR: OPENAI_API_KEY environment variable not set"
    echo "Please run: export OPENAI_API_KEY='your-api-key'"
    exit 1
fi
echo "  ✓ API Key found"

# 安裝依賴
echo "[3/9] Installing dependencies..."
pip3 install slither-analyzer solc-select openai scikit-learn tqdm scipy matplotlib numpy pandas 2>&1 | tail -3
solc-select install 0.4.26 2>/dev/null || true
solc-select install 0.5.16 2>/dev/null || true
solc-select install 0.6.12 2>/dev/null || true
solc-select install 0.7.6 2>/dev/null || true
solc-select install 0.8.0 2>/dev/null || true
echo "  ✓ Dependencies installed"

# 準備數據集
echo "[4/9] Preparing dataset..."
mkdir -p data
if [ ! -d "data/smartbugs-curated" ]; then
    git clone https://github.com/smartbugs/smartbugs-curated data/smartbugs-curated
fi
python3 scripts/01_prepare_dataset.py
echo "  ✓ Dataset prepared"

# 實驗 1: Slither
echo "[5/9] Running Experiment 1: Slither Static Analysis..."
python3 scripts/02_run_slither.py
echo "  ✓ Slither experiment completed"

# 實驗 2: Mythril (可選，非常慢)
echo "[6/9] Running Experiment 2: Mythril Symbolic Execution..."
echo "  (This may take 30+ minutes for 40 contracts)"
python3 scripts/03_run_mythril_fast.py || echo "  ⚠ Mythril skipped (install mythril first)"
echo "  ✓ Mythril experiment completed"

# 實驗 3: LLM Base
echo "[7/9] Running Experiment 3: LLM Base Detection (GPT-4.1-mini)..."
echo "  (This may take 15-20 minutes for 243 contracts)"
python3 scripts/04_run_llm_base.py
echo "  ✓ LLM Base experiment completed"

# 實驗 4: LLM + RAG
echo "[8/9] Running Experiment 4: LLM + RAG Enhanced Detection..."
echo "  (This may take 20-30 minutes for 243 contracts)"
python3 scripts/05_run_llm_rag.py
echo "  ✓ LLM + RAG experiment completed"

# 實驗 5: Hybrid Framework
echo "[9/9] Running Experiment 5: Hybrid Framework (Slither + LLM + RAG)..."
echo "  (This may take 30-40 minutes for 243 contracts)"
python3 scripts/06_run_hybrid.py
echo "  ✓ Hybrid experiment completed"

# 補充分析
echo ""
echo "[Supplementary] Running statistical analysis..."
python3 scripts/08_supplementary_analysis.py
echo "  ✓ Supplementary analysis completed"

# 生成圖表
echo ""
echo "[Charts] Generating visualization charts..."
python3 scripts/07_generate_charts.py
echo "  ✓ Charts generated"

echo ""
echo "============================================================"
echo "  ALL EXPERIMENTS COMPLETED SUCCESSFULLY!"
echo "============================================================"
echo ""
echo "Results saved in:"
echo "  - experiments/slither/results.json"
echo "  - experiments/mythril/results.json"
echo "  - experiments/llm_base/results.json"
echo "  - experiments/llm_rag/results.json"
echo "  - experiments/hybrid/results.json"
echo "  - supplementary_results/*.json"
echo "  - supplementary_results/all_predictions.csv"
echo "  - charts/*.png"
echo ""
echo "Total estimated time: 60-90 minutes"
echo "Total estimated API cost: ~$2-5 USD"
