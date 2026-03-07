#!/bin/bash
# =============================================================================
# EVMbench 延伸實驗 Runner
# 執行 2 個實驗:
#   1. Build ChromaDB knowledge base (if not exists)
#   2. LLM+RAG 偵測 (09_run_evmbench_detect.py)
#   3. 混合式框架 Hybrid Verification (10_run_evmbench_hybrid.py)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$SCRIPT_DIR"

# Load environment
if [ -f "$BASE_DIR/.env" ]; then
    export $(grep -v '^#' "$BASE_DIR/.env" | xargs)
fi

# Check prerequisites
if [ -z "$OPENAI_API_KEY" ]; then
    echo "ERROR: OPENAI_API_KEY is not set."
    echo "Please set it in $BASE_DIR/.env or export it in your shell."
    exit 1
fi

echo "============================================================"
echo "EVMbench 延伸實驗 (LLM+RAG + Hybrid Verification)"
echo "Timestamp: $(date -Iseconds)"
echo "Model: gpt-4.1-mini"
echo "============================================================"

# Step 0: Check EVMbench data
EVMBENCH_DIR="$BASE_DIR/data/evmbench/audits"
if [ ! -d "$EVMBENCH_DIR" ] || [ -z "$(ls -A $EVMBENCH_DIR 2>/dev/null)" ]; then
    echo ""
    echo "[Step 0] EVMbench data not found. Cloning frontier-evals..."
    cd /tmp
    git clone --depth 1 https://github.com/openai/frontier-evals.git frontier-evals-tmp
    mkdir -p "$BASE_DIR/data/evmbench"
    cp -r frontier-evals-tmp/project/evmbench/audits "$BASE_DIR/data/evmbench/"
    rm -rf frontier-evals-tmp
    echo "  EVMbench data installed."
    cd "$SCRIPT_DIR"
else
    echo "[Step 0] EVMbench data found at $EVMBENCH_DIR"
fi

# Step 1: Build ChromaDB knowledge base
CHROMA_DIR="$BASE_DIR/data/chroma_kb"
if [ ! -d "$CHROMA_DIR" ] || [ -z "$(ls -A $CHROMA_DIR 2>/dev/null)" ]; then
    echo ""
    echo "[Step 1] Building ChromaDB knowledge base..."
    python build_knowledge_base.py --reset
    echo "  ChromaDB built successfully."
else
    echo "[Step 1] ChromaDB knowledge base already exists at $CHROMA_DIR"
fi

# Step 2: Run LLM+RAG detection
echo ""
echo "============================================================"
echo "[Step 2] 實驗一: EVMbench LLM+RAG 偵測"
echo "============================================================"
python 09_run_evmbench_detect.py
echo "  LLM+RAG detection completed."

# Step 3: Run Hybrid Verification (Two-Stage Fusion)
echo ""
echo "============================================================"
echo "[Step 3] 實驗二: EVMbench 混合式框架 (Hybrid Verification)"
echo "============================================================"
python 10_run_evmbench_hybrid.py
echo "  Hybrid Verification completed."

# Summary
echo ""
echo "============================================================"
echo "ALL EXPERIMENTS COMPLETE"
echo "============================================================"
echo "Results saved to: $BASE_DIR/experiments/evmbench/"
echo ""
ls -la "$BASE_DIR/experiments/evmbench/"*.json 2>/dev/null
echo ""
echo "Log files: $BASE_DIR/experiments/evmbench/logs/"
