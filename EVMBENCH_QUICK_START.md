# EVMbench Scripts - Quick Start Guide

## Files Modified

```
scripts/
├── 09_run_evmbench_detect.py         ✅ REWRITTEN
├── 10_run_evmbench_hybrid.py         ✅ REWRITTEN
└── 10_run_evmbench_hybrid_3modes.py  ✅ REWRITTEN
```

## What Changed

### 1. Hardcoded Paths → Project-Relative Paths
```python
# BEFORE: /home/ubuntu/...
# AFTER:
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
EVMBENCH_DATA_DIR = os.path.join(BASE_DIR, "data", "evmbench", "audits")
```

### 2. Hardcoded RAG String → ChromaDB Vector Store
```python
# BEFORE: RAG_KNOWLEDGE = """...""" (static 500 lines)
# AFTER:
knowledge_base = VulnKnowledgeBase(CHROMA_DIR, COLLECTION_NAME, client)
retrieved = knowledge_base.retrieve(code, top_k=5)
rag_context = build_rag_context(retrieved)
```

### 3. Hardcoded Clone URLs → Dockerfile Parsing
```python
# BEFORE: url = f"https://github.com/evmbench-org/{audit_id}.git"
# AFTER:
repo_info = parse_dockerfile(audit_id)  # Parses GitHub URL from Dockerfile
clone_repo_at_commit(audit_id, repo_info)  # Checks out specific commit
```

### 4. No Pre-filtering → GPTScan-Style Slither Pre-filtering
```python
# NEW:
slither_findings = run_slither_quick(filepath)
filtered = prefilter_slither_findings(findings, code, solc_version)
# Removes 15+ known false-positive Slither checks
```

### 5. Basic Logging → Structured Logging
```python
# NEW:
logger.info(f"[{i+1}/{len(SAMPLE_AUDITS)}] {audit_id}")
logger.info(f"  Gold: {len(gold_vulns)} vulns")
# Logs to both console and file: experiments/evmbench/logs/detect_*.log
```

## Quick Usage

### Prerequisites
```bash
# Install ChromaDB
python build_knowledge_base.py

# Set API key
export OPENAI_API_KEY="sk-..."
```

### Run Scripts
```bash
# Script 1: LLM+RAG Detection
python scripts/09_run_evmbench_detect.py

# Script 2: Hybrid Two-Stage Fusion
python scripts/10_run_evmbench_hybrid.py

# Script 3: Three-Mode Comparison
python scripts/10_run_evmbench_hybrid_3modes.py
```

### View Results
```bash
# JSON results
cat experiments/evmbench/evmbench_detect_results.json

# CSV summary
cat experiments/evmbench/evmbench_detect_per_audit.csv

# Logs
tail -f experiments/evmbench/logs/detect_*.log
```

## Architecture Diagram

```
Script 1: 09_run_evmbench_detect.py
│
├─ Parse Dockerfile → get GitHub URL + commit
├─ Clone repo at commit hash
├─ Extract Solidity files
├─ ChromaDB RAG retrieval
├─ LLM detection prompt
├─ LLM Judge: is vulnerability detected?
└─ Output: detection_score per audit

Script 2: 10_run_evmbench_hybrid.py
│
├─ Stage 1: Independent LLM+RAG (no Slither)
├─ Stage 2: CONDITIONAL Slither-guided re-eval
│   └─ Only if: Stage1=SAFE AND Slither flags AND conf<0.75
├─ Pre-filter Slither to remove false positives
├─ LLM Judge: is vulnerability detected?
└─ Output: detection_score + stage breakdown

Script 3: 10_run_evmbench_hybrid_3modes.py
│
├─ Mode 1: Original (Slither → LLM)
├─ Mode 2: Verification (LLM with Slither hints)
├─ Mode 3: Context (LLM primary, Slither advisory)
├─ Compare detection scores across modes
└─ Output: best_mode + comparison metrics
```

## Key Improvements Checklist

- [x] **Path Resolution**: All paths relative to project root (SCRIPT_DIR/BASE_DIR pattern)
- [x] **RAG Integration**: ChromaDB semantic vector search with proper `VulnKnowledgeBase` class
- [x] **Dockerfile Parsing**: Extracts GitHub URL and commit hash for accurate repo cloning
- [x] **Slither Pre-filtering**: GPTScan-style domain-specific rules (15+ check types)
- [x] **Two-Stage Fusion**: Stage 1 (independent LLM+RAG) → Stage 2 (conditional Slither-guided)
- [x] **Anti-Bias Prompts**: Stage 2 explicitly warns about Slither's ~84% FPR
- [x] **Environment Variables**: Support for OPENAI_API_KEY via dotenv
- [x] **Structured Logging**: Timestamped logs to both console and file
- [x] **Error Handling**: Graceful fallbacks for network errors, timeouts, JSON parsing
- [x] **Type Hints**: Full type annotations throughout
- [x] **Reproducibility**: Fixed seed=42 for deterministic LLM outputs
- [x] **Production Quality**: Timeouts, rate limiting, encoding safety, path safety

## Configuration

### Environment Variables
```bash
export OPENAI_API_KEY="sk-proj-..."  # OpenAI API key
# OR create .env file:
OPENAI_API_KEY=sk-proj-...
```

### Model and Hyperparameters
All scripts use:
- **Model**: `gpt-4.1-mini`
- **Embedding Model**: `text-embedding-3-small`
- **RAG Top-K**: 5 (retrieve top 5 relevant vulnerability patterns)
- **Temperature**: 0.1 (deterministic LLM behavior)
- **Seed**: 42 (reproducible outputs)

Modifiable in each script:
```python
LLM_MODEL = "gpt-4.1-mini"
EMBEDDING_MODEL = "text-embedding-3-small"
RAG_TOP_K = 5
```

## Data Flow

### Input
```
data/evmbench/audits/
├── 2024-01-curves/
│   ├── config.yaml (vulnerability definitions)
│   ├── Dockerfile (GitHub URL + commit)
│   └── findings/ (gold standard findings)
├── ... (10 audits total)
└── 2026-01-tempo-stablecoin-dex/
```

### Processing
```
1. Parse Dockerfile (GitHub URL + commit)
2. Clone repo at specific commit
3. Extract Solidity source files
4. Retrieve RAG context from ChromaDB
5. Run LLM detection pipeline
6. Judge detected vulnerabilities against gold standard
```

### Output
```
experiments/evmbench/
├── logs/
│   ├── detect_20260221_103000.log
│   ├── hybrid_20260221_103500.log
│   └── 3modes_20260221_104000.log
├── evmbench_detect_results.json
├── evmbench_detect_per_audit.csv
├── evmbench_hybrid_results.json
├── evmbench_hybrid_per_audit.csv
├── evmbench_3modes_results.json
└── ...
```

## Metrics Explained

### Detection Score
```
detect_score = num_detected / num_gold_vulnerabilities

Example: 3/40 = 0.075 = 7.5%
```

Higher is better. Measures recall on gold standard vulnerabilities.

### Tokens Used
```
tokens_used = OpenAI API token consumption

Example: 45,000 tokens for 10 audits
Cost: ~$0.45 at gpt-4.1-mini rates
```

Useful for cost estimation when scaling to full benchmark.

### Time per Audit
```
time_seconds = LLM inference time per audit (excluding I/O, judging, Slither)

Example: 23.45 seconds average per audit
Total: ~4 minutes for 10 audits
```

### Stage 2 Triggers (Hybrid only)
```
stage2_triggered = How many contracts triggered Stage 2 re-evaluation

Example: 5/10 triggered Stage 2 (50%)
```

Lower is better - Stage 2 should only trigger when necessary.

## Testing

### Verify Syntax
```bash
python -m py_compile scripts/09_run_evmbench_detect.py
python -m py_compile scripts/10_run_evmbench_hybrid.py
python -m py_compile scripts/10_run_evmbench_hybrid_3modes.py
```

### Dry Run (First Audit Only)
Edit `SAMPLE_AUDITS` to test:
```python
SAMPLE_AUDITS = ["2024-01-curves"]  # Test with just one audit
```

Then run and check:
1. Dockerfile parsing works
2. Repository clones successfully
3. Solidity files extracted
4. RAG retrieval returns results
5. LLM generates valid JSON
6. Judge function works

## Troubleshooting

### "ChromaDB not found at..."
```bash
# Solution: Build knowledge base first
python scripts/build_knowledge_base.py
```

### "Failed to clone repository"
```bash
# Check Dockerfile parsing works
python -c "from scripts.s09_run_evmbench_detect import parse_dockerfile; print(parse_dockerfile('2024-01-curves'))"

# Check Git connectivity
git clone https://github.com/... /tmp/test
```

### "Invalid JSON response from LLM"
```bash
# This is handled gracefully in all scripts
# Check the raw_response in logs for debugging

# Can manually test prompt:
python -c "
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(
    model='gpt-4.1-mini',
    messages=[{'role': 'user', 'content': 'Output JSON: {\"test\": true}'}],
    temperature=0.1
)
print(response.choices[0].message.content)
"
```

### "Slither analysis failed"
```bash
# Verify Slither installation
slither --version
solc-select versions

# Install required Solidity versions
solc-select install 0.8.0
solc-select install 0.7.6
```

## Next Steps

1. **Run on full benchmark**: Modify `SAMPLE_AUDITS` to include all 40 audits
2. **Analyze results**: Compare detection scores across three modes
3. **Optimize prompts**: A/B test different LLM prompts for Stage 1/2
4. **Parallel execution**: Run multiple audits concurrently for faster results
5. **Extended evaluation**: Test on SmartBugs, DeFIVulns, or other benchmarks

## Citation

If using these scripts, cite:
- EVMbench: Paradigm + OpenAI (2026-02-18)
- GPTScan: Sun et al., ICSE 2024
- This implementation: DeFi LLM Vulnerability Detection Project

## License

Same as parent project (check LICENSE file)

## Support

For issues or questions:
1. Check `EVMBENCH_SCRIPTS_MIGRATION.md` for detailed documentation
2. Review script docstrings for architecture explanation
3. Check logs in `experiments/evmbench/logs/` for detailed error messages
4. Run single audit first to debug issues before scaling
