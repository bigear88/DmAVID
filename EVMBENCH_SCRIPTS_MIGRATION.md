# EVMbench Scripts Migration - Complete Rewrite

## Overview

Successfully rewrote three EVMbench experiment scripts to address critical architectural issues and implement best practices for DeFi smart contract vulnerability detection.

## Files Updated

1. **`scripts/09_run_evmbench_detect.py`** - LLM+RAG Detection on Gold Standard Vulnerabilities
2. **`scripts/10_run_evmbench_hybrid.py`** - Hybrid Verification Mode (Two-Stage Fusion)
3. **`scripts/10_run_evmbench_hybrid_3modes.py`** - Three-Mode Comparison (Original vs Verification vs Context)

## Major Improvements

### 1. Path Resolution (Relative to Project Root)

**Problem**: Hardcoded paths like `/home/ubuntu/...` made scripts non-portable.

**Solution**: All paths now relative to project root using the pattern:
```python
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)

# Then all paths computed relative to BASE_DIR
EVMBENCH_DATA_DIR = os.path.join(BASE_DIR, "data", "evmbench", "audits")
EVMBENCH_REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
RESULTS_DIR = os.path.join(BASE_DIR, "experiments", "evmbench")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")
```

This matches the architecture pattern used in `06_run_hybrid.py`.

### 2. ChromaDB RAG Integration

**Problem**: Scripts used hardcoded `RAG_KNOWLEDGE` string instead of the project's ChromaDB vector store.

**Solution**: Implemented proper `VulnKnowledgeBase` class that:
- Loads ChromaDB persistent client from `data/chroma_kb/`
- Performs semantic vector retrieval with `collection.query()`
- Retrieves relevant vulnerability patterns based on code similarity
- Supports `retrieve(query, top_k=5)` for flexible knowledge lookup

```python
class VulnKnowledgeBase:
    """ChromaDB-based vulnerability knowledge retrieval for RAG."""

    def __init__(self, chroma_dir: str, collection_name: str, llm_client: OpenAI):
        self.client = chromadb.PersistentClient(path=chroma_dir)
        self.collection = self.client.get_collection(collection_name)
        self.entry_count = self.collection.count()

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict]:
        """Retrieve top-k vulnerability knowledge entries."""
        results = self.collection.query(query_texts=[query], n_results=top_k)
        # ... parse and return formatted entries
```

### 3. Dockerfile Parsing for Repository Cloning

**Problem**: Scripts attempted to clone from hardcoded `evmbench-org` GitHub org which may not be correct. No support for specific commit hashes.

**Solution**: Implemented `parse_dockerfile()` function that:
- Parses GitHub URL from Dockerfile using regex: `https://github.com/([^\s/]+)/([^\s/.]+)`
- Extracts commit hash from `git checkout` command
- Returns structured dict with `url` and `commit` fields
- Gracefully handles missing Dockerfiles

```python
def parse_dockerfile(audit_id: str) -> Optional[Dict[str, str]]:
    """Parse Dockerfile to extract GitHub repo URL and commit hash."""
    # Regex patterns for https://github.com/org/repo and git checkout <hash>
    github_match = re.search(r'https://github\.com/([^\s/]+)/([^\s/.]+)', content)
    commit_match = re.search(r'git checkout\s+([a-f0-9]{40}|[a-f0-9]{7})', content)

    return {"url": f"https://github.com/{org}/{repo}.git", "commit": commit}
```

The `clone_repo_at_commit()` function then:
- Clones with `--depth=1` for speed
- Fetches the specific commit with `git fetch --depth=100`
- Checks out the exact commit hash for reproducibility

### 4. GPTScan-Style Pre-filtering for Slither

**Problem**: Scripts didn't use GPTScan-style domain-specific pre-filtering to remove Slither false positives before sending to LLM.

**Solution**: Implemented `prefilter_slither_findings()` function that:
- Uses domain-specific validation rules from `SLITHER_FP_FILTERS` dictionary
- Filters based on code patterns (require_patterns, exclude_patterns)
- Checks Solidity version requirements
- Removes known false-positive checks (naming-convention, assembly, dead-code, etc.)

This prevents false-positive contamination in Stage 2 of the hybrid pipeline and matches the implementation from `06_run_hybrid.py`.

### 5. Environment Variables and Logging

**Problem**: No support for environment variable configuration or structured logging.

**Solution**: Added:
- **`dotenv` support**: Uses `load_dotenv()` to load `OPENAI_API_KEY` from `.env` files
- **Structured logging**: All scripts log to both file and console with timestamps:
  ```python
  LOG_FILE = os.path.join(RESULTS_DIR, "logs", f"detect_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
  logging.basicConfig(
      level=logging.INFO,
      format='%(asctime)s - %(levelname)s - %(message)s',
      handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
  )
  ```

### 6. Two-Stage Fusion Architecture (Hybrid Script)

**Problem**: Hybrid script didn't implement proper two-stage fusion with conditional Stage 2 triggering.

**Solution**: Implemented in `10_run_evmbench_hybrid.py`:

**Stage 1**: Independent LLM+RAG analysis (no Slither influence)
- Retrieves relevant vulnerability patterns from ChromaDB
- LLM makes independent judgment
- Returns confidence score

**Stage 2**: Conditional Slither-guided re-evaluation (only if triggered)
- Triggered ONLY when ALL three conditions met:
  1. Stage 1 LLM said SAFE
  2. Slither found HIGH/MEDIUM alerts that pass pre-filtering
  3. Stage 1 confidence < threshold (default 0.75)
- Anti-bias prompt warns about Slither's ~84% false positive rate
- LLM only flips verdict if finding concrete exploitable flaws

### 7. Three-Mode Comparison Architecture

**Problem**: Original 3-modes script had hardcoded paths and no proper RAG integration.

**Solution**: Redesigned in `10_run_evmbench_hybrid_3modes.py` to compare:

1. **ORIGINAL MODE**: Slither findings fed directly to LLM (LLM tends to follow Slither)
2. **VERIFICATION MODE**: LLM as final judge with pre-filtered Slither as hints
3. **CONTEXT MODE**: LLM primary decision-maker, Slither as advisory context

All modes:
- Use shared ChromaDB RAG for consistency
- Share Slither analysis across modes (run once, reuse)
- Share pre-filtering logic
- Output comparable detection scores

## Technical Architecture

### Common Components (All Scripts)

```
VulnKnowledgeBase
├── ChromaDB PersistentClient
├── Collection: "vuln_knowledge"
├── Method: retrieve(query, top_k=5)
└── Returns: [Dict with category, title, vulnerability_pattern, safe_pattern]

build_rag_context(retrieved_entries)
├── Formats top-3 retrieved entries
├── Includes: category, title, description, patterns
└── Returns: Formatted context string for LLM prompts

Repository Management
├── parse_dockerfile(audit_id) → {"url": "...", "commit": "..."}
├── clone_repo_at_commit(audit_id, repo_info) → repo_dir
├── extract_solidity_files(repo_dir) → [{"path": "...", "content": "..."}]
└── load_audit_config(audit_id) → {"vulnerabilities": [gold_vulns]}

Slither Analysis
├── detect_solc_version(code) → "0.8.0" (extracted from pragma)
├── run_slither_quick(filepath) → [findings]
└── prefilter_slither_findings(findings, code, solc_version) → [filtered]

Judging
└── judge_detection(found_vulns, gold_vulns) → num_detected (LLM judge)
```

### Script-Specific Components

#### 09_run_evmbench_detect.py
```
run_llm_rag_detect(audit_id, sol_files, knowledge_base)
├── RAG retrieval via knowledge_base.retrieve()
├── Build detection prompt with RAG context
├── LLM generates JSON: {vulnerabilities: [...]}
└── Returns: {num_found, time_seconds, tokens_used, error}

Main Loop
├── For each audit in SAMPLE_AUDITS (10 audits = 25% of 40)
├── Load config with gold vulnerabilities
├── Parse Dockerfile → clone repo at commit
├── Extract Solidity files
├── Run LLM+RAG detection
├── Judge each gold vulnerability (detected or not)
└── Compute detection_score = num_detected / num_gold
```

#### 10_run_evmbench_hybrid.py
```
run_stage1(code, knowledge_base) → Dict
├── Retrieves RAG context
├── LLM analysis WITHOUT Slither influence
├── Returns: {predicted_vulnerable, confidence, reasoning}

format_slither_alerts(findings) → str
└── Formats HIGH/MEDIUM/LOW/INFO with check names

run_stage2(code, slither_findings, stage1) → Optional[Dict]
├── Triggered only if: Stage1=SAFE AND Slither has HIGH/MED AND conf < 0.75
├── Anti-bias prompt warns about Slither's 84% FPR
├── LLM re-evaluates code with Slither context
└── Returns: {predicted_vulnerable, verdict_changed, ...} or None

hybrid_decision(code, slither_findings, knowledge_base) → Dict
├── Stage 1: Independent LLM+RAG
├── Stage 2: Conditional Slither-guided (if triggered)
├── Returns combined result with both stage outputs
```

#### 10_run_evmbench_hybrid_3modes.py
```
run_mode_original(contract_text, slither_findings_text, kb) → Dict
├── Slither findings fed directly to LLM
├── LLM tends to follow Slither findings
└── Returns: {vulns}

run_mode_verification(contract_text, slither_findings_text, kb) → Dict
├── Slither findings provided for reference only
├── LLM makes independent assessment
└── Returns: {vulns}

run_mode_context(contract_text, slither_findings_text, kb) → Dict
├── Slither output marked as CONTEXT
├── LLM primary decision-maker
└── Returns: {vulns}

Main Comparison Loop
├── For each audit:
│   ├── Run Slither once (shared across modes)
│   ├── Run all 3 modes in parallel logic
│   ├── Judge each mode's findings
│   └── Collect detection scores per mode
├── Compute overall scores per mode
└── Return comparison with best_mode selection
```

## Output Format

### Detection Results (09_run_evmbench_detect.py)

**File**: `experiments/evmbench/evmbench_detect_results.json`

```json
{
  "experiment": "EVMbench Detect - LLM+RAG",
  "model": "gpt-4.1-mini",
  "embedding_model": "text-embedding-3-small",
  "rag_top_k": 5,
  "timestamp": "2026-02-21T10:30:00.000000",
  "num_audits": 10,
  "total_vulnerabilities": 40,
  "total_detected": 3,
  "overall_detect_score": 0.075,
  "total_time_seconds": 245.32,
  "total_tokens": 45000,
  "avg_time_per_audit": 24.53,
  "per_audit_results": [
    {
      "audit_id": "2024-01-curves",
      "status": "completed",
      "num_gold_vulns": 4,
      "num_found_by_llm": 2,
      "num_detected": 1,
      "detect_score": 0.25,
      "time_seconds": 23.45,
      "rag_time_seconds": 0.234,
      "tokens_used": 4500,
      "judge_results": [
        {
          "vuln_id": "H-1",
          "vuln_title": "Reentrancy in withdraw()",
          "detected": true,
          "reasoning": "..."
        }
      ]
    }
  ]
}
```

**CSV**: `experiments/evmbench/evmbench_detect_per_audit.csv`

```
audit_id,status,num_gold_vulns,num_found_by_llm,num_detected,detect_score,time_seconds,tokens_used
2024-01-curves,completed,4,2,1,0.25,23.45,4500
...
```

### Hybrid Results (10_run_evmbench_hybrid.py)

Similar structure with `overall_detect_score` and per-audit results.

### Three-Mode Comparison (10_run_evmbench_hybrid_3modes.py)

**File**: `experiments/evmbench/evmbench_3modes_results.json`

```json
{
  "experiment": "EVMbench Three-Mode Comparison",
  "model": "gpt-4.1-mini",
  "timestamp": "2026-02-21T11:00:00.000000",
  "results": {
    "original": {
      "total_vulns": 40,
      "total_detected": 2,
      "score": 0.05,
      "audits": [...]
    },
    "verification": {
      "total_vulns": 40,
      "total_detected": 4,
      "score": 0.10,
      "audits": [...]
    },
    "context": {
      "total_vulns": 40,
      "total_detected": 2,
      "score": 0.05,
      "audits": [...]
    }
  },
  "comparison": {
    "original_score": 0.05,
    "verification_score": 0.10,
    "context_score": 0.05,
    "best_mode": "verification"
  }
}
```

## EVMbench Dataset Structure

Scripts expect the following structure:

```
data/evmbench/audits/
├── 2024-01-curves/
│   ├── config.yaml          # Vulnerability definitions with ids/titles
│   ├── Dockerfile           # Contains GitHub URL + commit hash
│   └── findings/
│       ├── gold_audit.md
│       ├── H-1.md
│       ├── H-2.md
│       └── ...
├── 2024-03-taiko/
│   ├── config.yaml
│   ├── Dockerfile
│   └── findings/
└── ... (10 audits total = 25% of 40-audit benchmark)

data/evmbench_repos/              # Cloned repositories
├── 2024-01-curves/              # Repository clone at specific commit
├── 2024-03-taiko/
└── ...

experiments/evmbench/            # Results output
├── logs/
│   ├── detect_*.log
│   ├── hybrid_*.log
│   └── 3modes_*.log
├── evmbench_detect_results.json
├── evmbench_detect_per_audit.csv
├── evmbench_hybrid_results.json
├── evmbench_hybrid_per_audit.csv
├── evmbench_3modes_results.json
└── ...
```

## Sample Audits (10 Selected = 25%)

1. `2024-01-curves` - 4 vulnerabilities (DeFi curves library)
2. `2024-03-taiko` - 5 vulnerabilities (L2 blockchain)
3. `2024-05-olas` - 2 vulnerabilities (Tokenomics)
4. `2024-07-basin` - 2 vulnerabilities (DeFi aggregator)
5. `2024-01-renft` - 6 vulnerabilities (NFT rental)
6. `2024-06-size` - 4 vulnerabilities (Lending protocol)
7. `2024-08-phi` - 6 vulnerabilities (Social protocol)
8. `2024-12-secondswap` - 3 vulnerabilities (DEX)
9. `2025-04-forte` - 5 vulnerabilities (Recent protocol)
10. `2026-01-tempo-stablecoin-dex` - 3 vulnerabilities (Latest protocol)

**Total**: 40 gold standard vulnerabilities across 10 diverse audits

## Expected Results (Baselines for Comparison)

From existing experiments:
- **Slither standalone**: 0/40 detected (0.00%)
- **Mythril standalone**: 0/40 detected (0.00%)
- **LLM+RAG**: 3/40 detected (7.50%)
- **Hybrid (Original)**: 2/40 detected (5.00%)
- **Hybrid (Verification)**: 4/40 detected (10.00%)
- **Hybrid (Context)**: 2/40 detected (5.00%)

New scripts should produce comparable or improved scores with proper ChromaDB integration and optimized prompts.

## Prerequisites

### Installation
```bash
pip install -r requirements.txt
pip install -r requirements_rag.txt
pip install chromadb openai python-dotenv pyyaml
```

### Setup
1. **Build ChromaDB knowledge base** (required):
   ```bash
   python scripts/build_knowledge_base.py
   ```

2. **Set OPENAI_API_KEY**:
   ```bash
   export OPENAI_API_KEY="sk-..."
   # or create .env file with OPENAI_API_KEY=...
   ```

3. **Install Slither and solc-select**:
   ```bash
   pip install slither-analyzer solc-select
   solc-select install 0.8.0  # Install required Solidity versions
   ```

### Run Scripts

```bash
# Detect mode
python scripts/09_run_evmbench_detect.py

# Hybrid mode (two-stage fusion)
python scripts/10_run_evmbench_hybrid.py

# Three-mode comparison
python scripts/10_run_evmbench_hybrid_3modes.py
```

## Key Metrics

### Detection Score (Primary Metric)
```
detect_score = num_detected / num_gold_vulnerabilities

Range: 0.0 - 1.0 (0% - 100%)
```

Per audit and overall across all 10 audits.

### Secondary Metrics
- **Time per audit**: LLM inference time (excluding Slither, I/O, judging)
- **Tokens used**: OpenAI API token consumption (for cost tracking)
- **Stage 2 triggers**: For hybrid mode (how often re-evaluation occurred)
- **Verdict changes**: For hybrid mode (how often Stage 2 flipped Stage 1 decision)

## Production Quality Features

1. **Error Handling**: Graceful fallback for network errors, timeouts, JSON parsing failures
2. **Logging**: Comprehensive logs with timestamps for debugging and audit trails
3. **Rate Limiting**: `time.sleep()` between API calls to respect rate limits
4. **Timeout Protection**: Subprocess timeouts for Git and Slither operations
5. **File Encoding**: UTF-8 with error='ignore' for robust file reading
6. **Path Safety**: All paths computed relative to project root, no hardcoded absolute paths
7. **Configuration**: Environment variable support for OPENAI_API_KEY
8. **Reproducibility**: Fixed seed=42 for LLM temperature=0.1 calls
9. **Type Hints**: Full type annotations for better code maintainability

## Compatibility

- **Python**: 3.8+
- **OpenAI API**: Uses `gpt-4.1-mini` model (specified in scripts)
- **ChromaDB**: Persistent client, supports local vector database
- **Slither**: v0.9+ for JSON output support
- **Git**: For repository cloning and commit checkout
- **Operating System**: Linux/macOS/Windows with Python installed

## Future Enhancements

1. **Parallel Execution**: Run multiple audits concurrently to reduce total time
2. **Caching**: Cache Slither results and RAG retrievals per audit
3. **Metrics Dashboard**: Real-time visualization of detection scores
4. **Prompt Optimization**: A/B test different prompts for Stage 1/Stage 2
5. **Extended Benchmarks**: Run on full 40-audit EVMbench dataset
6. **Model Variants**: Test with different LLM models (GPT-4, Gemini, etc.)
7. **Ablation Studies**: Remove RAG, remove Slither pre-filtering, etc.

## References

- **EVMbench**: Paradigm + OpenAI, Released 2026-02-18
- **GPTScan**: Sun et al., ICSE 2024 (pre-filtering strategy)
- **Hybrid Architecture**: Based on two-stage fusion patterns from literature
- **ChromaDB**: Vector database for semantic retrieval
- **OpenAI GPT-4.1-mini**: State-of-the-art LLM for code analysis
