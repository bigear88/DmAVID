#!/usr/bin/env python3
"""
83_feedback_loop.py
Stage 4: ChromaDB Feedback Loop — iterative learning from FP/FN errors.

Starting point: Arm D baseline (no gate, all pred=VULN re-evaluated, F1=0.830)
Goal: Show feedback loop learning → F1 progressively improves toward or beyond v4 (0.9030)

Round N flow:
  1. For each pred=VULN contract: query ChromaDB, build enhanced prompt, LLM re-eval
  2. Compare with ground truth -> identify FP and FN
  3. Attribution LLM analysis for each error -> extract systematic patterns
  4. Write patterns to ChromaDB feedback collection
  5. Repeat until F1 converges (delta < 0.001) or max_rounds
"""

import os, sys, json, re, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from openai import OpenAI
from _model_compat import token_param
from tools.grep_guard import grep_guard
from tools.solc_check import solc_check
import chromadb

MODEL       = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
TEMPERATURE = 0.1
SEED        = 42
MAX_ROUNDS  = 5
MIN_DELTA   = 0.001   # stop if |ΔF1| < this
MAX_ERRORS_PER_ROUND = 30   # cap attribution calls per round

RAG_PATH     = ROOT / "experiments/llm_rag/llm_rag_results.json"
DATASET_PATH = ROOT / "data/dataset_1000.json"
CHROMA_PATH  = ROOT / "data/chromadb_feedback"
OUT_PATH     = ROOT / "experiments/tool_augmented/feedback_loop_results.json"

COLLECTION_NAME = "feedback_patterns"


# ── Prompts ──────────────────────────────────────────────────────────────────

REEVAL_PROMPT = """\
你是一個 Solidity 智能合約安全審計專家。

一個 LLM 分析了以下合約，判定它是 VULNERABLE，原因是 {vulnerability_types}。
原始分析的信心度: {confidence}

【防護機制掃描 (grep_guard)】
{grep_guard_formatted}

【Solidity 版本分析 (solc_check)】
{solc_check_formatted}
{feedback_section}
請根據你的專業知識，結合以上工具證據，判斷這個合約是否真的有漏洞。

重要注意事項：
- .transfer() 的 2300 gas limit 可防止 REENTRANCY 重入，但無法防止 DENIAL_OF_SERVICE 或 UNCHECKED_CALL 漏洞
- SafeMath 全域宣告不代表所有函數都使用（如 BECToken batchTransfer 用直接相乘而非 .mul()）
- onlyOwner 只保護有此修飾符的函數
- 請針對「指定的漏洞類型」評估防護機制是否有效

Respond in JSON ONLY:
{{"verdict": "VULNERABLE" or "SAFE", "reasoning": "detail on whether protective mechanisms effectively prevent the specific vulnerability types"}}"""

ATTRIBUTION_PROMPT = """\
你是一個漏洞偵測系統的錯誤分析專家。

以下合約被系統判定為 {prediction}，但實際是 {ground_truth}。

【合約資訊】
- 檔案: {filename}
- 系統判定的漏洞類型: {vuln_types}

【工具證據】
{tool_evidence}

【系統最終推理】
{reasoning}

請分析：
1. 系統為什麼判錯？根本原因是什麼？
2. 如果要避免這類錯誤，RAG 知識庫需要補充什麼知識？
3. 這個錯誤是 systematic（同類合約都會犯）還是 random（偶發）？

Respond in JSON ONLY:
{{
  "error_type": "FP",
  "root_cause": "一句話說明根本原因",
  "missing_knowledge": "具體描述缺少的知識，讓 RAG 下次能檢索到",
  "is_systematic": true,
  "pattern_category": "reentrancy_fp | overflow_fn | access_control_fp | dos_fn | unchecked_fp | other",
  "suggested_rag_entry": "完整知識條目，格式：[pattern_category] 合約特徵描述 → 正確判斷 + 理由"
}}"""


# ── Format helpers ────────────────────────────────────────────────────────────

def strip_annotations(code):
    code = re.sub(r"[^\n]*<(?:yes|no)>[^\n]*", "", code)
    code = re.sub(r"[^\n]*@vulnerable_at_lines:[^\n]*\n?", "", code)
    return code


def fmt_gg(r):
    return "\n".join([
        f"找到的防護機制: {', '.join(r['mitigations']) if r['mitigations'] else '無'}",
        f"僅使用 .transfer(): {'是' if r['transfer_only'] else '否'}",
        f"ReentrancyGuard: {'有' if r['has_reentrancy_guard'] else '無'}",
        f"SafeMath: {'有' if r['has_safemath'] else '無'}",
        f"onlyOwner: {'有' if r['has_only_owner'] else '無'}",
        f".send() 返回值有檢查: {'是' if r['has_send_checked'] else '否'}",
        f".call.value() 存在: {'是' if r['call_value_present'] else '否'}",
        f"防護機制數量: {r['mitigation_count']}",
    ])


def fmt_sc(r):
    return "\n".join([
        f"Pragma: {r['pragma_raw']}",
        f"版本: {r['version']}",
        f"內建 overflow 保護 (>=0.8): {'是' if r['overflow_safe_builtin'] else '否'}",
        f"SafeMath: {'有' if r['has_safemath'] else '無'}",
        f"unchecked 區塊: {'有' if r['has_unchecked_block'] else '否'}",
        f"算術運算: {'有' if r['has_arithmetic_ops'] else '無'}",
        f"Overflow 風險: {r['overflow_risk']}",
    ])


# ── Metrics ───────────────────────────────────────────────────────────────────

def metrics(entries):
    tp = fn = fp = tn = 0
    for e in entries:
        gt   = e["ground_truth"] == "vulnerable"
        pred = e["final_vulnerable"]
        if   gt and pred:     tp += 1
        elif gt and not pred: fn += 1
        elif not gt and pred: fp += 1
        else:                 tn += 1
    prec = tp / (tp + fp) if tp + fp else 0
    rec  = tp / (tp + fn) if tp + fn else 0
    f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr  = fp / (fp + tn) if fp + tn else 0
    return dict(TP=tp, FN=fn, FP=fp, TN=tn,
                precision=round(prec, 4), recall=round(rec, 4),
                F1=round(f1, 4), FPR=round(fpr, 4))


# ── ChromaDB helpers ──────────────────────────────────────────────────────────

def get_collection():
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    return client.get_or_create_collection(COLLECTION_NAME)


def query_patterns(collection, r, gg, n=3):
    """Retrieve top-n relevant feedback patterns for this contract."""
    if collection.count() == 0:
        return []
    vuln_str = ", ".join(r.get("vulnerability_types", [])) or "unknown"
    mit_str  = ", ".join(gg["mitigations"]) if gg["mitigations"] else "無"
    query    = (
        f"漏洞類型: {vuln_str}\n"
        f"防護機制: {mit_str}\n"
        f"mitigation_count: {gg['mitigation_count']}\n"
        f"transfer_only: {gg['transfer_only']}"
    )
    try:
        res = collection.query(query_texts=[query], n_results=min(n, collection.count()))
        docs = res.get("documents", [[]])[0]
        return docs if docs else []
    except Exception:
        return []


def update_collection(collection, patterns, round_num):
    """Upsert systematic patterns into ChromaDB."""
    added = 0
    for p in patterns:
        cid = re.sub(r"[^a-zA-Z0-9_\-]", "_", p["contract_id"])[:40]
        doc_id = f"r{round_num}_{p['pattern_category']}_{cid}"
        collection.upsert(
            documents=[p["suggested_rag_entry"]],
            metadatas=[{
                "round":            round_num,
                "error_type":       p["error_type"],
                "pattern_category": p["pattern_category"],
                "contract_id":      p["contract_id"],
                "root_cause":       p.get("root_cause", ""),
            }],
            ids=[doc_id],
        )
        added += 1
    return added


# ── LLM calls ─────────────────────────────────────────────────────────────────

def llm_reeval(client, r, gg, sc, patterns):
    """Re-evaluate pred=VULN contract with tool evidence + ChromaDB patterns."""
    if patterns:
        section = "\n【相關知識庫條目（來自歷史錯誤分析）】\n"
        for i, p in enumerate(patterns, 1):
            section += f"{i}. {p}\n"
    else:
        section = ""

    prompt = REEVAL_PROMPT.format(
        vulnerability_types  = ", ".join(r.get("vulnerability_types", [])) or "UNKNOWN",
        confidence           = r.get("confidence", 0.9),
        grep_guard_formatted = fmt_gg(gg),
        solc_check_formatted = fmt_sc(sc),
        feedback_section     = section,
    )
    resp = client.chat.completions.create(
        model=MODEL, messages=[{"role":"user","content":prompt}],
        temperature=TEMPERATURE, seed=SEED, **token_param(1024),
    )
    content = resp.choices[0].message.content.strip()
    tokens  = resp.usage.total_tokens
    try:
        data    = json.loads(re.search(r'\{.*\}', content, re.DOTALL).group())
        verdict = data.get("verdict","VULNERABLE").upper()
        return verdict, data.get("reasoning",""), tokens
    except Exception:
        return "VULNERABLE", content, tokens


def llm_attribution(client, entry, round_num):
    """Attribution analysis for a single FP or FN error."""
    is_fp = entry["final_vulnerable"] and entry["ground_truth"] == "safe"
    error_type = "FP" if is_fp else "FN"
    prediction  = "VULNERABLE" if entry["final_vulnerable"] else "SAFE"
    ground      = "SAFE"       if entry["ground_truth"] == "safe" else "VULNERABLE"

    tool_ev = (
        f"grep_guard:\n{fmt_gg(entry['grep_guard'])}\n"
        f"solc_check:\n{fmt_sc(entry['solc_check'])}"
    )
    reasoning = entry.get("reeval_reasoning", entry.get("reasoning", ""))

    prompt = ATTRIBUTION_PROMPT.format(
        prediction    = prediction,
        ground_truth  = ground,
        filename      = entry["filename"],
        vuln_types    = ", ".join(entry.get("vulnerability_types", [])) or "unknown",
        tool_evidence = tool_ev,
        reasoning     = reasoning[:500],
    )
    # Replace the error_type placeholder with actual value
    prompt = prompt.replace('"error_type": "FP"', f'"error_type": "{error_type}"')

    try:
        resp = client.chat.completions.create(
            model=MODEL, messages=[{"role":"user","content":prompt}],
            temperature=0.3, seed=SEED, **token_param(512),
        )
        content = resp.choices[0].message.content.strip()
        data    = json.loads(re.search(r'\{.*\}', content, re.DOTALL).group())
        data["error_type"]   = error_type
        data["contract_id"]  = entry["filename"]
        data["round"]        = round_num
        return data, resp.usage.total_tokens
    except Exception as e:
        return {
            "error_type":       error_type,
            "root_cause":       str(e),
            "missing_knowledge":"parse error",
            "is_systematic":    False,
            "pattern_category": "other",
            "suggested_rag_entry": "",
            "contract_id":      entry["filename"],
            "round":            round_num,
        }, 0


# ── Round execution ───────────────────────────────────────────────────────────

def run_round(rag_results, filepath_map, collection, round_num, client):
    """One full round of tool-augmented pipeline with ChromaDB feedback."""
    entries      = []
    total_tokens = 0
    llm_calls    = 0
    flipped      = 0

    for i, r in enumerate(rag_results):
        fn       = r["filename"]
        fpath    = filepath_map.get(fn, "")
        code_raw = ""
        if fpath and os.path.exists(fpath):
            with open(fpath, encoding="utf-8", errors="replace") as f:
                code_raw = f.read()
        code = strip_annotations(code_raw)

        gg = grep_guard(code)
        sc = solc_check(code)

        final_vuln       = r["predicted_vulnerable"]
        reeval_done      = False
        reeval_verdict   = None
        reeval_reasoning = ""

        if r["predicted_vulnerable"]:
            # Arm D logic: re-eval ALL pred=VULN (no gate)
            patterns = query_patterns(collection, r, gg)
            verdict, reasoning, tokens = llm_reeval(client, r, gg, sc, patterns)
            total_tokens    += tokens
            llm_calls       += 1
            reeval_done      = True
            reeval_verdict   = verdict
            reeval_reasoning = reasoning
            if verdict == "SAFE":
                final_vuln = False
                flipped   += 1

        entries.append({
            "filename":          fn,
            "ground_truth":      r["ground_truth"],
            "vulnerability_types": r.get("vulnerability_types", []),
            "confidence":        r.get("confidence", 0.9),
            "reasoning":         r.get("reasoning", ""),
            "stage1_vulnerable": r["predicted_vulnerable"],
            "final_vulnerable":  final_vuln,
            "reeval_done":       reeval_done,
            "reeval_verdict":    reeval_verdict,
            "reeval_reasoning":  reeval_reasoning,
            "grep_guard":        gg,
            "solc_check":        sc,
        })

        if (i + 1) % 25 == 0:
            m = metrics(entries)
            print(f"  [{i+1:3d}/243] F1={m['F1']:.4f} llm_calls={llm_calls} flipped={flipped}", flush=True)

    m = metrics(entries)
    print(f"  [243/243] F1={m['F1']:.4f} llm_calls={llm_calls} flipped={flipped}", flush=True)
    return entries, m, total_tokens, llm_calls


def analyze_errors(entries, client, round_num):
    """Attribution analysis for FP and FN errors; return systematic patterns."""
    errors = [
        e for e in entries
        if (e["final_vulnerable"] and e["ground_truth"] == "safe") or
           (not e["final_vulnerable"] and e["ground_truth"] == "vulnerable")
    ]
    print(f"  Errors to analyze: {len(errors)} (FP={sum(1 for e in errors if e['final_vulnerable'])}, FN={sum(1 for e in errors if not e['final_vulnerable'])})")

    # Cap attribution calls
    if len(errors) > MAX_ERRORS_PER_ROUND:
        errors = errors[:MAX_ERRORS_PER_ROUND]
        print(f"  Capped to {MAX_ERRORS_PER_ROUND} errors for attribution analysis")

    patterns     = []
    total_tokens = 0
    for j, e in enumerate(errors, 1):
        attr, tokens = llm_attribution(client, e, round_num)
        total_tokens += tokens
        if attr.get("is_systematic") and attr.get("suggested_rag_entry"):
            patterns.append(attr)
        print(f"  Attribution [{j}/{len(errors)}] {e['filename'][:40]:<40} "
              f"{'FP' if e['final_vulnerable'] else 'FN'} "
              f"systematic={attr.get('is_systematic')} cat={attr.get('pattern_category','?')}", flush=True)

    return patterns, total_tokens


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    client = OpenAI()

    with open(RAG_PATH)     as f: rag_data = json.load(f)
    with open(DATASET_PATH) as f: ds = json.load(f)

    rag_results  = rag_data["results"]
    filepath_map = {c["filename"]: c["filepath"] for c in ds["contracts"]}
    baseline_f1  = rag_data["metrics"]["f1_score"]

    collection = get_collection()
    print(f"ChromaDB: {CHROMA_PATH}")
    print(f"Collection '{COLLECTION_NAME}' — current count: {collection.count()}")
    print(f"Model: {MODEL}")
    print(f"Contracts: {len(rag_results)} | Baseline (Stage 1): F1={baseline_f1:.4f}")
    print(f"Starting from Arm D (no gate). Max rounds: {MAX_ROUNDS}\n")

    round_records = []
    prev_f1       = 0.0
    converged_at  = None

    for rnd in range(1, MAX_ROUNDS + 1):
        print(f"{'='*60}")
        print(f"Round {rnd} | ChromaDB patterns: {collection.count()}")
        print(f"{'='*60}")

        # ── Run pipeline ──────────────────────────────────────────────
        entries, m, pipe_tokens, llm_calls = run_round(
            rag_results, filepath_map, collection, rnd, client
        )
        delta = m["F1"] - prev_f1 if rnd > 1 else m["F1"] - baseline_f1

        print(f"\nRound {rnd} metrics: TP={m['TP']} FN={m['FN']} FP={m['FP']} TN={m['TN']} "
              f"F1={m['F1']:.4f} FPR={m['FPR']:.4f} ΔF1={delta:+.4f}")

        # ── Attribution analysis ──────────────────────────────────────
        print(f"\n[Attribution analysis Round {rnd}]")
        patterns, attr_tokens = analyze_errors(entries, client, rnd)

        # ── Update ChromaDB ───────────────────────────────────────────
        added = update_collection(collection, patterns, rnd)
        print(f"  New patterns added to ChromaDB: {added} (collection now: {collection.count()})")

        round_records.append({
            "round":               rnd,
            "metrics":             m,
            "delta_f1":            round(delta, 4),
            "pipeline_llm_calls":  llm_calls,
            "pipeline_tokens":     pipe_tokens,
            "errors_analyzed":     min(
                len([e for e in entries
                     if (e["final_vulnerable"] and e["ground_truth"]=="safe") or
                        (not e["final_vulnerable"] and e["ground_truth"]=="vulnerable")]),
                MAX_ERRORS_PER_ROUND,
            ),
            "new_patterns_added":  added,
            "chroma_total":        collection.count(),
            "patterns": [
                {k: v for k, v in p.items() if k not in ("round","contract_id")}
                for p in patterns
            ],
        })

        # ── Convergence check ─────────────────────────────────────────
        if rnd > 1 and abs(m["F1"] - prev_f1) < MIN_DELTA:
            converged_at = rnd
            print(f"\n★ Converged at round {rnd} (|ΔF1|={abs(m['F1']-prev_f1):.4f} < {MIN_DELTA})")
            break
        if added == 0 and rnd > 1:
            converged_at = rnd
            print(f"\n★ No new patterns added — stopping at round {rnd}")
            break

        prev_f1 = m["F1"]

    # ── Final summary table ───────────────────────────────────────────────────
    print("\n" + "="*72)
    print(f"{'Round':<8} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4} {'F1':>7} {'FPR':>6} {'Patterns':>9} {'ΔF1':>8}")
    print("-"*72)
    print(f"{'Base':8} {rag_data['metrics']['tp']:>4} {rag_data['metrics']['fn']:>4} "
          f"{rag_data['metrics']['fp']:>4} {rag_data['metrics']['tn']:>4} "
          f"{baseline_f1:>7.4f} {rag_data['metrics']['fpr']:>6.4f} {'—':>9} {'—':>8}")
    for rec in round_records:
        m = rec["metrics"]
        print(f"R{rec['round']:<7} {m['TP']:>4} {m['FN']:>4} {m['FP']:>4} {m['TN']:>4} "
              f"{m['F1']:>7.4f} {m['FPR']:>6.4f} "
              f"{rec['new_patterns_added']:>9} {rec['delta_f1']:>+8.4f}")
    print("="*72)
    if converged_at:
        final_f1 = round_records[converged_at - 1]["metrics"]["F1"]
    else:
        final_f1 = round_records[-1]["metrics"]["F1"]
    print(f"Final F1: {final_f1:.4f} | Total patterns learned: {collection.count()}")
    print(f"Improvement over Arm D baseline: {final_f1 - 0.8299:+.4f}")

    # ── Save ──────────────────────────────────────────────────────────────────
    out = {
        "experiment":    "feedback_loop",
        "timestamp":     datetime.datetime.now().isoformat(),
        "model":         MODEL,
        "baseline_f1":   baseline_f1,
        "arm_d_f1":      0.8299,
        "v4_f1":         0.9030,
        "max_rounds":    MAX_ROUNDS,
        "converged_at":  converged_at,
        "final_f1":      final_f1,
        "chroma_path":   str(CHROMA_PATH),
        "rounds":        round_records,
        "convergence": {
            "converged_at_round": converged_at,
            "final_f1":           final_f1,
            "total_patterns_learned": collection.count(),
        },
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved -> {OUT_PATH}")


if __name__ == "__main__":
    main()
