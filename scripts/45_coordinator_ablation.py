#!/usr/bin/env python3
"""
Sprint 7: Coordinator leave-out ablation.

模擬「拿掉 Coordinator」之 baseline：4 個 agent 並行投票 + simple majority。
Tie (2v vs 2s) 按 DeFi 偏好 precision 慣例 → 投 safe（保守）。

Agent 投票來源：
  Teacher    — ChromaDB top-1 距離 ≤ median 投 vulnerable（unsupervised median split）
  Student    — experiments/llm_rag/llm_rag_results.json 之 predicted_vulnerable
  Red Team   — NEW LLM call：產 1 個變體 + LLM 偵測該變體
  Blue Team  — experiments/ablation/ablation_v5_clean_self-verify_details.json 之 sv_verdict

Idempotent：Red Team 結果 cache 至 red_team_cache.json，重 run 跳過已處理。
Cost guard：超過 MAX_COST 自動 abort（cache 已保存可續跑）。

Output:
  experiments/coordinator_ablation/no_coordinator_results.json
  experiments/coordinator_ablation/red_team_cache.json (incremental cache)

Author: Curtis Chang (張宏睿), 2026
"""
import os
import sys
import re
import json
import statistics
from datetime import datetime
from pathlib import Path

import chromadb
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
LLM_RAG = ROOT / "experiments/llm_rag/llm_rag_results.json"
SV = ROOT / "experiments/ablation/ablation_v5_clean_self-verify_details.json"
DATASET = ROOT / "data/dataset_1000.json"
CHROMA_PATH = ROOT / "data/chroma_kb"

OUT_DIR = ROOT / "experiments/coordinator_ablation"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT = OUT_DIR / "no_coordinator_results.json"
CACHE = OUT_DIR / "red_team_cache.json"

MODEL = "gpt-4.1-mini"
EMBED_MODEL = "text-embedding-3-small"  # 與 KB build 時相同（1536-d）
PRICE_IN_PER_TOK = 0.40 / 1_000_000
PRICE_OUT_PER_TOK = 1.60 / 1_000_000
PRICE_EMBED_PER_TOK = 0.02 / 1_000_000  # text-embedding-3-small input
MAX_COST = 1.0  # USD ceiling

CODE_QUERY_CAP = 6000   # chars used as ChromaDB query
CODE_PROMPT_CAP = 4000  # chars sent to LLM (variant gen / detect)

VARIANT_PROMPT = """You are a Solidity refactoring tool. Apply ONE semantically-preserving transformation to the contract below. Choose ONE of: variable renaming, statement reordering within the same scope, or dead-code injection (a no-op assignment).

Output the modified Solidity code ONLY — no commentary, no markdown fences. Preserve all existing vulnerabilities and all behavior.

Original:
```solidity
{code}
```
"""

DETECT_PROMPT = """You are a smart contract security auditor. Determine whether the following Solidity code contains at least one security vulnerability (reentrancy, integer over/underflow, access control, denial of service, timestamp dependence, randomness, unchecked low-level calls, etc.).

Output ONLY a JSON object: {{"vulnerable": true|false, "type": "<short type or empty>"}}

Code:
```solidity
{code}
```
"""


# ============================================================
# 載入工具
# ============================================================
def load_dataset_paths():
    """id → filepath map（從 dataset_1000.json）"""
    d = json.loads(DATASET.read_text(encoding="utf-8"))
    fpmap = {}
    for c in d.get("contracts", []):
        cid = c.get("id", "")
        if cid:
            fpmap[cid] = c.get("filepath", "")
    return fpmap


def get_contract_code(fpmap, contract_id, cap=CODE_QUERY_CAP):
    fp = fpmap.get(contract_id, "")
    if not fp:
        return ""
    if not os.path.isabs(fp):
        fp = str(ROOT / fp)
    try:
        with open(fp, encoding="utf-8", errors="ignore") as f:
            return f.read()[:cap]
    except Exception:
        return ""


# ============================================================
# Teacher：ChromaDB median split（用同模型 OpenAI text-embedding-3-small embed query）
# ============================================================
def embed_query(client, text):
    """用 OpenAI text-embedding-3-small embed 文字，回傳 1536-d 向量 + token 數"""
    if not text:
        return None, 0
    try:
        r = client.embeddings.create(model=EMBED_MODEL, input=[text[:CODE_QUERY_CAP]])
        return r.data[0].embedding, r.usage.total_tokens
    except Exception as e:
        print(f"  embed err: {e}")
        return None, 0


def teacher_pass(collection, contracts, openai_client):
    """Teacher 使用 cache（避免重 run 時重複呼叫 OpenAI embed API）"""
    cache_file = OUT_DIR / "teacher_cache.json"
    cache = {}
    if cache_file.exists():
        try:
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    print(f"[Teacher] cached: {len(cache)},  待處理: {sum(1 for c in contracts if c['contract_id'] not in cache)}")
    embed_in_total = 0
    distances = []
    for i, c in enumerate(contracts):
        cid = c["contract_id"]
        if cid in cache:
            d = cache[cid].get("distance", float("inf"))
        else:
            code = c["_code"]
            d = float("inf")
            if code:
                vec, n_tok = embed_query(openai_client, code)
                embed_in_total += n_tok
                if vec is not None:
                    try:
                        r = collection.query(query_embeddings=[vec], n_results=1)
                        ds = r.get("distances", [[]])[0]
                        if ds:
                            d = float(ds[0])
                    except Exception as e:
                        print(f"  chroma query err [{cid}]: {e}")
            cache[cid] = {"distance": d if d != float("inf") else None, "embed_tokens": n_tok if 'n_tok' in dir() else 0}
            if (i + 1) % 50 == 0:
                cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                print(f"  {i+1}/{len(contracts)} queried")
        distances.append(d if d is not None else float("inf"))
    cache_file.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")

    finite = [d for d in distances if d != float("inf")]
    median_d = statistics.median(finite) if finite else 0.0
    votes = [(d <= median_d) for d in distances]
    embed_cost = embed_in_total * PRICE_EMBED_PER_TOK
    print(f"[Teacher] median distance = {median_d:.4f},  vuln votes = {sum(votes)}/{len(votes)}")
    print(f"[Teacher] embed input tokens = {embed_in_total:,},  cost = ${embed_cost:.4f}")
    return votes, distances, median_d, embed_in_total, embed_cost


# ============================================================
# Student / Blue Team：從既有實驗讀
# ============================================================
def student_votes_from_llmrag(contracts, llm_rag):
    by_id = {r["contract_id"]: r for r in llm_rag["results"]}
    return [bool(by_id.get(c["contract_id"], {}).get("predicted_vulnerable", False))
            for c in contracts]


def blue_team_votes_from_sv(contracts, sv):
    by_id = {r["contract_id"]: r for r in sv["results"]}
    return [str(by_id.get(c["contract_id"], {}).get("sv_verdict", "")).upper() == "VULNERABLE"
            for c in contracts]


# ============================================================
# Red Team：產變體 + 偵測（NEW LLM call，可恢復）
# ============================================================
def load_cache():
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_cache(cache):
    CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def strip_code_fences(text):
    """剝除可能的 ```solidity ... ``` markdown fence"""
    return re.sub(r"^```\w*\n?|```$", "", text.strip(), flags=re.MULTILINE).strip()


def red_team_vote_one(client, code):
    """產變體 → 偵測。回傳 (vote, in_tokens, out_tokens, error)"""
    if not code:
        return False, 0, 0, "no_code"
    in_tok, out_tok = 0, 0
    # (1) 產變體
    try:
        r = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user",
                       "content": VARIANT_PROMPT.format(code=code[:CODE_PROMPT_CAP])}],
            temperature=0.3, max_tokens=2400,
        )
        variant_raw = r.choices[0].message.content or ""
        variant = strip_code_fences(variant_raw)
        in_tok += r.usage.prompt_tokens
        out_tok += r.usage.completion_tokens
    except Exception as e:
        return False, in_tok, out_tok, f"variant_err:{type(e).__name__}"
    if not variant or len(variant) < 50:
        return False, in_tok, out_tok, "empty_variant"
    # (2) 偵測變體
    try:
        r2 = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user",
                       "content": DETECT_PROMPT.format(code=variant[:CODE_PROMPT_CAP])}],
            temperature=0.0, max_tokens=200,
            response_format={"type": "json_object"},
        )
        in_tok += r2.usage.prompt_tokens
        out_tok += r2.usage.completion_tokens
        try:
            j = json.loads(r2.choices[0].message.content)
            return bool(j.get("vulnerable", False)), in_tok, out_tok, ""
        except Exception:
            return False, in_tok, out_tok, "parse_err"
    except Exception as e:
        return False, in_tok, out_tok, f"detect_err:{type(e).__name__}"


def red_team_pass(contracts, client):
    cache = load_cache()
    todo = [(i, c) for i, c in enumerate(contracts) if c["contract_id"] not in cache]
    print(f"[Red Team] cached: {len(cache)},  待處理: {len(todo)}")

    if todo:
        # 預估
        avg_in, avg_out = 1100, 130
        est_in = len(todo) * avg_in
        est_out = len(todo) * avg_out
        est_cost = est_in * PRICE_IN_PER_TOK + est_out * PRICE_OUT_PER_TOK
        print(f"  est cost: ~${est_cost:.4f}  (ceiling ${MAX_COST})")
        if est_cost > MAX_COST:
            print(f"  ✗ 預估超過 ceiling，abort")
            sys.exit(1)

    in_total = sum(v.get("in_tokens", 0) for v in cache.values())
    out_total = sum(v.get("out_tokens", 0) for v in cache.values())

    for i, c in todo:
        cur_cost = in_total * PRICE_IN_PER_TOK + out_total * PRICE_OUT_PER_TOK
        if cur_cost > MAX_COST:
            print(f"  ⚠ cumulative ${cur_cost:.4f} > ${MAX_COST}, save & abort")
            save_cache(cache)
            sys.exit(1)
        cid = c["contract_id"]
        v, ti, to, err = red_team_vote_one(client, c["_code"])
        in_total += ti
        out_total += to
        cache[cid] = {"vote": v, "in_tokens": ti, "out_tokens": to, "error": err}
        if (i + 1) % 10 == 0 or i == len(contracts) - 1:
            cur_cost = in_total * PRICE_IN_PER_TOK + out_total * PRICE_OUT_PER_TOK
            print(f"  [{i+1:>3}/{len(contracts)}]  cumulative cost=${cur_cost:.4f}")
            save_cache(cache)
    save_cache(cache)

    final_cost = in_total * PRICE_IN_PER_TOK + out_total * PRICE_OUT_PER_TOK
    votes = [bool(cache[c["contract_id"]]["vote"]) for c in contracts]
    n_err = sum(1 for c in contracts if cache[c["contract_id"]].get("error"))
    print(f"[Red Team] final: in={in_total:,} out={out_total:,} cost=${final_cost:.4f} errors={n_err}")
    return votes, in_total, out_total, final_cost, n_err


# ============================================================
# Majority + metrics
# ============================================================
def majority_vote(votes_4):
    """4 votes; ≥3 = vulnerable; tie 2-2 → safe (conservative)"""
    return sum(votes_4) >= 3


def compute_metrics(predictions, ground_truths):
    tp = sum(1 for p, g in zip(predictions, ground_truths) if p and g)
    fp = sum(1 for p, g in zip(predictions, ground_truths) if p and not g)
    tn = sum(1 for p, g in zip(predictions, ground_truths) if (not p) and (not g))
    fn = sum(1 for p, g in zip(predictions, ground_truths) if (not p) and g)
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    return {
        "total": len(predictions), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
    }


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 70)
    print(f"Sprint 7 — Coordinator Leave-out  (model={MODEL})")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Cost ceiling: ${MAX_COST}")
    print("=" * 70)

    llm_rag = json.loads(LLM_RAG.read_text(encoding="utf-8"))
    sv = json.loads(SV.read_text(encoding="utf-8"))
    fpmap = load_dataset_paths()

    # 以 llm_rag.results 為 source-of-truth 排序，所有 agent 共用同一順序
    contracts = []
    for r in llm_rag["results"]:
        cid = r["contract_id"]
        contracts.append({
            "contract_id": cid,
            "ground_truth": r.get("ground_truth"),
            "category": r.get("category"),
            "_code": get_contract_code(fpmap, cid),
        })
    n_with_code = sum(1 for c in contracts if c["_code"])
    print(f"\nLoaded {len(contracts)} contracts  (有 code: {n_with_code})")

    # OpenAI client (shared by Teacher embed + Red Team chat)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("✗ OPENAI_API_KEY not set")
        sys.exit(1)
    openai_client = OpenAI(api_key=api_key)

    # Teacher
    chroma = chromadb.PersistentClient(path=str(CHROMA_PATH))
    kb = chroma.get_collection("vuln_knowledge")
    print(f"[KB] vuln_knowledge count={kb.count()}")
    teacher_v, distances, median_d, teacher_embed_tok, teacher_embed_cost = teacher_pass(kb, contracts, openai_client)

    # Student / Blue Team
    student_v = student_votes_from_llmrag(contracts, llm_rag)
    blue_v = blue_team_votes_from_sv(contracts, sv)
    print(f"[Student] vuln votes = {sum(student_v)}/{len(student_v)}")
    print(f"[Blue Team] vuln votes = {sum(blue_v)}/{len(blue_v)}")

    # Red Team
    red_v, rt_in, rt_out, rt_cost, rt_err = red_team_pass(contracts, openai_client)

    # Majority
    finals = [majority_vote([t, s, r, b])
              for t, s, r, b in zip(teacher_v, student_v, red_v, blue_v)]
    gts = [c["ground_truth"] == "vulnerable" for c in contracts]

    metrics = compute_metrics(finals, gts)
    metrics["actual_red_team_cost_usd"] = round(rt_cost, 4)
    metrics["red_team_input_tokens"] = rt_in
    metrics["red_team_output_tokens"] = rt_out
    metrics["red_team_errors"] = rt_err
    metrics["teacher_embed_tokens"] = teacher_embed_tok
    metrics["teacher_embed_cost_usd"] = round(teacher_embed_cost, 6)
    metrics["total_cost_usd"] = round(rt_cost + teacher_embed_cost, 4)

    out = {
        "experiment": "no_coordinator_simple_majority",
        "timestamp": datetime.now().isoformat(),
        "model": MODEL,
        "cost_ceiling_usd": MAX_COST,
        "voting_strategy": "majority of 4 agents; tie (2v vs 2s) → safe (conservative)",
        "teacher_threshold_method": "median of top-1 ChromaDB distances across N contracts",
        "teacher_median_distance": round(median_d, 4),
        "agent_vuln_votes": {
            "teacher": sum(teacher_v),
            "student": sum(student_v),
            "red_team": sum(red_v),
            "blue_team": sum(blue_v),
        },
        "metrics": metrics,
        "per_contract": [
            {
                "contract_id": c["contract_id"],
                "ground_truth": c["ground_truth"],
                "teacher_vote": teacher_v[i],
                "teacher_distance": round(distances[i], 4) if distances[i] != float("inf") else None,
                "student_vote": student_v[i],
                "red_team_vote": red_v[i],
                "blue_team_vote": blue_v[i],
                "vote_count_vuln": sum([teacher_v[i], student_v[i], red_v[i], blue_v[i]]),
                "final_predicted_vulnerable": finals[i],
            }
            for i, c in enumerate(contracts)
        ],
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Coordinator-leave-out Metrics]")
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print(f"\n→ Saved: {OUT}")


if __name__ == "__main__":
    main()
