#!/usr/bin/env python3
"""
CTC (Correctness/Thoroughness/Clarity) Explainability Evaluation
Reference: Li et al., "Smart-LLaMA-DPO", ISSTA 2025, DOI: 10.1145/3728878

Evaluates explanation quality for three methods on ground-truth-vulnerable contracts:
  - DmAVID  (ablation_v5_clean_self-verify_details.json)
  - LLM-only (llm_base/llm_base_results.json)
  - Slither  (slither/slither_results.json)

Usage:
  .venv/bin/python3 scripts/70_ctc_explainability_eval.py --dry-run
  .venv/bin/python3 scripts/70_ctc_explainability_eval.py --judge anthropic --resume
  .venv/bin/python3 scripts/70_ctc_explainability_eval.py --judge openai --resume
"""

import argparse, json, os, time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

BASE         = Path(__file__).parent.parent
DMAVID_PATH  = BASE / "experiments/ablation/ablation_v5_clean_self-verify_details.json"
LLM_PATH     = BASE / "experiments/llm_base/llm_base_results.json"
SLITHER_PATH = BASE / "experiments/slither/slither_results.json"
OUT_DIR      = BASE / "experiments/explainability"
CKPT_PATH    = OUT_DIR / "ctc_checkpoint.json"
SUMMARY_PATH = OUT_DIR / "ctc_eval_summary.json"

JUDGE_PROMPT = (
    "You are an expert in smart contract security. Evaluate a vulnerability explanation "
    "using the CTC framework (Li et al., Smart-LLaMA-DPO, ISSTA 2025).\n\n"
    "Contract: {contract_id}\nVulnerability category: {category}\n"
    "Ground truth: This contract IS vulnerable.\n\n"
    "Explanation:\n---\n{explanation}\n---\n\n"
    "## Important Scoring Guidelines\n"
    "- You MUST use the full 1-10 range. Do NOT anchor all scores to 4 or 5.\n"
    "- A score of 5 means AVERAGE quality. Reserve 8-10 for genuinely excellent, detailed explanations.\n"
    "- Scores of 1-3 are appropriate for minimal or incorrect explanations.\n"
    "- Before scoring, first analyze the explanation's strengths and weaknesses, THEN assign scores.\n"
    "- Compare against what an ideal security audit report would contain.\n\n"
    "## Evaluation Dimensions (score each 1-10)\n"
    "Correctness (C): correctly identifies vulnerability type and root cause\n"
    "  10=perfect | 7-9=mostly correct | 5-6=partial | 3-4=errors | 1-2=wrong/absent\n"
    "Thoroughness (T): covers attack vector, affected code, and impact\n"
    "  10=all aspects | 7-9=most aspects | 5-6=basic | 3-4=brief | 1-2=no detail\n"
    "Clarity (CL): clear, well-structured, understandable\n"
    "  10=crystal clear | 7-9=mostly clear | 5-6=adequate | 3-4=difficult | 1-2=incomprehensible\n\n"
    'Return ONLY valid JSON: {{"correctness": <1-10>, "thoroughness": <1-10>, "clarity": <1-10>, "reason": "<one sentence>"}}'
)


def build_explanation(method, record):
    if method == "dmavid":
        parts = [record.get("reasoning", "")]
        sv = record.get("sv_reasoning", "")
        ex = record.get("sv_exploit_evidence", "")
        if sv:
            parts.append("Self-verification: " + sv)
        if ex:
            parts.append("Exploit evidence: " + ex)
        return "\n".join(p for p in parts if p)
    if method == "llm":
        return record.get("reasoning", "") or "No explanation provided."
    if method == "slither":
        vtypes = record.get("vuln_types", [])
        sevs   = record.get("severities", [])
        if not vtypes:
            return "No vulnerabilities detected by Slither."
        high   = [v for v, s in zip(vtypes, sevs) if s == "High"]
        medium = [v for v, s in zip(vtypes, sevs) if s == "Medium"]
        other  = [v for v, s in zip(vtypes, sevs) if s not in ("High", "Medium")]
        parts  = [f"Slither detected {len(vtypes)} issue(s)."]
        if high:
            parts.append("High-severity: " + ", ".join(high) + ".")
        if medium:
            parts.append("Medium-severity: " + ", ".join(medium) + ".")
        if other:
            parts.append("Other: " + ", ".join(other) + ".")
        return " ".join(parts)
    return ""


def call_judge(client, judge, model, prompt, retries=3):
    for attempt in range(retries):
        try:
            if judge == "anthropic":
                msg  = client.messages.create(
                    model=model, max_tokens=150,
                    messages=[{"role": "user", "content": prompt}]
                )
                text = msg.content[0].text.strip()
            else:
                kwargs = dict(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                )
                # GPT-5.x uses max_completion_tokens; older models use max_tokens
                if any(x in model for x in ("5.", "o1", "o3")):
                    kwargs["max_completion_tokens"] = 200
                else:
                    kwargs["max_tokens"] = 150
                resp = client.chat.completions.create(**kwargs)
                text = resp.choices[0].message.content.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise
    return {"correctness": None, "thoroughness": None, "clarity": None, "reason": "parse_error"}


def load_data():
    ab  = json.load(open(DMAVID_PATH))
    llm = json.load(open(LLM_PATH))
    sl  = json.load(open(SLITHER_PATH))
    ab_map  = {r["contract_id"]: r for r in ab["results"]}
    llm_map = {r["contract_id"]: r for r in llm["results"]}
    sl_map  = {r["contract_id"]: r for r in sl["results"]}
    vuln    = [r for r in ab["results"] if r["ground_truth_vulnerable"]]
    return vuln, ab_map, llm_map, sl_map


def build_tasks(vuln, ab_map, llm_map, sl_map):
    tasks = []
    for rec in vuln:
        cid = rec["contract_id"]
        cat = rec.get("category", "unknown")
        tasks.append({"contract_id": cid, "category": cat, "method": "dmavid",  "record": ab_map[cid]})
        if cid in llm_map:
            tasks.append({"contract_id": cid, "category": cat, "method": "llm",     "record": llm_map[cid]})
        if cid in sl_map:
            tasks.append({"contract_id": cid, "category": cat, "method": "slither", "record": sl_map[cid]})
    return tasks


def avg(lst):
    return round(sum(lst) / len(lst), 3) if lst else None


def summarise(done, vuln, tasks, judge, model):
    ms = defaultdict(lambda: {"correctness": [], "thoroughness": [], "clarity": []})
    cs = defaultdict(lambda: defaultdict(lambda: {"correctness": [], "thoroughness": [], "clarity": []}))
    for rec in done.values():
        m, cat = rec["method"], rec.get("category", "unknown")
        for dim in ("correctness", "thoroughness", "clarity"):
            v = rec.get(dim)
            if v is not None:
                ms[m][dim].append(v)
                cs[cat][m][dim].append(v)
    out = {
        "reference": "Li et al., Smart-LLaMA-DPO, ISSTA 2025, DOI: 10.1145/3728878",
        "judge": judge, "model": model,
        "evaluated_at": datetime.now().isoformat(),
        "n_contracts": len(vuln), "n_tasks": len(tasks),
        "per_method": {}, "per_category": {}
    }
    for m, dims in ms.items():
        c, t, cl = avg(dims["correctness"]), avg(dims["thoroughness"]), avg(dims["clarity"])
        ctc = round((c + t + cl) / 3, 3) if all(v is not None for v in [c, t, cl]) else None
        out["per_method"][m] = {
            "n": len(dims["correctness"]),
            "correctness": c, "thoroughness": t, "clarity": cl, "ctc_avg": ctc
        }
    for cat, methods in cs.items():
        out["per_category"][cat] = {}
        for m, dims in methods.items():
            c, t, cl = avg(dims["correctness"]), avg(dims["thoroughness"]), avg(dims["clarity"])
            ctc = round((c + t + cl) / 3, 3) if all(v is not None for v in [c, t, cl]) else None
            out["per_category"][cat][m] = {
                "n": len(dims["correctness"]),
                "correctness": c, "thoroughness": t, "clarity": cl, "ctc_avg": ctc
            }
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--judge",       choices=["anthropic", "openai"], default="anthropic")
    parser.add_argument("--judge-model", default=None, help="Override model name (e.g. gpt-5.4)")
    parser.add_argument("--dry-run",     action="store_true")
    parser.add_argument("--resume",      action="store_true")
    parser.add_argument("--sample",      type=int, default=None)
    args = parser.parse_args()

    vuln, ab_map, llm_map, sl_map = load_data()
    if args.sample:
        vuln = vuln[:args.sample]
    tasks = build_tasks(vuln, ab_map, llm_map, sl_map)

    if args.judge == "anthropic":
        model    = args.judge_model or "claude-sonnet-4-6"
        est_cost = len(tasks) * (400 * 3 + 100 * 15) / 1_000_000
    else:
        model    = args.judge_model or "gpt-4o-mini"
        # GPT-5.4: $2.50/$15 per M; gpt-4o-mini: $0.15/$0.60
        if "5.4" in model or "5.5" in model:
            est_cost = len(tasks) * (400 * 2.50 + 100 * 15) / 1_000_000
        else:
            est_cost = len(tasks) * (400 * 0.15 + 100 * 0.6) / 1_000_000

    print(f"Ground-truth vulnerable contracts : {len(vuln)}")
    print(f"Total evaluation tasks            : {len(tasks)}  (x3 methods)")
    print(f"Judge model                       : {model}")
    print(f"Estimated cost                    : ${est_cost:.3f}")

    if args.dry_run:
        print("\n[dry-run] No API calls made.")
        t0     = tasks[0]
        expl   = build_explanation(t0["method"], t0["record"])
        prompt = JUDGE_PROMPT.format(
            contract_id=t0["contract_id"], category=t0["category"], explanation=expl[:600]
        )
        print("\n-- Sample prompt (first 1000 chars) --")
        print(prompt[:1000])
        return

    done = {}
    if args.resume and CKPT_PATH.exists():
        done = json.load(open(CKPT_PATH))
        print(f"[resume] Loaded {len(done)} completed evaluations.")

    if args.judge == "anthropic":
        import anthropic as _a
        client = _a.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    else:
        import openai as _o
        client = _o.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pending = [t for t in tasks if f"{t['contract_id']}::{t['method']}" not in done]
    print(f"Pending evaluations: {len(pending)}")

    for i, task in enumerate(pending, 1):
        cid    = task["contract_id"]
        meth   = task["method"]
        key    = f"{cid}::{meth}"
        expl   = build_explanation(meth, task["record"])
        prompt = JUDGE_PROMPT.format(
            contract_id=cid, category=task["category"], explanation=expl
        )
        scores = call_judge(client, args.judge, model, prompt)
        scores["method"]      = meth
        scores["contract_id"] = cid
        scores["category"]    = task["category"]
        done[key] = scores

        c, t, cl = scores.get("correctness"), scores.get("thoroughness"), scores.get("clarity")
        ctc_avg  = round((c + t + cl) / 3, 3) if all(v is not None for v in [c, t, cl]) else None
        print(f"[{i:3d}/{len(pending)}] {meth:8s} | {task['category']:22s} | "
              f"C={c} T={t} CL={cl} avg={ctc_avg}")

        if i % 10 == 0:
            json.dump(done, open(CKPT_PATH, "w"), ensure_ascii=False, indent=2)
            print(f"  [checkpoint: {len(done)} done]")

        time.sleep(0.3)

    json.dump(done, open(CKPT_PATH, "w"), ensure_ascii=False, indent=2)
    summary = summarise(done, vuln, tasks, args.judge, model)
    json.dump(summary, open(SUMMARY_PATH, "w"), ensure_ascii=False, indent=2)

    print("\n-- CTC Summary --")
    for m, s in summary["per_method"].items():
        print(f"  {m:10s}  C={s['correctness']}  T={s['thoroughness']}  "
              f"CL={s['clarity']}  CTC={s['ctc_avg']}")
    print(f"\nSummary -> {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
