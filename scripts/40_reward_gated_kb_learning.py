#!/usr/bin/env python3
"""Reward-gated knowledge learning on EVMbench (prototype).

Goal: demonstrate the one mechanism the current DmAVID iteration loop is missing
-- an ACCEPTANCE TEST (reward gate). Every candidate knowledge patch is committed
to the KB ONLY if it does not decrease detection on a held-out VALIDATION slice.
This turns the open-loop random walk (current loop: write every patch
unconditionally) into closed-loop hill-climbing.

Design (all temp=0, seed=42 -> deterministic, so re-eval and the gate are stable):
  * Split EVMbench 10 audits -> VAL (gate/select on) + TEST (held-out, report only).
  * Candidates = generic high-severity DeFi vuln patterns brainstormed by the LLM
    with NO audit/gold information (no leakage; unlike 22_..targeted_search).
  * GATED loop: for each candidate, tentatively add to KB, re-eval VAL; commit iff
    VAL score does not drop. -> VAL trajectory monotonic non-decreasing by design.
  * UNGATED control: add ALL candidates (= current DmAVID "write everything").
  * Report TEST(baseline) vs TEST(gated) vs TEST(ungated). Gate wins if it protects
    held-out TEST from the degradation that "write everything" can cause.

Reuses preprocessing / gold-loading / judging from 30_evmbench_smart_preprocess.py.
gold is used ONLY for scoring (matching), never injected into the prompt.
"""
import os, re, json, importlib.util, statistics

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "smart30", os.path.join(HERE, "30_evmbench_smart_preprocess.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SEED = 42
OUTPUT_DIR = os.path.join(m.BASE_DIR, "experiments", "reward_gated")

# headroom on both sides (per seed42 3-run): VAL has phi/basin/curves gaps,
# TEST has forte(0/5) gap -> improvement is observable on both.
VAL_AUDITS = ["2024-08-phi", "2024-07-basin", "2024-05-olas",
              "2024-01-curves", "2024-03-taiko"]
TEST_AUDITS = ["2025-04-forte", "2024-06-size", "2024-01-renft",
               "2024-12-secondswap", "2026-01-tempo-stablecoin-dex"]


def base_kb_entries():
    kb_path = os.path.join(m.BASE_DIR, "scripts", "knowledge", "vulnerability_knowledge.json")
    with open(kb_path) as f:
        kb = json.load(f)
    return kb.get("entries", [])[:20]


def fmt_entry(e):
    return f"[{e.get('category','?')}] {e.get('title','')}: {e.get('description','')[:200]}"


def build_kb_string(committed_candidates, base_entries):
    """Committed candidates FIRST (so they survive the prompt cap), then base."""
    parts = [f"[{c['category']}] {c['title']}: {c['description'][:220]}"
             for c in committed_candidates]
    parts += [fmt_entry(e) for e in base_entries]
    return "\n".join(parts)


def detect(preprocessed_code, kb_string):
    prompt = f"""You are an expert DeFi security auditor. Analyze this smart contract project for HIGH severity vulnerabilities.

## DeFi Vulnerability Knowledge Base:
{kb_string[:6000]}

## Smart Contract Project (preprocessed: interface summary + security-critical modules):
```solidity
{preprocessed_code}
```

## Task:
1. Identify ALL high-severity vulnerabilities
2. For each, provide: title, severity, root cause, exploit scenario
3. Focus on DeFi-specific issues: flash loan, oracle manipulation, reentrancy, access control, precision loss

Output JSON only:
{{"vulnerabilities": [{{"title": "...", "severity": "high", "summary": "...", "exploit_scenario": "..."}}]}}"""
    try:
        resp = m.client.chat.completions.create(
            model=m.MODEL, messages=[{"role": "user", "content": prompt}],
            temperature=0, seed=SEED, **m.token_param(2000))
        content = resp.choices[0].message.content.strip()
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            return json.loads(match.group()).get("vulnerabilities", [])
        return []
    except Exception as e:
        print(f"    detect ERROR: {e}")
        return []


# preprocess once per audit (deterministic, no LLM) and cache
_PRE = {}
def pre(audit):
    if audit not in _PRE:
        _PRE[audit] = m.smart_preprocess(audit)
    return _PRE[audit]


def eval_slice(audits, kb_string):
    """Return (detected, gold, per_audit) over a slice for a given KB."""
    det = gold = 0
    rows = []
    for a in audits:
        g = m.load_gold_vulns(a)
        p = pre(a)
        if not p:
            rows.append((a, 0, len(g))); gold += len(g); continue
        found = detect(p, kb_string)
        d = m.judge_detection(found, g)
        det += d; gold += len(g)
        rows.append((a, d, len(g)))
    return det, gold, rows


def generate_candidates(base_entries):
    """LLM brainstorms generic DeFi vuln patterns NOT already covered. No gold."""
    existing = "\n".join(f"- {e.get('category')}: {e.get('title')}" for e in base_entries)
    prompt = f"""You are a DeFi security knowledge engineer. Below are vulnerability patterns ALREADY in our knowledge base:
{existing}

Propose 8 ADDITIONAL, GENERIC high-severity DeFi vulnerability patterns that are NOT already covered above and are common in modern (2024-2026) DeFi protocols (e.g. cross-contract state dependency, proxy storage collision, fee-on-transfer accounting, TWAP/oracle edge cases, rounding/precision loss in share accounting, ERC777/ERC1155 callback hooks, liquidation logic flaws, governance/timelock bypass).

Do NOT reference any specific project or audit. Output JSON only:
{{"patterns": [{{"category": "...", "title": "...", "description": "one-sentence generic pattern + how it is exploited"}}]}}"""
    try:
        resp = m.client.chat.completions.create(
            model=m.MODEL, messages=[{"role": "user", "content": prompt}],
            temperature=0, seed=SEED, **m.token_param(1500))
        content = resp.choices[0].message.content.strip()
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            return json.loads(match.group()).get("patterns", [])
    except Exception as e:
        print("candidate gen ERROR:", e)
    return []


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base = base_kb_entries()
    base_kb = build_kb_string([], base)

    print("=" * 64)
    print(f"Reward-Gated KB Learning  (EVMbench, temp=0, seed={SEED}, model={m.MODEL})")
    print(f"VAL = {VAL_AUDITS}")
    print(f"TEST= {TEST_AUDITS}")
    print("=" * 64)

    # ---- baseline ----
    v_det0, v_gold, _ = eval_slice(VAL_AUDITS, base_kb)
    t_det0, t_gold, t_rows0 = eval_slice(TEST_AUDITS, base_kb)
    val0 = v_det0 / v_gold
    test0 = t_det0 / t_gold
    print(f"\n[baseline]  VAL {v_det0}/{v_gold}={val0:.4f}   TEST {t_det0}/{t_gold}={test0:.4f}")

    # ---- candidates ----
    cands = generate_candidates(base)
    print(f"\nGenerated {len(cands)} candidate patterns:")
    for c in cands:
        print(f"  - [{c.get('category','?')}] {c.get('title','?')}")

    # ---- GATED loop: commit iff VAL does not drop ----
    committed = []
    val_cur = v_det0
    val_traj = [{"step": 0, "candidate": "(baseline)", "val_detected": v_det0,
                 "decision": "baseline"}]
    for i, c in enumerate(cands):
        trial_kb = build_kb_string(committed + [c], base)
        v_det, _, _ = eval_slice(VAL_AUDITS, trial_kb)
        # gate: commit iff the candidate does not decrease VAL detection
        if v_det > val_cur:
            committed.append(c); val_cur = v_det; dec = "COMMIT (+%d)" % (v_det - (val_traj[-1]["val_detected"]))
        elif v_det == val_cur:
            committed.append(c); dec = "COMMIT (tie)"
        else:
            dec = "REJECT (-%d)" % (val_cur - v_det)
        val_traj.append({"step": i + 1, "candidate": c.get("title", "?"),
                         "val_detected": v_det, "val_current": val_cur, "decision": dec})
        print(f"  cand {i+1:>2} {dec:<14} VAL->{v_det}/{v_gold}  | {c.get('title','?')[:48]}")

    gated_kb = build_kb_string(committed, base)
    vg_det, _, _ = eval_slice(VAL_AUDITS, gated_kb)
    tg_det, _, tg_rows = eval_slice(TEST_AUDITS, gated_kb)
    val_gated = vg_det / v_gold
    test_gated = tg_det / t_gold

    # ---- UNGATED control: add ALL candidates ----
    ungated_kb = build_kb_string(cands, base)
    vu_det, _, _ = eval_slice(VAL_AUDITS, ungated_kb)
    tu_det, _, tu_rows = eval_slice(TEST_AUDITS, ungated_kb)
    val_ungated = vu_det / v_gold
    test_ungated = tu_det / t_gold

    print("\n" + "=" * 64)
    print("RESULTS")
    print("=" * 64)
    print(f"  baseline        VAL {v_det0}/{v_gold}={val0:.4f}   TEST {t_det0}/{t_gold}={test0:.4f}")
    print(f"  GATED  ({len(committed)}/{len(cands)} committed)  VAL {vg_det}/{v_gold}={val_gated:.4f}   TEST {tg_det}/{t_gold}={test_gated:.4f}")
    print(f"  UNGATED (all {len(cands)})       VAL {vu_det}/{v_gold}={val_ungated:.4f}   TEST {tu_det}/{t_gold}={test_ungated:.4f}")
    print(f"\n  TEST delta  gated  vs baseline : {test_gated-test0:+.4f}")
    print(f"  TEST delta  ungated vs baseline: {test_ungated-test0:+.4f}")

    out = {
        "experiment": "reward_gated_kb_learning",
        "model": m.MODEL, "temperature": 0, "seed": SEED,
        "val_audits": VAL_AUDITS, "test_audits": TEST_AUDITS,
        "n_candidates": len(cands), "n_committed": len(committed),
        "candidates": cands,
        "committed_titles": [c.get("title") for c in committed],
        "val_trajectory": val_traj,
        "baseline":  {"val": round(val0, 4), "test": round(test0, 4),
                      "val_detected": v_det0, "test_detected": t_det0,
                      "val_gold": v_gold, "test_gold": t_gold,
                      "test_rows": t_rows0},
        "gated":     {"val": round(val_gated, 4), "test": round(test_gated, 4),
                      "val_detected": vg_det, "test_detected": tg_det,
                      "test_rows": tg_rows},
        "ungated":   {"val": round(val_ungated, 4), "test": round(test_ungated, 4),
                      "val_detected": vu_det, "test_detected": tu_det,
                      "test_rows": tu_rows},
        "test_delta_gated_vs_baseline": round(test_gated - test0, 4),
        "test_delta_ungated_vs_baseline": round(test_ungated - test0, 4),
    }
    with open(os.path.join(OUTPUT_DIR, "reward_gated_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved: {OUTPUT_DIR}/reward_gated_results.json")


if __name__ == "__main__":
    main()
