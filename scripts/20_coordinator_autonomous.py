#!/usr/bin/env python3
"""DmAVID Coordinator: Autonomous version with LLM-based decision-making.

Upgrade from 19_coordinator_round2.py:
  - SharedState   : unified persistent state across all agents (JSON-backed)
  - CoordinatorDecisionEngine : Coordinator queries LLM at 3 decision points
      (1) start-of-round strategy  (2) mid-round Red-Team sizing  (3) early-stop
  - All decisions logged with LLM reasoning for traceability

Detection pipeline (Teacher→Student→RedTeam→Foundry→BlueTeam→SelfVerify)
is identical to script 19 — existing experiment results remain reproducible.
"""

import os
import sys
import json
import time
import random
import logging
import argparse
import subprocess
import importlib.util
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from openai import OpenAI

sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
BASE_DIR = os.environ.get("DMAVID_BASE_DIR", "/home/curtis/DmAVID")
MODEL    = os.environ.get("DMAVID_MODEL",    "gpt-4.1-mini")
client   = OpenAI()

DATASET_FILE  = os.path.join(BASE_DIR, "data/dataset_1000.json")
BASELINE_FILE = os.path.join(BASE_DIR, "experiments/llm_rag/llm_rag_results.json")
OUTPUT_DIR    = os.path.join(BASE_DIR, "experiments/dmavid_autonomous")
BASELINE_F1   = 0.9061

COST_PER_1K_TOKENS = 0.01

VULN_TYPES = [
    "reentrancy", "integer_overflow", "access_control", "unchecked_call",
    "denial_of_service", "front_running", "time_manipulation",
    "tx_origin", "delegatecall", "selfdestruct",
    "price_oracle_manipulation", "flash_loan_attack",
]


# ── SharedState ───────────────────────────────────────────────────────────────
class SharedState:
    """Persistent shared state accessible to all DmAVID agents.

    Replaces the ad-hoc JSON-file passing between stages in script 19.
    Serialised to experiments/dmavid_autonomous/shared_state.json after
    every round so other agents can read it without in-process coupling.
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.path = os.path.join(output_dir, "shared_state.json")
        self.round_history: List[Dict] = []
        self.fn_patterns: Dict[str, int] = {}     # vuln_type → cumulative FN count
        self.learned_defenses: List[str] = []     # vuln_types with synthesised defenses
        self.coordinator_decisions: List[Dict] = []
        self.started_at = datetime.now().isoformat()

    # ── Mutations ──────────────────────────────────────────────────────────
    def record_round(self, round_data: Dict):
        self.round_history.append(round_data)
        # Accumulate FN patterns from student results
        for r in round_data.get("student_results", []):
            if r.get("ground_truth_vulnerable") and not r.get("predicted_vulnerable"):
                vtype = r.get("category", "unknown")
                self.fn_patterns[vtype] = self.fn_patterns.get(vtype, 0) + 1

    def record_decision(self, round_num: int, stage: str, decision: Dict, reasoning: str):
        self.coordinator_decisions.append({
            "round": round_num,
            "stage": stage,
            "decision": decision,
            "reasoning": reasoning,
            "ts": datetime.now().isoformat(),
        })

    def add_learned_defenses(self, vuln_types: List[str]):
        for vt in vuln_types:
            if vt not in self.learned_defenses:
                self.learned_defenses.append(vt)

    # ── Serialise ──────────────────────────────────────────────────────────
    def save(self):
        os.makedirs(self.output_dir, exist_ok=True)
        payload = {
            "started_at": self.started_at,
            "updated_at": datetime.now().isoformat(),
            "fn_patterns": self.fn_patterns,
            "learned_defenses": self.learned_defenses,
            "coordinator_decisions": self.coordinator_decisions,
            "round_summaries": [
                {
                    "round": r["round"],
                    "f1_post": r.get("student_post_verify", {}).get("f1"),
                    "fn_count": r.get("fn_count", 0),
                    "patterns_added": r.get("blue_team_patterns", 0),
                }
                for r in self.round_history
            ],
        }
        with open(self.path, "w") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    # ── Summary for LLM prompt ─────────────────────────────────────────────
    def to_prompt_summary(self) -> str:
        lines = ["=== DmAVID Shared State ==="]
        if self.round_history:
            last = self.round_history[-1]
            m = last.get("student_post_verify", {})
            lines.append(f"Last round F1={m.get('f1','?')}  FPR={m.get('fpr','?')}  "
                         f"FN={last.get('fn_count',0)}")
        top_fn = sorted(self.fn_patterns.items(), key=lambda x: -x[1])[:5]
        lines.append(f"Top FN vuln types: {top_fn}")
        lines.append(f"Learned defenses so far: {self.learned_defenses}")
        lines.append(f"Rounds completed: {len(self.round_history)}")
        return "\n".join(lines)


# ── CoordinatorDecisionEngine ─────────────────────────────────────────────────
class CoordinatorDecisionEngine:
    """Coordinator Agent's LLM-powered decision maker.

    Called at three points per round:
      decide_round_strategy()  — before Teacher stage
      decide_red_team_sizing() — after Student evaluation (knows actual FN count)
      decide_early_stop()      — after Blue Team, before next round
    """

    SYSTEM_PROMPT = (
        "You are the Coordinator Agent of DmAVID, a multi-agent smart contract "
        "vulnerability detection framework. Your role is to allocate resources and "
        "adapt strategy each iteration round based on the current detection state. "
        "Respond ONLY with the JSON asked for — no extra text."
    )

    def __init__(self, openai_client, model: str = MODEL):
        self.client = openai_client
        self.model  = model
        self.total_tokens = 0

    def _call(self, user_msg: str, max_tokens: int = 350) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            temperature=0.15,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            **token_param(max_tokens),
        )
        self.total_tokens += resp.usage.total_tokens if resp.usage else 0
        return resp.choices[0].message.content.strip()

    # ── Decision 1: Round strategy ─────────────────────────────────────────
    def decide_round_strategy(
        self, state: SharedState, round_num: int, total_rounds: int,
        budget_remaining: float, dry_run: bool
    ) -> Dict:
        """Decide which vuln types to focus on and what thresholds to use."""
        default = {
            "focus_vuln_types": VULN_TYPES[:6],
            "challenges_per_type": 1,
            "sv_threshold": round(0.85 + 0.03 * round_num, 2),
            "reasoning": "default (dry-run or LLM skip)",
        }
        if dry_run:
            return default

        prompt = f"""{state.to_prompt_summary()}

Round {round_num}/{total_rounds} is starting. Budget remaining: ${budget_remaining:.2f}
Available vulnerability types: {VULN_TYPES}

Select strategy for this round. Respond with exactly this JSON:
{{
  "focus_vuln_types": ["type1", "type2", "type3"],
  "challenges_per_type": 1,
  "sv_threshold": 0.90,
  "reasoning": "one sentence"
}}

Rules:
- focus_vuln_types: 3–6 items from the available list, prioritise types with high FN counts
- challenges_per_type: 1 or 2 (2 only if budget_remaining > $5)
- sv_threshold: float 0.80–0.96, higher = fewer FP flips, lower = more aggressive FP reduction"""

        try:
            raw = self._call(prompt, max_tokens=250)
            import re
            m = re.search(r"\{[\s\S]*\}", raw)
            decision = json.loads(m.group()) if m else default
            # Sanitise
            decision["focus_vuln_types"] = [
                v for v in decision.get("focus_vuln_types", VULN_TYPES[:6])
                if v in VULN_TYPES
            ] or VULN_TYPES[:6]
            decision["sv_threshold"] = float(
                max(0.80, min(0.96, decision.get("sv_threshold", 0.90)))
            )
            return decision
        except Exception as e:
            logger.warning(f"[COORDINATOR] decide_round_strategy failed ({e}), using default")
            return default

    # ── Decision 2: Red Team sizing ────────────────────────────────────────
    def decide_red_team_sizing(
        self, state: SharedState, fn_count: int, budget_remaining: float, dry_run: bool
    ) -> int:
        """Decide how many FN variants Red Team should generate."""
        if dry_run or fn_count == 0:
            return min(fn_count, 10)

        prompt = f"""{state.to_prompt_summary()}

Student just finished. False negatives this round: {fn_count}
Budget remaining: ${budget_remaining:.2f}

How many FN cases should Red Team generate adversarial variants for?
Respond with exactly: {{"max_fn_variants": <int 1-20>, "reasoning": "one sentence"}}

Rules: if budget < $2 use ≤ 5; if FN count < 5 use all; otherwise balance coverage vs cost."""

        try:
            raw = self._call(prompt, max_tokens=100)
            import re
            m = re.search(r"\{[\s\S]*\}", raw)
            parsed = json.loads(m.group()) if m else {}
            return int(max(1, min(20, parsed.get("max_fn_variants", min(fn_count, 10)))))
        except Exception as e:
            logger.warning(f"[COORDINATOR] decide_red_team_sizing failed ({e}), using default")
            return min(fn_count, 10)

    # ── Decision 3: Early stop ─────────────────────────────────────────────
    def decide_early_stop(
        self, state: SharedState, rounds_remaining: int, budget_remaining: float,
        dry_run: bool
    ) -> Tuple[bool, str]:
        """Decide whether to stop iterating before all rounds are exhausted."""
        if dry_run or rounds_remaining <= 0:
            return False, "no stop (dry-run or last round)"

        prompt = f"""{state.to_prompt_summary()}

Rounds remaining: {rounds_remaining}. Budget remaining: ${budget_remaining:.2f}

Should we stop early? Respond with:
{{"stop": true/false, "reasoning": "one sentence"}}

Stop if: F1 has not improved > 0.002 for 2+ consecutive rounds AND FN count is stable."""

        try:
            raw = self._call(prompt, max_tokens=120)
            import re
            m = re.search(r"\{[\s\S]*\}", raw)
            parsed = json.loads(m.group()) if m else {}
            stop = bool(parsed.get("stop", False))
            reason = parsed.get("reasoning", "")
            return stop, reason
        except Exception as e:
            logger.warning(f"[COORDINATOR] decide_early_stop failed ({e})")
            return False, f"error: {e}"


# ── Helpers (identical to script 19) ─────────────────────────────────────────
class CostTracker:
    def __init__(self, budget: float):
        self.budget = budget
        self.total_tokens = 0
        self.total_cost = 0.0
        self.per_stage: Dict[str, Dict] = {}

    def add(self, stage: str, tokens: int):
        cost = (tokens / 1000) * COST_PER_1K_TOKENS
        self.total_tokens += tokens
        self.total_cost   += cost
        e = self.per_stage.setdefault(stage, {"tokens": 0, "cost": 0.0})
        e["tokens"] += tokens
        e["cost"]   += cost

    def under_budget(self) -> bool:
        return self.total_cost < self.budget

    def remaining(self) -> float:
        return max(0.0, self.budget - self.total_cost)

    def summary(self) -> Dict:
        return {
            "total_tokens":       self.total_tokens,
            "total_cost_usd":     round(self.total_cost, 4),
            "budget_usd":         self.budget,
            "budget_remaining_usd": round(self.remaining(), 4),
            "per_stage": {k: {"tokens": v["tokens"], "cost_usd": round(v["cost"], 4)}
                          for k, v in self.per_stage.items()},
        }


def compute_metrics(results):
    tp = fp = tn = fn = 0
    for r in results:
        gt   = r.get("ground_truth_vulnerable", r.get("ground_truth") == "vulnerable")
        pred = r.get("predicted_vulnerable", False)
        if gt and pred:     tp += 1
        elif not gt and pred: fp += 1
        elif gt and not pred: fn += 1
        else:               tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2*precision*recall / (precision+recall) if (precision+recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4), "total_samples": len(results)}


def load_module(name: str):
    path = os.path.join(os.path.dirname(__file__), f"{name}.py")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Module not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_dataset(path: str) -> List[Dict]:
    if not os.path.exists(path):
        logger.error(f"Dataset not found: {path}")
        return []
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return data.get("contracts", data.get("results", data.get("samples", [])))


# ── Stage runners (identical logic to script 19, accept focus_types) ─────────
def run_teacher_stage(teacher_mod, knowledge_base, num_per_type, cost, dry_run, focus_types=None):
    logger.info("[TEACHER] Generating challenges...")
    types = focus_types or random.sample(VULN_TYPES, min(len(VULN_TYPES), 10))
    challenges = []
    for vt in types:
        for _ in range(num_per_type):
            if not cost.under_budget():
                return challenges
            difficulty = random.randint(1, 5)
            if dry_run:
                ch = {"challenge_id": f"dry_{vt}_{int(time.time())}", "vuln_type": vt,
                      "difficulty": difficulty, "contract_code": f"// placeholder {vt}", "tokens_used": 0}
            else:
                ch = teacher_mod.generate_challenge(vt, difficulty, knowledge_base)
            if ch:
                challenges.append(ch)
                cost.add("teacher", ch.get("tokens_used", 0))
            time.sleep(0.2)
    logger.info(f"[TEACHER] Generated {len(challenges)} challenges")
    return challenges


def run_student_stage(rag_mod, dataset, cost, dry_run):
    logger.info(f"[STUDENT] Evaluating {len(dataset)} contracts...")
    results = []
    for idx, sample in enumerate(dataset):
        if not cost.under_budget():
            break
        code = ""
        fp = sample.get("filepath", "")
        if fp and os.path.exists(fp):
            try:
                code = open(fp, encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
        if not code.strip():
            continue
        gt   = sample.get("label") == "vulnerable" or sample.get("ground_truth") == "vulnerable"
        cid  = sample.get("id", sample.get("contract_id", f"s_{idx}"))
        cat  = sample.get("category", sample.get("vulnerability_type", "unknown"))
        if dry_run:
            pred = random.random() > 0.3
            r = {"contract_id": cid, "ground_truth_vulnerable": gt, "category": cat,
                 "predicted_vulnerable": pred, "confidence": random.uniform(0.4, 0.95),
                 "vulnerability_types": [cat] if pred else [], "reasoning": "dry-run", "tokens_used": 0}
        else:
            analysis = rag_mod.analyze_with_rag(code)
            r = {"contract_id": cid, "ground_truth_vulnerable": gt, "category": cat,
                 "predicted_vulnerable": analysis.get("predicted_vulnerable", False),
                 "confidence": analysis.get("confidence", 0.5),
                 "vulnerability_types": analysis.get("vulnerability_types", []),
                 "reasoning": analysis.get("reasoning", ""),
                 "tokens_used": analysis.get("tokens_used", 0)}
        cost.add("student", r.get("tokens_used", 0))
        results.append(r)
        if (idx+1) % 50 == 0:
            logger.info(f"[STUDENT] {idx+1}/{len(dataset)}")
    logger.info(f"[STUDENT] Done: {len(results)} contracts")
    return results


def run_red_team_stage(red_mod, student_results, dataset, cost, dry_run, max_fn=10):
    logger.info("[RED TEAM] Generating adversarial variants...")
    fn_cases = [r for r in student_results
                if r.get("ground_truth_vulnerable") and not r.get("predicted_vulnerable")][:max_fn]
    if not fn_cases:
        return []
    id_to_src = {}
    for s in dataset:
        cid = s.get("id", s.get("contract_id", ""))
        fp  = s.get("filepath", "")
        if cid and fp and os.path.exists(fp):
            try:
                src = open(fp, encoding="utf-8", errors="ignore").read()
                if src.strip():
                    id_to_src[cid] = src
            except Exception:
                pass
    transforms = ["variable_renaming", "code_reordering", "dead_code_injection", "control_flow_obfuscation"]
    variants = []
    for fn in fn_cases:
        if not cost.under_budget():
            break
        cid = fn.get("contract_id", "")
        src = id_to_src.get(cid, "")
        vt  = fn.get("category", "unknown")
        if not src:
            continue
        tf = random.choice(transforms)
        if dry_run:
            vs, ta, note, tokens = f"// variant {cid}", tf, "dry-run", 0
        else:
            vs, ta, note = red_mod.generate_adversarial_variant(src, vt, tf)
            tokens = 500
        variants.append({"variant_id": f"{cid}_{vt}_{tf}", "original_contract_id": cid,
                         "vulnerability_type": vt, "transformation_applied": ta,
                         "preservation_note": note, "contract_source": vs,
                         "generated_at": datetime.now().isoformat()})
        cost.add("red_team", tokens)
    logger.info(f"[RED TEAM] Generated {len(variants)} variants")
    return variants


def run_foundry_stage(variants, dry_run):
    logger.info(f"[FOUNDRY] Validating {len(variants)} variants...")
    validated = []
    for i, v in enumerate(variants):
        src = v.get("contract_source", "")
        if not src or dry_run:
            v["compile_success"] = bool(dry_run)
            validated.append(v)
            continue
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                sol = os.path.join(tmp, "Variant.sol")
                with open(sol, "w") as f:
                    if "pragma solidity" not in src:
                        f.write("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n\n")
                    f.write(src)
                r = subprocess.run(["forge", "build", "--root", tmp],
                                   capture_output=True, text=True, timeout=60)
                v["compile_success"] = r.returncode == 0
        except FileNotFoundError:
            v["compile_success"] = True
        except Exception:
            v["compile_success"] = False
        validated.append(v)
    compiled = sum(1 for v in validated if v.get("compile_success"))
    logger.info(f"[FOUNDRY] {compiled}/{len(validated)} compiled")
    return validated


def run_blue_team_stage(blue_mod, validated, cost, dry_run):
    logger.info("[BLUE TEAM] Synthesising defense patterns...")
    compilable = [v for v in validated if v.get("compile_success")]
    if not compilable:
        return []
    by_type: Dict[str, List] = {}
    for v in compilable:
        by_type.setdefault(v.get("vulnerability_type", "unknown"), []).append(v)
    all_entries = []
    for vt, vs in by_type.items():
        if not cost.under_budget():
            break
        if dry_run:
            all_entries.append({"id": f"BT-DRY-{vt}", "category": vt, "title": f"dry {vt}",
                                 "description": "dry-run", "tokens_used": 0})
        else:
            entries = blue_mod.synthesize_defense_patterns(vs, vt)
            for e in entries:
                cost.add("blue_team", e.get("tokens_used", 0))
            all_entries.extend(entries)
    if not dry_run and all_entries:
        blue_mod.update_knowledge_files(all_entries)
    logger.info(f"[BLUE TEAM] Synthesised {len(all_entries)} patterns")
    return all_entries


def run_self_verify_stage(student_results, cost, dry_run, conf_threshold=0.90):
    logger.info(f"[SELF-VERIFY] threshold={conf_threshold:.2f}")
    verified, flipped, skipped = [], 0, 0
    for r in student_results:
        nr = dict(r)
        pred, conf = r.get("predicted_vulnerable"), float(r.get("confidence", 0.5))
        do_verify = pred and not dry_run and cost.under_budget()
        if do_verify and conf >= conf_threshold:
            do_verify = False
            skipped += 1
        if do_verify:
            reasoning = r.get("reasoning", "")[:1500]
            vstr = ", ".join(r.get("vulnerability_types", [])) or "a potential vulnerability"
            prompt = (f"You previously classified a smart contract as VULNERABLE due to {vstr}.\n"
                      f"Reasoning: \"{reasoning}\"\n"
                      f"Can you construct a CONCRETE exploit path? "
                      f"If NOT, respond exactly: NO_EXPLOIT_PATH")
            try:
                resp = client.chat.completions.create(
                    model=MODEL, temperature=0.1,
                    messages=[{"role": "user", "content": prompt}],
                    **token_param(512))
                content = resp.choices[0].message.content.strip()
                cost.add("self_verify", resp.usage.total_tokens if resp.usage else 0)
                if "NO_EXPLOIT_PATH" in content.upper():
                    nr["predicted_vulnerable"] = False
                    nr["verify_flipped"] = True
                    nr["verify_reason"] = "No concrete exploit path"
                    flipped += 1
                else:
                    nr["verify_flipped"] = False
                    nr["verify_reason"] = content[:300]
            except Exception as e:
                nr["verify_flipped"] = False
                nr["verify_reason"] = f"error: {e}"
            time.sleep(0.1)
        else:
            nr["verify_flipped"] = False
            nr["verify_reason"] = ""
        verified.append(nr)
    logger.info(f"[SELF-VERIFY] Flipped {flipped} (skipped_high_conf={skipped})")
    return verified


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DmAVID Autonomous Coordinator")
    parser.add_argument("--rounds",              type=int,   default=3)
    parser.add_argument("--budget",              type=float, default=20.0)
    parser.add_argument("--dry-run",             action="store_true")
    parser.add_argument("--dataset",             type=str,   default=DATASET_FILE)
    parser.add_argument("--challenges-per-type", type=int,   default=1)
    args = parser.parse_args()

    logger.info("=" * 70)
    logger.info("DmAVID Autonomous Coordinator")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info(f"Model: {MODEL}  Rounds: {args.rounds}  Budget: ${args.budget:.2f}  Dry-run: {args.dry_run}")
    logger.info("=" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load dataset
    all_c = load_dataset(args.dataset)
    if not all_c:
        logger.error("Dataset not loaded. Exiting.")
        sys.exit(1)
    vuln_c = [c for c in all_c if c.get("label") == "vulnerable"]
    safe_c = [c for c in all_c if c.get("label") == "safe"]
    random.shuffle(safe_c)
    dataset = vuln_c + safe_c[:100]
    random.shuffle(dataset)
    logger.info(f"Dataset: {len(vuln_c)} vuln + {min(100,len(safe_c))} safe = {len(dataset)}")

    # Load sub-modules
    try:
        teacher_mod = load_module("11_teacher_challenge")
        rag_mod     = load_module("05_run_llm_rag")
        red_mod     = load_module("12_red_team_generate")
        blue_mod    = load_module("18_blue_team_defense")
    except FileNotFoundError as e:
        logger.error(f"Module load failed: {e}")
        sys.exit(1)
    knowledge_base = teacher_mod.load_knowledge_base()

    # Initialise shared state and decision engine
    state      = SharedState(OUTPUT_DIR)
    coordinator = CoordinatorDecisionEngine(client, MODEL)
    cost        = CostTracker(args.budget)
    progression = {
        "config": {"rounds": args.rounds, "budget_usd": args.budget, "model": MODEL,
                   "dataset_size": len(dataset), "baseline_f1": BASELINE_F1,
                   "dry_run": args.dry_run, "mode": "autonomous",
                   "started_at": datetime.now().isoformat()},
        "rounds": [],
    }

    # ── Iteration rounds ─────────────────────────────────────────────────
    for round_num in range(1, args.rounds + 1):
        round_start = time.time()
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"  ROUND {round_num}/{args.rounds}")
        logger.info("=" * 70)

        if not cost.under_budget():
            logger.warning("Budget exhausted. Stopping.")
            break

        # ── COORDINATOR DECISION 1: Round strategy ──────────────────────
        strategy = coordinator.decide_round_strategy(
            state, round_num, args.rounds, cost.remaining(), args.dry_run
        )
        focus_types  = strategy.get("focus_vuln_types", VULN_TYPES[:6])
        sv_threshold = strategy.get("sv_threshold", round(0.85 + 0.03*round_num, 2))
        n_per_type   = strategy.get("challenges_per_type", args.challenges_per_type)
        logger.info(f"[COORDINATOR] Strategy → focus={focus_types}  sv_thr={sv_threshold:.2f}  n_per_type={n_per_type}")
        logger.info(f"[COORDINATOR] Reasoning: {strategy.get('reasoning','—')}")
        state.record_decision(round_num, "round_strategy", strategy, strategy.get("reasoning",""))
        cost.add("coordinator", coordinator.total_tokens); coordinator.total_tokens = 0

        round_data: Dict[str, Any] = {"round": round_num, "coordinator_strategy": strategy}

        # (a) Teacher
        challenges = run_teacher_stage(
            teacher_mod, knowledge_base, n_per_type, cost, args.dry_run, focus_types
        )
        round_data["teacher_challenges"] = len(challenges)

        # (b) Student
        student_results = run_student_stage(rag_mod, dataset, cost, args.dry_run)
        pre_m = compute_metrics(student_results)
        round_data["student_pre_verify"] = pre_m
        logger.info(f"[STUDENT] Pre-verify F1={pre_m['f1']:.4f}  FPR={pre_m['fpr']:.4f}")

        fn_count = pre_m["fn"]
        round_data["fn_count"] = fn_count

        # ── COORDINATOR DECISION 2: Red Team sizing ─────────────────────
        max_fn = coordinator.decide_red_team_sizing(
            state, fn_count, cost.remaining(), args.dry_run
        )
        logger.info(f"[COORDINATOR] Red Team max_fn_variants={max_fn}")
        cost.add("coordinator", coordinator.total_tokens); coordinator.total_tokens = 0

        # (c) Red Team
        variants = run_red_team_stage(red_mod, student_results, dataset, cost, args.dry_run, max_fn)
        round_data["red_team_variants"] = len(variants)

        # (d) Foundry
        validated = run_foundry_stage(variants, args.dry_run)
        compiled  = sum(1 for v in validated if v.get("compile_success"))
        round_data["foundry_compiled"] = compiled

        # (e) Blue Team
        defenses = run_blue_team_stage(blue_mod, validated, cost, args.dry_run)
        round_data["blue_team_patterns"] = len(defenses)
        state.add_learned_defenses([d.get("category","") for d in defenses])

        # (f) Self-Verify
        verified = run_self_verify_stage(student_results, cost, args.dry_run, sv_threshold)
        post_m   = compute_metrics(verified)
        round_data["student_post_verify"]  = post_m
        round_data["student_results"]      = verified   # stored in SharedState only
        logger.info(f"[EVALUATE] Post-verify F1={post_m['f1']:.4f}  FPR={post_m['fpr']:.4f}")
        logger.info(f"[EVALUATE] Δ vs baseline: {post_m['f1']-BASELINE_F1:+.4f}")

        round_data["round_time_seconds"] = round(time.time() - round_start, 2)
        round_data["cost_snapshot"]      = cost.summary()
        progression["rounds"].append(round_data)

        # Update shared state
        state.record_round(round_data)
        state.save()

        # Save intermediate
        rf = os.path.join(OUTPUT_DIR, f"round_{round_num}_results.json")
        with open(rf, "w") as f:
            json.dump({"round": round_num, "metrics": post_m, "pre_verify_metrics": pre_m,
                       "coordinator_strategy": strategy, "cost": cost.summary(),
                       "results": [{k: v for k, v in r.items() if k != "student_results"}
                                   for r in verified]}, f, indent=2)
        logger.info(f"Round {round_num} saved → {rf}")

        # ── COORDINATOR DECISION 3: Early stop ─────────────────────────
        rounds_left = args.rounds - round_num
        stop, stop_reason = coordinator.decide_early_stop(
            state, rounds_left, cost.remaining(), args.dry_run
        )
        cost.add("coordinator", coordinator.total_tokens); coordinator.total_tokens = 0
        if stop:
            logger.info(f"[COORDINATOR] Early stop decided: {stop_reason}")
            state.record_decision(round_num, "early_stop", {"stop": True}, stop_reason)
            state.save()
            break
        else:
            logger.info(f"[COORDINATOR] Continuing: {stop_reason}")

    # ── Final output ──────────────────────────────────────────────────────
    progression["completed_at"] = datetime.now().isoformat()
    progression["final_cost"]   = cost.summary()

    pf = os.path.join(OUTPUT_DIR, "autonomous_progression.json")
    with open(pf, "w") as f:
        json.dump(progression, f, indent=2)

    logger.info("")
    logger.info("=" * 70)
    logger.info("DmAVID Autonomous Coordinator — Summary")
    logger.info("=" * 70)
    logger.info(f"Rounds completed: {len(progression['rounds'])}/{args.rounds}")
    logger.info(f"Coordinator decisions: {len(state.coordinator_decisions)}")
    if progression["rounds"]:
        last = progression["rounds"][-1]
        m    = last.get("student_post_verify", {})
        logger.info(f"Final F1:  {m.get('f1', 0):.4f}  ({m.get('f1',0)-BASELINE_F1:+.4f} vs baseline)")
        logger.info(f"Final FPR: {m.get('fpr', 0):.4f}")
    ci = cost.summary()
    logger.info(f"Total cost: ${ci['total_cost_usd']:.4f} / ${args.budget:.2f}")
    logger.info(f"Output: {OUTPUT_DIR}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
