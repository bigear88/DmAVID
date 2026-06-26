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
import re
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
try:
    from chroma_rag import write_blue_team_to_chroma as _write_chroma
    _CHROMA_ENABLED = True
except Exception:
    _CHROMA_ENABLED = False
    def _write_chroma(entries): return 0

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
                 "vulnerability_types": [cat] if pred else [], "reasoning": "dry-run",
                 "filepath": fp, "tokens_used": 0}
        else:
            analysis = rag_mod.analyze_with_rag(code)
            r = {"contract_id": cid, "ground_truth_vulnerable": gt, "category": cat,
                 "predicted_vulnerable": analysis.get("predicted_vulnerable", False),
                 "confidence": analysis.get("confidence", 0.5),
                 "vulnerability_types": analysis.get("vulnerability_types", []),
                 "reasoning": analysis.get("reasoning", ""),
                 "filepath": fp,
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
            # Emit variant in modern Solidity so a forge-std PoC can exercise it
            vs, ta, note = red_mod.generate_adversarial_variant(src, vt, tf,
                                                                target_solidity="^0.8.20")
            tokens = 500
        variants.append({"variant_id": f"{cid}_{vt}_{tf}", "original_contract_id": cid,
                         "vulnerability_type": vt, "transformation_applied": ta,
                         "preservation_note": note, "contract_source": vs,
                         "generated_at": datetime.now().isoformat()})
        cost.add("red_team", tokens)
    logger.info(f"[RED TEAM] Generated {len(variants)} variants")
    return variants


def run_foundry_stage(variants, red_mod, cost, dry_run, round_num=0):
    """Genuine two-stage Foundry validation (S5): solc compile + forge test PoC.

    For each variant the Red Team's PoC generator produces a real Foundry
    exploit test, which is run with `forge test` (with iterative self-repair).
    A variant is dual-validated iff it compiles AND its exploit PoC genuinely
    passes (non-trivial assertion enforced by the runner's anti-cheat check).
    Per-variant validation artefacts are persisted for auditability.
    """
    poc_mod = load_module("13b_foundry_poc")
    logger.info(f"[FOUNDRY] Genuine dual validation on {len(variants)} variants...")
    validated = []
    audit = []
    for i, v in enumerate(variants):
        src = v.get("contract_source", "")
        if not src or dry_run:
            v["compile_success"] = bool(dry_run)
            v["poc_passed"] = bool(dry_run)
            v["gas_used"] = 0
            validated.append(v)
            continue
        vt = v.get("vulnerability_type", "unknown")
        try:
            r = poc_mod.validate_with_repair(
                src, vt, red_mod.generate_poc_template, red_mod.repair_poc,
                max_attempts=3)
            v["compile_success"] = r["compile_success"]
            v["poc_passed"]      = r["poc_passed"]
            v["gas_used"]        = r.get("gas_used", 0)
            v["poc_attempts"]    = r.get("attempts", 0)
            v["poc_source"]      = r.get("poc_source", "")
            # ~1 generation + (attempts-1) repairs, ~2k tokens each
            cost.add("red_team", 2000 * max(1, r.get("attempts", 1)))
            audit.append({"variant_id": v.get("variant_id", f"v{i}"),
                          "vulnerability_type": vt,
                          "compile_success": r["compile_success"],
                          "poc_passed": r["poc_passed"],
                          "gas_used": r.get("gas_used", 0),
                          "attempts": r.get("attempts", 0),
                          "trace": r.get("trace", []),
                          "contract_source": src,
                          "poc_source": r.get("poc_source", "")})
            status = "PoC-PASS" if r["poc_passed"] else ("compiled" if r["compile_success"] else "FAIL")
            logger.info(f"[FOUNDRY] Variant {i+1}/{len(variants)} ({vt}): {status} "
                        f"(attempts={r.get('attempts',0)})")
        except Exception as e:
            logger.error(f"[FOUNDRY] Error validating variant {i}: {e}")
            v["compile_success"] = False
            v["poc_passed"] = False
        validated.append(v)

    # Persist audit trail so variant sources + PoCs are never lost again
    try:
        out_dir = os.path.join(BASE_DIR, "experiments", "dmavid_autonomous", "foundry_poc")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"round_{round_num}_foundry_poc.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"round": round_num, "results": audit}, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"[FOUNDRY] could not persist audit: {e}")

    compiled = sum(1 for v in validated if v.get("compile_success"))
    passed   = sum(1 for v in validated if v.get("poc_passed"))
    logger.info(f"[FOUNDRY] {compiled}/{len(validated)} compiled, {passed}/{len(validated)} PoC-exploitable")
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
        n_chroma = _write_chroma(all_entries)
        logger.info(f"[BLUE TEAM] ChromaDB upserted {n_chroma} new docs (chroma_enabled={_CHROMA_ENABLED})")
    logger.info(f"[BLUE TEAM] Synthesised {len(all_entries)} patterns")
    return all_entries


# ── Three-class Self-Verify (conf-agnostic) ────────────────────────────────────
# Ported from 31_ablation_study_v5_clean.py: verify ALL vuln predictions (no gating);
# only SAFE with a verifiable in-code mitigation flips, UNCERTAIN preserves baseline.
SELF_VERIFY_SYSTEM = """You are an expert Smart Contract Security Analyst. A previous analysis flagged this contract as VULNERABLE. Your task is to verify whether the vulnerability is genuinely exploitable.

IMPORTANT BIAS WARNING: You have a natural tendency to second-guess vulnerability reports and classify contracts as SAFE. Resist this tendency. The previous detector has a high recall rate — when it says VULNERABLE, it is almost always correct. You should only override it with VERY strong evidence.

Classify into exactly ONE of three categories:

## VULNERABLE (confirmed exploitable) — DEFAULT when the exploit pattern exists
The vulnerability pattern is present in the code. Choose this unless you have DEFINITIVE proof of mitigation. Even partial or complex exploit paths should be classified as VULNERABLE. When in doubt between VULNERABLE and UNCERTAIN, choose VULNERABLE.

## SAFE (definitively mitigated) — ONLY when you can cite a specific Solidity keyword
You found a SPECIFIC, NAMED mitigation IN THE CODE that completely blocks the exploit:
- The exact modifier name applied to the function (e.g., `nonReentrant`, `onlyOwner`)
- A specific `require()` statement with the condition that blocks the attack
- State variable assignment BEFORE the external call (Checks-Effects-Interactions)
- `pragma solidity ^0.8` for integer overflow claims

STRICT RULES for SAFE:
1. You MUST quote the exact Solidity code line containing the mitigation
2. "The function is internal" is NOT a valid mitigation unless the function is literally declared `internal` or `private`
3. "The call target is trusted" is NOT a valid mitigation — any address can be malicious
4. "No state update after call" is NOT sufficient if state was read before the call
5. If ANY public/external function in the contract could serve as an entry point for re-entrancy, it is NOT SAFE

## UNCERTAIN (cannot confirm or deny)
Use this when the vulnerability pattern partially exists but mitigation status is unclear, the code is too complex, or you are not fully confident in either VULNERABLE or SAFE.

DEFAULT BEHAVIOR: When in doubt, choose VULNERABLE. The cost of missing a real vulnerability far exceeds the cost of a false positive.

Respond strictly in JSON:
{
  "exploit_evidence": "<specific code pattern/line that enables the exploit, or null>",
  "mitigation_found": "<the EXACT Solidity code line containing the mitigation, or null>",
  "reasoning": "<brief explanation of your analysis>",
  "verdict": "VULNERABLE" or "SAFE" or "UNCERTAIN"
}"""

VALID_MITIGATION_KEYWORDS = [
    "nonreentrant", "onlyowner", "onlyadmin", "onlyminter", "onlyauthorized",
    "whennotpaused", "require(msg.sender", "require(_msgsender",
    "modifier ", "pragma solidity ^0.8", "pragma solidity >=0.8",
    "locked", "mutex", "reentrancyguard",
]


def run_self_verify_stage(student_results, cost, dry_run, conf_threshold=0.90):
    """Three-class, conf-agnostic Self-Verify.

    Verifies EVERY predicted_vulnerable case (no confidence gating). The verdict is
    one of VULNERABLE / SAFE / UNCERTAIN:
      - SAFE      → flip to safe, but only if the claimed mitigation is verifiable
                    in the actual code (or confidence < conf_threshold as a fallback)
      - VULNERABLE→ preserve baseline (still vulnerable)
      - UNCERTAIN → preserve baseline (still vulnerable)

    conf_threshold is NO LONGER a gate; it only bounds the low-confidence override
    when a SAFE mitigation is claimed but cannot be located in the code.
    """
    logger.info(f"[SELF-VERIFY] three-class conf-agnostic (low-conf override < {conf_threshold:.2f})")
    verified, flipped, confirmed, uncertain = [], 0, 0, 0
    for r in student_results:
        nr = dict(r)
        nr["verify_flipped"] = False
        nr["sv_verdict"] = None

        if not r.get("predicted_vulnerable") or dry_run or not cost.under_budget():
            verified.append(nr)
            continue

        # Load contract source for in-code mitigation verification
        code = ""
        fp = r.get("filepath", "")
        if fp and os.path.exists(fp):
            try:
                code = open(fp, encoding="utf-8", errors="ignore").read()
            except Exception:
                code = ""
        code_short = code[:8000]

        vuln_types = r.get("vulnerability_types", [])
        reasoning  = r.get("reasoning", "")[:1500]
        user_msg = (
            f"The previous analysis flagged this contract as VULNERABLE.\n"
            f"Claimed vulnerability types: {', '.join(vuln_types) if vuln_types else 'unspecified'}\n"
            f"Previous reasoning: \"{reasoning}\"\n\n"
            f"## Contract Code:\n```solidity\n{code_short}\n```\n\n"
            f"Verify: is this genuinely exploitable, definitively mitigated, or uncertain?"
        )
        try:
            resp = client.chat.completions.create(
                model=MODEL, temperature=0.1, seed=42,
                messages=[{"role": "system", "content": SELF_VERIFY_SYSTEM},
                          {"role": "user", "content": user_msg}],
                **token_param(800))
            content = resp.choices[0].message.content.strip()
            cost.add("self_verify", resp.usage.total_tokens if resp.usage else 0)

            jm = re.search(r"\{[\s\S]*\}", content)
            parsed = json.loads(jm.group()) if jm else {"verdict": "UNCERTAIN"}
            verdict    = parsed.get("verdict", "UNCERTAIN").upper()
            mitigation = parsed.get("mitigation_found")
            nr["sv_verdict"]    = verdict
            nr["sv_reasoning"]  = parsed.get("reasoning", "")
            nr["sv_mitigation"] = mitigation

            if verdict == "SAFE":
                has_mitigation = mitigation not in (None, "null", "")
                code_lower = code_short.lower()
                mitigation_in_code = False
                if has_mitigation:
                    for kw in VALID_MITIGATION_KEYWORDS:
                        if kw in code_lower:
                            mitigation_in_code = True
                            break
                    if not mitigation_in_code and len(str(mitigation)) > 10:
                        for ident in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{3,}', str(mitigation)):
                            il = ident.lower()
                            if il in code_lower and il not in (
                                "function", "contract", "require", "return", "public",
                                "external", "internal", "private", "memory", "storage",
                                "address", "uint256", "bool", "true", "false", "null",
                                "vulnerable", "safe", "exploit", "attack", "this",
                                "that", "with", "from", "call", "value", "send"):
                                mitigation_in_code = True
                                break
                is_low_conf = float(r.get("confidence", 0.5)) < conf_threshold
                if has_mitigation and mitigation_in_code:
                    nr["predicted_vulnerable"] = False
                    nr["verify_flipped"] = True
                    flipped += 1
                elif has_mitigation and is_low_conf:
                    nr["predicted_vulnerable"] = False
                    nr["verify_flipped"] = True
                    nr["sv_verdict"] = "SAFE (low-conf override)"
                    flipped += 1
                else:
                    nr["sv_verdict"] = "UNCERTAIN (mitigation not verified)"
                    uncertain += 1
            elif verdict == "VULNERABLE":
                confirmed += 1
            else:
                uncertain += 1
        except Exception as e:
            uncertain += 1
            nr["sv_verdict"] = "UNCERTAIN (error)"
            nr["verify_reason"] = f"error: {e}"
        time.sleep(0.1)
        verified.append(nr)

    logger.info(f"[SELF-VERIFY] confirmed={confirmed} flipped_SAFE={flipped} uncertain={uncertain}")
    return verified


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DmAVID Autonomous Coordinator")
    parser.add_argument("--rounds",              type=int,   default=3)
    parser.add_argument("--budget",              type=float, default=20.0)
    parser.add_argument("--dry-run",             action="store_true")
    parser.add_argument("--dataset",             type=str,   default=DATASET_FILE)
    parser.add_argument("--challenges-per-type", type=int,   default=1)
    parser.add_argument("--no-early-stop",       action="store_true",
                        help="Disable the Coordinator's autonomous early-stop; always run all rounds")
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
        # Closed-loop knowledge feedback: reload the dynamic KB so Blue Team
        # patches written in previous rounds are visible to the Student's RAG.
        if hasattr(rag_mod, "reload_dynamic_kb"):
            rag_mod.reload_dynamic_kb()
            n_bt_vuln = sum(len(v) for v in getattr(rag_mod, "_BT_VULN_PATTERNS", {}).values())
            n_bt_safe = sum(len(v) for v in getattr(rag_mod, "_BT_SAFE_PATTERNS", {}).values())
            logger.info(f"[FEEDBACK] Reloaded dynamic KB: {n_bt_vuln} learned vuln-patterns, "
                        f"{n_bt_safe} safe-patterns visible to Student")
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

        # (d) Foundry — genuine dual validation: solc compile + forge test PoC
        validated = run_foundry_stage(variants, red_mod, cost, args.dry_run, round_num)
        compiled   = sum(1 for v in validated if v.get("compile_success"))
        poc_passed = sum(1 for v in validated if v.get("poc_passed"))
        round_data["foundry_compiled"]   = compiled
        round_data["foundry_poc_passed"] = poc_passed
        round_data["foundry_total"]      = len(validated)
        logger.info(f"[FOUNDRY] dual-validation: {compiled}/{len(validated)} compiled, "
                    f"{poc_passed}/{len(validated)} PoC-exploitable")

        # (e) Blue Team — only DUAL-validated variants (compile + PoC) feed synthesis
        dual = [v for v in validated if v.get("compile_success") and v.get("poc_passed")]
        defenses = run_blue_team_stage(blue_mod, dual, cost, args.dry_run)
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
        if args.no_early_stop:
            logger.info("[COORDINATOR] Early-stop disabled (--no-early-stop); continuing all rounds")
            continue
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
