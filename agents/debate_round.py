#!/usr/bin/env python3
"""
DmAVID Debate Round - Multi-Agent Adversarial Debate for Disputed Cases.

Implements the debate mechanism from Du et al. (2023) "Improving Factuality
and Reasoning in Language Models through Multiagent Debate."

For each disputed case (FN or FP), Red Team and Student argue their positions
across multiple rounds. A Coordinator adjudicates based on argument quality.

Flow:
  1. Identify disputed cases (FN + FP from Student detection)
  2. For each case:
     a. Red Team argues FOR vulnerability (provides attack scenario)
     b. Student argues AGAINST (provides defense reasoning)
     c. Up to 3 rounds of rebuttal
     d. Coordinator adjudicates: flip prediction or keep
  3. Re-compute metrics with flipped predictions

Author: Curtis Chang
"""

import os
import sys
import json
import re
import time
from typing import Dict, List, Any, Optional

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
from _model_compat import token_param

from openai import OpenAI

MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()


# ---------------------------------------------------------------------------
# Debate Prompts
# ---------------------------------------------------------------------------

RED_TEAM_ATTACK_PROMPT = """You are a Red Team attacker analyzing a smart contract.
Your goal is to find and PROVE any vulnerability in this contract.

## Contract Code:
```solidity
{code}
```

{rebuttal_context}

## Your Task:
Construct a CONCRETE attack scenario:
1. Preconditions: What state must the contract be in?
2. Attack steps: What transactions does the attacker send?
3. Expected outcome: What does the attacker gain?
4. Code evidence: Which specific lines are vulnerable?

If you truly cannot find an exploitable vulnerability, say "NO_ATTACK_FOUND".

Respond in JSON:
{{"attack_feasible": true/false, "preconditions": "...", "attack_steps": ["step1", "step2"], "expected_outcome": "...", "code_evidence": "line X: ...", "confidence": 0.0-1.0}}"""

STUDENT_DEFENSE_PROMPT = """You are a smart contract security analyst defending your assessment.
You previously classified this contract. Now respond to the Red Team's attack argument.

## Contract Code:
```solidity
{code}
```

## Red Team's Attack Argument:
{attack_argument}

{rebuttal_context}

## Your Task:
Rebut the Red Team's argument. For each attack step, explain:
1. Why the attack would fail, OR
2. What defense mechanism prevents it, OR
3. If you now agree the vulnerability exists, say "CONCEDE"

Respond in JSON:
{{"defense_holds": true/false, "rebuttals": ["rebuttal1", "rebuttal2"], "concede": false, "revised_assessment": "vulnerable/safe", "confidence": 0.0-1.0}}"""

COORDINATOR_ADJUDICATE_PROMPT = """You are an impartial security coordinator adjudicating a debate.

## Contract Code:
```solidity
{code}
```

## Debate Transcript:
{transcript}

## Your Task:
Based on the quality of arguments from both sides, determine:
1. Is this contract VULNERABLE or SAFE?
2. Which side presented stronger evidence?
3. Confidence in your decision (0.0-1.0)

Respond in JSON:
{{"final_verdict": "vulnerable/safe", "stronger_side": "red_team/student", "reasoning": "...", "confidence": 0.0-1.0}}"""


# ---------------------------------------------------------------------------
# Debate Agent
# ---------------------------------------------------------------------------

class DebateRound:
    """Orchestrates multi-round debates between Red Team and Student."""

    def __init__(self, model: str = None, max_debate_rounds: int = 2,
                 max_cases: int = 15):
        self.model = model or MODEL
        self.max_debate_rounds = max_debate_rounds
        self.max_cases = max_cases
        self.total_tokens = 0

    def _call_llm(self, system_msg: str, user_msg: str):
        """Call LLM and return (content, tokens)."""
        try:
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.3,
                **token_param(1000),
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            self.total_tokens += tokens
            return content, tokens
        except Exception as e:
            return json.dumps({"error": str(e)}), 0

    def _parse_json(self, text: str) -> Dict:
        try:
            match = re.search(r"\{[\s\S]*\}", text)
            if match:
                return json.loads(match.group())
        except json.JSONDecodeError:
            pass
        return {"error": "parse_failed", "raw": text[:500]}

    def debate_single_case(self, code: str,
                           student_original_prediction: bool,
                           student_reasoning: str) -> Dict:
        """
        Run a multi-round debate on a single contract.

        Args:
            code: Solidity source code.
            student_original_prediction: True if Student predicted vulnerable.
            student_reasoning: Student's original reasoning.

        Returns:
            Dict with debate transcript, final verdict, and whether to flip.
        """
        transcript = []
        code_short = code[:6000] if len(code) > 6000 else code

        # Round 1: Red Team attacks
        rebuttal_ctx = ""
        red_prompt = RED_TEAM_ATTACK_PROMPT.format(
            code=code_short, rebuttal_context=rebuttal_ctx
        )
        red_content, red_tokens = self._call_llm(
            "You are an aggressive Red Team attacker trying to find exploits.",
            red_prompt
        )
        red_parsed = self._parse_json(red_content)
        transcript.append({"role": "red_team", "round": 1, "argument": red_parsed})

        # Check if Red Team found an attack
        if red_parsed.get("attack_feasible") == False or "NO_ATTACK_FOUND" in red_content:
            # Red Team concedes - no debate needed
            return {
                "debate_rounds": 1,
                "transcript": transcript,
                "final_verdict": "safe",
                "red_team_conceded": True,
                "flip_prediction": student_original_prediction,  # Flip if Student said vuln
                "new_prediction": False,  # Coordinator says safe
                "tokens_used": red_tokens,
            }

        # Round 1: Student defends
        attack_summary = json.dumps(red_parsed, indent=2)[:1500]
        student_prompt = STUDENT_DEFENSE_PROMPT.format(
            code=code_short,
            attack_argument=attack_summary,
            rebuttal_context=f"Your original reasoning was: \"{student_reasoning[:800]}\"",
        )
        student_content, student_tokens = self._call_llm(
            "You are a careful security analyst defending your assessment.",
            student_prompt
        )
        student_parsed = self._parse_json(student_content)
        transcript.append({"role": "student", "round": 1, "argument": student_parsed})

        # Check if Student concedes
        if student_parsed.get("concede") == True:
            return {
                "debate_rounds": 1,
                "transcript": transcript,
                "final_verdict": "vulnerable",
                "student_conceded": True,
                "flip_prediction": not student_original_prediction,  # Flip if Student said safe
                "new_prediction": True,  # Coordinator says vulnerable
                "tokens_used": red_tokens + student_tokens,
            }

        # Additional debate rounds
        for rnd in range(2, self.max_debate_rounds + 1):
            # Red Team rebuts Student's defense
            prev_defense = json.dumps(student_parsed, indent=2)[:1000]
            rebuttal_ctx = f"Student's defense from previous round:\n{prev_defense}\n\nCounter their rebuttals."

            red_prompt = RED_TEAM_ATTACK_PROMPT.format(
                code=code_short, rebuttal_context=rebuttal_ctx
            )
            red_content, _ = self._call_llm(
                "You are an aggressive Red Team attacker. Counter the defense.",
                red_prompt
            )
            red_parsed = self._parse_json(red_content)
            transcript.append({"role": "red_team", "round": rnd, "argument": red_parsed})

            # Student rebuts
            attack_summary = json.dumps(red_parsed, indent=2)[:1000]
            rebuttal_ctx = f"This is debate round {rnd}. The Red Team has escalated their argument."
            student_prompt = STUDENT_DEFENSE_PROMPT.format(
                code=code_short,
                attack_argument=attack_summary,
                rebuttal_context=rebuttal_ctx,
            )
            student_content, _ = self._call_llm(
                "You are a careful security analyst. This is your final chance to defend.",
                student_prompt
            )
            student_parsed = self._parse_json(student_content)
            transcript.append({"role": "student", "round": rnd, "argument": student_parsed})

            if student_parsed.get("concede") == True:
                break

            time.sleep(0.1)

        # Coordinator adjudicates
        transcript_text = ""
        for t in transcript:
            role = t["role"].replace("_", " ").title()
            arg = json.dumps(t["argument"], indent=2)[:600]
            transcript_text += f"\n[{role} - Round {t['round']}]\n{arg}\n"

        coord_prompt = COORDINATOR_ADJUDICATE_PROMPT.format(
            code=code_short, transcript=transcript_text
        )
        coord_content, _ = self._call_llm(
            "You are an impartial security coordinator making the final call.",
            coord_prompt
        )
        coord_parsed = self._parse_json(coord_content)

        final_verdict = coord_parsed.get("final_verdict", "safe")
        new_pred = final_verdict == "vulnerable"
        flip = new_pred != student_original_prediction

        return {
            "debate_rounds": len([t for t in transcript if t["role"] == "red_team"]),
            "transcript": transcript,
            "coordinator_verdict": coord_parsed,
            "final_verdict": final_verdict,
            "flip_prediction": flip,
            "new_prediction": new_pred,
            "tokens_used": self.total_tokens,
        }

    def run_debates(self, disputed_cases: List[Dict], code_loader) -> Dict[str, Any]:
        """
        Run debates on all disputed cases (FN + FP).

        Args:
            disputed_cases: List of dicts with contract_id, category,
                           reasoning, is_fn, ground_truth_vulnerable.
            code_loader: Callable(contract_id) -> source code.

        Returns:
            Dict with debate results and flip decisions.
        """
        cases = disputed_cases[:self.max_cases]
        debate_results = []
        flips = {"flip_to_vuln": 0, "flip_to_safe": 0, "no_change": 0}

        print(f"  [DEBATE] Running {len(cases)} debates (max {self.max_debate_rounds} rounds each)...")

        for i, case in enumerate(cases):
            cid = case.get("contract_id", "unknown")
            code = code_loader(cid)
            if not code:
                continue

            student_pred = case.get("student_prediction", True)
            print(f"    Debate {i+1}/{len(cases)}: {cid} (pred={'vuln' if student_pred else 'safe'})", end="")

            result = self.debate_single_case(
                code=code,
                student_original_prediction=student_pred,
                student_reasoning=case.get("reasoning", ""),
            )
            result["contract_id"] = cid
            result["student_original_prediction"] = student_pred

            if result.get("flip_prediction"):
                new_pred = result.get("new_prediction", not student_pred)
                if new_pred:
                    flips["flip_to_vuln"] += 1
                    print(f" -> FLIP to vulnerable")
                else:
                    flips["flip_to_safe"] += 1
                    print(f" -> FLIP to safe")
            else:
                flips["no_change"] += 1
                print(f" -> no change")

            debate_results.append(result)
            time.sleep(0.2)

        return {
            "total_debates": len(debate_results),
            "flips": flips,
            "debate_results": debate_results,
            "total_tokens": self.total_tokens,
        }


# ---------------------------------------------------------------------------
# Integration: apply debate flips to student results
# ---------------------------------------------------------------------------
def apply_debate_flips(student_results: List[Dict], debate_output: Dict) -> List[Dict]:
    """
    Apply debate flip decisions to student results.

    Returns a new list of results with flipped predictions.
    """
    flip_map = {}
    for dr in debate_output.get("debate_results", []):
        if dr.get("flip_prediction"):
            cid = dr["contract_id"]
            flip_map[cid] = dr.get("new_prediction", dr["final_verdict"] == "vulnerable")

    updated = []
    for r in student_results:
        new_r = dict(r)
        cid = r.get("contract_id", "")
        if cid in flip_map:
            new_r["predicted_vulnerable"] = flip_map[cid]
            new_r["debate_flipped"] = True
        else:
            new_r["debate_flipped"] = False
        updated.append(new_r)

    return updated


if __name__ == "__main__":
    print("DebateRound module loaded successfully.")
    print(f"Model: {MODEL}")
    dr = DebateRound()
    print(f"Max debate rounds: {dr.max_debate_rounds}")
    print(f"Max cases: {dr.max_cases}")
