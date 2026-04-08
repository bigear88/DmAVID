#!/usr/bin/env python3
"""
DmAVID Critic Agent - Failure Analysis for Iterative Improvement.

Analyzes False Positives and False Negatives from Student detection results,
producing structured failure reports that guide the next iteration.

Inspired by Reflexion (Shinn et al., 2023): verbal self-reflection as feedback.

Author: Curtis Chang
"""

import os
import sys
import json
import re
import time
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
from _model_compat import token_param

from openai import OpenAI

MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()


# ---------------------------------------------------------------------------
# Failure Analysis Prompt Templates
# ---------------------------------------------------------------------------

FN_ANALYSIS_PROMPT = """You are a smart contract security expert providing a second opinion.

The Student detector classified this contract as SAFE. However, you suspect it may contain vulnerabilities that were missed.

## Contract Code:
```solidity
{code}
```

## Student's Reasoning for classifying as SAFE:
"{reasoning}"

## Your Task:
Independently analyze the contract and determine if the Student missed any vulnerabilities. Provide:

1. **root_cause**: If you find a vulnerability the Student missed, explain why the Student's reasoning failed.
2. **missed_pattern**: What specific code pattern indicates a potential vulnerability?
3. **corrective_hint**: A concise instruction the Student should follow to improve detection.
4. **confidence_calibration**: Was the Student overconfident in its "safe" classification?

If you agree the contract is safe, set root_cause to "Student assessment appears correct".

Respond in JSON:
{{"root_cause": "...", "missed_pattern": "...", "corrective_hint": "...", "confidence_calibration": "overconfident/appropriate/underconfident"}}"""

FP_ANALYSIS_PROMPT = """You are a smart contract security expert providing a second opinion.

The Student detector classified this contract as VULNERABLE. You need to verify whether this assessment is correct.

## Contract Code:
```solidity
{code}
```

## Student's Reasoning for classifying as VULNERABLE:
"{reasoning}"

## Student's Claimed Vulnerability Types:
{vuln_types}

## Your Task:
Independently analyze the contract. Determine if the Student's vulnerability assessment is justified or a false alarm. Provide:

1. **root_cause**: If this is a false alarm, explain why the Student was wrong. If the vulnerability is real, say "Student assessment appears correct".
2. **false_trigger**: What specific code pattern may have misled the Student?
3. **corrective_hint**: A concise instruction to help the Student make more accurate assessments.
4. **mitigation_missed**: What defense mechanisms exist in the code that the Student may have overlooked?

Respond in JSON:
{{"root_cause": "...", "false_trigger": "...", "corrective_hint": "...", "mitigation_missed": "..."}}"""


# ---------------------------------------------------------------------------
# Critic Agent
# ---------------------------------------------------------------------------

class CriticAgent:
    """
    Analyzes Student detection errors (FP/FN) and produces structured
    failure reports for iterative self-improvement.
    """

    def __init__(self, model: str = None, max_fn: int = 15, max_fp: int = 10):
        self.model = model or MODEL
        self.max_fn = max_fn
        self.max_fp = max_fp
        self.total_tokens = 0

    def _call_llm(self, prompt: str):
        """Call LLM and return (content, tokens_used)."""
        try:
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert smart contract security auditor performing failure analysis."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                **token_param(800),
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            self.total_tokens += tokens
            return content, tokens
        except Exception as e:
            return json.dumps({"error": str(e)}), 0

    def _parse_json(self, text: str) -> Dict:
        """Extract JSON from LLM response."""
        try:
            match = re.search(r"\{[\s\S]*\}", text)
            if match:
                return json.loads(match.group())
        except json.JSONDecodeError:
            pass
        return {"error": "parse_failed", "raw": text[:500]}

    def analyze_false_negatives(self, fn_cases: List[Dict], code_loader) -> List[Dict]:
        """Analyze false negative cases."""
        analyses = []
        cases = fn_cases[:self.max_fn]

        for case in cases:
            cid = case.get("contract_id", "unknown")
            code = code_loader(cid)
            if not code:
                continue

            prompt = FN_ANALYSIS_PROMPT.format(
                code=code[:8000],
                reasoning=case.get("reasoning", "No reasoning provided")[:1500],
            )
            content, tokens = self._call_llm(prompt)
            parsed = self._parse_json(content)

            analyses.append({
                "contract_id": cid,
                "error_type": "false_negative",
                "category": case.get("category", "unknown"),
                "analysis": parsed,
                "tokens_used": tokens,
            })
            time.sleep(0.15)

        return analyses

    def analyze_false_positives(self, fp_cases: List[Dict], code_loader) -> List[Dict]:
        """Analyze false positive cases."""
        analyses = []
        cases = fp_cases[:self.max_fp]

        for case in cases:
            cid = case.get("contract_id", "unknown")
            code = code_loader(cid)
            if not code:
                continue

            vuln_types = case.get("vulnerability_types", [])
            prompt = FP_ANALYSIS_PROMPT.format(
                code=code[:8000],
                reasoning=case.get("reasoning", "No reasoning provided")[:1500],
                vuln_types=", ".join(vuln_types) if vuln_types else "unspecified",
            )
            content, tokens = self._call_llm(prompt)
            parsed = self._parse_json(content)

            analyses.append({
                "contract_id": cid,
                "error_type": "false_positive",
                "analysis": parsed,
                "tokens_used": tokens,
            })
            time.sleep(0.15)

        return analyses

    def generate_failure_report(self, student_results: List[Dict], code_loader) -> Dict[str, Any]:
        """
        Full failure analysis: identify FP/FN, analyze each, produce report.

        Args:
            student_results: List of dicts with contract_id, ground_truth_vulnerable,
                             predicted_vulnerable, reasoning, category, etc.
            code_loader: Callable(contract_id) -> str.

        Returns:
            Dict with fn_analyses, fp_analyses, summary, corrective_hints.
        """
        fn_cases = [
            r for r in student_results
            if r.get("ground_truth_vulnerable") and not r.get("predicted_vulnerable")
        ]
        fp_cases = [
            r for r in student_results
            if not r.get("ground_truth_vulnerable") and r.get("predicted_vulnerable")
        ]

        print(f"  [CRITIC] Found {len(fn_cases)} FN, {len(fp_cases)} FP")

        fn_analyses = self.analyze_false_negatives(fn_cases, code_loader)
        fp_analyses = self.analyze_false_positives(fp_cases, code_loader)

        # Extract corrective hints
        fn_hints = []
        for a in fn_analyses:
            hint = a.get("analysis", {}).get("corrective_hint", "")
            pattern = a.get("analysis", {}).get("missed_pattern", "")
            if hint:
                fn_hints.append({
                    "category": a.get("category", "unknown"),
                    "hint": hint,
                    "missed_pattern": pattern,
                })

        fp_hints = []
        for a in fp_analyses:
            hint = a.get("analysis", {}).get("corrective_hint", "")
            mitigation = a.get("analysis", {}).get("mitigation_missed", "")
            if hint:
                fp_hints.append({
                    "hint": hint,
                    "mitigation_missed": mitigation,
                })

        return {
            "fn_count": len(fn_cases),
            "fp_count": len(fp_cases),
            "fn_analyzed": len(fn_analyses),
            "fp_analyzed": len(fp_analyses),
            "fn_analyses": fn_analyses,
            "fp_analyses": fp_analyses,
            "corrective_hints": {
                "for_false_negatives": fn_hints,
                "for_false_positives": fp_hints,
            },
            "total_tokens": self.total_tokens,
        }

    def format_hints_for_prompt(self, report: Dict) -> str:
        """
        Format failure analysis into a concise context string
        to inject into the Student's next-round prompt.
        """
        lines = ["## Failure Analysis from Previous Round\n"]
        lines.append(
            f"Previous round had {report['fn_count']} false negatives "
            f"and {report['fp_count']} false positives.\n"
        )

        fn_hints = report.get("corrective_hints", {}).get("for_false_negatives", [])
        if fn_hints:
            lines.append("### Missed Vulnerabilities (avoid these mistakes):")
            for i, h in enumerate(fn_hints[:8], 1):
                lines.append(f"{i}. [{h['category']}] {h['hint']}")
                if h.get("missed_pattern"):
                    lines.append(f"   Pattern to watch: {h['missed_pattern']}")
            lines.append("")

        fp_hints = report.get("corrective_hints", {}).get("for_false_positives", [])
        if fp_hints:
            lines.append("### False Alarms (avoid these triggers):")
            for i, h in enumerate(fp_hints[:6], 1):
                lines.append(f"{i}. {h['hint']}")
                if h.get("mitigation_missed"):
                    lines.append(f"   Defense to recognize: {h['mitigation_missed']}")
            lines.append("")

        return "\n".join(lines)


if __name__ == "__main__":
    print("CriticAgent module loaded successfully.")
    print(f"Model: {MODEL}")
    critic = CriticAgent()
    print(f"Max FN to analyze: {critic.max_fn}")
    print(f"Max FP to analyze: {critic.max_fp}")
