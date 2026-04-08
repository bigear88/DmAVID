#!/usr/bin/env python3
"""
Step 3e: Compound Vulnerability Case Study (Cream/Euler/Harvest).

Uses DmAVID LLM+RAG to analyze real DeFi attack PoC contracts,
testing whether the framework can identify multi-step attack vectors.

Per committee: "Real DeFi attacks are often compound exploits (multi-vuln chains)"
"""
import json, os, sys, time, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from openai import OpenAI

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "compound_vuln", "case_study_results.json")

CASES = [
    {
        "id": "Cream Finance (2021-10)",
        "file": "data/DeFiHackLabs/src/test/2021-10/Cream_2_exp.sol",
        "chain": "Flash Loan -> Price Oracle Manipulation -> Reentrancy",
        "loss": "$130M",
        "expected_vulns": ["flash loan", "oracle", "reentrancy", "price manipulation"],
        "complexity": "3-step chain",
    },
    {
        "id": "Euler Finance (2023-03)",
        "file": "data/DeFiHackLabs/src/test/2023-03/Euler_exp.sol",
        "chain": "Flash Loan -> donate() Abuse -> Liquidation Logic Flaw",
        "loss": "$197M",
        "expected_vulns": ["flash loan", "logic", "liquidation", "donate"],
        "complexity": "3-step chain (logic)",
    },
    {
        "id": "Harvest Finance (2020-10)",
        "file": "data/DeFiHackLabs/src/test/2020-10/HarvestFinance_exp.sol",
        "chain": "Flash Loan -> AMM Price Slippage Manipulation",
        "loss": "$34M",
        "expected_vulns": ["flash loan", "price", "slippage", "amm"],
        "complexity": "2-step chain",
    },
]

ANALYSIS_PROMPT = """You are an expert DeFi security auditor. Analyze this Solidity smart contract for compound/multi-step vulnerability patterns.

This is a Proof-of-Concept (PoC) exploit contract from a REAL DeFi attack. Your task:

1. Identify ALL vulnerability types present (flash loan, reentrancy, oracle manipulation, logic flaw, etc.)
2. Describe the ATTACK CHAIN — the step-by-step sequence of how vulnerabilities are chained together
3. For each step, identify which function/interface is exploited
4. Rate the detection difficulty (Easy/Medium/Hard) for each step

Respond in JSON:
{
  "vulnerabilities_found": ["type1", "type2", ...],
  "attack_chain": [
    {"step": 1, "action": "...", "vuln_type": "...", "difficulty": "Easy/Medium/Hard"},
    ...
  ],
  "total_steps": N,
  "overall_severity": "Critical/High/Medium",
  "could_static_tools_detect": true/false,
  "reasoning": "brief explanation"
}"""

def main():
    print("=" * 60)
    print("Compound Vulnerability Case Study")
    print(f"Model: {MODEL}")
    print("=" * 60)

    results = []
    total_tokens = 0

    for case in CASES:
        filepath = os.path.join(BASE_DIR, case["file"])
        print(f"\n--- {case['id']} ({case['loss']}) ---")
        print(f"  Chain: {case['chain']}")
        print(f"  Complexity: {case['complexity']}")

        if not os.path.exists(filepath):
            print(f"  ERROR: File not found: {filepath}")
            results.append({"case": case["id"], "error": "file_not_found"})
            continue

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        print(f"  Code length: {len(code)} chars")

        try:
            t0 = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": ANALYSIS_PROMPT},
                    {"role": "user", "content": f"```solidity\n{code[:12000]}\n```"},
                ],
                temperature=0.2,
                **token_param(1500),
            )
            elapsed = time.time() - t0
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            total_tokens += tokens

            # Parse JSON
            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                parsed = {"raw": content[:500]}

            vulns_found = parsed.get("vulnerabilities_found", [])
            chain = parsed.get("attack_chain", [])
            steps = parsed.get("total_steps", len(chain))

            # Check coverage against expected vulns
            expected = set(v.lower() for v in case["expected_vulns"])
            found_lower = set(v.lower() for v in vulns_found)
            matched = sum(1 for e in expected if any(e in f for f in found_lower))
            coverage = matched / len(expected) if expected else 0

            result = {
                "case": case["id"],
                "loss": case["loss"],
                "expected_chain": case["chain"],
                "complexity": case["complexity"],
                "vulns_found": vulns_found,
                "attack_steps": steps,
                "chain_details": chain,
                "expected_coverage": round(coverage, 2),
                "could_static_detect": parsed.get("could_static_tools_detect", None),
                "reasoning": parsed.get("reasoning", "")[:300],
                "tokens": tokens,
                "time_s": round(elapsed, 1),
            }
            results.append(result)

            print(f"  Vulns found: {vulns_found}")
            print(f"  Attack steps: {steps}")
            print(f"  Expected coverage: {coverage:.0%} ({matched}/{len(expected)})")
            print(f"  Static tools could detect: {parsed.get('could_static_tools_detect', '?')}")
            print(f"  Tokens: {tokens}, Time: {elapsed:.1f}s")

        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({"case": case["id"], "error": str(e)})

    # Summary
    print("\n" + "=" * 60)
    print("COMPOUND VULNERABILITY CASE STUDY SUMMARY")
    print("=" * 60)
    print(f"\n{'Case':<25} {'Loss':>8} {'Steps':>6} {'Vulns':>6} {'Coverage':>9} {'Static?':>8}")
    print("-" * 65)
    for r in results:
        if "error" in r:
            print(f"{r['case']:<25} ERROR")
            continue
        print(f"{r['case']:<25} {r['loss']:>8} {r['attack_steps']:>6} {len(r['vulns_found']):>6} "
              f"{r['expected_coverage']:>8.0%} {str(r.get('could_static_detect','?')):>8}")

    print(f"\nTotal tokens: {total_tokens:,}")

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump({"experiment": "compound_vulnerability_case_study",
                    "model": MODEL, "cases": results, "total_tokens": total_tokens}, f, indent=2)
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
