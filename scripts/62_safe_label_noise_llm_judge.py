#!/usr/bin/env python3
"""Safe Label Noise LLM-as-judge - v52
Judge 16 strict-flagged safe contracts using GPT-4.1-mini.
"""
import json
import os
import time
from collections import Counter
from datetime import datetime
from openai import OpenAI

SLITHER_JSON = "/home/curtis/DmAVID/experiments/slither/slither_results.json"
NOISE_AUDIT = "/home/curtis/DmAVID/experiments/audit/safe_label_noise_audit.json"
WILD_REPO = "/home/curtis/DmAVID/data/smartbugs_wild_repo/contracts"
OUT_JSON = "/home/curtis/DmAVID/experiments/audit/safe_label_noise_llm_judge.json"

# Known Slither High-severity detectors (from Slither docs)
HIGH_DETECTORS = {
    "reentrancy-eth": "Reentrancy: ETH can be stolen via cross-function reentrancy",
    "reentrancy-no-gas": "Reentrancy: ETH sent via transfer/send (limited gas but still possible)",
    "suicidal": "Contract can be killed by anyone (selfdestruct)",
    "arbitrary-send-eth": "Arbitrary ETH send: ETH sent to an attacker-controlled address",
    "arbitrary-send-erc20": "Arbitrary ERC20 send: tokens sent to attacker-controlled address",
    "controlled-delegatecall": "Delegatecall to attacker-controlled address",
    "unchecked-transfer": "Unchecked ERC20 transfer return value; failed transfers silently ignored",
    "unchecked-send": "Unchecked send() return value; ETH transfer failure silently ignored",
    "msg-value-loop": "msg.value used in a loop (multi-call pattern)",
    "shadowing-state": "State variable shadowing: a state variable shadows an inherited one",
    "storage-array": "Array deletion only removes reference, not storage data",
    "delegatecall-loop": "Delegatecall inside a loop",
    "write-after-write": "Variable written twice with no read in between",
    "incorrect-modifier": "Modifier does not execute _ or revert, breaking control flow",
}

DETECTOR_DESCRIPTIONS = {
    "external-function": "INFORMATIONAL: Public function could be declared external (gas optimization, NOT security)",
    "too-many-digits": "INFORMATIONAL: Literals with many digits (style)",
    "naming-convention": "INFORMATIONAL: Naming convention violation",
    "reentrancy-benign": "LOW: Benign reentrancy (no ETH transfer, state change order issue only)",
    "reentrancy-unlimited-gas": "MEDIUM: Reentrancy via call with unlimited gas",
    "reentrancy-events": "LOW: Reentrancy in event emission order",
    "unused-return": "MEDIUM: Return value not checked",
    "timestamp": "MEDIUM: Block timestamp dependence",
    "uninitialized-local": "MEDIUM: Uninitialized local variable",
    "missing-zero-check": "LOW: Missing zero-address check",
    "deprecated-standards": "INFORMATIONAL: Use of deprecated Solidity features",
    "boolean-equal": "INFORMATIONAL: Unnecessary comparison to a Boolean constant",
    "constable-states": "OPTIMIZATION: State variable can be declared constant",
    "solc-version": "INFORMATIONAL: Outdated Solidity compiler version",
    "dead-code": "INFORMATIONAL: Dead code that is never executed",
    "assembly": "INFORMATIONAL: Assembly usage",
    "calls-loop": "LOW: Calls inside a loop",
    "events-maths": "LOW: Missing events for arithmetic operations",
    "events-access": "LOW: Missing events for access control changes",
    "unindexed-event-address": "INFORMATIONAL: Unindexed event address parameter",
    "missing-inheritance": "INFORMATIONAL: Missing inheritance from interface",
    "divide-before-multiply": "MEDIUM: Integer division before multiplication",
}

JUDGE_SYSTEM = """You are a senior Ethereum smart contract security auditor with 8+ years of experience.
Your task: Given Solidity source code and Slither static analysis findings, determine whether the HIGH-severity findings represent REAL exploitable vulnerabilities or Slither false positives.

Respond ONLY with a JSON object (no markdown, no explanation outside JSON):
{
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | AMBIGUOUS",
  "reasoning": "1-3 sentences explaining your judgment",
  "confidence": 0.0-1.0,
  "exploitability": "high | medium | low | none",
  "key_finding": "the specific detector name that is the main concern"
}

Verdicts:
- TRUE_POSITIVE: The code has a real, exploitable vulnerability that a real attacker could use
- FALSE_POSITIVE: Slither is wrong; the code is safe (pattern match but no real exploit path)
- AMBIGUOUS: Cannot determine without more context (e.g., depends on how it's called)"""


def load_sol(filename: str) -> str:
    path = os.path.join(WILD_REPO, filename)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as f:
        code = f.read()
    # Truncate very long files
    if len(code) > 6000:
        code = code[:6000] + "\n// [TRUNCATED]"
    return code


def build_prompt(record, slither_record) -> str:
    filename = record["filename"]
    source = load_sol(filename)
    vuln_types = slither_record["vuln_types"]
    severities = slither_record["severities"]

    sev_counts = Counter(s for s in severities)
    high_dets = [d for d in vuln_types if d in HIGH_DETECTORS]
    other_dets = [d for d in vuln_types if d not in HIGH_DETECTORS]

    lines = [
        f"Contract: {filename}",
        f"Lines: {slither_record.get('lines', '?')}",
        "",
        "=== Slither High-Severity Findings ===",
    ]
    for d in high_dets:
        lines.append(f"  [{d}]: {HIGH_DETECTORS[d]}")
    if not high_dets:
        lines.append("  (no known high-severity detectors; 1 unrecognized high-severity finding)")

    lines += [
        "",
        f"=== Severity Distribution ===",
        f"  High={sev_counts.get('High',0)}, Medium={sev_counts.get('Medium',0)}, "
        f"Low={sev_counts.get('Low',0)}, Informational={sev_counts.get('Informational',0)}",
        "",
        "=== Other Detectors (context) ===",
    ]
    for d in other_dets[:6]:
        desc = DETECTOR_DESCRIPTIONS.get(d, d)
        lines.append(f"  [{d}]: {desc}")

    if source:
        lines += ["", "=== Solidity Source Code ===", source]
    else:
        lines.append(f"\n(Source file not found: {filename})")

    lines += [
        "",
        "=== Question ===",
        "Based on the HIGH-severity findings and the source code, is this a TRUE security vulnerability "
        "or a Slither false positive? Consider the actual code structure, call patterns, and whether "
        "a real attacker can exploit this.",
    ]
    return "\n".join(lines)


def judge(client: OpenAI, prompt: str) -> dict:
    resp = client.chat.completions.create(
        model="gpt-4.1-mini",
        temperature=0.0,
        max_tokens=300,
        messages=[
            {"role": "system", "content": JUDGE_SYSTEM},
            {"role": "user", "content": prompt},
        ],
    )
    raw = resp.choices[0].message.content.strip()
    cost_in = resp.usage.prompt_tokens * 0.0004 / 1000
    cost_out = resp.usage.completion_tokens * 0.0016 / 1000
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract JSON block
        import re
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        parsed = json.loads(m.group()) if m else {"verdict": "AMBIGUOUS", "reasoning": raw, "confidence": 0.5, "exploitability": "unknown"}
    return parsed, cost_in + cost_out


def main():
    client = OpenAI()

    with open(NOISE_AUDIT) as f:
        noise_data = json.load(f)
    with open(SLITHER_JSON) as f:
        slither_data = json.load(f)

    slither_map = {r["contract_id"]: r for r in slither_data["results"]}
    strict_flagged = [c for c in noise_data["per_contract"] if c["slither_pred_strict"] == "vulnerable"]
    assert len(strict_flagged) == 16

    judgments = []
    total_cost = 0.0

    for i, record in enumerate(strict_flagged):
        contract_id = record["id"]
        slither_record = slither_map.get(contract_id, {})
        prompt = build_prompt(record, slither_record)

        print(f"[{i+1:2d}/16] Judging {record['filename'][:40]}...")
        result, cost = judge(client, prompt)
        total_cost += cost

        vuln_types = slither_record.get("vuln_types", [])
        high_dets = [d for d in vuln_types if d in HIGH_DETECTORS]

        judgments.append({
            "id": contract_id,
            "filename": record["filename"],
            "n_high": record["n_high"],
            "n_medium": record["n_medium"],
            "known_high_detectors": high_dets,
            "verdict": result.get("verdict", "AMBIGUOUS"),
            "confidence": result.get("confidence", 0.5),
            "exploitability": result.get("exploitability", "unknown"),
            "key_finding": result.get("key_finding", ""),
            "reasoning": result.get("reasoning", ""),
        })
        print(f"         verdict={result.get('verdict')}  conf={result.get('confidence')}  exploit={result.get('exploitability')}")

        time.sleep(0.3)

    n_tp = sum(1 for j in judgments if j["verdict"] == "TRUE_POSITIVE")
    n_fp = sum(1 for j in judgments if j["verdict"] == "FALSE_POSITIVE")
    n_amb = sum(1 for j in judgments if j["verdict"] == "AMBIGUOUS")
    verified_noise = n_tp / 100.0

    assert n_tp + n_fp + n_amb == 16, f"Counts don't sum to 16: {n_tp}+{n_fp}+{n_amb}"

    if verified_noise == 0:
        interpretation = (
            f"LLM-as-judge 二次驗證 16 個 Slither strict-flagged 合約，全部判定為 false positive 或 ambiguous。"
            f"verified safe label noise = 0%（n=16 GPT-4.1-mini judged）。"
            f"保留 strict noise upper bound 16% 作為保守上界。"
        )
    elif verified_noise <= 0.03:
        interpretation = (
            f"16 個 flagged 中 {n_tp} 個為真實 mislabel（GPT-4.1-mini 確認），"
            f"verified safe label noise = {verified_noise*100:.1f}%，"
            f"遠低於 strict upper bound 16%；此 {verified_noise*100:.1f}% 為 F1 估值之 noise floor。"
        )
    else:
        interpretation = (
            f"16 個 flagged 中 {n_tp} 個被 GPT-4.1-mini 確認為真實漏洞，"
            f"verified safe label noise = {verified_noise*100:.1f}%。"
            f"建議第伍章研究限制章節揭露此偏差，並說明對 F1 估值之影響。"
        )

    output = {
        "version": "v52_llm_judge_safe_noise",
        "timestamp": datetime.now().isoformat(),
        "n_strict_flagged": 16,
        "n_total_safe": 100,
        "judge_model": "gpt-4.1-mini",
        "judge_temperature": 0.0,
        "judgments": judgments,
        "summary": {
            "n_true_positive": n_tp,
            "n_false_positive": n_fp,
            "n_ambiguous": n_amb,
            "slither_strict_noise_upper_bound": 0.16,
            "verified_safe_label_noise": round(verified_noise, 4),
            "slither_fp_rate_on_flagged": round(n_fp / 16, 4),
        },
        "interpretation": interpretation,
        "cost_usd": round(total_cost, 6),
    }

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n=== LLM-as-judge Summary ===")
    print(f"TRUE_POSITIVE  (real mislabel):  {n_tp}/16")
    print(f"FALSE_POSITIVE (Slither FP):     {n_fp}/16")
    print(f"AMBIGUOUS:                       {n_amb}/16")
    print(f"verified_safe_label_noise:       {verified_noise*100:.1f}%  ({n_tp}/100)")
    print(f"slither_fp_rate_on_flagged:      {n_fp/16*100:.1f}%")
    print(f"Total cost: ${total_cost:.4f}")
    print(f"\nInterpretation:\n{interpretation}")
    print(f"\nOutput: {OUT_JSON}")


if __name__ == "__main__":
    main()
