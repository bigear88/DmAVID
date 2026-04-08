#!/usr/bin/env python3
"""
DmAVID Critic Loop - Iterative Improvement with Failure Analysis Feedback.

Unlike the original ratchet loop (29_) which only adds KB entries without
re-running detection, this loop implements genuine iterative improvement:

  Round N:
    1. Student detects vulnerabilities (with feedback from round N-1)
    2. Compute metrics (F1, Precision, Recall)
    3. Critic analyzes FP/FN errors
    4. Format failure analysis as corrective hints
    5. Inject hints into Student prompt for round N+1
    6. Ratchet: keep results only if F1 improves

This implements the Reflexion pattern (Shinn et al., 2023) where verbal
self-reflection guides the agent to avoid repeating mistakes.

Author: Curtis Chang
"""

import os
import sys
import json
import time
import random
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

# Path setup
BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
sys.path.insert(0, os.path.join(BASE_DIR, "agents"))

from _model_compat import token_param
from openai import OpenAI
from critic_agent import CriticAgent

random.seed(42)
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/critic_loop")

# RAG Knowledge Base (imported from script 05)
VULN_KNOWLEDGE_BASE = {
    "reentrancy": {
        "patterns": ["call.value() before state update", "external call followed by state change",
                     "msg.sender.call{value: amount}('')"],
        "safe_patterns": ["Checks-Effects-Interactions pattern", "ReentrancyGuard modifier",
                          "nonReentrant modifier", "State update before external call"],
    },
    "integer_overflow": {
        "patterns": ["Arithmetic without SafeMath (Solidity < 0.8)", "Unchecked { } block with arithmetic",
                     "Type casting to smaller integer types"],
        "safe_patterns": ["Using SafeMath library", "Solidity >= 0.8.0 (built-in overflow checks)",
                          "require() before arithmetic"],
    },
    "access_control": {
        "patterns": ["Missing onlyOwner modifier", "tx.origin for authentication",
                     "Public/external visibility on sensitive functions"],
        "safe_patterns": ["onlyOwner modifier", "Role-based access control (RBAC)",
                          "OpenZeppelin Ownable"],
    },
    "unchecked_call": {
        "patterns": ["address.call() without checking return value",
                     "send() without checking return bool"],
        "safe_patterns": ["require(success) after call", "Using transfer() instead of send()"],
    },
    "denial_of_service": {
        "patterns": ["Unbounded loop over dynamic array", "External call in loop",
                     "Block gas limit vulnerability"],
        "safe_patterns": ["Pull over push pattern", "Pagination pattern", "Gas-aware loops"],
    },
    "front_running": {
        "patterns": ["Price-sensitive operations without slippage protection",
                     "approve() followed by transferFrom()"],
        "safe_patterns": ["Commit-reveal scheme", "Slippage tolerance parameter"],
    },
    "time_manipulation": {
        "patterns": ["block.timestamp for critical logic", "now keyword dependency"],
        "safe_patterns": ["Block number instead of timestamp", "Tolerance windows"],
    },
    "tx_origin": {
        "patterns": ["require(tx.origin == owner)", "tx.origin for authorization"],
        "safe_patterns": ["msg.sender instead of tx.origin"],
    },
}

RAG_SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in Ethereum/DeFi.
Analyze the given Solidity contract for vulnerabilities.

IMPORTANT: You must respond with ONLY a JSON object in this exact format:
{"has_vulnerability": true/false, "confidence": 0.0-1.0, "vulnerability_types": ["type1"], "severity": "critical/high/medium/low/none", "reasoning": "explanation"}"""


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------
def load_dataset():
    """Load and sample the SmartBugs dataset (143 vuln + 100 safe = 243)."""
    with open(DATASET_FILE, "r") as f:
        data = json.load(f)
    contracts = data["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]
    random.shuffle(sample)
    return sample


def load_contract_code(filepath):
    """Load Solidity source code from filepath."""
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# RAG context builder
# ---------------------------------------------------------------------------
def build_rag_context(code):
    """Build RAG context by matching vulnerability patterns to code."""
    matched = []
    code_lower = code.lower()
    for vuln_type, info in VULN_KNOWLEDGE_BASE.items():
        for pattern in info["patterns"]:
            if any(kw in code_lower for kw in pattern.lower().split()):
                matched.append(f"[{vuln_type}] Watch for: {pattern}")
                matched.append(f"  Safe alternative: {info['safe_patterns'][0]}")
                break
    return "\n".join(matched[:10]) if matched else "No specific patterns matched."


# ---------------------------------------------------------------------------
# Student detection (with optional Critic feedback)
# ---------------------------------------------------------------------------
def run_student_detection(contracts, critic_feedback: str = "") -> List[Dict]:
    """
    Run LLM+RAG detection on all contracts.

    Args:
        contracts: List of contract dicts from dataset.
        critic_feedback: Optional failure analysis from Critic Agent.

    Returns:
        List of result dicts.
    """
    results = []
    total_tokens = 0

    for i, contract in enumerate(contracts):
        code = load_contract_code(contract.get("filepath", ""))
        if not code.strip():
            continue

        if len(code) > 12000:
            code = code[:12000] + "\n// ... (truncated)"

        rag_context = build_rag_context(code)

        # Build user message with RAG context + optional Critic feedback
        user_msg = f"## RAG Knowledge Base Context:\n{rag_context}\n\n"
        if critic_feedback:
            user_msg += f"{critic_feedback}\n\n"
        user_msg += f"## Contract to Analyze:\n```solidity\n{code}\n```"

        try:
            start = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": RAG_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                **token_param(1024),
                seed=42,
            )
            elapsed = time.time() - start
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            total_tokens += tokens

            # Parse JSON response
            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                parsed = json.loads(content)

            gt_vuln = contract.get("label") == "vulnerable"
            result = {
                "contract_id": contract.get("id", f"c_{i}"),
                "ground_truth_vulnerable": gt_vuln,
                "category": contract.get("category", contract.get("vulnerability_type", "unknown")),
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "reasoning": parsed.get("reasoning", ""),
                "tokens_used": tokens,
                "time_seconds": round(elapsed, 3),
            }
        except json.JSONDecodeError:
            gt_vuln = contract.get("label") == "vulnerable"
            has_vuln = any(w in content.lower() for w in ["true", "vulnerable"])
            result = {
                "contract_id": contract.get("id", f"c_{i}"),
                "ground_truth_vulnerable": gt_vuln,
                "category": contract.get("category", "unknown"),
                "predicted_vulnerable": has_vuln,
                "confidence": 0.5,
                "vulnerability_types": [],
                "reasoning": content[:500] if content else "",
                "tokens_used": tokens,
                "time_seconds": round(time.time() - start, 3),
            }
        except Exception as e:
            gt_vuln = contract.get("label") == "vulnerable"
            result = {
                "contract_id": contract.get("id", f"c_{i}"),
                "ground_truth_vulnerable": gt_vuln,
                "category": contract.get("category", "unknown"),
                "predicted_vulnerable": False,
                "confidence": 0.0,
                "vulnerability_types": [],
                "reasoning": f"Error: {e}",
                "tokens_used": 0,
                "time_seconds": 0,
            }

        results.append(result)

        if (i + 1) % 50 == 0:
            print(f"    Progress: {i+1}/{len(contracts)} ({total_tokens:,} tokens)")

        time.sleep(0.1)

    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(results: List[Dict]) -> Dict[str, float]:
    """Compute F1, Precision, Recall from results."""
    tp = fp = tn = fn = 0
    for r in results:
        gt = r.get("ground_truth_vulnerable", False)
        pred = r.get("predicted_vulnerable", False)
        if gt and pred:
            tp += 1
        elif not gt and pred:
            fp += 1
        elif gt and not pred:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "total": len(results),
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="DmAVID Critic Loop")
    parser.add_argument("--rounds", type=int, default=3, help="Number of iteration rounds")
    parser.add_argument("--max-fn", type=int, default=10, help="Max FN to analyze per round")
    parser.add_argument("--max-fp", type=int, default=8, help="Max FP to analyze per round")
    parser.add_argument("--dry-run", action="store_true", help="Load dataset but skip API calls")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("DmAVID Critic Loop - Iterative Improvement with Failure Analysis")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print(f"Rounds: {args.rounds}")
    print("=" * 70)

    # Load dataset
    contracts = load_dataset()
    print(f"Dataset: {len(contracts)} contracts")

    # Build code loader for Critic Agent
    id_to_filepath = {}
    for c in contracts:
        cid = c.get("id", "")
        fp = c.get("filepath", "")
        if cid and fp:
            id_to_filepath[cid] = fp

    def code_loader(contract_id):
        fp = id_to_filepath.get(contract_id, "")
        return load_contract_code(fp)

    # Initialize Critic
    critic = CriticAgent(max_fn=args.max_fn, max_fp=args.max_fp)

    # Track progression
    progression = []
    best_f1 = 0.0
    best_results = None
    critic_feedback = ""  # No feedback for first round
    total_tokens = 0

    for round_id in range(1, args.rounds + 1):
        round_start = time.time()
        print(f"\n{'='*50}")
        print(f"Round {round_id}/{args.rounds}")
        if critic_feedback:
            print(f"  Critic feedback: {len(critic_feedback)} chars injected")
        else:
            print(f"  Critic feedback: None (baseline round)")
        print(f"{'='*50}")

        if args.dry_run:
            print("  [DRY RUN] Skipping API calls")
            break

        # Step 1: Student detection (with Critic feedback from previous round)
        print(f"\n  [STUDENT] Running detection on {len(contracts)} contracts...")
        results = run_student_detection(contracts, critic_feedback)
        student_tokens = sum(r.get("tokens_used", 0) for r in results)
        total_tokens += student_tokens

        # Step 2: Compute metrics
        metrics = compute_metrics(results)
        print(f"\n  [METRICS] F1={metrics['f1']:.4f}  P={metrics['precision']:.4f}  "
              f"R={metrics['recall']:.4f}  (TP={metrics['tp']} FP={metrics['fp']} "
              f"FN={metrics['fn']} TN={metrics['tn']})")

        # Step 3: Ratchet check
        if metrics["f1"] >= best_f1:
            improvement = metrics["f1"] - best_f1
            best_f1 = metrics["f1"]
            best_results = results
            action = "KEEP"
            print(f"  [RATCHET] KEEP (F1 improved by +{improvement:.4f})")
        else:
            action = "REVERT"
            print(f"  [RATCHET] REVERT (F1={metrics['f1']:.4f} < best={best_f1:.4f})")

        # Step 4: Critic analysis (even if reverted, we learn from errors)
        print(f"\n  [CRITIC] Analyzing errors...")
        critic_report = critic.generate_failure_report(results, code_loader)
        critic_tokens = critic_report.get("total_tokens", 0) - sum(
            p.get("critic_tokens", 0) for p in progression
        )
        total_tokens += critic_tokens

        # Step 5: Format hints for next round
        critic_feedback = critic.format_hints_for_prompt(critic_report)
        print(f"  [CRITIC] Generated {len(critic_report['corrective_hints']['for_false_negatives'])} FN hints, "
              f"{len(critic_report['corrective_hints']['for_false_positives'])} FP hints")

        round_time = time.time() - round_start

        # Record round
        round_record = {
            "round": round_id,
            "metrics": metrics,
            "action": action,
            "best_f1": best_f1,
            "student_tokens": student_tokens,
            "critic_tokens": critic_tokens,
            "fn_analyzed": critic_report["fn_analyzed"],
            "fp_analyzed": critic_report["fp_analyzed"],
            "fn_hints": len(critic_report["corrective_hints"]["for_false_negatives"]),
            "fp_hints": len(critic_report["corrective_hints"]["for_false_positives"]),
            "critic_feedback_length": len(critic_feedback),
            "round_time_seconds": round(round_time, 1),
        }
        progression.append(round_record)

        # Save intermediate results
        intermediate = {
            "experiment": "critic_loop",
            "model": MODEL,
            "timestamp": datetime.now().isoformat(),
            "current_round": round_id,
            "total_rounds": args.rounds,
            "progression": progression,
            "total_tokens": total_tokens,
            "best_f1": best_f1,
        }
        with open(os.path.join(OUTPUT_DIR, "critic_loop_progress.json"), "w") as f:
            json.dump(intermediate, f, indent=2)

    # Final summary
    print(f"\n{'='*70}")
    print("CRITIC LOOP SUMMARY")
    print(f"{'='*70}")

    if progression:
        print(f"\nRound | F1     | P      | R      | Action | FN hints | FP hints")
        print("-" * 70)
        for p in progression:
            m = p["metrics"]
            print(f"  {p['round']}   | {m['f1']:.4f} | {m['precision']:.4f} | "
                  f"{m['recall']:.4f} | {p['action']:6s} | {p['fn_hints']:8d} | {p['fp_hints']:8d}")

        first_f1 = progression[0]["metrics"]["f1"]
        print(f"\nBaseline F1 (Round 1): {first_f1:.4f}")
        print(f"Best F1:               {best_f1:.4f}")
        print(f"Improvement:           +{best_f1 - first_f1:.4f} ({(best_f1 - first_f1) / max(first_f1, 0.001) * 100:.1f}%)")
        print(f"Total tokens:          {total_tokens:,}")
    else:
        print("No rounds completed (dry run).")

    # Save final results
    output = {
        "experiment": "critic_loop",
        "description": "Iterative improvement with Critic Agent failure analysis feedback (Reflexion pattern)",
        "model": MODEL,
        "dataset_size": len(contracts),
        "rounds": args.rounds,
        "timestamp": datetime.now().isoformat(),
        "progression": progression,
        "best_f1": best_f1,
        "total_tokens": total_tokens,
        "method": "Student(LLM+RAG) + CriticAgent(failure analysis) iterative loop",
    }

    # Save detailed results of best round
    if best_results:
        output["best_round_results"] = best_results

    outfile = os.path.join(OUTPUT_DIR, "critic_loop_results.json")
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {outfile}")


if __name__ == "__main__":
    main()
