#!/usr/bin/env python3
"""
DmAVID Teacher Agent: Generates vulnerability challenges for Student Agent.

The Teacher Agent is responsible for:
1. Identifying uncovered vulnerability types from the SWC Registry
2. Generating Solidity code snippets that contain specific vulnerabilities
3. Evaluating the Student Agent's detection coverage and accuracy
4. Dynamically adjusting challenge difficulty based on student performance
5. Maintaining a knowledge base of generated challenges for benchmarking

This script implements the core logic for the multi-agent framework where the Teacher
continuously generates adversarial challenges tailored to improve the Student Agent's
vulnerability detection capabilities across all SWC categories.
"""

import os
import json
import time
import random
from datetime import datetime
from openai import OpenAI

import sys; sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param, MODEL as COMPAT_MODEL

random.seed(42)

# Configuration
BASE_DIR = os.environ.get("DAVID_BASE_DIR", "/home/curtis/DmAVID")
KNOWLEDGE_DIR = os.path.join(BASE_DIR, "scripts/knowledge")
EXPERIMENTS_DIR = os.path.join(BASE_DIR, "experiments")
TEACHER_CHALLENGES_DIR = os.path.join(EXPERIMENTS_DIR, "teacher_challenges")
KNOWLEDGE_FILE = os.path.join(KNOWLEDGE_DIR, "vulnerability_knowledge.json")

client = OpenAI()
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")

# SWC vulnerability categories (from Smart Contract Weakness Classification Registry)
SWC_CATEGORIES = {
    "reentrancy": "SWC-107",
    "integer_overflow": "SWC-101",
    "access_control": "SWC-103",
    "unchecked_return": "SWC-104",
    "denial_of_service": "SWC-113",
    "front_running": "SWC-114",
    "time_manipulation": "SWC-116",
    "tx_origin": "SWC-115",
    "delegatecall": "SWC-112",
    "selfdestruct": "SWC-106",
    "price_oracle_manipulation": "SWC-125",
    "flash_loan_attack": "Custom-001"
}


def load_knowledge_base():
    """Load the vulnerability knowledge base from JSON files."""
    if not os.path.exists(KNOWLEDGE_FILE):
        print(f"Warning: Knowledge base not found at {KNOWLEDGE_FILE}")
        return {"entries": [], "metadata": {}}

    with open(KNOWLEDGE_FILE, 'r') as f:
        knowledge = json.load(f)

    print(f"Loaded knowledge base with {len(knowledge.get('entries', []))} entries")
    return knowledge


def generate_challenge(vuln_type, difficulty_level, knowledge_base):
    """
    Generate a Solidity smart contract challenge containing a specific vulnerability.

    Args:
        vuln_type (str): The vulnerability category (e.g., "reentrancy")
        difficulty_level (int): Challenge difficulty 1-5 (1=easy, 5=hard)
        knowledge_base (dict): The loaded vulnerability knowledge base

    Returns:
        dict: Challenge metadata with contract code, vulnerability details, and metadata
    """
    # Find relevant knowledge entries for this vulnerability type
    relevant_entries = [
        e for e in knowledge_base.get("entries", [])
        if e.get("category") == vuln_type
    ]

    if not relevant_entries:
        print(f"Warning: No knowledge entries found for {vuln_type}")
        return None

    # Select a random entry as basis
    base_entry = random.choice(relevant_entries)

    # Create prompt for LLM to generate a challenge
    prompt = f"""You are an expert smart contract security researcher. Generate a Solidity smart contract
    code snippet that contains a specific {vuln_type} vulnerability at difficulty level {difficulty_level}/5.

    Knowledge base reference:
    - Title: {base_entry.get('title', 'Unknown')}
    - Description: {base_entry.get('description', 'No description')}
    - Vulnerable Pattern: {base_entry.get('vulnerability_pattern', 'No pattern')}
    - Mitigation: {base_entry.get('mitigation', 'No mitigation')}
    - Real-world case: {base_entry.get('real_world_case', 'No case')}

    Generate a Solidity contract with the following requirements:
    1. Difficulty level {difficulty_level}: {'Simple single-function vulnerability' if difficulty_level == 1 else 'Add obfuscation' if difficulty_level <= 3 else 'Complex cross-contract interactions'}
    2. The vulnerability should be CLEARLY present for demonstration purposes
    3. Include line numbers as comments (e.g., // L1, // L2, etc.)
    4. The contract should compile without syntax errors
    5. Include helper functions if needed to make the vulnerability more realistic

    Respond in JSON format ONLY:
    {{
      "contract_code": "// Full Solidity code with line numbers as comments",
      "vulnerability_location": [3, 7, 12],
      "vulnerability_summary": "Brief description of the vulnerability",
      "difficulty_explanation": "Why this is difficulty level {difficulty_level}"
    }}"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            **token_param(2048),
        )

        content = response.choices[0].message.content.strip()

        # Parse JSON from response
        import re
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            parsed = json.loads(json_match.group())
        else:
            parsed = json.loads(content)

        # Build challenge object
        challenge = {
            "challenge_id": f"{vuln_type}_L{difficulty_level}_{int(time.time())}",
            "vuln_type": vuln_type,
            "swc_id": SWC_CATEGORIES.get(vuln_type, "Unknown"),
            "difficulty": difficulty_level,
            "contract_code": parsed.get("contract_code", ""),
            "vuln_location": parsed.get("vulnerability_location", []),
            "vuln_summary": parsed.get("vulnerability_summary", ""),
            "difficulty_explanation": parsed.get("difficulty_explanation", ""),
            "knowledge_base_reference": base_entry.get("id", "Unknown"),
            "timestamp": datetime.now().isoformat(),
            "tokens_used": response.usage.total_tokens if response.usage else 0
        }

        return challenge

    except Exception as e:
        print(f"Error generating challenge for {vuln_type}: {str(e)}")
        return None


def evaluate_student_coverage(student_results, challenges):
    """
    Evaluate the Student Agent's vulnerability detection coverage.

    Args:
        student_results (dict): Student Agent's detection results
        challenges (list): List of generated challenges

    Returns:
        dict: Coverage analysis with per-type statistics and identified gaps
    """
    coverage_analysis = {
        "total_challenges": len(challenges),
        "per_vuln_type": {},
        "overall_coverage": 0.0,
        "uncovered_types": []
    }

    # Analyze coverage per vulnerability type
    for vuln_type in SWC_CATEGORIES.keys():
        type_challenges = [c for c in challenges if c.get("vuln_type") == vuln_type]

        if not type_challenges:
            continue

        # Count correctly detected challenges
        correctly_detected = 0
        for challenge in type_challenges:
            challenge_id = challenge.get("challenge_id")
            if challenge_id in student_results:
                detection = student_results[challenge_id]
                # Simple check: if student detected this type, count as correct
                if vuln_type in detection.get("detected_types", []):
                    correctly_detected += 1

        coverage_rate = correctly_detected / len(type_challenges) if type_challenges else 0

        coverage_analysis["per_vuln_type"][vuln_type] = {
            "total_challenges": len(type_challenges),
            "correctly_detected": correctly_detected,
            "coverage_rate": round(coverage_rate, 3),
            "gaps": len(type_challenges) - correctly_detected
        }

        # Identify uncovered types (0% detection rate)
        if coverage_rate == 0.0:
            coverage_analysis["uncovered_types"].append(vuln_type)

    # Calculate overall coverage
    total_detected = sum(
        v["correctly_detected"] for v in coverage_analysis["per_vuln_type"].values()
    )
    total_challenges = coverage_analysis["total_challenges"]
    coverage_analysis["overall_coverage"] = (
        total_detected / total_challenges if total_challenges > 0 else 0.0
    )

    return coverage_analysis


def adjust_difficulty(coverage_results, current_challenges):
    """
    Dynamically adjust challenge difficulty based on student performance.

    Args:
        coverage_results (dict): Coverage analysis from evaluate_student_coverage()
        current_challenges (list): Current set of challenges

    Returns:
        dict: Recommendations for new challenges (difficulty adjustments and focus areas)
    """
    recommendations = {
        "increase_difficulty_types": [],
        "maintain_difficulty_types": [],
        "decrease_difficulty_types": [],
        "generate_more_variants": [],
        "priority_focus_areas": []
    }

    for vuln_type, stats in coverage_results.get("per_vuln_type", {}).items():
        coverage = stats.get("coverage_rate", 0.0)

        # High coverage (>80%): increase difficulty
        if coverage > 0.8:
            recommendations["increase_difficulty_types"].append({
                "type": vuln_type,
                "current_coverage": coverage,
                "recommendation": "Increase difficulty to make challenges harder"
            })

        # Medium coverage (30-80%): maintain and add more variants
        elif coverage >= 0.3:
            recommendations["maintain_difficulty_types"].append({
                "type": vuln_type,
                "current_coverage": coverage,
                "recommendation": "Maintain current difficulty and add more variants"
            })
            recommendations["generate_more_variants"].append(vuln_type)

        # Low/zero coverage (<30%): lower difficulty or focus
        else:
            recommendations["decrease_difficulty_types"].append({
                "type": vuln_type,
                "current_coverage": coverage,
                "recommendation": "Decrease difficulty to help student learn"
            })
            recommendations["priority_focus_areas"].append(vuln_type)

    # Uncovered types are top priority
    uncovered = coverage_results.get("uncovered_types", [])
    if uncovered:
        recommendations["priority_focus_areas"] = uncovered + recommendations["priority_focus_areas"]

    return recommendations


def main():
    """Main execution flow for the Teacher Agent."""
    print("=" * 70)
    print("DMAVID TEACHER AGENT: Challenge Generation and Coverage Analysis")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print("=" * 70)

    # Load knowledge base
    print("\n[1/5] Loading vulnerability knowledge base...")
    knowledge_base = load_knowledge_base()
    if not knowledge_base.get("entries"):
        print("Error: Knowledge base is empty. Cannot generate challenges.")
        return

    # Scan for uncovered vulnerability types
    print("\n[2/5] Scanning for uncovered vulnerability types...")
    available_types = list(SWC_CATEGORIES.keys())
    print(f"  Total SWC categories available: {len(available_types)}")
    print(f"  Categories: {', '.join(available_types[:6])}...")

    # Generate challenges
    print("\n[3/5] Generating vulnerability challenges...")
    num_challenges = 10  # Default configurable
    challenges = []

    # Distribute challenges across difficulty levels
    difficulty_distribution = [1, 1, 2, 2, 3, 3, 4, 4, 5, 5]  # 10 challenges
    selected_types = random.sample(available_types, min(len(available_types), num_challenges))

    for i, (vuln_type, difficulty) in enumerate(zip(selected_types, difficulty_distribution)):
        print(f"  [{i+1}/{num_challenges}] Generating {vuln_type} challenge (difficulty {difficulty})...", end=" ")

        challenge = generate_challenge(vuln_type, difficulty, knowledge_base)
        if challenge:
            challenges.append(challenge)
            print(f"OK (ID: {challenge['challenge_id']})")
        else:
            print("FAILED")

        time.sleep(0.5)  # Rate limiting

    print(f"\n  Successfully generated {len(challenges)} challenges")

    # Create output directory
    print("\n[4/5] Saving challenges to disk...")
    os.makedirs(TEACHER_CHALLENGES_DIR, exist_ok=True)

    round_num = 1
    challenge_file = os.path.join(TEACHER_CHALLENGES_DIR, f"challenges_round_{round_num}.json")

    # Find next round number if file exists
    while os.path.exists(challenge_file):
        round_num += 1
        challenge_file = os.path.join(TEACHER_CHALLENGES_DIR, f"challenges_round_{round_num}.json")

    # Save challenges
    output = {
        "round": round_num,
        "timestamp": datetime.now().isoformat(),
        "total_challenges": len(challenges),
        "challenges": challenges,
        "metadata": {
            "model": MODEL,
            "knowledge_base_size": len(knowledge_base.get("entries", [])),
            "swc_categories_targeted": len(set(c.get("vuln_type") for c in challenges))
        }
    }

    with open(challenge_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"  Challenges saved to: {challenge_file}")

    # Summary statistics
    print("\n[5/5] Summary Statistics")
    print("=" * 70)

    # Per-type distribution
    type_counts = {}
    for challenge in challenges:
        vuln_type = challenge.get("vuln_type")
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

    print("\nChallenges per Vulnerability Type:")
    for vuln_type in sorted(type_counts.keys()):
        count = type_counts[vuln_type]
        print(f"  {vuln_type:25s}: {count:2d} challenges")

    # Difficulty distribution
    difficulty_counts = {}
    for challenge in challenges:
        diff = challenge.get("difficulty")
        difficulty_counts[diff] = difficulty_counts.get(diff, 0) + 1

    print("\nChallenges per Difficulty Level:")
    for level in sorted(difficulty_counts.keys()):
        count = difficulty_counts[level]
        print(f"  Level {level}/5: {count:2d} challenges")

    # Token usage
    total_tokens = sum(c.get("tokens_used", 0) for c in challenges)
    avg_tokens = total_tokens / len(challenges) if challenges else 0
    print(f"\nToken Usage:")
    print(f"  Total tokens used: {total_tokens:,}")
    print(f"  Average per challenge: {avg_tokens:.0f}")

    print("\n" + "=" * 70)
    print(f"Teacher Agent round {round_num} completed successfully!")
    print(f"Output file: {challenge_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
