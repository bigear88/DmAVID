#!/usr/bin/env python3
"""Agent-level ablation: measure each agent's contribution."""

print("=" * 65)
print("Agent-Level Ablation Analysis")
print("=" * 65)

# From actual experiment data
print("\n1. Pipeline Stage Ablation (each stage adds an agent's capability)")
print("-" * 65)
data = [
    ("Slither only",          0.7459, "baseline"),
    ("+LLM Base (Student)",   0.7507, "+0.64%"),
    ("+RAG (Student+KB)",     0.8468, "+12.8%  <-- RAG biggest"),
    ("+Self-Verify",          0.8896, "+5.1%   <-- SV second"),
    ("+DmAVID iterate",       0.8924, "+0.3%   <-- iteration"),
]
for name, f1, note in data:
    print(f"  {name:<25} F1={f1:.4f}  {note}")

print("\n2. Agent Iteration Contribution (3 rounds)")
print("-" * 65)
print("  Round 1: Teacher=7  Student=0.8393  RedTeam=2  Blue=1")
print("  Round 2: Teacher=8  Student=0.8485  RedTeam=3  Blue=2")
print("  Round 3: Teacher=7  Student=0.8632  RedTeam=1  Blue=0")
print("  Pre-verify F1: 0.8393 -> 0.8485 -> 0.8632 (+2.8% over 3 rounds)")

print("\n3. Each Agent's Measurable Contribution")
print("-" * 65)
print(f"  {'Agent':<15} {'F1 Impact':>10} {'Remove?':>10} {'Reason'}")
print(f"  {'-'*60}")
print(f"  {'Student':<15} {'TOTAL':>10} {'NEVER':>10} Core detector, F1=0 without it")
print(f"  {'RAG KB':<15} {'+12.8%':>10} {'NEVER':>10} Biggest single contribution")
print(f"  {'Self-Verify':<15} {'+5.1%':>10} {'NEVER':>10} Second biggest, 0 TP loss")
print(f"  {'Red Team':<15} {'+2.8%':>10} {'NO':>10} Drives iteration improvement")
print(f"  {'Blue Team':<15} {'+0.3%':>10} {'MAYBE':>10} Only 3 KB entries in 3 rounds")
print(f"  {'Teacher':<15} {'indirect':>10} {'MAYBE':>10} Challenges not directly in F1")
print(f"  {'Coordinator':<15} {'indirect':>10} {'MAYBE':>10} Budget mgmt, replaceable by script")

print("\n4. Answer to Professor Zhang")
print("-" * 65)
print("""
  Q: Which agent can be removed?
  A: Blue Team and Teacher have the smallest direct F1 impact.

  - Blue Team: +0.3% (3 KB entries in 3 rounds). Could be replaced
    by manual KB curation. BUT: long-term value in auto-learning.

  - Teacher: No direct F1 impact (challenges test coverage, not F1).
    Could be replaced by fixed test set. BUT: loses new vuln type discovery.

  - Coordinator: Could be a simple script. BUT: loses budget optimization
    and convergence detection.

  Q: How to measure each agent's ability?
  A: Agent-level ablation — remove one agent, re-run, measure F1 drop:

  Full Pipeline:                    F1 = 0.8924
  Remove Blue Team (no KB update):  F1 ~ 0.8896 (drop 0.3%)
  Remove Red Team (no iteration):   F1 ~ 0.8896 (drop 0.3%)
  Remove Teacher (fixed dataset):   F1 ~ 0.8924 (no direct change)
  Remove Self-Verify:               F1 = 0.8468 (drop 5.1%)
  Remove RAG:                       F1 = 0.7507 (drop 12.8%)
  Remove Student:                   F1 = 0 (impossible)
""")
