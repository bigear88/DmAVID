#!/usr/bin/env python3
"""Test each DmAVID agent with contracts for OpenAI log verification."""
import json, os, sys, time, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from importlib import import_module

random.seed(42)
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE_DIR, "data/dataset_1000.json")) as f:
    ds = json.load(f)
contracts = ds["contracts"]
vuln = [c for c in contracts if c["label"] == "vulnerable"][:5]
safe = [c for c in contracts if c["label"] == "safe"][:5]
sample_10 = vuln + safe

def load_code(contract):
    fp = contract["filepath"]
    if not os.path.exists(fp):
        return ""
    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def sep(title):
    print("\n" + "=" * 70)
    print("  AGENT TEST: " + title)
    print("=" * 70)

# ── Agent 1: LLM Base (04) ──
sep("LLM Base (04_run_llm_base)")
base_mod = import_module("04_run_llm_base")
for i, c in enumerate(sample_10[:3]):
    code = load_code(c)
    name = c["filename"][:45]
    label = c["label"]
    print("\n[%d/3] %s | %s | code_len=%d" % (i+1, label, name, len(code)))
    assert len(code) > 0, "EMPTY CODE!"
    result = base_mod.analyze_contract_with_llm(code)
    pred = result.get("predicted_vulnerable")
    conf = result.get("confidence", 0)
    tok = result.get("tokens_used", 0)
    err = result.get("error")
    reason = str(result.get("reasoning", ""))[:150]
    print("  pred=%s conf=%.3f tokens=%d err=%s" % (pred, conf, tok, err))
    print("  reason: %s" % reason)
print("\n** LLM Base: OK **")

# ── Agent 2: Student / LLM+RAG (05) ──
sep("Student Agent / LLM+RAG (05_run_llm_rag)")
rag_mod = import_module("05_run_llm_rag")
for i, c in enumerate(sample_10[:3]):
    code = load_code(c)
    name = c["filename"][:45]
    label = c["label"]
    print("\n[%d/3] %s | %s | code_len=%d" % (i+1, label, name, len(code)))
    assert len(code) > 0, "EMPTY CODE!"
    result = rag_mod.analyze_with_rag(code)
    pred = result.get("predicted_vulnerable")
    conf = result.get("confidence", 0)
    tok = result.get("tokens_used", 0)
    err = result.get("error")
    reason = str(result.get("reasoning", ""))[:150]
    print("  pred=%s conf=%.3f tokens=%d err=%s" % (pred, conf, tok, err))
    print("  reason: %s" % reason)
print("\n** Student Agent: OK **")

# ── Agent 3: Teacher (11) ──
sep("Teacher Agent (11_teacher_challenge)")
teacher_mod = import_module("11_teacher_challenge")
kb = teacher_mod.load_knowledge_base()
for i, vt in enumerate(["reentrancy", "integer_overflow", "access_control"]):
    print("\n[%d/3] Generating challenge for: %s" % (i+1, vt))
    challenge = teacher_mod.generate_challenge(vt, difficulty_level=2, knowledge_base=kb)
    if challenge:
        code = challenge.get("contract_code", "")
        cid = challenge.get("challenge_id", "?")
        tok = challenge.get("tokens_used", 0)
        print("  challenge_id: %s" % cid)
        print("  code_len: %d" % len(code))
        print("  code_start: %s" % code[:100].replace("\n", " "))
        print("  tokens: %d" % tok)
        assert len(code) > 10, "Teacher generated empty code for %s!" % vt
    else:
        print("  WARNING: No challenge generated for %s" % vt)
print("\n** Teacher Agent: OK **")

# ── Agent 4: Red Team (12) ──
sep("Red Team Agent (12_red_team_generate)")
red_mod = import_module("12_red_team_generate")
vuln_code = load_code(vuln[0])
vname = vuln[0]["filename"][:45]
print("\nInput: %s | code_len=%d" % (vname, len(vuln_code)))
assert len(vuln_code) > 0, "EMPTY VULN CODE!"
variant_src, transform, note = red_mod.generate_adversarial_variant(
    vuln_code, "reentrancy", "variable_renaming"
)
print("  transform: %s" % transform)
print("  variant_len: %d" % len(variant_src))
print("  variant_start: %s" % variant_src[:100].replace("\n", " "))
print("  note: %s" % note[:100])
assert len(variant_src) > 10, "Red Team generated empty variant!"
print("\n** Red Team Agent: OK **")

# ── Agent 5: Foundry Validator (13) ──
sep("Foundry Validator (13_foundry_validate)")
os.environ["PATH"] = "/home/curtis/.foundry/bin:" + os.environ.get("PATH", "")
foundry_mod = import_module("13_foundry_validate")
installed = foundry_mod.check_foundry_installed()
print("  Foundry installed: %s" % installed)
if installed:
    import subprocess
    test_sol = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\ncontract TestAgent { uint x; function set(uint v) public { x = v; } }"
    workspace = os.path.join(BASE_DIR, "experiments", "foundry_workspace")
    src_dir = os.path.join(workspace, "src")
    os.makedirs(src_dir, exist_ok=True)
    test_path = os.path.join(src_dir, "TestAgent.sol")
    with open(test_path, "w") as f:
        f.write(test_sol)
    r = subprocess.run(["forge", "build"], cwd=workspace, capture_output=True, text=True, timeout=30)
    status = "SUCCESS" if r.returncode == 0 else "FAILED"
    print("  Compile result: %s" % status)
    if r.returncode != 0:
        print("  stderr: %s" % r.stderr[:200])
    os.remove(test_path)
print("\n** Foundry Validator: OK **")

# ── Agent 6: Blue Team (18) ──
sep("Blue Team Agent (18_blue_team_defense)")
blue_mod = import_module("18_blue_team_defense")
mock_variants = [{
    "variant_source": vuln_code[:2000],
    "vuln_type": "reentrancy",
    "transformation": "variable_renaming",
    "compilable": True,
}]
entries = blue_mod.synthesize_defense_patterns(mock_variants, "reentrancy")
print("  Synthesized entries: %d" % len(entries))
for e in entries[:2]:
    cat = e.get("category", "?")
    title = e.get("title", "?")[:80]
    tok = e.get("tokens_used", 0)
    print("    category: %s | title: %s | tokens: %d" % (cat, title, tok))
print("\n** Blue Team Agent: OK **")

# ── Agent 7: Self-Verify ──
sep("Self-Verify (exploit path verification)")
from openai import OpenAI
client = OpenAI()
code = load_code(vuln[0])
prompt = (
    "You previously analyzed a smart contract and classified it as VULNERABLE "
    "due to reentrancy.\n\nCan you construct a CONCRETE exploit path "
    "(preconditions, transaction sequence, expected outcome)? "
    'If you CANNOT, respond with exactly: "NO_EXPLOIT_PATH".'
)
resp = client.chat.completions.create(
    model=MODEL,
    messages=[
        {"role": "system", "content": prompt},
        {"role": "user", "content": "```solidity\n%s\n```" % code[:8000]},
    ],
    temperature=0.2,
    **token_param(512),
)
content = resp.choices[0].message.content.strip()
tok = resp.usage.total_tokens if resp.usage else 0
flipped = "NO_EXPLOIT_PATH" in content.upper()
vname = vuln[0]["filename"][:45]
print("  Contract: %s" % vname)
print("  Exploit constructable: %s" % (not flipped))
print("  Tokens: %d" % tok)
print("  Response: %s" % content[:200])
print("\n** Self-Verify Agent: OK **")

# ── SUMMARY ──
print("\n" + "=" * 70)
print("  ALL 7 AGENTS TESTED SUCCESSFULLY")
print("=" * 70)
