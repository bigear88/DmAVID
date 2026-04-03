#!/usr/bin/env python3
"""
Step 3f: Anti-Detection Experiment — testing DmAVID's limitations.

Generates obfuscated vulnerable contracts that attempt to evade detection.
Per committee: "Design an independent adversary system to test framework limitations."

Obfuscation strategies:
1. Variable renaming (semantic obfuscation)
2. Control flow restructuring
3. Adding decoy safe patterns (ReentrancyGuard that doesn't actually protect)
4. Splitting vulnerability across multiple functions
"""
import json, os, sys, time, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from openai import OpenAI

BASE_DIR = os.environ.get("DAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments", "anti_detection", "anti_detection_results.json")

# Original vulnerable contracts (known TP from SmartBugs)
ORIGINAL_VULN = """pragma solidity ^0.4.19;
contract DEP_BANK {
    mapping (address=>uint256) public balances;
    uint public MinSum;
    LogFile Log;
    bool intitalized;
    function SetMinSum(uint _val) public { if(intitalized)throw; MinSum = _val; }
    function SetLogFile(address _log) public { if(intitalized)throw; Log = LogFile(_log); }
    function Initialized() public { intitalized = true; }
    function Deposit() public payable { balances[msg.sender]+= msg.value; Log.AddMessage(msg.sender,msg.value,"Put"); }
    function Collect(uint _am) public payable {
        if(balances[msg.sender]>=MinSum && _am<=balances[msg.sender]) {
            if(msg.sender.call.value(_am)()) { balances[msg.sender]-=_am; Log.AddMessage(msg.sender,_am,"Collect"); }
        }
    }
    function() public payable{}
}
contract LogFile { function AddMessage(address _adr,uint _val,string _data) public {} }"""

OBFUSCATION_PROMPT = """You are a smart contract obfuscation expert. Take this VULNERABLE Solidity contract and apply the specified obfuscation technique to make the vulnerability HARDER to detect, while preserving the exact same vulnerability.

Original contract (has reentrancy vulnerability):
```solidity
{code}
```

Obfuscation technique: {technique}

Requirements:
1. The obfuscated contract MUST still contain the same reentrancy vulnerability
2. The vulnerability must be functional (exploitable)
3. Apply ONLY the specified technique
4. Output the complete obfuscated Solidity contract
5. Do NOT add comments about the vulnerability

Output ONLY the Solidity code, no explanation."""

TECHNIQUES = [
    ("variable_rename", "Rename all variables and functions to meaningless names (e.g., balances→_d7x, Collect→_f3k). Keep the logic identical."),
    ("decoy_guard", "Add a fake ReentrancyGuard modifier that appears to protect but actually does nothing (e.g., modifier noReentrancy() { _; } applied to the wrong function). Keep the vulnerable function unprotected."),
    ("split_function", "Split the vulnerable Collect function into 3 smaller internal functions that together form the same vulnerability. The external call and state update should be in different functions."),
    ("add_complexity", "Add 3-4 unrelated but legitimate-looking functions (getBalance, setAdmin, pause/unpause) to make the contract look like a real production contract. Keep the vulnerability intact."),
]

def generate_obfuscated(code, technique_name, technique_desc):
    """Use LLM to generate obfuscated version."""
    prompt = OBFUSCATION_PROMPT.format(code=code, technique=technique_desc)
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            **token_param(2000),
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        # Extract code
        code_match = re.search(r"```solidity\s*([\s\S]*?)```", content)
        if code_match:
            return code_match.group(1).strip(), tokens
        # Try without markers
        if "pragma solidity" in content:
            return content, tokens
        return content, tokens
    except Exception as e:
        return f"// ERROR: {e}", 0

def detect_with_llm_rag(code):
    """Run LLM+RAG detection on the contract."""
    try:
        from importlib import import_module
        rag_mod = import_module("05_run_llm_rag")
        result = rag_mod.analyze_with_rag(code)
        return {
            "predicted_vulnerable": result.get("predicted_vulnerable", False),
            "confidence": result.get("confidence", 0),
            "vulnerability_types": result.get("vulnerability_types", []),
            "reasoning": str(result.get("reasoning", ""))[:200],
            "tokens": result.get("tokens_used", 0),
        }
    except Exception as e:
        return {"error": str(e)}

def main():
    print("=" * 60)
    print("Anti-Detection Experiment")
    print(f"Model: {MODEL}")
    print("=" * 60)

    # Step 1: Test original
    print("\n--- Original Contract (known reentrancy) ---")
    orig_result = detect_with_llm_rag(ORIGINAL_VULN)
    print(f"  Detected: {orig_result.get('predicted_vulnerable', '?')}")
    print(f"  Confidence: {orig_result.get('confidence', '?')}")
    print(f"  Types: {orig_result.get('vulnerability_types', [])}")

    results = [{
        "technique": "original",
        "description": "Unmodified vulnerable contract",
        "detected": orig_result.get("predicted_vulnerable", False),
        "confidence": orig_result.get("confidence", 0),
        "types": orig_result.get("vulnerability_types", []),
    }]

    total_tokens = orig_result.get("tokens", 0)

    # Step 2: Generate and test obfuscated versions
    for tech_name, tech_desc in TECHNIQUES:
        print(f"\n--- Technique: {tech_name} ---")

        obf_code, gen_tokens = generate_obfuscated(ORIGINAL_VULN, tech_name, tech_desc)
        total_tokens += gen_tokens
        print(f"  Generated: {len(obf_code)} chars ({gen_tokens} tokens)")

        det_result = detect_with_llm_rag(obf_code)
        total_tokens += det_result.get("tokens", 0)

        detected = det_result.get("predicted_vulnerable", False)
        conf = det_result.get("confidence", 0)
        evaded = not detected

        print(f"  Detected: {detected} (conf={conf})")
        print(f"  {'⚠️ EVADED!' if evaded else '✅ Caught'}")
        if evaded:
            print(f"  Reasoning: {det_result.get('reasoning', '')[:150]}")

        results.append({
            "technique": tech_name,
            "description": tech_desc[:80],
            "obfuscated_length": len(obf_code),
            "detected": detected,
            "confidence": conf,
            "types": det_result.get("vulnerability_types", []),
            "evaded": evaded,
            "reasoning": det_result.get("reasoning", "")[:200],
        })

    # Summary
    print("\n" + "=" * 60)
    print("ANTI-DETECTION EXPERIMENT SUMMARY")
    print("=" * 60)

    total = len(results)
    caught = sum(1 for r in results if r.get("detected"))
    evaded = total - caught

    print(f"\n{'Technique':<20} {'Detected':>9} {'Conf':>6} {'Evaded':>8}")
    print("-" * 50)
    for r in results:
        status = "✅" if r.get("detected") else "⚠️ EVADE"
        print(f"{r['technique']:<20} {status:>9} {r.get('confidence',0):>6.2f} {'YES' if r.get('evaded') else 'no':>8}")

    detection_rate = caught / total if total > 0 else 0
    evasion_rate = evaded / total if total > 0 else 0

    print(f"\nDetection rate: {caught}/{total} ({detection_rate:.0%})")
    print(f"Evasion rate: {evaded}/{total} ({evasion_rate:.0%})")
    print(f"Total tokens: {total_tokens:,}")

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    output = {
        "experiment": "anti_detection_test",
        "model": MODEL,
        "original_contract": "DEP_BANK (reentrancy)",
        "techniques_tested": len(TECHNIQUES),
        "detection_rate": round(detection_rate, 4),
        "evasion_rate": round(evasion_rate, 4),
        "caught": caught,
        "evaded": evaded,
        "total": total,
        "total_tokens": total_tokens,
        "results": results,
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
