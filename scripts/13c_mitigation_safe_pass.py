#!/usr/bin/env python3
"""
13c_mitigation_safe_pass.py — Mitigation-gated SAFE adversarial pass for Self-Verify.

Problem it fixes: the three-class Self-Verify rubber-stamps predicted-vulnerable
contracts as VULNERABLE even when its own reasoning acknowledges a concrete
mitigation (transfer's 2300-gas stipend, require(balance>=x) before subtraction,
Checks-Effects-Interactions, access-control modifiers, SafeMath). The verdict has
no working path to SAFE.

This pass plays devil's advocate FOR safety, but is strictly gated:
  - It must map EACH claimed vulnerability to a CONCRETE mitigation actually
    present in the source. Only if EVERY claimed vuln is mitigated -> SAFE.
  - If ANY claimed vuln lacks a verified, code-grounded mitigation -> VULNERABLE.
This prevents blanket flipping (anti-cheat): SAFE requires evidence, not optimism.
"""
import os, re, json
from openai import OpenAI

MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
_client = None
def _c():
    global _client
    if _client is None: _client = OpenAI()
    return _client

PROMPT = (
 "You are a skeptical verification agent arguing whether a flagged contract is actually SAFE. "
 "A detector claims the contract has the vulnerabilities listed below. For EACH claimed "
 "vulnerability, decide whether a CONCRETE, code-grounded mitigation neutralizes it.\n\n"
 "Recognized concrete mitigations (must be literally present in the code):\n"
 "- reentrancy/unchecked-call: uses .transfer()/.send() (2300-gas stipend) for the value move, "
 "OR a nonReentrant guard, OR strict Checks-Effects-Interactions (state updated before the external call).\n"
 "- integer overflow/arithmetic: uses SafeMath, OR an explicit require(balance >= amount) before "
 "subtraction and a matching add-overflow guard, OR Solidity >=0.8 checked arithmetic.\n"
 "- access control: the privileged function carries a working owner/role modifier or require(msg.sender==owner).\n"
 "- denial of service: the only unbounded loop is over data that solely a privileged role can grow, "
 "or there is no unbounded external-call loop reachable by an attacker.\n\n"
 "STRICT GATE: Return verdict SAFE only if EVERY claimed vulnerability has such a concrete mitigation "
 "you can cite. If ANY claimed vulnerability lacks a verified mitigation (or the 'mitigation' is only "
 "partial/bypassable), return VULNERABLE. Do not flip to SAFE on optimism or general code quality.\n\n"
 'Reply STRICT JSON: {"verdict":"SAFE|VULNERABLE","per_claim":[{"vuln":"..","mitigated":true|false,'
 '"evidence":"concrete code reference"}],"summary":"one sentence"}'
)

def mitigation_gated_safe_pass(contract_source, claimed_types, prior_reasoning="", max_src=7000):
    """Return dict: verdict (SAFE/VULNERABLE), per_claim[], summary. VULNERABLE on error."""
    src = (contract_source or "")[:max_src]
    user = (f"{PROMPT}\n\n=== Detector's claimed vulnerabilities ===\n{claimed_types}\n\n"
            f"=== Detector's reasoning (may overstate risk) ===\n{(prior_reasoning or '')[:1200]}\n\n"
            f"=== Contract source ===\n{src}")
    try:
        r = _c().chat.completions.create(model=MODEL, temperature=0,
            messages=[{"role": "user", "content": user}],
            response_format={"type": "json_object"})
        j = json.loads(r.choices[0].message.content)
    except Exception as e:
        return {"verdict": "VULNERABLE", "per_claim": [], "summary": f"error: {e}"[:120]}
    # Anti-cheat: SAFE requires every per_claim mitigated with non-empty evidence
    if j.get("verdict") == "SAFE":
        claims = j.get("per_claim") or []
        if not claims or any((not c.get("mitigated")) or (not str(c.get("evidence", "")).strip())
                             for c in claims):
            j["verdict"] = "VULNERABLE"
            j["summary"] = "gate: not all claims had concrete verified mitigation -> kept VULNERABLE"
    return j


EOA_PROMPT = (
 "You are an exploit-construction verifier. A detector claims the contract below has the listed "
 "vulnerabilities. Burden of proof is on VULNERABLE: to uphold it you must CONSTRUCT a concrete, "
 "realistic exploit — the exact attacker setup, the transaction/call sequence, and the resulting "
 "damage (funds stolen or permanently locked, or a core invariant broken). \n"
 "If you CANNOT construct such an exploit for ANY claimed vulnerability — because a defensive "
 "pattern blocks every attempt (e.g. .transfer()/.send() caps gas at 2300 so the reentrancy never "
 "executes; require(balance>=amount) before subtraction blocks the underflow; an owner/role modifier "
 "blocks the privileged call; SafeMath/Solidity>=0.8 reverts on overflow; the only unbounded loop is "
 "over data only the owner can grow) — then return SAFE. A vulnerability with no constructible exploit "
 "is not a vulnerability. Do NOT invent speculative or theoretical exploits; if the attack would revert "
 "or yield no attacker gain, it does not count.\n\n"
 'Reply STRICT JSON: {"verdict":"SAFE|VULNERABLE","exploit":"concrete attacker steps + resulting '
 'damage, or NONE","blocking_mitigation":"what blocks it (if SAFE)"}'
)

def exploit_or_acquit_pass(contract_source, claimed_types, prior_reasoning="", max_src=7000):
    """Verdict VULNERABLE only if a concrete exploit can be constructed; else SAFE.
    Anti-cheat: VULNERABLE requires a non-empty, non-NONE exploit string."""
    src = (contract_source or "")[:max_src]
    user = (f"{EOA_PROMPT}\n\n=== Claimed vulnerabilities ===\n{claimed_types}\n\n"
            f"=== Detector reasoning (may overstate) ===\n{(prior_reasoning or '')[:1000]}\n\n"
            f"=== Contract source ===\n{src}")
    try:
        r = _c().chat.completions.create(model=MODEL, temperature=0,
            messages=[{"role": "user", "content": user}],
            response_format={"type": "json_object"})
        j = json.loads(r.choices[0].message.content)
    except Exception as e:
        return {"verdict": "VULNERABLE", "exploit": "", "blocking_mitigation": f"error: {e}"[:120]}
    # Anti-cheat: VULNERABLE must come with a concrete exploit, else it is unsubstantiated
    ex = str(j.get("exploit", "")).strip()
    if j.get("verdict") == "VULNERABLE" and (not ex or ex.upper() == "NONE"):
        j["verdict"] = "SAFE"
        j["blocking_mitigation"] = "no constructible exploit provided -> acquitted"
    return j


if __name__ == "__main__":
    print("module ok; MODEL=", MODEL)
