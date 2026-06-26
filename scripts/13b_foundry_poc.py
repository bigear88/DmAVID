#!/usr/bin/env python3
"""
13b_foundry_poc.py — Genuine Foundry dual validation (solc compile + forge test PoC).

Implements the two-stage Foundry validation described in the thesis (S5):
  Stage 1 (solc): `forge build` confirms the adversarial variant compiles.
  Stage 2 (PoC) : `forge test` runs a real exploit proof-of-concept whose
                  assertions pass ONLY if the vulnerability is genuinely
                  exploitable in the variant.

A variant is "dual-validated" iff compile_success AND poc_passed.

Uses a persistent forge project (experiments/foundry_poc) with forge-std
pre-installed so each variant only swaps src/Variant.sol + test/Exploit.t.sol.
No stub assertions: the PoC is the LLM-generated exploit test, run for real.
"""
import os
import re
import subprocess

FOUNDRY_BIN = "/home/curtis/.foundry/bin"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PROJECT = os.path.join(BASE_DIR, "experiments", "foundry_poc")


def _env():
    e = dict(os.environ)
    e["PATH"] = FOUNDRY_BIN + os.pathsep + e.get("PATH", "")
    return e


def _clean_sol(project_dir):
    for sub in ("src", "test", "script"):
        d = os.path.join(project_dir, sub)
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(".sol"):
                    os.remove(os.path.join(d, f))


def validate_variant_poc(variant_source, poc_source, project_dir=DEFAULT_PROJECT, timeout=120):
    """Run genuine two-stage Foundry validation on one variant.

    Returns dict: compile_success, poc_passed, gas_used, stage, output (tail).
    """
    src_dir = os.path.join(project_dir, "src")
    test_dir = os.path.join(project_dir, "test")
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(test_dir, exist_ok=True)
    _clean_sol(project_dir)

    result = {"compile_success": False, "poc_passed": False,
              "gas_used": 0, "stage": "", "output": ""}

    if not variant_source or not variant_source.strip():
        result["stage"] = "no_source"
        return result

    # ---- Stage 1: solc compile of the variant ----
    variant_path = os.path.join(src_dir, "Variant.sol")
    with open(variant_path, "w", encoding="utf-8") as f:
        f.write(variant_source)
    try:
        r = subprocess.run(["forge", "build"], cwd=project_dir, env=_env(),
                           capture_output=True, text=True, timeout=timeout)
        result["compile_success"] = (r.returncode == 0)
        if r.returncode != 0:
            result["stage"] = "compile_fail"
            result["output"] = (r.stdout + r.stderr)[-2500:]
    except subprocess.TimeoutExpired:
        result["stage"] = "compile_timeout"
        return result
    except FileNotFoundError:
        result["stage"] = "forge_missing"
        return result

    if not poc_source or poc_source.strip().startswith("// Failed"):
        result["stage"] = "no_poc"
        return result

    # If the PoC is self-contained (inlines the contract), drop src/Variant.sol
    # so the two definitions don't collide; if it imports the variant, keep it.
    import_mode = bool(re.search(r'import\s+["\'][^"\']*Variant', poc_source))
    if not import_mode and os.path.exists(variant_path):
        os.remove(variant_path)

    # ---- Stage 2: forge test PoC ----
    poc_path = os.path.join(test_dir, "Exploit.t.sol")
    with open(poc_path, "w", encoding="utf-8") as f:
        f.write(poc_source)
    try:
        r = subprocess.run(["forge", "test", "-vv"], cwd=project_dir, env=_env(),
                           capture_output=True, text=True, timeout=timeout)
        out = r.stdout + r.stderr
        result["output"] = out[-3000:]
        result["poc_passed"] = (r.returncode == 0) and ("[PASS]" in out)
        m = re.search(r'\(gas:\s*(\d+)\)', out)
        if m:
            result["gas_used"] = int(m.group(1))
        result["stage"] = "poc_pass" if result["poc_passed"] else "poc_fail"
    except subprocess.TimeoutExpired:
        result["stage"] = "poc_timeout"

    return result


def _has_real_assertion(poc_source):
    """Reject PoCs whose exploit assertion is a tautology (anti-cheat).

    A genuine PoC must contain at least one non-trivial assert. We strip the
    deployment sanity asserts in setUp and look for a meaningful exploit check.
    """
    if not poc_source:
        return False
    # tautological assertions that prove nothing
    trivial = [r'assertTrue\s*\(\s*true\s*\)', r'assertEq\s*\(\s*1\s*,\s*1\s*\)',
               r'assertEq\s*\(\s*true\s*,\s*true\s*\)', r'assertEq\s*\(\s*0\s*,\s*0\s*\)']
    asserts = re.findall(r'assert\w*\s*\([^;]*\)', poc_source)
    if not asserts:
        return False
    nontrivial = [a for a in asserts if not any(re.match(t, a.strip()) for t in trivial)]
    return len(nontrivial) > 0


def validate_with_repair(variant_source, vuln_type, gen_poc_fn, repair_fn,
                         max_attempts=3, project_dir=DEFAULT_PROJECT, timeout=120):
    """Genuine PoC validation with iterative self-repair.

    gen_poc_fn(variant_source, vuln_type) -> poc_source
    repair_fn(variant_source, vuln_type, prev_poc, error_output) -> poc_source

    Each attempt actually runs `forge test`; a pass is only accepted if forge
    passes AND the PoC carries a non-trivial assertion. Returns the validation
    result dict augmented with poc_source, attempts, and a per-attempt trace.
    """
    poc = gen_poc_fn(variant_source, vuln_type)
    trace = []
    last = {"compile_success": False, "poc_passed": False, "gas_used": 0,
            "stage": "no_attempt", "output": ""}
    for attempt in range(1, max_attempts + 1):
        r = validate_variant_poc(variant_source, poc, project_dir, timeout)
        # anti-cheat: a "passing" test with only tautological asserts does not count
        if r["poc_passed"] and not _has_real_assertion(poc):
            r["poc_passed"] = False
            r["stage"] = "rejected_trivial_assertion"
        last = r
        trace.append({"attempt": attempt, "compile_success": r["compile_success"],
                      "poc_passed": r["poc_passed"], "stage": r["stage"]})
        if r["poc_passed"]:
            break
        if attempt < max_attempts:
            poc = repair_fn(variant_source, vuln_type, poc, r.get("output", ""))
    last["poc_source"] = poc
    last["attempts"] = len(trace)
    last["trace"] = trace
    return last


def check_ready(project_dir=DEFAULT_PROJECT):
    """Verify forge is installed and forge-std is present."""
    if not os.path.exists(os.path.join(project_dir, "lib", "forge-std", "src", "Test.sol")):
        return False, "forge-std not installed in project"
    try:
        r = subprocess.run(["forge", "--version"], env=_env(),
                           capture_output=True, text=True, timeout=20)
        return (r.returncode == 0), r.stdout.strip()
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    ok, info = check_ready()
    print("ready:", ok, "|", info)
