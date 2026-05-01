#!/usr/bin/env python3
"""
Sprint 8 Step 1：對 SmartBugs Curated 243 合約逐一編譯為 bytecode

來源 list：experiments/llm_rag/llm_rag_results.json 之 contract_id 順序（與 Sprint 1-7 對齊）
路徑映射：data/dataset_1000.json 之 id → filepath
編譯流程：
  1. 從 .sol 抓 pragma → 找最匹配的 installed solc 版本
  2. solc-select use <ver>（per-contract，但按版本排序減少切換）
  3. py-solc-x 編譯，timeout 60s
  4. 取主合約 bytecode（合約名 == 檔名 stem 的優先）
  5. 失敗記錄 reason

Output:
  experiments/bytecode_ml/compile_results.json
  experiments/bytecode_ml/bytecodes/<contract_id>.hex
"""
import os
import re
import sys
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parent.parent
LLM_RAG = ROOT / "experiments/llm_rag/llm_rag_results.json"
DATASET = ROOT / "data/dataset_1000.json"
OUT_DIR = ROOT / "experiments/bytecode_ml"
BC_DIR = OUT_DIR / "bytecodes"
OUT_DIR.mkdir(parents=True, exist_ok=True)
BC_DIR.mkdir(parents=True, exist_ok=True)
OUT_JSON = OUT_DIR / "compile_results.json"

PER_FILE_TIMEOUT = 60
SOLC_SELECT = os.environ.get("SOLC_SELECT_BIN", "/home/curtis/.local/bin/solc-select")

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)


def installed_solc_versions():
    r = subprocess.run([SOLC_SELECT, "versions"], capture_output=True, text=True, timeout=20)
    out = r.stdout + r.stderr
    versions = []
    for line in out.split("\n"):
        line = line.strip()
        # solc-select 列出已裝版本，如 "0.4.26" 或 "0.4.26 <-- current"
        m = re.match(r"^(\d+\.\d+\.\d+)", line)
        if m:
            versions.append(m.group(1))
    return sorted(set(versions), key=lambda v: tuple(int(x) for x in v.split(".")))


def parse_pragma(text):
    """從 .sol text 抓第一個 pragma，回傳原字串"""
    m = PRAGMA_RE.search(text)
    return m.group(1).strip() if m else None


def select_solc_for_pragma(pragma_str, installed):
    """把 pragma string 解析成最匹配的 installed 版本字串

    規則（簡化版）：
    - "^0.4.19"  → 取最高的 0.4.x（>= 0.4.19, < 0.5.0），若無則取 >=0.4.19 中最低
    - "0.5.7"    → 精確匹配；若無則取最高的 0.5.x
    - ">=0.4.0 <0.6.0" → 取最高的 0.5.x，回退 0.4.x
    - 取不到回 None
    """
    if not pragma_str:
        return None
    p = pragma_str.replace(" ", "")
    # 抽出所有 x.y.z
    nums = re.findall(r"(\d+)\.(\d+)\.(\d+)", p)
    if not nums:
        return None

    def vt(s):
        return tuple(int(x) for x in s.split("."))

    inst_t = [vt(v) for v in installed]

    # 處理 caret ^x.y.z → 取同 minor 的最高 patch
    if p.startswith("^"):
        major, minor, patch = nums[0]
        candidates = [v for v in installed if vt(v)[0] == int(major) and vt(v)[1] == int(minor) and vt(v) >= (int(major), int(minor), int(patch))]
        if candidates:
            return max(candidates, key=vt)
        # fallback：同 minor 任意，再 fallback 同 major 最高
        same_minor = [v for v in installed if vt(v)[0] == int(major) and vt(v)[1] == int(minor)]
        if same_minor:
            return max(same_minor, key=vt)
        same_major = [v for v in installed if vt(v)[0] == int(major)]
        if same_major:
            return max(same_major, key=vt)
        return None

    # range "x >= ... < ..."
    if ">=" in p or "<" in p or ">" in p:
        # 解析最 conservative：取最高合法版本
        ge_m = re.search(r">=?(\d+\.\d+\.\d+)", p)
        lt_m = re.search(r"<(\d+\.\d+\.\d+)", p)
        ge = vt(ge_m.group(1)) if ge_m else (0, 0, 0)
        lt = vt(lt_m.group(1)) if lt_m else (99, 99, 99)
        candidates = [v for v in installed if ge <= vt(v) < lt]
        if candidates:
            return max(candidates, key=vt)
        return None

    # 精確 x.y.z
    target = nums[0]
    target_s = ".".join(target)
    if target_s in installed:
        return target_s
    # fallback：同 minor 最高
    candidates = [v for v in installed if vt(v)[0] == int(target[0]) and vt(v)[1] == int(target[1])]
    if candidates:
        return max(candidates, key=vt)
    return None


def switch_solc(version, current):
    """切換 solc 版本（避免重複切換相同版本）"""
    if version == current:
        return current
    r = subprocess.run([SOLC_SELECT, "use", version], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        return None
    return version


def compile_one(sol_path, contract_id, version):
    """編譯一個 .sol，回傳 (success, bytecode_hex_or_none, error_str_or_none)"""
    import solcx
    try:
        solcx.set_solc_version(version)
        with open(sol_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        result = solcx.compile_source(
            source,
            output_values=["bin"],
            solc_version=version,
            allow_paths=str(sol_path.parent),
        )
        # result keys are like "<stdin>:ContractName"
        # 取主合約：name == filename stem 優先；否則取第一個 non-empty bin
        stem = sol_path.stem.lower()
        best_bin = None
        best_name = None
        for k, v in result.items():
            cname = k.split(":")[-1]
            bcode = v.get("bin", "")
            if not bcode:
                continue
            if cname.lower() == stem:
                best_bin = bcode
                best_name = cname
                break
            if best_bin is None:
                best_bin = bcode
                best_name = cname
        if not best_bin:
            return False, None, "no_bytecode_in_output"
        return True, best_bin, None
    except Exception as e:
        msg = str(e)
        # 分類錯誤 type
        low = msg.lower()
        if "syntax" in low or "parsererror" in low:
            tag = "syntax_error"
        elif "doesn't exist" in low or "not found" in low:
            tag = "import_not_found"
        elif "out of memory" in low or "memory" in low:
            tag = "oom"
        elif "stack too deep" in low:
            tag = "stack_too_deep"
        elif "version" in low:
            tag = "version_mismatch"
        else:
            tag = "compile_error"
        return False, None, f"{tag}: {msg[:200]}"


def load_dataset_paths():
    d = json.loads(DATASET.read_text(encoding="utf-8"))
    fpmap = {}
    for c in d.get("contracts", []):
        cid = c.get("id", "")
        fp = c.get("filepath", "")
        if cid:
            fpmap[cid] = fp
    return fpmap


def load_contracts():
    """從 llm_rag results 取 243 contract list（source-of-truth 順序）"""
    d = json.loads(LLM_RAG.read_text(encoding="utf-8"))
    fpmap = load_dataset_paths()
    contracts = []
    for r in d["results"]:
        cid = r["contract_id"]
        fp = fpmap.get(cid, "")
        if fp and not os.path.isabs(fp):
            fp = str(ROOT / fp)
        contracts.append({
            "contract_id": cid,
            "filepath": fp,
            "label": r.get("ground_truth"),
            "category": r.get("category"),
        })
    return contracts


def main():
    print("=" * 70)
    print(f"Sprint 8 Step 1 — Compile 243 contracts  ({datetime.now().isoformat()})")
    print("=" * 70)

    installed = installed_solc_versions()
    print(f"\n[Setup] solc installed versions: {len(installed)}")
    print(f"  {installed}")

    contracts = load_contracts()
    print(f"[Setup] target contracts: {len(contracts)}")

    # idempotent：已存在的 .hex 跳過
    existing = {p.stem for p in BC_DIR.glob("*.hex")}
    todo_count = sum(1 for c in contracts if c["contract_id"] not in existing)
    print(f"[Setup] existing bytecodes: {len(existing)},  待編譯: {todo_count}")

    # Pre-process：讀 pragma 並挑版本，按版本排序減少 solc-select 切換
    rows = []
    for c in contracts:
        fp = c["filepath"]
        if not fp or not os.path.isfile(fp):
            rows.append({**c, "pragma": None, "selected_solc": None,
                         "compile_status": "fail", "fail_reason": "file_not_found"})
            continue
        try:
            text = open(fp, "r", encoding="utf-8", errors="ignore").read()
        except Exception as e:
            rows.append({**c, "pragma": None, "selected_solc": None,
                         "compile_status": "fail", "fail_reason": f"read_error:{e}"})
            continue
        prag = parse_pragma(text)
        ver = select_solc_for_pragma(prag, installed) if prag else None
        rows.append({**c, "pragma": prag, "selected_solc": ver,
                     "compile_status": None, "fail_reason": None})

    # 排序：按 selected_solc 分組（使切換 solc 次數最小）
    rows_with_ver = [r for r in rows if r["selected_solc"] and r["compile_status"] is None]
    rows_no_ver = [r for r in rows if r["compile_status"] == "fail"]
    rows_skip_pragma = [r for r in rows if r["selected_solc"] is None and r["compile_status"] is None]
    rows_with_ver.sort(key=lambda r: tuple(int(x) for x in r["selected_solc"].split(".")))

    print(f"\n[Pre] 有 pragma 且找到 solc 版本: {len(rows_with_ver)}")
    print(f"[Pre] 找不到對應 solc 版本: {len(rows_skip_pragma)}")
    print(f"[Pre] 路徑/讀取問題: {len(rows_no_ver)}")
    ver_counter = Counter(r["selected_solc"] for r in rows_with_ver)
    print(f"[Pre] 編譯版本分布:")
    for v, n in ver_counter.most_common():
        print(f"    {v}: {n}")

    # 編譯
    current = None
    success = 0
    t0 = time.time()
    for i, r in enumerate(rows_with_ver, 1):
        cid = r["contract_id"]
        if cid in existing:
            r["compile_status"] = "success"
            r["bytecode_path"] = str(BC_DIR / f"{cid}.hex")
            success += 1
            continue
        ver = r["selected_solc"]
        if ver != current:
            new_cur = switch_solc(ver, current)
            if new_cur is None:
                r["compile_status"] = "fail"
                r["fail_reason"] = f"solc_select_use_failed:{ver}"
                continue
            current = new_cur
        ok, bc, err = compile_one(Path(r["filepath"]), cid, current)
        if ok:
            (BC_DIR / f"{cid}.hex").write_text(bc, encoding="utf-8")
            r["compile_status"] = "success"
            r["bytecode_path"] = str(BC_DIR / f"{cid}.hex")
            success += 1
        else:
            r["compile_status"] = "fail"
            r["fail_reason"] = err
        if i % 20 == 0:
            elapsed = time.time() - t0
            rate = i / max(elapsed, 1)
            eta = (len(rows_with_ver) - i) / max(rate, 1e-3)
            print(f"  [{i:>3}/{len(rows_with_ver)}]  success={success}  elapsed={elapsed:.0f}s  eta={eta:.0f}s")

    # 整合 fail rows
    for r in rows_skip_pragma:
        r["compile_status"] = "fail"
        r["fail_reason"] = "pragma_not_found_or_no_solc_version"

    all_rows = rows_with_ver + rows_skip_pragma + rows_no_ver
    # 整合既有的 .hex（idempotent 之前處理失敗）
    for r in all_rows:
        if r.get("compile_status") is None:
            r["compile_status"] = "fail"
            r["fail_reason"] = r.get("fail_reason") or "unknown"

    n_success = sum(1 for r in all_rows if r["compile_status"] == "success")
    n_fail = sum(1 for r in all_rows if r["compile_status"] == "fail")

    fail_breakdown = Counter()
    for r in all_rows:
        if r["compile_status"] == "fail":
            tag = (r.get("fail_reason") or "unknown").split(":")[0]
            fail_breakdown[tag] += 1

    out = {
        "experiment": "sprint8_compile",
        "timestamp": datetime.now().isoformat(),
        "total_contracts": len(all_rows),
        "compiled_success": n_success,
        "compiled_fail": n_fail,
        "fail_breakdown": dict(fail_breakdown),
        "solc_versions_used": dict(ver_counter),
        "contracts": all_rows,
    }
    OUT_JSON.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Done] success={n_success}/{len(all_rows)}  fail={n_fail}")
    print(f"[Fail breakdown] {dict(fail_breakdown)}")
    print(f"\n→ Saved: {OUT_JSON}")


if __name__ == "__main__":
    main()
