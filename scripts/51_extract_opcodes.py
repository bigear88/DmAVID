#!/usr/bin/env python3
"""
Sprint 8 Step 2：從 bytecode 抽 opcode 序列

對所有 compiled_success：
  1. 讀 .hex
  2. pyevmasm.disassemble_all() → opcode list
  3. 對 PUSH1..PUSH32 合併為 PUSH；DUP/SWAP 同樣 normalize
  4. 寫 opcodes/<contract_id>.txt（每行一個 opcode）

Output:
  experiments/bytecode_ml/opcodes/<contract_id>.txt
  experiments/bytecode_ml/opcode_vocab.json
"""
import json
import re
from pathlib import Path
from collections import Counter
from datetime import datetime

import pyevmasm

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "experiments/bytecode_ml"
BC_DIR = OUT_DIR / "bytecodes"
OP_DIR = OUT_DIR / "opcodes"
OP_DIR.mkdir(parents=True, exist_ok=True)
COMPILE = OUT_DIR / "compile_results.json"
VOCAB = OUT_DIR / "opcode_vocab.json"


def normalize(opcode):
    """PUSH1..PUSH32 → PUSH；DUP1..DUP16 → DUP；SWAP1..SWAP16 → SWAP；LOG0..LOG4 → LOG"""
    if re.match(r"^PUSH\d+$", opcode):
        return "PUSH"
    if re.match(r"^DUP\d+$", opcode):
        return "DUP"
    if re.match(r"^SWAP\d+$", opcode):
        return "SWAP"
    if re.match(r"^LOG\d+$", opcode):
        return "LOG"
    return opcode


def disassemble(hex_str):
    """從 hex 字串拆 opcode list（normalized）"""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    try:
        bcode = bytes.fromhex(hex_str)
    except ValueError:
        return []
    ops = []
    try:
        for ins in pyevmasm.disassemble_all(bcode):
            ops.append(normalize(ins.name))
    except Exception:
        pass
    return ops


def main():
    print("=" * 70)
    print(f"Sprint 8 Step 2 — Extract Opcodes  ({datetime.now().isoformat()})")
    print("=" * 70)

    d = json.loads(COMPILE.read_text(encoding="utf-8"))
    success = [c for c in d["contracts"] if c.get("compile_status") == "success"]
    print(f"  compiled_success: {len(success)}")

    vocab = Counter()
    n_done = 0
    n_empty = 0
    for i, c in enumerate(success, 1):
        cid = c["contract_id"]
        bc_path = BC_DIR / f"{cid}.hex"
        if not bc_path.exists():
            continue
        hex_str = bc_path.read_text(encoding="utf-8").strip()
        ops = disassemble(hex_str)
        if not ops:
            n_empty += 1
            continue
        (OP_DIR / f"{cid}.txt").write_text("\n".join(ops), encoding="utf-8")
        for op in ops:
            vocab[op] += 1
        n_done += 1
        if i % 50 == 0:
            print(f"  [{i:>3}/{len(success)}] done={n_done} empty={n_empty}")

    out = {
        "experiment": "sprint8_extract_opcodes",
        "timestamp": datetime.now().isoformat(),
        "n_contracts_extracted": n_done,
        "n_empty_disasm": n_empty,
        "total_unique_opcodes": len(vocab),
        "opcode_freq": dict(vocab.most_common()),
    }
    VOCAB.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[Done] {n_done} opcode files,  unique opcodes={len(vocab)}")
    print(f"  Top 10: {vocab.most_common(10)}")
    print(f"\n→ Saved: {VOCAB}")


if __name__ == "__main__":
    main()
