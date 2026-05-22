#!/usr/bin/env python3
"""
#43 升級 RAG 知識庫：加入 false-positive patterns

從 Sprint 4 ablation 分析中發現 29 個 FP 合約的保護模式分布：
  require      69%   ← 大量 require 檢查讓 LLM 誤判
  modifier     48%   ← 自訂 modifier 保護
  onlyOwner    31%   ← 存取控制正確
  emit          24%  ← 事件追蹤
  SafeMath     10%   ← 算術保護

本腳本：
1. 在 scripts/knowledge/vulnerability_knowledge.json 新增 8 個 FP category 條目
2. 更新 metadata（版本、類別清單、條目數）
3. 可選：重建 ChromaDB（--rebuild）

不修改 05_run_llm_rag.py（論文主實驗），只升級供 hybrid/EVMbench 用的 ChromaDB 向量庫。

Usage:
    python 84_upgrade_rag_fp_patterns.py [--rebuild] [--dry-run]
"""

import os
import sys
import json
import argparse
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
KB_FILE = os.path.join(SCRIPT_DIR, "knowledge", "vulnerability_knowledge.json")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")

# ── 8 False-Positive Pattern Entries ─────────────────────────────────────────
# Each entry teaches the LLM: "this pattern LOOKS dangerous but IS SAFE because..."
FP_ENTRIES = [
    {
        "id": "FP-001",
        "category": "false_positive",
        "title": "Reentrancy-Guarded External Call",
        "description": (
            "A contract that uses ReentrancyGuard (nonReentrant modifier) is protected "
            "against reentrancy even if it makes external calls. The nonReentrant modifier "
            "sets a lock before execution and clears it after, preventing re-entrant calls. "
            "Presence of call.value() or msg.sender.call() alone does NOT indicate vulnerability "
            "when ReentrancyGuard is properly applied."
        ),
        "vulnerability_pattern": (
            "msg.sender.call{value: amount}('') combined with state variable access "
            "— looks like reentrancy but protected by mutex lock."
        ),
        "safe_pattern": (
            "contract MyContract is ReentrancyGuard { "
            "function withdraw(uint amount) external nonReentrant { "
            "require(balances[msg.sender] >= amount); "
            "balances[msg.sender] -= amount; "
            "(bool ok,) = msg.sender.call{value: amount}(''); require(ok); } }"
        ),
        "mitigation": "ReentrancyGuard / nonReentrant modifier from OpenZeppelin.",
        "severity": "Safe",
        "keywords": [
            "ReentrancyGuard", "nonReentrant", "mutex", "reentrancy guard",
            "OpenZeppelin", "is ReentrancyGuard"
        ],
        "false_positive_signals": [
            "contract inherits ReentrancyGuard",
            "nonReentrant modifier on function",
            "using ReentrancyGuardUpgradeable"
        ],
        "real_world_case": "Uniswap V2 / Compound — use nonReentrant on all state-mutating functions safely."
    },
    {
        "id": "FP-002",
        "category": "false_positive",
        "title": "Checks-Effects-Interactions (CEI) Pattern",
        "description": (
            "A function that zeroes the balance BEFORE making the external call follows the "
            "Checks-Effects-Interactions pattern and is NOT vulnerable to reentrancy. "
            "The critical signal is the ORDER: state update happens before external call. "
            "This is the correct pattern despite having both state access and external call."
        ),
        "vulnerability_pattern": (
            "withdraw() with balances[msg.sender] access and external call "
            "— safe if balance is zeroed before the call."
        ),
        "safe_pattern": (
            "function withdraw() public { "
            "uint amount = balances[msg.sender]; "
            "balances[msg.sender] = 0;  // state update FIRST "
            "(bool ok,) = msg.sender.call{value: amount}(''); require(ok); }"
        ),
        "mitigation": "Checks-Effects-Interactions: perform all state updates before any external calls.",
        "severity": "Safe",
        "keywords": [
            "CEI", "checks effects interactions", "balance zeroed before call",
            "state update before external call", "balances[msg.sender] = 0"
        ],
        "false_positive_signals": [
            "balance set to 0 before call{value:",
            "amount variable captured, then state cleared, then call",
            "effects before interactions"
        ],
        "real_world_case": "OpenZeppelin PullPayment — correct CEI prevents reentrancy without a mutex."
    },
    {
        "id": "FP-003",
        "category": "false_positive",
        "title": "OnlyOwner-Protected Sensitive State Change",
        "description": (
            "Sensitive state-changing functions (setOwner, withdraw, pause) guarded by "
            "onlyOwner modifier are NOT access control vulnerabilities. The modifier "
            "restricts execution to the contract owner. Presence of onlyOwner from Ownable "
            "inheritance is a PROTECTIVE signal, not a vulnerability signal."
        ),
        "vulnerability_pattern": (
            "Public function that changes critical state (owner, parameters, balances) "
            "— safe when protected by onlyOwner or equivalent modifier."
        ),
        "safe_pattern": (
            "import '@openzeppelin/contracts/access/Ownable.sol'; "
            "contract MyContract is Ownable { "
            "function setFee(uint _fee) external onlyOwner { fee = _fee; } "
            "function withdrawAll() external onlyOwner { payable(owner()).transfer(address(this).balance); } }"
        ),
        "mitigation": "onlyOwner modifier, Ownable inheritance, or role-based access control (RBAC).",
        "severity": "Safe",
        "keywords": [
            "onlyOwner", "Ownable", "owner()", "transferOwnership",
            "is Ownable", "require(msg.sender == owner)"
        ],
        "false_positive_signals": [
            "contract inherits Ownable",
            "onlyOwner modifier on sensitive function",
            "require(msg.sender == owner()) before state change"
        ],
        "real_world_case": "ERC-20 owner-only mint/burn functions — protected by access control, not vulnerabilities."
    },
    {
        "id": "FP-004",
        "category": "false_positive",
        "title": "SafeMath or Solidity 0.8+ Protected Arithmetic",
        "description": (
            "Arithmetic operations are NOT overflow/underflow vulnerabilities when: "
            "(1) using SafeMath library (Solidity < 0.8), or "
            "(2) using Solidity >= 0.8.0 which has built-in overflow checks. "
            "The pragma version is the most reliable signal for overflow protection."
        ),
        "vulnerability_pattern": (
            "Arithmetic operations (+=, -=, *) on uint/int types "
            "— safe with SafeMath or Solidity 0.8+."
        ),
        "safe_pattern": (
            "// Pattern 1: SafeMath\npragma solidity ^0.7.0;\nimport '@openzeppelin/contracts/math/SafeMath.sol';\n"
            "contract Safe { using SafeMath for uint256; function add(uint a, uint b) public pure returns (uint) { return a.add(b); } }\n\n"
            "// Pattern 2: Solidity 0.8+ (built-in)\npragma solidity ^0.8.0;\n"
            "contract Safe { function add(uint a, uint b) public pure returns (uint) { return a + b; } }"
        ),
        "mitigation": "SafeMath library (Solidity <0.8) or upgrade to Solidity >=0.8.0 for built-in checks.",
        "severity": "Safe",
        "keywords": [
            "SafeMath", "using SafeMath for", "pragma solidity ^0.8",
            "pragma solidity >=0.8", ".add(", ".sub(", ".mul(", ".div("
        ],
        "false_positive_signals": [
            "using SafeMath for uint256",
            "pragma solidity ^0.8.0 or higher",
            "SafeMath.add / SafeMath.sub usage"
        ],
        "real_world_case": "Post-0.8.0 ERC-20 tokens — arithmetic is safe by default without SafeMath."
    },
    {
        "id": "FP-005",
        "category": "false_positive",
        "title": "Require-Validated External Call (Not Unchecked)",
        "description": (
            "An external call followed immediately by require(success) is NOT an unchecked-call "
            "vulnerability. The return value IS checked. Additionally, calls preceded by "
            "balance/allowance checks via require() are properly validated. "
            "Presence of require() both before and after the call is a strong safety signal."
        ),
        "vulnerability_pattern": (
            "address.call() or .send() — safe when return value is checked with require()."
        ),
        "safe_pattern": (
            "function sendFunds(address payable to, uint amount) internal { "
            "require(address(this).balance >= amount, 'Insufficient balance'); "
            "(bool success,) = to.call{value: amount}(''); "
            "require(success, 'Transfer failed'); "
            "emit FundsSent(to, amount); }"
        ),
        "mitigation": "Always check return value: require(success) after call(), or use transfer().",
        "severity": "Safe",
        "keywords": [
            "require(success)", "require(ok)", "if (!success) revert",
            "bool success", "call{value:", "require before call"
        ],
        "false_positive_signals": [
            "require(success) immediately after call()",
            "bool success assigned from call(), then require(success)",
            "require() both before (balance check) and after (return check) call"
        ],
        "real_world_case": "OpenZeppelin Address.sendValue — uses call() with require(success) correctly."
    },
    {
        "id": "FP-006",
        "category": "false_positive",
        "title": "Multi-Modifier Access Control Stack",
        "description": (
            "Functions protected by multiple modifiers (e.g., onlyOwner + whenNotPaused, "
            "or onlyRole + nonReentrant) have layered defenses. Each modifier independently "
            "gates execution. A function with 2+ protective modifiers is more secure, not "
            "less. Do NOT flag these as access control vulnerabilities."
        ),
        "vulnerability_pattern": (
            "Function with multiple modifiers on sensitive operations "
            "— these are defense-in-depth, not vulnerability."
        ),
        "safe_pattern": (
            "contract Secure is Ownable, Pausable, ReentrancyGuard { "
            "function emergencyWithdraw(uint amount) "
            "external onlyOwner whenNotPaused nonReentrant { "
            "require(amount <= address(this).balance); "
            "payable(owner()).transfer(amount); "
            "emit EmergencyWithdraw(amount); } }"
        ),
        "mitigation": "Multiple modifiers provide defense-in-depth. Standard pattern in production contracts.",
        "severity": "Safe",
        "keywords": [
            "onlyOwner whenNotPaused", "nonReentrant onlyOwner",
            "Pausable", "whenNotPaused", "whenPaused", "pause()", "unpause()",
            "multiple modifiers"
        ],
        "false_positive_signals": [
            "two or more access modifiers on same function",
            "Pausable + Ownable combined",
            "nonReentrant + onlyOwner on withdraw"
        ],
        "real_world_case": "Compound / Aave emergency functions — use onlyOwner + Pausable stack for safety."
    },
    {
        "id": "FP-007",
        "category": "false_positive",
        "title": "Pull-Payment Pattern (Not a DoS)",
        "description": (
            "Contracts using pull-payment (pendingWithdrawals mapping + separate withdraw() function) "
            "are NOT vulnerable to denial-of-service. The push-to-pull conversion means each user "
            "withdraws their own funds independently. External call failures affect only the caller, "
            "not other users or contract state. This is the recommended pattern."
        ),
        "vulnerability_pattern": (
            "Loop with transfers or external calls — safe when using pull-payment mapping instead of push loop."
        ),
        "safe_pattern": (
            "mapping(address => uint) public pendingWithdrawals;\n\n"
            "function claimRefund() internal { pendingWithdrawals[msg.sender] += refundAmount; }\n\n"
            "function withdraw() external nonReentrant { "
            "uint amount = pendingWithdrawals[msg.sender]; "
            "require(amount > 0); "
            "pendingWithdrawals[msg.sender] = 0; "
            "payable(msg.sender).transfer(amount); }"
        ),
        "mitigation": "Pull-payment pattern: accumulate in mapping, let users withdraw individually.",
        "severity": "Safe",
        "keywords": [
            "pendingWithdrawals", "pull payment", "pull over push",
            "withdraw pattern", "pendingReturns", "allowedWithdrawals"
        ],
        "false_positive_signals": [
            "pendingWithdrawals[msg.sender] mapping",
            "separate withdraw() function for each user",
            "pull-payment design pattern"
        ],
        "real_world_case": "OpenZeppelin PullPayment — canonical safe withdrawal pattern for auctions/sales."
    },
    {
        "id": "FP-008",
        "category": "false_positive",
        "title": "Event-Emitting State Change with Input Validation",
        "description": (
            "A state-changing function that: (1) validates inputs with require(), "
            "(2) performs state updates, and (3) emits events is following best practices. "
            "Event emission provides audit trail. require() gates prevent invalid states. "
            "Do NOT flag these as vulnerabilities merely because they change state."
        ),
        "vulnerability_pattern": (
            "State mutation function with external visibility "
            "— safe when accompanied by require() validation and emit for audit trail."
        ),
        "safe_pattern": (
            "function updateConfig(uint newFee, address newTreasury) external onlyOwner { "
            "require(newFee <= MAX_FEE, 'Fee too high'); "
            "require(newTreasury != address(0), 'Zero address'); "
            "uint oldFee = fee; "
            "fee = newFee; "
            "treasury = newTreasury; "
            "emit ConfigUpdated(oldFee, newFee, newTreasury); }"
        ),
        "mitigation": "Input validation + state update + event emission is the correct pattern for state changes.",
        "severity": "Safe",
        "keywords": [
            "emit", "event", "require before state change", "input validation",
            "require(newX != 0)", "require(amount > 0)", "emit Transfer", "emit Approval"
        ],
        "false_positive_signals": [
            "require() checks before state mutation",
            "emit event after state update",
            "address(0) check + zero-amount check before transfer"
        ],
        "real_world_case": "Standard ERC-20 transfer() — require checks + state update + emit Transfer is safe."
    }
]


def load_kb(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_kb(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  Saved: {path}")


def add_fp_entries(kb: dict) -> dict:
    existing_ids = {e["id"] for e in kb["entries"]}
    new_entries = [e for e in FP_ENTRIES if e["id"] not in existing_ids]
    skipped = len(FP_ENTRIES) - len(new_entries)

    if skipped:
        print(f"  Skipped {skipped} already-present FP entries.")

    kb["entries"].extend(new_entries)

    # Update metadata
    if "false_positive" not in kb["metadata"]["categories"]:
        kb["metadata"]["categories"].append("false_positive")
    kb["metadata"]["total_entries"] = len(kb["entries"])
    kb["metadata"]["version"] = "1.1"
    kb["metadata"]["last_updated"] = datetime.utcnow().isoformat()
    kb["metadata"]["sources"].append(
        "Sprint 4 FP analysis — 29 FP contracts from SmartBugs Curated ablation"
    )

    print(f"  Added {len(new_entries)} FP entries (total now: {len(kb['entries'])})")
    return kb


def rebuild_chromadb(kb: dict) -> None:
    try:
        import chromadb
        from openai import OpenAI
    except ImportError as e:
        print(f"  [SKIP] ChromaDB rebuild requires missing package: {e}")
        return

    client = OpenAI()

    print(f"  Connecting to ChromaDB at {CHROMA_DIR} ...")
    chroma = chromadb.PersistentClient(path=CHROMA_DIR)

    # Delete old collection and recreate
    try:
        chroma.delete_collection("vuln_knowledge")
        print("  Deleted old 'vuln_knowledge' collection.")
    except Exception:
        pass

    collection = chroma.create_collection(
        name="vuln_knowledge",
        metadata={"hnsw:space": "cosine"}
    )

    entries = kb["entries"]
    docs, ids, metas = [], [], []

    for e in entries:
        parts = [
            f"[{e['category'].upper()}] {e['title']}",
            f"Description: {e['description']}",
            f"Vulnerability Pattern: {e.get('vulnerability_pattern', '')}",
            f"Safe Pattern: {e.get('safe_pattern', '')}",
            f"Mitigation: {e.get('mitigation', '')}",
            f"Severity: {e.get('severity', 'Unknown')}",
        ]
        if e.get("false_positive_signals"):
            parts.append("FP Signals: " + "; ".join(e["false_positive_signals"]))
        if e.get("keywords"):
            parts.append("Keywords: " + ", ".join(e["keywords"]))
        if e.get("real_world_case"):
            parts.append(f"Case: {e['real_world_case']}")
        docs.append("\n".join(parts))
        ids.append(e["id"])
        metas.append({
            "category": e["category"],
            "severity": e.get("severity", "Unknown"),
            "title": e["title"],
        })

    # Batch embed
    print(f"  Embedding {len(docs)} entries via text-embedding-3-small ...")
    BATCH = 100
    embeddings = []
    for i in range(0, len(docs), BATCH):
        batch = docs[i:i + BATCH]
        resp = client.embeddings.create(model="text-embedding-3-small", input=batch)
        embeddings.extend([r.embedding for r in resp.data])

    collection.add(documents=docs, embeddings=embeddings, ids=ids, metadatas=metas)
    print(f"  ChromaDB rebuilt: {len(docs)} entries in 'vuln_knowledge' collection.")


def main():
    parser = argparse.ArgumentParser(description="Add FP patterns to RAG knowledge base")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild ChromaDB after updating JSON")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change, don't write")
    args = parser.parse_args()

    print("=" * 60)
    print("#43 RAG 知識庫升級：加入 false-positive patterns")
    print("=" * 60)

    print(f"\n[1/3] Loading knowledge base from {KB_FILE}")
    kb = load_kb(KB_FILE)
    print(f"  Current entries: {kb['metadata']['total_entries']}")
    print(f"  Current categories: {kb['metadata']['categories']}")

    print("\n[2/3] Adding FP entries ...")
    updated_kb = add_fp_entries(kb)

    if args.dry_run:
        print("\n[DRY RUN] Would write the following FP entry IDs:")
        for e in FP_ENTRIES:
            print(f"  {e['id']}: {e['title']}")
        print("\nNo files written (--dry-run).")
        return

    save_kb(updated_kb, KB_FILE)

    if args.rebuild:
        print("\n[3/3] Rebuilding ChromaDB ...")
        rebuild_chromadb(updated_kb)
    else:
        print("\n[3/3] ChromaDB rebuild skipped (pass --rebuild to rebuild).")
        print(f"  To rebuild: python {os.path.basename(__file__)} --rebuild")

    print("\n✅ Done.")
    print(f"  knowledge base: {KB_FILE}")
    print(f"  New total entries: {updated_kb['metadata']['total_entries']}")
    print(f"  New categories:    {updated_kb['metadata']['categories']}")


if __name__ == "__main__":
    main()
