import re

def grep_guard(code: str) -> dict:
    """Scan Solidity code for protective mechanisms. Returns facts, not verdicts."""
    mitigations = []

    transfer_only = (
        ".transfer(" in code and
        ".call.value(" not in code and
        ".call{value:" not in code
    )
    if transfer_only:
        mitigations.append(".transfer()-only")

    has_reentrancy_guard = bool(re.search(r'\b(ReentrancyGuard|nonReentrant)\b', code))
    if has_reentrancy_guard:
        mitigations.append("ReentrancyGuard")

    has_safemath = bool(re.search(r'\bSafeMath\b', code))
    if has_safemath:
        mitigations.append("SafeMath")

    has_only_owner = bool(re.search(r'\b(onlyOwner|Ownable)\b', code))
    if has_only_owner:
        mitigations.append("onlyOwner")

    has_send_checked = bool(re.search(r'(require|if|assert)[^;]*\.send\(', code))
    if has_send_checked:
        mitigations.append("send-checked")

    call_value_present = bool(re.search(r'\.call\.value\(|\.call\{value:', code))

    return {
        "mitigations": mitigations,
        "transfer_only": transfer_only,
        "has_reentrancy_guard": has_reentrancy_guard,
        "has_safemath": has_safemath,
        "has_only_owner": has_only_owner,
        "has_send_checked": has_send_checked,
        "call_value_present": call_value_present,
        "mitigation_count": len(mitigations),
    }
