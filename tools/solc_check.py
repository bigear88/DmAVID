import re

def solc_check(code: str) -> dict:
    """Parse Solidity version and report overflow-related facts."""
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', code)
    pragma_raw = pragma_match.group(1).strip() if pragma_match else "unknown"

    ver_match = re.search(r'(\d+\.\d+)', pragma_raw)
    if ver_match:
        version = ver_match.group(1)
        version_float = float(version)
    else:
        version = "0.8"
        version_float = 0.8

    overflow_safe_builtin = version_float >= 0.8
    has_safemath = bool(re.search(r'\bSafeMath\b', code))
    has_unchecked_block = bool(re.search(r'\bunchecked\s*\{', code))

    # Simple arithmetic ops check (excluding comments)
    code_no_comments = re.sub(r'//[^\n]*', '', code)
    code_no_comments = re.sub(r'/\*.*?\*/', '', code_no_comments, flags=re.DOTALL)
    has_arithmetic_ops = bool(re.search(r'[^=!<>]=\s*[^=].*[+\-\*]|[+\-\*]=', code_no_comments))

    if overflow_safe_builtin and not has_unchecked_block:
        overflow_risk = "none"
    elif version_float < 0.8 and has_safemath:
        overflow_risk = "low"
    elif version_float < 0.8 and not has_safemath and has_arithmetic_ops:
        overflow_risk = "high"
    else:
        overflow_risk = "low"

    return {
        "pragma_raw": pragma_raw,
        "version": version,
        "version_float": version_float,
        "overflow_safe_builtin": overflow_safe_builtin,
        "has_safemath": has_safemath,
        "has_unchecked_block": has_unchecked_block,
        "overflow_risk": overflow_risk,
        "has_arithmetic_ops": has_arithmetic_ops,
    }
