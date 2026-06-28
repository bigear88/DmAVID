#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan the whole docx body for citations and flag likely AUTHOR-LESS ones
(system/tool/method name + year, instead of Surname/et al. + year)."""
import re
from docx import Document
d = Document("/mnt/d/OneDrive/DmAVID/DmAVID_20260622_v11.docx")

# match （2024） （2025b） （ISSTA 2025） and (Name, 2024) etc.
year_paren = re.compile(r"[（(]\s*([A-Za-z .,&\-]*?\s*)?(19|20)\d\d[a-z]?\s*[)）]")
# a token that looks like an author cite: ends with 'et al.' or a capitalized surname/&
author_like = re.compile(r"(et al\.?|[A-Z][a-z]+(\s*&\s*[A-Z][a-z]+)?|[一-鿿]{2,4}(、[一-鿿]{2,4})*)\s*$")

flagged = []
allc = []
for i, p in enumerate(d.paragraphs):
    t = p.text
    for m in re.finditer(r"[（(][^（）()]{0,40}?(19|20)\d\d[a-z]?[^（）()]{0,12}?[)）]", t):
        s = m.start()
        pre = t[max(0, s-22):s]
        cite = m.group(0)
        allc.append((i, pre, cite))
        # author-less heuristic: preceding text ends with a system-name-ish token
        # (contains uppercase+lowercase mix with digits/hyphen, or a known product), no 'et al.' and no CJK surname right before
        tail = pre.strip()
        # if cite itself contains an author (comma + surname) it's fine
        has_inside_author = bool(re.search(r"[A-Za-z]{3,},?\s*(et al\.|&|\d{4})", cite)) and not re.fullmatch(r"[（(]\s*(19|20)\d\d[a-z]?\s*[)）]", cite)
        # token immediately before paren
        tok = re.search(r"([A-Za-z][A-Za-z0-9\-]*|[一-鿿、]+|et al\.?)\s*$", tail)
        token = tok.group(1) if tok else ""
        is_sysname = bool(re.search(r"[A-Z].*[a-z]", token) and (any(c.isdigit() for c in token) or "-" in token or token[0].isupper())) and "et" not in token
        cjk_author = bool(re.search(r"[一-鿿]{2,4}$", token))
        etal = token == "al." or tail.endswith("et al.") or tail.endswith("et al")
        # cite with explicit author inside parens (English style)
        eng_author_inside = bool(re.match(r"^[（(]\s*[A-Z][a-zA-Z]+", cite))
        if not has_inside_author and not cjk_author and not etal and not eng_author_inside and token and is_sysname:
            flagged.append((i, token, cite, pre))

print("===== 疑似無作者引用（系統/工具名 + 年）=====")
seen = set()
for i, token, cite, pre in flagged:
    k = (i, token, cite)
    if k in seen: continue
    seen.add(k)
    print(f"P{i}: 「...{pre}{cite}」  ← 前置 token: {token!r}")
print(f"\n旗標數: {len(seen)}")
print(f"全文 (年份) 引用總數: {len(allc)}")
