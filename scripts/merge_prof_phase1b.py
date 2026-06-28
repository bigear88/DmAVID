#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 1b: apply professor's localized edits to the 6 diverged paragraphs while
preserving my file's added technical content. (P383 seed / P385 CTC already aligned
by a prior session -> skipped.)"""
from docx import Document

SRC = "/mnt/d/OneDrive/DmAVID/DmAVID_20260622_v11.docx"
doc = Document(SRC)


def set_text(p, txt):
    p.runs[0].text = txt
    for r in p.runs[1:]:
        r._element.getparent().remove(r._element)


REPS = [  # (old_substring, new_substring) — each unique in its paragraph
 ("（Self-Verify）機制以及多代理", "（Self-Verify）以及多代理"),
 ("第二階段輸出之門控式旁支", "第二階段輸出之閘控式旁支"),
 ("（Generative Adversarial Network, GAN）之攻防博弈概念與軟體",
  "（Generative Adversarial Network, GAN；Goodfellow et al., 2014）之攻防博弈概念，與軟體"),
 ("（Red Team/Blue Team）測試方法論。", "（Red Team/Blue Team）測試方法論（Perez et al., 2022）。"),
 ("S1 為 Student 偵測階段。Student", "S1 為 Student 偵測階段：Student"),
 ("S5 為 Foundry 驗證階段。系統將", "S5 為 Foundry 驗證階段：系統將"),
 ("S6 為 Blue Team 知識合成階段。Blue Team", "S6 為 Blue Team 知識合成階段：Blue Team"),
 ("S7 為 RAG 知識庫更新與回饋階段。更新完成後", "S7 為 RAG 知識庫更新與回饋階段：更新完成後"),
]
done = [0] * len(REPS)
for p in doc.paragraphs:
    t = p.text
    new = t
    for i, (old, rep) in enumerate(REPS):
        if old in new:
            new = new.replace(old, rep); done[i] += 1
    if new != t:
        set_text(p, new)
for i, (old, _) in enumerate(REPS):
    print(("[OK]" if done[i] else "[MISS]"), f"{done[i]}x", old[:34])
doc.save(SRC)
print("saved")
