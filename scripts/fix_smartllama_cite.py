#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attribute the Smart-LLaMA-DPO / CTC citations to the correct first author (Yu et al.),
matching reference entry 'Yu, L., ... (2025). Smart-LLaMA-DPO'. P247 'Li et al.' is IRIS
(correct) and left untouched."""
from docx import Document
SRC = "/mnt/d/OneDrive/DmAVID/DmAVID_20260622_v11.docx"
doc = Document(SRC)

def set_text(p, txt):
    p.runs[0].text = txt
    for r in p.runs[1:]:
        r._element.getparent().remove(r._element)

REPS = [
 ("Smart-LLaMA-DPO（2025）於 ISSTA 2025 提出了結合直接偏好最佳化",
  "Yu et al.（2025）於 ISSTA 2025 提出之 Smart-LLaMA-DPO 結合了直接偏好最佳化"),
 ("三維度框架（Smart-LLaMA-DPO, ISSTA 2025）",
  "三維度框架（Yu et al., 2025）"),
 ("該框架源自 Smart-LLaMA-DPO（ISSTA 2025）",
  "該框架源自 Yu et al.（2025）提出之 Smart-LLaMA-DPO"),
]
done = [0]*len(REPS)
for p in doc.paragraphs:
    t = p.text; new = t
    for i,(old,rep) in enumerate(REPS):
        if old in new:
            new = new.replace(old, rep); done[i]+=1
    if new != t:
        set_text(p, new)
for i,(old,_) in enumerate(REPS):
    print(("[OK]" if done[i] else "[MISS]"), old[:34])
doc.save(SRC)
print("saved")
