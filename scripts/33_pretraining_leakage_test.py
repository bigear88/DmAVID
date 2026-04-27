#!/usr/bin/env python3
"""
Sprint 2: 預訓練資料洩漏量化驗證 (Pre-training Data Leakage Quantification)

目的：量化 gpt-4.1-mini 在 SmartBugs 上 F1=0.9121 的「真實泛化能力」與
      「預訓練語料記憶」之比例。透過將 DmAVID Hybrid 管線套用於模型
      cutoff (2024-10) 之後才公開的 8 個 EVMbench audit packs，
      建立「絕對 post-cutoff」基準，與既有 SmartBugs 0.9121 / EVMbench 2024
      30.77% 結果三向對照。

設計：
- 完全沿用 scripts/10_run_evmbench_hybrid.py 的偵測邏輯與判讀流程
- 僅覆寫 SAMPLE_AUDITS 與 RESULTS_DIR，避免重寫核心程式碼
- 輸出獨立至 experiments/leakage_test/，不污染既有 evmbench 結果

post-cutoff 子集 (8 個 audits, 2025-01 ~ 2026-01)：
  2025-01-liquid-ron, 2025-04-forte, 2025-04-virtuals,
  2025-05-blackhole, 2025-06-panoptic,
  2026-01-tempo-feeamm, 2026-01-tempo-mpp-streams, 2026-01-tempo-stablecoin-dex

執行：
  cd /home/curtis/DmAVID
  python scripts/33_pretraining_leakage_test.py

  # 想先驗證 1 個 audit：
  python scripts/33_pretraining_leakage_test.py --first-only

Author: Curtis Chang (張宏睿), 2026
"""

import os
import sys
import argparse
from pathlib import Path

# ============================================================
# Sprint 2 子集定義 (post-cutoff audits, 2025-01 ~ 2026-01)
# ============================================================

POST_CUTOFF_AUDITS = [
    "2025-01-liquid-ron",
    "2025-04-forte",
    "2025-04-virtuals",
    "2025-05-blackhole",
    "2025-06-panoptic",
    "2026-01-tempo-feeamm",
    "2026-01-tempo-mpp-streams",
    "2026-01-tempo-stablecoin-dex",
]

# ============================================================
# 主流程：覆寫 10 號腳本的 SAMPLE_AUDITS 與 RESULTS_DIR
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Sprint 2 — 預訓練資料洩漏量化驗證")
    parser.add_argument(
        "--first-only", action="store_true",
        help="僅執行第一個 audit，做煙霧測試 (~3-5 分鐘)",
    )
    parser.add_argument(
        "--audits", nargs="+", default=None,
        help="指定 audit IDs，覆蓋預設 post-cutoff 集合",
    )
    args = parser.parse_args()

    # 路徑設定
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.dirname(SCRIPT_DIR)
    sys.path.insert(0, SCRIPT_DIR)

    # 決定要跑的 audits
    if args.audits:
        target_audits = args.audits
    elif args.first_only:
        target_audits = POST_CUTOFF_AUDITS[:1]
    else:
        target_audits = POST_CUTOFF_AUDITS

    print("=" * 70)
    print("Sprint 2 — 預訓練資料洩漏量化驗證")
    print(f"Audits to run : {len(target_audits)}")
    for a in target_audits:
        print(f"  - {a}")
    print("=" * 70)

    # 驗證所有 audit 資料存在
    missing = []
    for audit_id in target_audits:
        audit_path = os.path.join(BASE_DIR, "data", "evmbench", "audits", audit_id)
        if not os.path.exists(audit_path):
            missing.append(audit_id)
    if missing:
        print(f"\n⚠ 以下 audit 資料夾不存在 (檢查 data/evmbench/audits/):")
        for m in missing:
            print(f"  - {m}")
        print("請先確認 evmbench 資料集完整再執行。")
        sys.exit(1)

    # 覆寫前先建立輸出目錄 (避免 logger 初始化時找不到)
    RESULTS_DIR_OVERRIDE = os.path.join(BASE_DIR, "experiments", "leakage_test")
    os.makedirs(RESULTS_DIR_OVERRIDE, exist_ok=True)
    os.makedirs(os.path.join(RESULTS_DIR_OVERRIDE, "logs"), exist_ok=True)

    # 動態載入 10 號腳本，並 monkey-patch 模組級變數
    # 注意：10 號腳本初始化時會建立 logger，所以要在 import 之前
    # 透過環境變數或 sys.argv 處理，這裡採取 import 後立即覆寫的方式
    import importlib.util
    h10_path = os.path.join(SCRIPT_DIR, "10_run_evmbench_hybrid.py")
    spec = importlib.util.spec_from_file_location("h10", h10_path)
    h10 = importlib.util.module_from_spec(spec)

    # 載入前先用環境變數讓 10 號用我們指定的目錄
    # (因 10 號的 RESULTS_DIR 是常數，要在 exec_module 後 monkey-patch)
    spec.loader.exec_module(h10)

    # Monkey-patch
    h10.SAMPLE_AUDITS = target_audits
    h10.RESULTS_DIR = RESULTS_DIR_OVERRIDE

    # 重新指向 logger 的 file handler 到新目錄 (避免 log 跑去 evmbench/)
    import logging
    from datetime import datetime
    new_log = os.path.join(RESULTS_DIR_OVERRIDE, "logs",
                           f"leakage_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    # 移除舊 handler
    for h in list(h10.logger.handlers):
        if isinstance(h, logging.FileHandler):
            h10.logger.removeHandler(h)
            h.close()
    # 加新 handler
    fh = logging.FileHandler(new_log)
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    h10.logger.addHandler(fh)

    print(f"\nResults will be saved to: {RESULTS_DIR_OVERRIDE}")
    print(f"Log file:                 {new_log}\n")

    # 執行 (10 號腳本的 main 會自動讀取剛剛覆寫的 SAMPLE_AUDITS / RESULTS_DIR)
    h10.main()

    # 額外輸出：Sprint 2 專屬 summary CSV，含三向對照
    summary_path = os.path.join(RESULTS_DIR_OVERRIDE, "leakage_test_summary.csv")
    src_csv = os.path.join(RESULTS_DIR_OVERRIDE, "evmbench_hybrid_per_audit.csv")
    if os.path.exists(src_csv):
        # 讀取 per-audit 結果並加上類別標籤
        import csv
        with open(src_csv) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        total_vulns = sum(int(r["num_gold_vulns"]) for r in rows)
        total_detected = sum(int(r["num_detected"]) for r in rows)
        overall_rate = total_detected / total_vulns if total_vulns > 0 else 0.0

        # 寫三向對照表
        with open(summary_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["dataset", "n_samples_or_vulns", "metric", "value", "cutoff_status"])
            w.writerow(["A. SmartBugs Hybrid (existing)", "243", "F1", "0.9121", "pre-2023 (likely leaked)"])
            w.writerow(["B. EVMbench 2024 (existing)", "39", "Detection Rate", "0.3077", "boundary (cutoff=2024-10)"])
            w.writerow(["C. EVMbench 2025+ (Sprint 2)", str(total_vulns),
                        "Detection Rate", f"{overall_rate:.4f}", "post-cutoff (clean)"])
            w.writerow([])
            w.writerow(["per-audit detail (post-cutoff)"])
            w.writerow(["audit_id", "num_gold_vulns", "num_detected", "detect_rate"])
            for r in rows:
                w.writerow([r["audit_id"], r["num_gold_vulns"],
                            r["num_detected"], r["detect_score"]])

        print(f"\n→ Sprint 2 三向對照 summary: {summary_path}")
        print(f"\n=== 關鍵結論 ===")
        print(f"A. SmartBugs F1=0.9121 (likely contains pre-training memory)")
        print(f"B. EVMbench 2024 detection rate=0.3077 (boundary)")
        print(f"C. EVMbench 2025+ detection rate={overall_rate:.4f} (CLEAN, post-cutoff)")
        if overall_rate >= 0.50:
            print(f"   → C ≥ 50%: 強證據顯示 DmAVID 具真實泛化能力，非單純記憶")
        elif overall_rate >= 0.30:
            print(f"   → C ≈ B: 跨 cutoff 一致，記憶成分有限")
        else:
            print(f"   → C < B: SmartBugs 0.9121 高分含記憶成分，需在論文承認")


if __name__ == "__main__":
    main()
