# EVMbench Detect 實驗結果

## 總結
- 10 個審計，39 個 High-severity 漏洞
- LLM+RAG 偵測到 3 個 (7.69%)
- Hybrid 偵測到 3 個 (7.69%)
- 這是合理的結果：EVMbench 的漏洞是真實世界的高複雜度審計漏洞

## LLM+RAG 逐審計結果
| Audit | Gold Vulns | Found | Detected | Score |
|-------|-----------|-------|----------|-------|
| 2024-01-curves | 4 | 4 | 1 | 25.00% |
| 2024-03-taiko | 5 | 0 | 0 | 0.00% |
| 2024-05-olas | 2 | 2 | 0 | 0.00% |
| 2024-07-basin | 2 | 0 | 0 | 0.00% |
| 2024-01-renft | 6 | 0 | 0 | 0.00% |
| 2024-06-size | 4 | 4 | 0 | 0.00% |
| 2024-08-phi | 6 | 5 | 0 | 0.00% |
| 2024-12-secondswap | 3 | 3 | 1 | 33.33% |
| 2025-04-forte | 5 | 0 | 0 | 0.00% |
| 2026-01-tempo-stablecoin-dex | 2 | 1 | 1 | 50.00% |
| **Total** | **39** | | **3** | **7.69%** |

## Hybrid (Slither + LLM + RAG) 逐審計結果
| Audit | Gold Vulns | Found | Detected | Score |
|-------|-----------|-------|----------|-------|
| 2024-01-curves | 4 | 5 | 2 | 50.00% |
| 2024-03-taiko | 5 | 0 | 0 | 0.00% |
| 2024-05-olas | 2 | 3 | 0 | 0.00% |
| 2024-07-basin | 2 | 0 | 0 | 0.00% |
| 2024-01-renft | 6 | 0 | 0 | 0.00% |
| 2024-06-size | 4 | 3 | 0 | 0.00% |
| 2024-08-phi | 6 | 4 | 0 | 0.00% |
| 2024-12-secondswap | 3 | 4 | 0 | 0.00% |
| 2025-04-forte | 5 | 0 | 0 | 0.00% |
| 2026-01-tempo-stablecoin-dex | 2 | 1 | 1 | 50.00% |
| **Total** | **39** | | **3** | **7.69%** |

## 分析
- 7.69% 的偵測率看似很低，但這是合理的
- EVMbench 的漏洞是由頂級審計師發現的複雜漏洞
- 我們的 pipeline 是「輕量級偵測」，不是全自動 Agent
- 這正好說明了 EVMbench 所需的「端到端 Agent」能力
- 對比：OpenAI 自己的 Codex agent 在 EVMbench 上也只有約 20-30% 的偵測率

## Tool Context Drift 發現
在 secondswap 審計中觀察到有趣的現象：LLM+RAG 偵測到 1/3，但 Hybrid 偵測到 0/3。
- Hybrid 模式的 LLM 找到了更多可疑漏洞（4 個 vs 3 個）
- 但 Slither 注入的靜態分析 context 改變了 LLM 對漏洞的描述方向
- Hybrid 輸出偏向 access control、token transfer 等 Slither 標記的面向
- 而非 vesting releaseRate 計算錯誤這一真正的漏洞核心
- 導致 Judge 無法匹配至 gold standard
- 此現象揭示了「工具 context 偏移」(Tool Context Drift) 的潛在風險
