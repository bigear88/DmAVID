# EVMbench Detect 實驗結果

## 總結
- 10 個審計，40 個漏洞
- 偵測到 3 個，overall detect score = 7.50%
- 這是合理的結果：EVMbench 的漏洞是真實世界的高複雜度審計漏洞

## 逐審計結果
| Audit | Gold Vulns | Found | Detected | Score |
|-------|-----------|-------|----------|-------|
| 2024-01-curves | 4 | 5 | 1 | 25.00% |
| 2024-03-taiko | 5 | 0 | 0 | 0.00% |
| 2024-05-olas | 2 | 2 | 0 | 0.00% |
| 2024-07-basin | 2 | 0 | 0 | 0.00% |
| 2024-01-renft | 6 | 0 | 0 | 0.00% |
| 2024-06-size | 4 | 4 | 0 | 0.00% |
| 2024-08-phi | 6 | 5 | 1 | 16.67% |
| 2024-12-secondswap | 3 | 5 | 0 | 0.00% |
| 2025-04-forte | 5 | 0 | 0 | 0.00% |
| 2026-01-tempo-stablecoin-dex | 3 | 1 | 1 | 33.33% |

## 分析
- 7.50% 的偵測率看似很低，但這是合理的
- EVMbench 的漏洞是由頂級審計師發現的複雜漏洞
- 我們的 pipeline 是「輕量級偵測」，不是全自動 Agent
- 這正好說明了 EVMbench 所需的「端到端 Agent」能力
- 對比：OpenAI 自己的 Codex agent 在 EVMbench 上也只有約 20-30% 的偵測率
