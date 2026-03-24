# GitHub 與論文數據交叉驗證

## 1. 混淆矩陣（表 4-7）交叉驗證

### Slither
- 論文：TP=135, FP=84, FN=8, TN=16, Acc=0.6214, Prec=0.6164, Rec=0.9441, F1=0.7459, FPR=0.8400
- GitHub：TP=135, FP=84, FN=8, TN=16, Acc=0.6214, Prec=0.6164, Rec=0.9441, F1=0.7459, FPR=0.84
- **結果：✅ 完全一致**

### Mythril
- 論文：TP=15, FP=6, FN=5, TN=14, Acc=0.7250, Prec=0.7143, Rec=0.7500, F1=0.7317, FPR=0.3000
- GitHub：TP=15, FP=6, FN=5, TN=14, Acc=0.725, Prec=0.7143, Rec=0.75, F1=0.7317, FPR=0.3
- **結果：✅ 完全一致**

### LLM Base
- 論文：TP=143, FP=95, FN=0, TN=5, Acc=0.6091, Prec=0.6008, Rec=1.0000, F1=0.7507, FPR=0.9500
- GitHub：TP=143, FP=95, FN=0, TN=5, Acc=0.6091, Prec=0.6008, Rec=1.0, F1=0.7507, FPR=0.95
- **結果：✅ 完全一致**

### LLM+RAG
- 論文：TP=142, FP=57, FN=1, TN=43, Acc=0.7613, Prec=0.7136, Rec=0.9930, F1=0.8304, FPR=0.5700
- GitHub：TP=142, FP=57, FN=1, TN=43, Acc=0.7613, Prec=0.7136, Rec=0.993, F1=0.8304, FPR=0.57
- **結果：✅ 完全一致**

### Hybrid
- 論文：TP=142, FP=52, FN=1, TN=48, Acc=0.7819, Prec=0.7320, Rec=0.9930, F1=0.8427, FPR=0.5200
- GitHub：TP=142, FP=52, FN=1, TN=48, Acc=0.7819, Prec=0.732, Rec=0.993, F1=0.8427, FPR=0.52
- **結果：✅ 完全一致**

## 2. McNemar 檢驗（表 4-6）交叉驗證

### LLM+RAG vs LLM Base
- 論文：共同合約=243, χ²=33.23, p<0.0001, ***
- GitHub：共同合約=243, χ²=33.2308, p=0.0, significant_at_001=true
- **結果：✅ 一致**

### LLM+RAG vs Hybrid
- 論文：共同合約=243, χ²=1.23, p=0.2673, n.s.
- GitHub：共同合約=243, χ²=1.2308, p=0.267257, significant_at_005=false
- **結果：✅ 一致**

### Hybrid vs LLM Base
- 論文：共同合約=243, χ²=35.02, p<0.0001, ***
- GitHub：共同合約=243, χ²=35.0208, p=0.0, significant_at_001=true
- **結果：✅ 一致**

### LLM+RAG vs Slither
- 論文：共同合約=143, χ²=4.00, p=0.0455, *
- GitHub：共同合約=143, χ²=4.0, p=0.0455, significant_at_005=true
- **結果：✅ 一致**

### Hybrid vs Slither
- 論文：共同合約=143, χ²=4.00, p=0.0455, *
- GitHub：共同合約=143, χ²=4.0, p=0.0455, significant_at_005=true
- **結果：✅ 一致**

## 3. 成本敏感分析（表 4-5）交叉驗證

| FN/FP 比率 | 論文 Slither | GitHub Slither | 論文 LLM Base | GitHub LLM Base | 論文 LLM+RAG | GitHub LLM+RAG | 論文 Hybrid | GitHub Hybrid | 論文最佳 | GitHub最佳 |
|-----------|------------|----------------|-------------|-----------------|------------|----------------|-----------|---------------|---------|-----------|
| 1x | 92 | 92 | 95 | 95 | 58 | 58 | 53 | 53 | Hybrid | hybrid ✅ |
| 2x | 100 | 100 | 95 | 95 | 59 | 59 | 54 | 54 | Hybrid | hybrid ✅ |
| 5x | 124 | 124 | 95 | 95 | 62 | 62 | 57 | 57 | Hybrid | hybrid ✅ |
| 10x | 164 | 164 | 95 | 95 | 67 | 67 | 62 | 62 | Hybrid | hybrid ✅ |
| 20x | 244 | 244 | 95 | 95 | 77 | 77 | 72 | 72 | Hybrid | hybrid ✅ |
| 50x | 484 | 484 | 95 | 95 | 107 | 107 | 102 | 102 | LLM Base | llm_base ✅ |

**結果：✅ 全部完全一致**

## 總結
所有論文中的實驗數據（混淆矩陣、McNemar 檢驗、成本敏感分析）均與 GitHub 倉庫中的 JSON 數據**完全一致**，無任何不匹配。


## 4. 漏洞類型檢測召回率（表 4-4）交叉驗證

### 論文 vs GitHub 數據比較

| 漏洞類型 | 合約數 | 論文 Slither | GitHub Slither | 論文 LLM Base | GitHub LLM Base | 論文 LLM+RAG | GitHub LLM+RAG | 論文 Hybrid | GitHub Hybrid |
|---------|--------|------------|----------------|-------------|-----------------|------------|----------------|-----------|---------------|
| reentrancy | 31 | 94% | 90.32% | 100% | 100% | 100% | 100% | 100% | 100% |
| unchecked_low_level | 52 | 96% | 96.15% | 100% | 100% | 98% | 100% | 100% | 100% |
| access_control | 18 | 94% | 94.44% | 100% | 100% | 100% | 100% | 100% | 100% |
| arithmetic | 15 | 93% | 93.33% | 93% | 100% | 87% | 93.33% | 87% | 93.33% |
| bad_randomness | 8 | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| denial_of_service | 6 | 83% | 83.33% | 100% | 100% | 100% | 100% | 100% | 100% |
| front_running | 4 | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| time_manipulation | 5 | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |

### 發現的不一致

1. **reentrancy - Slither**: 論文寫 94%，GitHub 數據為 90.32%（28/31）。⚠️ 不一致
   - 94% 對應 29/31 或 30/31，但 GitHub 顯示 28/31 = 90.32%
   
2. **unchecked_low_level - LLM+RAG**: 論文寫 98%，GitHub 數據為 100%（52/52）。⚠️ 不一致
   - 98% 意味著漏掉了 1 個，但 GitHub 顯示全部檢測到

3. **arithmetic - LLM Base**: 論文寫 93%，GitHub 數據為 100%（15/15）。⚠️ 不一致
   - 93% 意味著漏掉了 1 個，但 GitHub 顯示全部檢測到

4. **arithmetic - LLM+RAG**: 論文寫 87%，GitHub 數據為 93.33%（14/15）。⚠️ 不一致
   - 87% 對應 13/15，但 GitHub 顯示 14/15

5. **arithmetic - Hybrid**: 論文寫 87%，GitHub 數據為 93.33%（14/15）。⚠️ 不一致
   - 同上

### 結論
表 4-4（漏洞類型召回率）存在 **5 處數據不一致**，需要修正。Slither 的 reentrancy 召回率、以及 arithmetic 和 unchecked_low_level 的多個方法數據與 GitHub 不匹配。


## 5. 漏洞類別計數不一致

### README vs 論文表 4-4 vs GitHub JSON

README 中的漏洞類別計數：
- Reentrancy: 31
- Access Control: 17
- Arithmetic (Integer Overflow): 22
- Unchecked Return Values: 16
- Denial of Service: 6
- Front Running: 4
- Time Manipulation: 5
- Other: 42

論文表 4-4 中的漏洞類別計數：
- reentrancy: 31
- unchecked_low_level: 52
- access_control: 18
- arithmetic: 15
- bad_randomness: 8
- denial_of_service: 6
- front_running: 4
- time_manipulation: 5

GitHub JSON 中的漏洞類別計數（vulnerability_type_comparison.json）：
- reentrancy: 31
- unchecked_low_level_calls: 52
- access_control: 18
- arithmetic: 15
- bad_randomness: 8
- denial_of_service: 6
- front_running: 4
- time_manipulation: 5
- short_addresses: 1
- other: 3

### 不一致之處：
1. **Access Control**: README 寫 17，論文和 JSON 都寫 18 → ⚠️ README 與論文不一致
2. **Arithmetic**: README 寫 22，論文和 JSON 都寫 15 → ⚠️ README 與論文不一致
3. **Unchecked Return Values vs unchecked_low_level**: README 寫 16，論文和 JSON 都寫 52 → ⚠️ 類別名稱和數量都不同
4. **bad_randomness**: README 未列出，論文和 JSON 寫 8
5. **short_addresses**: 僅在 JSON 中出現（1 個），論文和 README 都未提及
6. **Other**: README 寫 42，JSON 寫 3

**分析**: README 的漏洞類別計數似乎使用了不同的分類方式。README 的總數 (31+17+22+16+6+4+5+42=143) 等於 143，與論文一致。但 JSON 中的總數 (31+52+18+15+8+6+4+5+1+3=143) 也等於 143。這表明分類方式不同但總數一致。


## 6. 混淆矩陣數學計算驗證

所有混淆矩陣中的 Accuracy、Precision、Recall、F1、FPR 數值均通過數學驗證，計算結果與論文和 GitHub 數據完全一致。

**結果：✅ 全部正確**

Mythril 的 TP+FN=20, FP+TN=20，總計 40 份合約（因 47.5% 超時率僅分析了 40 份），這與論文描述一致。

## 7. 消融實驗 F1 計算驗證

| 方法 | 論文 Prec | 論文 Rec | 論文 F1 | 計算 F1 | 差異 |
|------|----------|---------|---------|---------|------|
| Slither only | 0.62 | 0.94 | 0.75 | 0.7472 | ⚠️ 0.003 |
| LLM only | 0.60 | 1.00 | 0.75 | 0.7500 | ✅ |
| LLM+RAG | 0.71 | 0.99 | 0.83 | 0.8269 | ⚠️ 0.003 |
| Hybrid | 0.73 | 0.99 | 0.84 | 0.8403 | ✅ |

**分析**: 消融實驗的 F1 值存在微小的四捨五入差異（0.003 以內），這是因為 Precision 和 Recall 本身就是四捨五入到兩位小數的值。如果使用原始精確值計算，F1 應該更精確。這屬於正常的四捨五入誤差，不構成數據造假。

## 8. McNemar 檢驗計算驗證

使用 GitHub JSON 中的 b、c 值重新計算 χ²：

| 比較對 | 論文 χ² | GitHub b | GitHub c | 重算 χ² | 匹配 |
|--------|---------|----------|----------|---------|------|
| LLM+RAG vs LLM Base | 33.23 | 38 | 1 | 35.10 | ⚠️ 不匹配 |
| LLM+RAG vs Hybrid | 1.23 | 4 | 9 | 1.92 | ⚠️ 不匹配 |
| Hybrid vs LLM Base | 35.02 | 45 | 3 | 36.75 | ⚠️ 不匹配 |
| LLM+RAG vs Slither | 4.00 | 8 | 1 | 5.44 | ⚠️ 不匹配 |
| Hybrid vs Slither | 4.00 | 8 | 1 | 5.44 | ⚠️ 不匹配 |

**重要發現**: McNemar 檢驗的 χ² 值在使用 GitHub JSON 中的 b、c 值重新計算後，與論文中報告的值不匹配。但 GitHub JSON 中的 chi2_statistic 值（33.2308, 1.2308, 35.0208, 4.0, 4.0）與論文中的值（33.23, 1.23, 35.02, 4.00, 4.00）是一致的。

**這意味著**: GitHub JSON 中的 chi2_statistic 是直接存儲的計算結果，但 b、c 值可能使用了 Yates 連續性修正（continuity correction），即 χ² = (|b-c|-1)² / (b+c)。讓我驗證。

使用 Yates 修正重新計算：
- LLM+RAG vs LLM Base: (|38-1|-1)²/(38+1) = 36²/39 = 33.23 ✅
- LLM+RAG vs Hybrid: (|4-9|-1)²/(4+9) = 4²/13 = 1.23 ✅
- Hybrid vs LLM Base: (|45-3|-1)²/(45+3) = 41²/48 = 35.02 ✅
- LLM+RAG vs Slither: (|8-1|-1)²/(8+1) = 6²/9 = 4.00 ✅
- Hybrid vs Slither: (|8-1|-1)²/(8+1) = 6²/9 = 4.00 ✅

**結論**: ✅ 所有 McNemar 檢驗值使用 Yates 連續性修正後完全正確。論文使用了帶 Yates 修正的 McNemar 檢驗，這是統計學上的標準做法。
