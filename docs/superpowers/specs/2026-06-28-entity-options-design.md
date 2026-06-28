# Log De-identification Tool — Entity 擴充與 GUI 選項設計

**日期：** 2026-06-28  
**狀態：** 已核准，待實作

---

## 背景

現有工具只啟用了 9 個 entity（CJK / DOMAIN / EMAIL / OSUSER / EMPID / TW_PHONE / TW_ID / CREDIT_CARD / ORG），但 Presidio 提供更多有效 recognizer 未被使用。同時 ORG regex 存在 bug，UUID 的勾選邏輯語意與其他選項相反。

---

## 目標

1. 補上 Presidio 中對 SOC / 威脅分析有用的 entity
2. 修正 ORG_PATTERN regex bug（遮蔽殘缺問題）
3. 所有可選 entity 改以統一語意：**「勾選 = 保留明文，不勾選 = 遮蔽」**
4. GUI 呈現 5 個勾選框，預設值反映 SOC 分析需求

---

## Entity 決策清單

### 新增啟用

| Entity | Presidio Class | 預設 | 說明 |
|---|---|---|---|
| `DATE_TIME` | `DateRecognizer` | **保留**（預設勾選） | 攻擊時間線分析核心，不宜預設遮蔽 |
| `CRYPTO` | `CryptoRecognizer` | 遮蔽 | 勒索錢包地址為 IOC；放寬 context 門檻（score 從 0.5 降至 0.3，允許無 context 觸發） |
| `IBAN_CODE` | `IbanRecognizer` | 遮蔽 | 金融詐騙場景中出現的帳號 |
| `US_PASSPORT` | `UsPassportRecognizer` | 遮蔽 | 護照號碼屬個資，台灣場景偶有出現 |

### 不補（明確排除）

| Entity | 原因 |
|---|---|
| `US_BANK_NUMBER` | regex 過於寬鬆（8-17 位數字），誤判率極高 |
| `US_SSN` | 台灣場景幾乎不出現 |
| `US_ITIN` | 台灣場景幾乎不出現 |
| `UK_NHS` | 格式與台灣電話衝突，且為英國特有 |
| `MEDICAL_LICENSE` | 偵測效果差，台灣場景不適用 |
| `SpacyRecognizer` | 需要 spaCy NLP，架構上已移除 |

### 現有修正

| Entity | 問題 | 修法 |
|---|---|---|
| `ORG` | `Microsoft Corporation` → `<ORG_1>oration`，regex 吃不完整 suffix | 修正 `ORG_PATTERN`，使用 non-capturing group 確保 suffix 完整匹配 |
| `UUID` | 原邏輯「勾選才遮蔽」與其他選項語意相反 | 改成預設遮蔽，勾選才保留 |

---

## GUI 設計

### 勾選框（全部語意：勾選 = 保留明文）

| 勾選框文字 | 對應 entity | 預設值 |
|---|---|---|
| 保留時間資訊（攻擊時間線分析） | `DATE_TIME` | ✅ 預設勾選 |
| 保留公開 IP（C2 位址分析） | `EXT_IP` | 未勾選 |
| 保留網域（IOC 分析） | `DOMAIN` | 未勾選 |
| 保留加密錢包地址（勒索 IOC） | `CRYPTO` | 未勾選 |
| 保留 UUID / Machine Code（行為路徑分析） | `UUID` | 未勾選 |

### 佈局

現有 2 個勾選框區域（`opt_frame`）擴充為 5 個，分兩列排列：
- 第一列：保留時間資訊、保留公開 IP、保留網域
- 第二列：保留加密錢包地址、保留 UUID / Machine Code

視窗高度從 640 調整為 700 以容納額外列。

---

## 架構變動

### `deidentify.py` — `build_engines()`

**現有簽名：**
```python
def build_engines(redact_uuid: bool, custom_id_patterns: List[str] = None)
```

**新簽名：**
```python
def build_engines(options: Dict[str, bool] = None, custom_id_patterns: List[str] = None)
```

`options` 支援的 key（全部預設 False = 遮蔽）：

```python
{
    "keep_datetime":    False,  # True = 不掛入 DateRecognizer
    "keep_public_ip":  False,  # True = redact_ip_literals 跳過公開 IP
    "keep_domain":     False,  # True = 不掛入 DOMAIN recognizer
    "keep_crypto":     False,  # True = 不掛入 CryptoRecognizer
    "keep_uuid":       False,  # True = 不掛入 UUID recognizer
}
```

CLI 的 `--redact-uuid` 旗標轉換為 `options["keep_uuid"] = False`（行為不變）。

### `engine.py` — `run()`

options dict 直接透傳給 `build_engines()`，移除原有的 `redact_uuid` 單獨處理。

新 options key 對應：

```python
options = {
    "keep_datetime":   bool,
    "keep_public_ip":  bool,
    "keep_domain":     bool,
    "keep_crypto":     bool,
    "keep_uuid":       bool,
}
```

### `gui.py`

5 個 `BooleanVar` + `CTkCheckBox`，傳給 `engine.run(options=...)`：

```python
self._keep_datetime  = ctk.BooleanVar(value=True)   # 預設勾選
self._keep_public_ip = ctk.BooleanVar(value=False)
self._keep_domain    = ctk.BooleanVar(value=False)
self._keep_crypto    = ctk.BooleanVar(value=False)
self._keep_uuid      = ctk.BooleanVar(value=False)
```

---

## 測試策略

### 新增測試檔：`tests/test_entity_options.py`

每個新增 entity 覆蓋：
1. 預設（遮蔽）：輸出不含原始值
2. 保留選項開啟：輸出含原始值

ORG bug regression：
- `Microsoft Corporation paid` → 輸出為 `<ORG_1> paid`（完整遮蔽，無殘缺）

UUID 語意變更：
- 預設：UUID 被遮蔽
- `keep_uuid=True`：UUID 保留明文

### 現有測試

42 個現有測試全部必須繼續通過（不得破壞現有行為）。

---

## 實作順序

1. 修 `ORG_PATTERN` bug → 補 regression test（RED → GREEN）
2. 重構 `build_engines()` 改 options dict → 更新所有呼叫點
3. 新增 CRYPTO / IBAN_CODE / DATE_TIME / US_PASSPORT entity → TDD
4. UUID 語意改為預設遮蔽 → 更新測試
5. 更新 `engine.py` options 傳遞
6. 更新 `gui.py` 5 個勾選框
7. 跑全部測試（目標 50+ 通過）
8. 重新打包 EXE
