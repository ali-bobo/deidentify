# Log De-identification Tool

將日誌中的個人資訊（IP、Email、使用者名、中文姓名、MAC Address 等）自動替換為匿名佔位符，產出可安全對外分享的去識別化版本，並保留僅在本地存放的還原對照表。

核心引擎使用 [Microsoft Presidio](https://github.com/microsoft/presidio) 的 NLP 識別框架，在本地離線運行，不對外傳送任何資料。

---

## 打包為 EXE（開發者）

需先安裝依賴與 PyInstaller：

```bash
pip install -r requirements.txt
pip install pyinstaller
```

> `requirements.txt` 已包含 `customtkinter` 與 `tkinterdnd2`，無需額外安裝。

接著在專案根目錄執行：

```bash
python -m PyInstaller deidentify-tool.spec --noconfirm
```

打包完成後，執行檔位於 `dist/deidentify-tool/deidentify-tool.exe`。

> **注意事項**
> - 打包約需 2–5 分鐘，過程中出現 `WARNING` 屬正常現象
> - 打包環境需與目標平台相同（Windows 打 Windows 版）
> - `dist/` 與 `build/` 已加入 `.gitignore`，不會進入版本控制

---

## 使用方式（EXE）

直接執行 `deidentify-tool.exe`，不需安裝 Python 環境。

### 步驟

1. **選擇檔案**：點擊「＋ 選擇檔案」或將檔案拖曳至視窗
   - 支援格式：`.log` `.txt` `.csv` `.json`
2. **設定保留選項**：勾選不需遮蔽的欄位（時間、公開 IP、網域等）
3. **點擊「開始去識別化」**

### 輸出

| 位置 | 說明 |
|------|------|
| `deidentified_output/` | 去識別化後的檔案，可對外分享 |
| `deidentify_mapping/` | 還原對照表，**請勿對外傳送** |

### 自訂黑名單

複製 `rules.yaml.example` 為 `rules.yaml`，填入需要額外遮蔽的關鍵字，或直接在 GUI 的「⚙ 黑名單」中編輯。

---

## 自動偵測的資訊類型

| 類型 | 說明 |
|------|------|
| 中文姓名 / CJK | 中文字元序列 |
| Email | 電子郵件地址 |
| IP 位址 | IPv4 / IPv6，可選擇保留公開 IP |
| MAC Address | `AA:BB:CC` 與 `AA-BB-CC` 格式 |
| 網域 | 可選擇保留（IOC 分析用） |
| 日期時間 | 可選擇保留（攻擊時間線分析用） |
| UUID | 可選擇保留（行為路徑關聯用） |
| 加密錢包地址 | BTC/ETH 等，可選擇保留 |
| 台灣身分證字號 | 格式驗證 |
| 信用卡號 | Luhn 演算法驗證 |
| 員工編號 | 格式 A-NNNNNN |
| 命令列憑證 | `--password`、`/credential:`、`net user` 等格式 |
| 機密 JSON 欄位 | `token`、`api_key` 等鍵值對 |

---

## 安全說明

- **完全離線**：不連接任何外部服務
- **對照表保密**：`deidentify_mapping/` 含有原始值，絕對不能上傳
- **密碼需輪換**：遮蔽密碼後仍應輪換憑證，遮蔽不等同撤銷

---

## 授權

本專案以 [MIT License](LICENSE) 發布。

核心 NLP 識別能力來自 [Microsoft Presidio](https://github.com/microsoft/presidio)（MIT License，© Microsoft Corporation）。詳細第三方授權請見 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
