# -*- coding: utf-8 -*-
"""
gui.py — Log De-identification Tool GUI
"""

import sys
import threading
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog
try:
    import tkinterdnd2 as _dnd
    _DND_AVAILABLE = True
except ImportError:
    _dnd = None
    _DND_AVAILABLE = False

from engine import DeidentifyEngine, ALLOWED_SUFFIXES

_ANIM_FRAMES = ["(＞ω＜)", "(≧ω≦)", "( ˘ω˘)", "(＾ω＾)", "( •ω•)"]
_ANIM_INTERVAL_MS = 300
_TIMEOUT_SECONDS = 120

EXE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent


def _get_engine() -> DeidentifyEngine:
    return DeidentifyEngine(exe_dir=EXE_DIR)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Log De-identification Tool")
        self.geometry("620x680")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        if _DND_AVAILABLE:
            _dnd.TkinterDnD._require(self)

        self._files: list[Path] = []
        self._engine = _get_engine()
        self._rules_info = self._engine.load_rules_if_present()

        self._build_ui()

    def _build_ui(self):
        # ── 頂部狀態列（規則檔）──
        rules_text = self._rules_status_text()
        rules_color = "#4ade80" if self._rules_info["loaded"] else "#facc15"
        self._rules_label = ctk.CTkLabel(
            self, text=rules_text, anchor="w",
            text_color=rules_color, font=ctk.CTkFont(size=12),
        )
        self._rules_label.pack(fill="x", padx=20, pady=(12, 4))

        # ── 步驟 1：選擇檔案 ──
        hdr1 = ctk.CTkFrame(self, fg_color="transparent")
        hdr1.pack(fill="x", padx=20, pady=(4, 2))
        ctk.CTkLabel(hdr1, text="1", width=22, height=22,
                     fg_color="#1f6aa5", corner_radius=11,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(hdr1, text="選擇日誌檔",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr1, text=".log .txt .csv .json",
                     text_color="gray", font=ctk.CTkFont(size=11)).pack(side="left", padx=8)
        ctk.CTkButton(hdr1, text="＋ 選擇檔案",
                      command=self._on_select_files,
                      width=100, height=28).pack(side="right")

        # 檔案清單（沒有檔案時顯示提示）
        self._file_frame = ctk.CTkScrollableFrame(self, height=100)
        self._file_frame.pack(fill="x", padx=20, pady=(0, 6))
        if _DND_AVAILABLE:
            # CTkScrollableFrame 的可視區域是 _parent_canvas（tkinter.Canvas）
            # tkinterdnd2 把 drop_target_register/dnd_bind patch 到 BaseWidget，canvas 繼承它
            _dnd_canvas = self._file_frame._parent_canvas
            _dnd_canvas.drop_target_register(_dnd.DND_FILES)
            _dnd_canvas.dnd_bind("<<Drop>>", self._on_drop)
            # _parent_frame 是放子 widget 的內層 frame，也一起綁以覆蓋完整區域
            _dnd_inner = self._file_frame._parent_frame
            _dnd_inner.drop_target_register(_dnd.DND_FILES)
            _dnd_inner.dnd_bind("<<Drop>>", self._on_drop)
        self._refresh_file_list()

        # ── 步驟 2：保留不遮蔽的欄位 ──
        hdr2 = ctk.CTkFrame(self, fg_color="transparent")
        hdr2.pack(fill="x", padx=20, pady=(4, 2))
        ctk.CTkLabel(hdr2, text="2", width=22, height=22,
                     fg_color="#1f6aa5", corner_radius=11,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(hdr2, text="保留不遮蔽的欄位",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr2, text="勾選 ＝ 保留明文",
                     text_color="gray", font=ctk.CTkFont(size=11)).pack(side="left", padx=8)

        self._keep_datetime  = ctk.BooleanVar(value=True)
        self._keep_public_ip = ctk.BooleanVar(value=False)
        self._keep_domain    = ctk.BooleanVar(value=False)
        self._keep_crypto    = ctk.BooleanVar(value=False)
        self._keep_uuid      = ctk.BooleanVar(value=False)
        self._keep_mac       = ctk.BooleanVar(value=False)

        opts_frame = ctk.CTkFrame(self, fg_color="transparent")
        opts_frame.pack(fill="x", padx=28, pady=(0, 6))

        checkboxes = [
            ("時間資訊（攻擊時間線）",          self._keep_datetime),
            ("公開 IP（C2 分析）",              self._keep_public_ip),
            ("網域（IOC 分析）",                self._keep_domain),
            ("加密錢包地址（勒索 IOC）",        self._keep_crypto),
            ("UUID / Machine Code（行為路徑）", self._keep_uuid),
            ("MAC Address（設備識別）",         self._keep_mac),
        ]
        for i, (label, var) in enumerate(checkboxes):
            row, col = divmod(i, 2)
            ctk.CTkCheckBox(opts_frame, text=label, variable=var).grid(
                row=row, column=col, sticky="w", padx=(0, 24), pady=3,
            )

        # ── 按鈕列（黑名單 + 對照表 + 開始）──
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(6, 4))
        ctk.CTkButton(btn_row, text="⚙ 黑名單",
                      command=self._on_edit_rules,
                      width=90, height=42,
                      fg_color="#2d2d2d", hover_color="#3a3a3a",
                      border_width=1, border_color="#555",
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 6))
        ctk.CTkButton(btn_row, text="🔍 對照表",
                      command=self._on_view_mapping,
                      width=90, height=42,
                      fg_color="#2d2d2d", hover_color="#3a3a3a",
                      border_width=1, border_color="#555",
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 8))
        self._run_btn = ctk.CTkButton(
            btn_row, text="開始去識別化",
            command=self._on_run,
            height=42, font=ctk.CTkFont(size=15, weight="bold"),
        )
        self._run_btn.pack(side="left", fill="x", expand=True)

        # ── 進度條 ──
        self._progress = ctk.CTkProgressBar(self)
        self._progress.set(0)
        self._progress.pack(fill="x", padx=20, pady=(0, 2))

        # ── 進度動畫列（小生物 + 行數）──
        anim_row = ctk.CTkFrame(self, fg_color="transparent")
        anim_row.pack(fill="x", padx=20, pady=(0, 4))
        self._anim_label = ctk.CTkLabel(
            anim_row, text="", width=90,
            font=ctk.CTkFont(size=14),
        )
        self._anim_label.pack(side="left")
        self._progress_label = ctk.CTkLabel(
            anim_row, text="",
            text_color="gray", font=ctk.CTkFont(size=11),
        )
        self._progress_label.pack(side="left", padx=8)
        self._anim_running = False
        self._anim_frame_idx = 0

        # ── 執行結果 ──
        result_hdr = ctk.CTkFrame(self, fg_color="transparent")
        result_hdr.pack(fill="x", padx=20)
        ctk.CTkLabel(result_hdr, text="執行結果",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(side="left")
        self._stats_label = ctk.CTkLabel(result_hdr, text="",
                                         text_color="gray",
                                         font=ctk.CTkFont(size=11),
                                         anchor="e")
        self._stats_label.pack(side="right")

        self._result_box = ctk.CTkTextbox(
            self, height=220, state="disabled",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self._result_box.pack(fill="x", padx=20, pady=(4, 12))

    # ------------------------------------------------------------------
    # 事件處理
    # ------------------------------------------------------------------

    def _on_edit_rules(self):
        if hasattr(self, "_rules_win") and self._rules_win.winfo_exists():
            self._rules_win.focus()
            return
        self._rules_win = RulesEditor(self, self._engine, self._on_rules_saved)

    def _on_view_mapping(self):
        if hasattr(self, "_mapping_win") and self._mapping_win.winfo_exists():
            self._mapping_win.focus()
            return
        self._mapping_win = MappingViewer(self, EXE_DIR / "deidentify_mapping")

    def _on_rules_saved(self):
        self._rules_info = self._engine.load_rules_if_present()
        rules_color = "#4ade80" if self._rules_info["loaded"] else "#facc15"
        self._rules_label.configure(
            text=self._rules_status_text(),
            text_color=rules_color,
        )

    def _on_drop(self, event):
        raw = event.data
        # tkinterdnd2 在 Windows 回傳 {path with spaces} 或 path1 path2
        paths = self.tk.splitlist(raw)
        skipped = []
        for p in paths:
            path = Path(p)
            if not path.is_file():
                continue
            if path.suffix.lower() not in ALLOWED_SUFFIXES:
                skipped.append(path.name)
                continue
            if path not in self._files:
                self._files.append(path)
        self._refresh_file_list()
        if skipped:
            self._log(f"⚠ 略過不支援的格式：{', '.join(skipped)}")

    def _on_select_files(self):
        exts = " ".join(f"*{s}" for s in sorted(ALLOWED_SUFFIXES))
        paths = filedialog.askopenfilenames(
            title="選擇日誌檔",
            filetypes=[("所有支援格式", exts)],
        )
        for p in paths:
            path = Path(p)
            if path not in self._files:
                self._files.append(path)
        self._refresh_file_list()

    def _on_remove_file(self, path: Path):
        self._files = [f for f in self._files if f != path]
        self._refresh_file_list()

    def _on_run(self):
        if not self._files:
            self._log("⚠ 請先選擇至少一個檔案")
            return

        self._run_btn.configure(state="disabled", text="執行中…")
        self._progress.set(0)
        self._clear_log()
        self._stats_label.configure(text="")
        self._start_anim()

        options = {
            "keep_datetime":   self._keep_datetime.get(),
            "keep_public_ip":  self._keep_public_ip.get(),
            "keep_domain":     self._keep_domain.get(),
            "keep_crypto":     self._keep_crypto.get(),
            "keep_uuid":       self._keep_uuid.get(),
            "keep_mac":        self._keep_mac.get(),
        }
        results_container = []

        # 120 秒 watchdog
        _timed_out = threading.Event()
        def _watchdog():
            _timed_out.set()
            self.after(0, self._on_timeout)
        watchdog = threading.Timer(_TIMEOUT_SECONDS, _watchdog)
        watchdog.daemon = True
        watchdog.start()

        def _on_progress(filename, file_idx, total_files, line_count):
            if _timed_out.is_set():
                return
            pct = (file_idx + 0.5) / max(total_files, 1)
            line_str = f"{line_count:,} 行" if line_count else ""
            label = f"處理中 {filename}　{line_str}"
            self.after(0, self._progress.set, pct)
            self.after(0, self._progress_label.configure, {"text": label})

        def _worker():
            try:
                results = self._engine.run(self._files, options=options,
                                           progress_cb=_on_progress)
                results_container.extend(results)
            finally:
                watchdog.cancel()
            if not _timed_out.is_set():
                self.after(0, self._show_results, results_container)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_timeout(self):
        self._stop_anim()
        self._progress.set(0)
        self._progress_label.configure(text="")
        self._run_btn.configure(state="normal", text="開始去識別化")
        self._log(f"✗ 逾時：處理超過 {_TIMEOUT_SECONDS} 秒，請拆分大檔或聯繫開發者")

    def _show_results(self, results):
        self._stop_anim()
        out_dir = EXE_DIR / "deidentified_output"
        for r in results:
            icon = "✓" if r["success"] else "✗"
            name = r["file"].name
            if r["success"]:
                self._log(f"{icon} {name}  →  完成")
            else:
                self._log(f"{icon} {name}  →  失敗：{r['error']}")

        success = sum(1 for r in results if r["success"])
        self._stats_label.configure(text=f"{success} 檔案  ·  輸出 → {out_dir.name}/")
        self._log(f"輸出位置：{out_dir}")
        self._progress.set(1)
        self._progress_label.configure(text="")
        self._run_btn.configure(state="normal", text="開始去識別化")

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def _start_anim(self):
        self._anim_running = True
        self._anim_frame_idx = 0
        self._tick_anim()

    def _stop_anim(self):
        self._anim_running = False
        self._anim_label.configure(text="")

    def _tick_anim(self):
        if not self._anim_running:
            return
        frame = _ANIM_FRAMES[self._anim_frame_idx % len(_ANIM_FRAMES)]
        self._anim_label.configure(text=frame)
        self._anim_frame_idx += 1
        self.after(_ANIM_INTERVAL_MS, self._tick_anim)

    def _refresh_file_list(self):
        for w in self._file_frame.winfo_children():
            w.destroy()

        if not self._files:
            hint = "尚未選擇檔案　·　點擊「＋ 選擇檔案」或拖曳至此區域" if _DND_AVAILABLE \
                   else "尚未選擇檔案，請點擊右上角「＋ 選擇檔案」"
            ctk.CTkLabel(self._file_frame,
                         text=hint,
                         text_color="gray", font=ctk.CTkFont(size=12)).pack(pady=8)
            return

        for path in self._files:
            size_kb = path.stat().st_size / 1024 if path.exists() else 0
            size_str = f"{size_kb/1024:.1f} MB" if size_kb > 1024 else f"{size_kb:.0f} KB"
            row = ctk.CTkFrame(self._file_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"  {path.name}",
                         anchor="w").pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(row, text=size_str,
                         text_color="gray",
                         font=ctk.CTkFont(size=11)).pack(side="right", padx=(0, 8))
            ctk.CTkButton(row, text="✕", width=28, height=24,
                          command=lambda p=path: self._on_remove_file(p),
                          fg_color="transparent", hover_color="#555").pack(side="right")

    def _rules_status_text(self) -> str:
        info = self._rules_info
        if info["loaded"]:
            return f"☑ 規則檔已載入　{info['keywords']} 個關鍵字 · {info['patterns']} 個 regex"
        return "⚠ 未找到 rules.yaml，僅使用內建規則"

    def _log(self, text: str):
        self._result_box.configure(state="normal")
        self._result_box.insert("end", text + "\n")
        self._result_box.see("end")
        self._result_box.configure(state="disabled")

    def _clear_log(self):
        self._result_box.configure(state="normal")
        self._result_box.delete("1.0", "end")
        self._result_box.configure(state="disabled")


class MappingViewer(ctk.CTkToplevel):
    """去識別化對照表查詢視窗（唯讀）。"""

    _COL_WIDTHS = (200, 280, 120)
    _COL_HEADERS = ("佔位符", "原始值", "類型")

    def __init__(self, parent, mapping_dir: Path):
        super().__init__(parent)
        self.title("去識別化對照表")
        self.geometry("660x520")
        self.resizable(True, True)

        self._mapping_dir = mapping_dir
        self._rows: list[tuple[str, str, str]] = []   # (placeholder, original, entity_type)
        self._filtered: list[tuple[str, str, str]] = []
        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", self._on_search_change)

        self._build_ui()
        self._load_mapping()

    def _build_ui(self):
        # 搜尋列
        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(search_row, text="搜尋：",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self._search_entry = ctk.CTkEntry(
            search_row, textvariable=self._search_var,
            placeholder_text="輸入佔位符或原始值…", width=300,
        )
        self._search_entry.pack(side="left", padx=8, fill="x", expand=True)
        self._count_label = ctk.CTkLabel(
            search_row, text="", text_color="gray",
            font=ctk.CTkFont(size=11),
        )
        self._count_label.pack(side="right")

        # 欄位標頭
        hdr = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=0)
        hdr.pack(fill="x", padx=16)
        for i, (title, w) in enumerate(zip(self._COL_HEADERS, self._COL_WIDTHS)):
            ctk.CTkLabel(hdr, text=title, width=w, anchor="w",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#93c5fd").grid(row=0, column=i, padx=6, pady=6, sticky="w")

        # 資料列（ScrollableFrame）
        self._data_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._data_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # 底部：重新載入 + 警告
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=16, pady=(0, 12))
        ctk.CTkLabel(footer, text="⚠ 此檔案含敏感資料，請勿傳送至外部",
                     text_color="#f59e0b", font=ctk.CTkFont(size=11),
                     anchor="w").pack(side="left")
        ctk.CTkButton(footer, text="↺ 重新載入", width=90, height=28,
                      command=self._load_mapping,
                      fg_color="#2d2d2d", hover_color="#3a3a3a",
                      border_width=1, border_color="#555",
                      font=ctk.CTkFont(size=11)).pack(side="right")

    def _load_mapping(self):
        import json
        self._rows.clear()
        if self._mapping_dir.exists():
            for jf in sorted(self._mapping_dir.glob("*.json")):
                try:
                    data = json.loads(jf.read_text(encoding="utf-8"))
                    mapping = data.get("mapping", {})
                    for entity_type, entries in mapping.items():
                        if isinstance(entries, dict):
                            for placeholder, original in entries.items():
                                self._rows.append((placeholder, str(original), entity_type))
                except (json.JSONDecodeError, OSError):
                    pass

        if not self._rows:
            self._rows.append(("（尚無對照資料，請先執行去識別化）", "", ""))

        self._search_var.set("")
        self._apply_filter("")

    def _on_search_change(self, *_):
        self._apply_filter(self._search_var.get())

    def _apply_filter(self, query: str):
        q = query.strip().lower()
        if q:
            self._filtered = [
                r for r in self._rows
                if q in r[0].lower() or q in r[1].lower() or q in r[2].lower()
            ]
        else:
            self._filtered = list(self._rows)

        self._count_label.configure(text=f"{len(self._filtered)} 筆")
        self._render_rows()

    def _render_rows(self):
        for w in self._data_frame.winfo_children():
            w.destroy()

        alt = False
        for placeholder, original, entity_type in self._filtered:
            bg = "#1e1e2e" if alt else "transparent"
            row = ctk.CTkFrame(self._data_frame, fg_color=bg, corner_radius=4)
            row.pack(fill="x", pady=1)
            for col_idx, (text, w) in enumerate(zip((placeholder, original, entity_type), self._COL_WIDTHS)):
                ctk.CTkLabel(
                    row, text=text, width=w, anchor="w",
                    font=ctk.CTkFont(family="Consolas", size=11),
                    wraplength=w - 10,
                ).grid(row=0, column=col_idx, padx=6, pady=4, sticky="w")
            alt = not alt


class RulesEditor(ctk.CTkToplevel):
    """黑名單編輯子視窗。"""

    def __init__(self, parent: App, engine: DeidentifyEngine, on_saved):
        super().__init__(parent)
        self.title("編輯黑名單規則")
        self.geometry("500x620")
        self.resizable(False, True)
        self.grab_set()  # 鎖定焦點在子視窗

        self._engine = engine
        self._on_saved = on_saved
        rules = engine.get_rules()
        self._keywords: list[str] = list(rules["block"])
        self._patterns: list[str] = list(rules["block_patterns"])

        self._build_ui()

    def _build_ui(self):
        # ── 底部固定區必須最先 pack，才能真正釘在底部 ──
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=20, pady=(8, 16))
        self._err_label = ctk.CTkLabel(bottom, text="", text_color="#f87171",
                                       font=ctk.CTkFont(size=11), anchor="w")
        self._err_label.pack(fill="x", pady=(0, 6))
        ctk.CTkButton(bottom, text="儲存並關閉",
                      command=self._save,
                      height=38, font=ctk.CTkFont(size=13, weight="bold"),
                      ).pack(fill="x")

        # ── 關鍵字區 ──
        ctk.CTkLabel(self, text="關鍵字　（直接字串比對，不分大小寫）",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     anchor="w").pack(fill="x", padx=20, pady=(16, 4))

        self._kw_frame = ctk.CTkScrollableFrame(self, height=110)
        self._kw_frame.pack(fill="x", padx=20, pady=(0, 6))

        kw_add_row = ctk.CTkFrame(self, fg_color="transparent")
        kw_add_row.pack(fill="x", padx=20, pady=(0, 10))
        self._kw_entry = ctk.CTkEntry(kw_add_row, placeholder_text="輸入關鍵字，如 ProjectX")
        self._kw_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._kw_entry.bind("<Return>", lambda _: self._add_keyword())
        ctk.CTkButton(kw_add_row, text="＋ 新增", width=80,
                      command=self._add_keyword).pack(side="left")

        # ── Regex 規則區 ──
        ctk.CTkLabel(self, text="Regex 規則　（進階，支援正規表達式）",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     anchor="w").pack(fill="x", padx=20, pady=(4, 4))

        self._pat_frame = ctk.CTkScrollableFrame(self, height=100)
        self._pat_frame.pack(fill="x", padx=20, pady=(0, 6))

        pat_add_row = ctk.CTkFrame(self, fg_color="transparent")
        pat_add_row.pack(fill="x", padx=20, pady=(0, 6))
        self._pat_entry = ctk.CTkEntry(pat_add_row, placeholder_text=r"如 PROJ-\d+  或  SRV\d{3}")
        self._pat_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._pat_entry.bind("<Return>", lambda _: self._add_pattern())
        ctk.CTkButton(pat_add_row, text="＋ 新增", width=80,
                      command=self._add_pattern).pack(side="left")

        self._refresh_kw()
        self._refresh_pat()

    # ── 關鍵字操作 ──

    def _refresh_kw(self):
        for w in self._kw_frame.winfo_children():
            w.destroy()
        if not self._keywords:
            ctk.CTkLabel(self._kw_frame, text="（尚無關鍵字）",
                         text_color="gray").pack(pady=6)
            return
        for kw in self._keywords:
            self._make_item_row(self._kw_frame, kw,
                                lambda k=kw: self._remove_keyword(k))

    def _add_keyword(self):
        val = self._kw_entry.get().strip()
        if not val:
            return
        if val not in self._keywords:
            self._keywords.append(val)
            self._refresh_kw()
        self._kw_entry.delete(0, "end")

    def _remove_keyword(self, kw: str):
        self._keywords = [k for k in self._keywords if k != kw]
        self._refresh_kw()

    # ── Regex 操作 ──

    def _refresh_pat(self):
        for w in self._pat_frame.winfo_children():
            w.destroy()
        if not self._patterns:
            ctk.CTkLabel(self._pat_frame, text="（尚無 regex 規則）",
                         text_color="gray").pack(pady=6)
            return
        for pat in self._patterns:
            self._make_item_row(self._pat_frame, pat,
                                lambda p=pat: self._remove_pattern(p))

    def _add_pattern(self):
        import re
        val = self._pat_entry.get().strip()
        if not val:
            return
        try:
            re.compile(val)
        except re.error as exc:
            self._err_label.configure(text=f"無效的 regex：{exc}")
            return
        self._err_label.configure(text="")
        if val not in self._patterns:
            self._patterns.append(val)
            self._refresh_pat()
        self._pat_entry.delete(0, "end")

    def _remove_pattern(self, pat: str):
        self._patterns = [p for p in self._patterns if p != pat]
        self._refresh_pat()

    # ── 共用列元件 ──

    def _make_item_row(self, parent, text: str, on_remove):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text=f"  {text}", anchor="w",
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(row, text="✕", width=28, height=24,
                      command=on_remove,
                      fg_color="transparent", hover_color="#7f1d1d",
                      text_color="#f87171").pack(side="right")

    # ── 儲存 ──

    def _save(self):
        err = self._engine.save_rules(self._keywords, self._patterns)
        if err:
            self._err_label.configure(text=err)
            return
        self._on_saved()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
