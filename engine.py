# -*- coding: utf-8 -*-
"""
engine.py — DeidentifyEngine

GUI 邏輯層，將 deidentify.py 的核心函數包裝成可測試的類別。
與介面完全分離：不 import 任何 GUI 套件。
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None

from deidentify import (
    build_engines,
    build_operator_configs,
    load_rules,
    process_file,
)

ALLOWED_SUFFIXES = {".log", ".txt", ".csv", ".json"}


class DeidentifyEngine:
    """去識別化執行引擎，供 GUI 和測試使用。"""

    def __init__(self, exe_dir: Path):
        self.exe_dir = Path(exe_dir)
        self._rules: Dict[str, List] = {"block": [], "block_patterns": []}
        self._rules_loaded = False
        self._rules_checked = False

    def load_rules_if_present(self) -> Dict[str, Any]:
        """尋找 exe_dir/rules.yaml，存在則載入。

        回傳 {"loaded": bool, "keywords": int, "patterns": int}
        """
        # 優先讀取 exe 旁的使用者版本，找不到再用 _internal/ 的預設版本
        rules_path = self.exe_dir / "rules.yaml"
        if not rules_path.exists():
            internal = self.exe_dir / "_internal" / "rules.yaml"
            if internal.exists():
                rules_path = internal

        self._rules_checked = True
        if not rules_path.exists():
            self._rules = {"block": [], "block_patterns": []}
            self._rules_loaded = False
            return {"loaded": False, "keywords": 0, "patterns": 0}

        self._rules = load_rules(rules_path)
        self._rules_loaded = True
        return {
            "loaded": True,
            "keywords": len(self._rules["block"]),
            "patterns": len(self._rules["block_patterns"]),
        }

    def get_rules(self) -> Dict[str, List]:
        """回傳目前載入的規則（供 GUI 編輯用）。"""
        return {
            "block": list(self._rules.get("block", [])),
            "block_patterns": list(self._rules.get("block_patterns", [])),
        }

    def save_rules(self, block: List[str], block_patterns: List[str]) -> str:
        """驗證並儲存規則到 rules.yaml，重新載入後回傳狀態文字。

        回傳錯誤訊息字串；空字串代表成功。
        """
        for pat in block_patterns:
            try:
                re.compile(pat)
            except re.error as exc:
                return f"無效的 regex：{pat!r} — {exc}"

        if yaml is None:
            return "缺少 PyYAML，無法儲存"

        rules_path = self.exe_dir / "rules.yaml"
        data = {"block": block, "block_patterns": block_patterns}
        rules_path.write_text(
            yaml.dump(data, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
        self._rules = {"block": block, "block_patterns": block_patterns}
        self._rules_loaded = True
        self._rules_checked = True
        return ""

    def run(self, files: List[Path], options: Dict[str, Any],
            progress_cb=None) -> List[Dict[str, Any]]:
        """對 files 執行去識別化，回傳每個檔案的結果。

        options 支援：
          keep_public_ip (bool, 預設 False)
          redact_uuid    (bool, 預設 False)

        progress_cb(filename: str, file_index: int, total_files: int, line_count: int)
          在每個檔案開始處理前呼叫。

        回傳 list of:
          {"file": Path, "success": bool, "output": Path|None, "error": str|None}
        """
        if not self._rules_checked:
            self.load_rules_if_present()

        keywords = list(self._rules.get("block", []))
        block_patterns = list(self._rules.get("block_patterns", []))

        output_dir = self.exe_dir / "deidentified_output"
        mapping_dir = self.exe_dir / "deidentify_mapping"

        analyzer, anonymizer, entities = build_engines(
            options=options, custom_id_patterns=[]
        )
        keep_public_ip = options.get("keep_public_ip", False)
        entity_mapping: Dict = {}
        operators = build_operator_configs(entity_mapping, entities)

        results = []
        all_secret_lines: Dict = {}
        source_files = []
        total_files = len(files)

        for idx, path in enumerate(files):
            path = Path(path)
            source_files.append(str(path))

            if progress_cb is not None:
                line_count = 0
                if path.exists() and path.suffix.lower() in ALLOWED_SUFFIXES:
                    try:
                        line_count = sum(1 for _ in path.open("rb"))
                    except OSError:
                        pass
                progress_cb(path.name, idx, total_files, line_count)

            if not path.exists():
                results.append({
                    "file": path,
                    "success": False,
                    "output": None,
                    "error": f"找不到檔案：{path.name}",
                })
                continue

            if path.suffix.lower() not in ALLOWED_SUFFIXES:
                results.append({
                    "file": path,
                    "success": False,
                    "output": None,
                    "error": f"不支援的檔案格式 {path.suffix!r}，僅接受 {', '.join(sorted(ALLOWED_SUFFIXES))}",
                })
                continue

            try:
                out_path, _enc, _fmt, secrets, _edr = process_file(
                    path, analyzer, anonymizer, entity_mapping, entities, operators,
                    keep_public_ip, keywords, output_dir,
                    max_mb=10.0, do_dedup=True, mapping_dir=mapping_dir,
                    block_patterns=block_patterns,
                )
                if secrets:
                    all_secret_lines[path.name] = secrets
                # EDR 路徑 out_path 為 None，輸出在 output_dir 下
                if out_path is None:
                    out_path = output_dir / (path.stem + "_parsed_deidentified.json")
                results.append({
                    "file": path,
                    "success": True,
                    "output": out_path,
                    "error": None,
                })
            except Exception as exc:
                results.append({
                    "file": path,
                    "success": False,
                    "output": None,
                    "error": str(exc),
                })

        # 寫 mapping 檔（只要有成功處理的檔案就寫）
        if any(r["success"] for r in results):
            import json
            mapping_dir.mkdir(parents=True, exist_ok=True)
            first_success = next(r["file"] for r in results if r["success"])
            map_path = mapping_dir / (first_success.stem + "_mapping.json")
            map_path.write_text(json.dumps({
                "_warning": "SENSITIVE — local use only. Never upload this mapping file.",
                "source_files": source_files,
                "mapping": entity_mapping,
                "secret_lines": all_secret_lines,
            }, ensure_ascii=False, indent=2), encoding="utf-8")

        return results
